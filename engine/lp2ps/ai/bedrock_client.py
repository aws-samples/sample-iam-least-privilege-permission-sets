"""Grounded Bedrock invoke 래퍼 (하네스 §4a).

자유 생성이 아니라 **구조화된 하네스**로 Bedrock 을 감싼다:
- structured output: Converse API + JSON 스키마 지시 → pydantic 으로 검증(자유 텍스트 결정 없음).
- grounding gate: 호출 전 참조 principal/action 이 grounding 셋에 있는지 assert(anti-hallucination
  전단), 호출 후 출력의 cited action/principal 이 grounding 밖이면 거부·flag(후단 verifier).
- 재시도: 스키마 검증 실패·throttle 시 제한 재시도. 재시도가 무의미한 종료 사유는 즉시 예외.
- Hard separation: 결정 경로(위험·정책·IaC)는 이 모듈을 import 하지 않는다(불변식 ③).

`ai.enabled=false` 면 이 모듈은 로드/호출되지 않는다(assistant 라우터만 조건부 import).

Trust boundary (see invoke_structured): externally-sourced text -- IAM action strings taken
verbatim from member-account policy documents, and the operator's question -- is passed as
`guardContent` blocks so the guardrail trace says which segment tripped, and so our own instructions
are not themselves submitted for prompt-attack evaluation.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, ValidationError

from .grounding import GroundingSet, HallucinationError, verify_output_actions

if TYPE_CHECKING:  # pragma: no cover
    pass

T = TypeVar("T", bound=BaseModel)

_MAX_RETRIES = 2

# Stop reasons for which retrying the identical request cannot succeed. Retrying wastes latency and
# tokens and, worse, hides the real cause behind a generic schema-validation error three calls later.
#   - guardrail_intervened / content_filtered: the request was blocked. The body of
#     output.message.content[0].text is the guardrail's blockedInputMessaging, not JSON, so schema
#     validation fails for a reason that has nothing to do with the schema.
#   - max_tokens / model_context_window_exceeded: the response was truncated. The JSON is cut
#     mid-token, so it cannot parse; a retry at temperature=0 truncates at the same place.
#   - malformed_model_output / malformed_tool_use: the service itself judged the output malformed.
#   - stop_sequence / tool_use: not configured by this caller; treated as terminal rather than
#     silently retried, so an unexpected change surfaces instead of costing 3x.
# Enumerated from the live service model (botocore bedrock-runtime StopReason) rather than from the
# docs, so this list matches what the API can actually return.
_TERMINAL_STOP_REASONS = frozenset(
    {
        "guardrail_intervened",
        "content_filtered",
        "max_tokens",
        "model_context_window_exceeded",
        "malformed_model_output",
        "malformed_tool_use",
        "stop_sequence",
        "tool_use",
    }
)

# 가드레일 system 프롬프트(prompts.GUARDRAIL_SYSTEM 와 함께 사용). 결정에 쓰는 자유텍스트 금지.
_JSON_INSTRUCTION = (
    "\n\nRespond with ONLY a single valid JSON object matching this schema (no prose, no markdown "
    "fences):\n{schema}\n"
)


class AiDisabledError(RuntimeError):
    """ai.enabled=false 인데 AI 경로를 호출했을 때(코어가 실수로 부르면 드러남)."""


class TerminalStopReason(RuntimeError):
    """Converse ended for a reason that makes retrying the same request pointless.

    Carries the stop reason and, when the guardrail intervened, a *summary* of the trace: which
    policy fired and which guarded segment it fired on. The trace itself is never carried or
    logged wholesale -- `GuardrailPiiEntityFilter.match` holds the matched substring and
    `GuardrailTraceAssessment.modelOutput` holds generated text, so both would leak prompt/output
    content into logs.
    """

    def __init__(self, stop_reason: str, detail: str = "", blocked: dict | None = None) -> None:
        super().__init__(f"Converse stopped with stopReason={stop_reason}{detail and f': {detail}'}")
        self.stop_reason = stop_reason
        self.blocked = blocked or {}

    @property
    def is_block(self) -> bool:
        """True when the request was refused by a guardrail rather than truncated/malformed."""
        return self.stop_reason in ("guardrail_intervened", "content_filtered")


def invoke_structured(
    model_id: str,
    system: str,
    prompt: str,
    schema: type[T],
    grounding: GroundingSet,
    *,
    region: str = "us-west-2",
    max_tokens: int = 1024,
    guarded_data: str | None = None,
    guarded_query: str | None = None,
) -> T:
    """Bedrock Converse 호출 → schema(pydantic) 검증 → grounding 후단 verify → 인스턴스 반환.

    출력이 grounding 밖 action/principal 을 지어내면 HallucinationError. 스키마 불일치는 재시도.

    Trust boundary. `prompt` is our own instruction text and is sent as a plain content block.
    `guarded_data` and `guarded_query` are externally-sourced text and are sent inside separate
    `guardContent` blocks. This narrows what the guardrail evaluates to the trust boundary, which
    buys two things:

      - Trace attributability. The assessment names which segment tripped, so a block on collected
        IAM metadata is distinguishable from a block on what the operator typed. The audit event
        emitted by the assistant router depends on this.
      - Our own instructions are not themselves submitted for prompt-attack evaluation. A developer
        instruction and an override attempt look alike to that filter; our system prompt and QA
        instruction are structurally "ignore other instructions, follow this schema". Keeping them
        out reduces the false-positive surface, and the evaluated payload stays smaller.

    Not a precondition. An earlier version of this docstring read the documented "If there are no
    tags, prompt attacks for those use cases will not be filtered" as meaning a bare guardrailConfig
    buys no prompt-attack filtering at all, and justified the split on that basis. Direct observation
    on this API does not support that reading -- see lp2ps-finding2-measurements.md for the probe
    conditions -- so the split is a scoping choice, not load-bearing for coverage. Commit 0cd6dc8's
    message still states the withdrawn version.

    The system prompt is deliberately left unguarded -- "If you don't provide the guardContent
    field, the guardrail doesn't assess the system prompt message."

    Raises TerminalStopReason when Converse ends for a reason that a retry cannot fix (blocked,
    truncated, malformed). That check runs *before* schema validation, so a block surfaces as a
    block instead of as a schema failure after three billed attempts.
    """
    import boto3

    client = boto3.client("bedrock-runtime", region_name=region)
    schema_json = json.dumps(schema.model_json_schema(), ensure_ascii=False)
    sys_text = system + _JSON_INSTRUCTION.format(schema=schema_json)
    masked = _mask_pii(prompt)
    # Externally-sourced segments get the same sanitizing as the instruction text. This runs before
    # the guardrail sees them, which is the intent: hidden-unicode stripping removes the zero-width
    # and bidi characters used to smuggle instructions past a text classifier.
    guarded = [
        (kind, _mask_pii(text))
        for kind, text in (("data", guarded_data), ("query", guarded_query))
        if text
    ]

    last_err: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        resp = _converse_with_retry(client, model_id, sys_text, masked, max_tokens, guarded)

        # Terminal-stop check precedes schema validation: on a guardrail block the text body is the
        # configured blockedInputMessaging, not JSON, and on truncation the JSON is cut mid-token.
        # Validating first would misreport both as "AI 출력이 스키마 검증을 3회 모두 실패".
        stop_reason = resp.get("stopReason", "")
        if stop_reason in _TERMINAL_STOP_REASONS:
            raise TerminalStopReason(
                stop_reason,
                detail=f"attempt {attempt + 1}",
                blocked=_summarize_guardrail_trace(resp),
            )

        text = resp["output"]["message"]["content"][0]["text"]
        try:
            obj = schema.model_validate_json(_extract_json(text))
        except (ValidationError, ValueError) as e:
            last_err = e
            continue  # 스키마 불일치 → 재시도(end_turn 인데 JSON 이 깨진 경우만 여기 온다)

        _verify_grounding(obj, grounding)
        return obj

    raise ValueError(f"AI 출력이 스키마 검증을 {_MAX_RETRIES + 1}회 모두 실패: {last_err}")


def _summarize_guardrail_trace(resp: dict) -> dict:
    """Guardrail trace → minimal, content-free summary of what fired.

    Records policy kind, filter/topic identifiers and the assessment key only. Deliberately omits
    every field that can echo input or output text: `GuardrailPiiEntityFilter.match` (the matched
    substring), `GuardrailTraceAssessment.modelOutput` (generated text), and custom word matches.
    """
    assessments = (resp.get("trace") or {}).get("guardrail") or {}
    out: dict = {}
    for phase in ("inputAssessment", "outputAssessments"):
        for key, entry in (assessments.get(phase) or {}).items():
            # outputAssessments maps to a list, inputAssessment to a single assessment.
            for item in entry if isinstance(entry, list) else [entry]:
                fired: list[str] = []
                for f in (item.get("contentPolicy") or {}).get("filters") or []:
                    if f.get("action") == "BLOCKED":
                        fired.append(f"content:{f.get('type')}:{f.get('confidence')}")
                for t in (item.get("topicPolicy") or {}).get("topics") or []:
                    if t.get("action") == "BLOCKED":
                        fired.append(f"topic:{t.get('name')}")
                for p in (item.get("sensitiveInformationPolicy") or {}).get("piiEntities") or []:
                    if p.get("action") in ("BLOCKED", "ANONYMIZED"):
                        fired.append(f"pii:{p.get('type')}:{p.get('action')}")
                if fired:
                    out.setdefault(phase, {})[key] = sorted(fired)
    return out


def _guardrail_config() -> dict:
    """Guardrail config from the environment, or {} when unconfigured.

    Read inside the call, not at import time: a module-level os.environ.get() freezes the value at
    first import, which in a warm Lambda means a later configuration change never takes effect.
    Absent config yields {} so the assistant still works (degraded, unguarded) rather than failing
    closed on a missing env var -- the guardrail is defense in depth layered on top of the
    structured harness, not the only control.
    """
    import os

    ident = os.environ.get("LP2PS_GUARDRAIL_ID", "").strip()
    version = os.environ.get("LP2PS_GUARDRAIL_VERSION", "").strip()
    if not ident or not version:
        return {}
    return {
        "guardrailIdentifier": ident,
        "guardrailVersion": version,
        # Tracing is what makes a block auditable at all; without it a refusal is indistinguishable
        # from an ordinary answer. Only a content-free summary is ever logged
        # (_summarize_guardrail_trace).
        "trace": "enabled",
    }


def _build_content(prompt: str, guarded: list[tuple[str, str]]) -> list[dict]:
    """Message content blocks: our instructions plain, externally-sourced text in guardContent.

    Qualifiers are intentionally NOT set. `grounding_source`/`query` select the contextual grounding
    policy, which this guardrail does not configure; an unqualified guardContent block is what the
    content filters (including PROMPT_ATTACK) evaluate.

    The split scopes evaluation to the trust boundary; it is not what makes the filter active. See
    invoke_structured.
    """
    content: list[dict] = [{"text": prompt}]
    content += [{"guardContent": {"text": {"text": text}}} for _kind, text in guarded]
    return content


def _converse_with_retry(client, model_id, sys_text, prompt, max_tokens, guarded=()):  # noqa: ANN001
    """Bedrock converse — throttle 시 지수 백오프 재시도(AI 경로라 sleep 허용, 결정론 코어 아님)."""
    import time

    from botocore.exceptions import ClientError

    kwargs: dict = {}
    guardrail = _guardrail_config()
    if guardrail:
        kwargs["guardrailConfig"] = guardrail

    for i in range(_MAX_RETRIES + 1):
        try:
            return client.converse(
                modelId=model_id,
                system=[{"text": sys_text}],
                messages=[{"role": "user", "content": _build_content(prompt, list(guarded))}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
                **kwargs,
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ThrottlingException", "TooManyRequestsException") and i < _MAX_RETRIES:
                time.sleep(2**i)  # 1s, 2s
                continue
            raise
    raise RuntimeError("unreachable")


def _verify_grounding(obj: BaseModel, grounding: GroundingSet) -> None:
    """후단 anti-hallucination: 출력이 인용한 action 이 grounding 밖이면 거부.

    스키마에 cited_actions/cited_principals 필드가 있으면 검사(없으면 통과 — 인용 없는 서술 등).
    """
    data = obj.model_dump()
    cited_actions = data.get("cited_actions") or []
    ungrounded = verify_output_actions(cited_actions, grounding)
    if ungrounded:
        raise HallucinationError(f"AI 가 grounding 밖 action 을 인용: {ungrounded}")
    cited_principals = data.get("cited_principals") or []
    unknown_p = [p for p in cited_principals if p not in grounding.principals]
    if unknown_p:
        raise HallucinationError(f"AI 가 grounding 밖 principal 을 인용: {sorted(unknown_p)}")


def _extract_json(text: str) -> str:
    """모델이 앞뒤에 텍스트/펜스를 붙였을 때 첫 '{' ~ 마지막 '}' 만 취한다."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return text
    return text[start : end + 1]


# 프롬프트 인젝션에 쓰이는 숨은 유니코드(제로폭·양방향 제어·태그 문자) 제거용.
#  - U+200B~200F: zero-width space/joiner + RLM/LRM
#  - U+202A~202E: bidi 임베딩/오버라이드(LRE/RLE/PDF/LRO/RLO)
#  - U+2066~2069: bidi isolate(LRI/RLI/FSI/PDI)
#  - U+FEFF: zero-width no-break space(BOM)
#  - U+E0000~E007F: 태그 문자(비가시 인스트럭션 은닉)
_HIDDEN_UNICODE_RE = None  # 지연 컴파일


def _strip_hidden_unicode(text: str) -> str:
    """LLM 입력에서 비가시/제어 유니코드를 제거(프롬프트 인젝션 은닉 방지,)."""
    import re

    global _HIDDEN_UNICODE_RE
    if _HIDDEN_UNICODE_RE is None:
        # 코드 포인트를 **이스케이프로만** 표기(소스 파일에 literal 비가시 문자를 넣지 않는다 —
        # bandit B613 trojan-source 회피). 범위: 200B~200F, 202A~202E, 2066~2069, FEFF, E0000~E007F.
        _HIDDEN_UNICODE_RE = re.compile(
            "[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff"
            "\U000e0000-\U000e007f]"
        )
    return _HIDDEN_UNICODE_RE.sub("", text)


def _mask_pii(text: str) -> str:
    """프롬프트 PII 마스킹(방어적). ARN 은 분석 대상이라 유지; 액세스키 ID·계정 외 식별자만.

    현 데이터는 ARN·action 위주라 마스킹 대상이 적으나, 자유입력(assistant question)에 섞일
    수 있는 AKIA/ASIA 액세스키 패턴을 마스킹한다.

    마스킹 전후로 숨은 유니코드(zero-width/bidi/tag)를 제거한다 — 비가시 문자로 마스킹
    패턴을 우회하거나 프롬프트 인젝션을 은닉하는 것을 막는다(전: 우회 방지, 후: 잔여 제거).
    """
    import re

    text = _strip_hidden_unicode(text)
    masked = re.sub(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED_KEY]", text)
    return _strip_hidden_unicode(masked)
