"""POST /assistant/ask — grounded Q&A(AI). ai.enabled=false 면 비활성 안내 반환.

불변식③: AI 는 순수 가산. ai.enabled=false 면 grounded=false 안내(500 아님). enabled 면 catalog+
normalized 로 GroundingSet 구성 → bedrock grounded invoke → anti-hallucination verify → AssistantAnswer.
`lp2ps.ai` 는 enabled 경로에서만 지연 import(코어 아닌 assistant 라우터 한정, 결정 경로와 분리).
"""

from __future__ import annotations

import json
import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from lp2ps.models import AssistantAnswer, Citation

from ..audit import audit_event
from ..auth import require_auth
from . import get_repos

router = APIRouter(tags=["assistant"])


class AskRequest(BaseModel):
    # 길이 제한(1~4000자) — 빈 질문 거부 + LLM 비용/지연 증폭(DoS) 방지. 경계에서 422.
    question: str = Field(..., min_length=1, max_length=4000)


@router.post("/assistant/ask")
def ask(req: AskRequest, claims: dict = Depends(require_auth)) -> AssistantAnswer:
    # 활성 여부는 런타임 토글(SSM, settings 라우터)로 판단 — 대시보드에서 즉시 on/off.
    from .settings import ai_enabled

    # assistant 질의 감사(질문 본문은 남기지 않음 — 프롬프트 미로깅).
    audit_event(action="assistant_ask", resource="assistant", result="request", claims=claims)
    if not ai_enabled():
        return AssistantAnswer(
            answer="AI 어시스턴트가 비활성화되어 있습니다. 대시보드 설정에서 AI 기능을 켜면 "
            "사용할 수 있습니다. 카탈로그·백로그·리포트는 결정론 데이터로 그대로 이용 가능합니다.",
            grounded=False,
            citations=[],
        )
    return _grounded_answer(req.question, _ai_config().get("model", ""))


def _grounded_answer(question: str, model_id: str) -> AssistantAnswer:
    """grounded 하네스로 답변 생성. import·호출 실패는 안전한 미응답으로 degrade(500 안 냄)."""
    try:
        # enabled 경로 전용 지연 import — 코어 결정 경로는 lp2ps.ai 를 import 하지 않음(불변식③).
        from lp2ps.ai.bedrock_client import TerminalStopReason, invoke_structured
        from lp2ps.ai.grounding import GroundingSet, HallucinationError
        from lp2ps.ai.prompts import ASSISTANT_QA_INSTRUCTION, GUARDRAIL_SYSTEM
        from lp2ps.ai.schemas import AssistantAnswerDraft
    except Exception:  # noqa: BLE001 — ai 패키지 미배포 등
        return _unavailable("AI 하네스 로드 실패")

    repos = get_repos()
    catalog = repos.get_catalog()
    cleanup = repos.get_cleanup()
    accounts = repos.list_accounts()
    # grounding 셋 = 카탈로그 principal(멤버 ARN) + persona 명 + 실사용 action + cleanup principal
    # + 계정 ID. cleanup·계정 정보를 넣지 않으면 "575 계정 조치 항목 몇 개?" 같은 질문에 verifier 가
    # 잘못 거부한다. 계정 ID 도 참조 대상이라 principal 화이트리스트에 포함.
    principals: set[str] = set()
    actions: set[str] = set()
    for e in catalog:
        principals.update(e.members)
        principals.add(e.persona)
        actions.update(a.action for a in e.actions)
    for it in cleanup:
        principals.add(it.principal)
    for a in accounts:
        principals.add(a["account_id"])
    grounding = GroundingSet(principals=principals, actions=actions)

    # 프롬프트에 grounding 컨텍스트를 명시(모델이 이 밖을 지어내면 verifier 가 거부).
    #
    # Trust split, by provenance rather than by convenience. `_build_context` returns two parts:
    #   - aggregates: account IDs, item counts by type/risk, persona counts. Computed here from
    #     validated model fields; no collected free text reaches them. Sent as instruction context.
    #   - the persona catalog: persona names come from a closed taxonomy (m5_catalog builds them as
    #     f"{key}Persona" over a fixed domain map), but the **action strings are collected**, taken
    #     verbatim from member-account inline policy documents (m2_normalizer._actions_from_document
    #     copies whatever string is in the Action element with no format validation). That is the
    #     untrusted segment, so it goes inside guardContent along with the operator question.
    aggregates, catalog_block = _build_context(catalog, cleanup, accounts, split=True)

    try:
        draft = invoke_structured(
            model_id=model_id or "us.anthropic.claude-haiku-4-5-20251001-v1:0",
            system=GUARDRAIL_SYSTEM,
            prompt=aggregates + "\n\n" + ASSISTANT_QA_INSTRUCTION,
            schema=AssistantAnswerDraft,
            grounding=grounding,
            region=os.environ.get("AWS_REGION", "us-west-2"),
            guarded_data=catalog_block,
            guarded_query=question,
        )
    except HallucinationError:
        # 후단 verifier 가 grounding 밖 인용을 잡음 → 노출하지 않고 안전 미응답.
        return _unavailable("근거 데이터 밖 내용이 감지되어 답변을 보류했습니다(anti-hallucination).")
    except TerminalStopReason as e:
        # 감사에 남기는 것은 종료 사유와 어느 세그먼트에서 어떤 정책이 걸렸는지 요약뿐 —
        # 질문·프롬프트 본문은 넣지 않는다(audit.py 원칙과 동일).
        audit_event(
            action="assistant_blocked" if e.is_block else "assistant_incomplete",
            resource="assistant",
            result="blocked" if e.is_block else "error",
            stop_reason=e.stop_reason,
            guardrail=e.blocked or None,
        )
        if e.is_block:
            return _unavailable(
                "요청이 안전 정책에 의해 차단되었습니다. 수집된 IAM 메타데이터나 질문에 "
                "허용되지 않는 내용이 포함된 것으로 판단되었습니다."
            )
        return _unavailable(
            "AI 응답이 완성되지 않아 답변을 보류했습니다(응답 길이 초과 등). 질문 범위를 "
            "좁혀 다시 시도해 주세요."
        )
    except Exception:  # noqa: BLE001 — Bedrock 오류 등
        return _unavailable("AI 응답 생성 중 오류가 발생했습니다.")

    citations = [Citation(action=a, source="catalog") for a in draft.cited_actions]
    citations += [Citation(principal=p, source="catalog") for p in draft.cited_principals]
    return AssistantAnswer(answer=draft.answer, grounded=draft.grounded, citations=citations)


def _build_context(catalog, cleanup, accounts, *, split: bool = False):  # noqa: ANN001, ANN201
    """grounding 데이터를 프롬프트 컨텍스트 문자열로.

    persona 카탈로그 + 계정 목록 + 조치 필요 항목(cleanup)의 **계정별·유형별·위험도별 집계**를
    미리 계산해 넣는다. '575 계정 조치 항목 몇 개?' 같은 집계 질문에 LLM 이 세다 틀리지 않도록
    수치는 여기서 확정한다(모델은 표현만).

    split=True 면 `(집계, persona 카탈로그)` 튜플을 반환한다 — 호출부가 카탈로그(수집된 action
    문자열 포함)만 guardContent 로 감싸기 위해 필요하다. 기본값은 기존 단일 문자열(호환).
    """
    lines: list[str] = []

    # 1) 계정 목록·상태
    if accounts:
        lines.append("Accounts analyzed:")
        for a in accounts:
            tag = " (tooling/관제)" if a.get("is_tooling") else ""
            lines.append(f"- {a['account_id']}{tag} · collection status={a.get('status')}")

    # 2) 조치 필요 항목(cleanup) 집계 — 계정별 총계 + 유형별 + 위험도별.
    if cleanup:
        by_acct: dict[str, int] = {}
        by_acct_type: dict[str, dict[str, int]] = {}
        by_acct_risk: dict[str, dict[str, int]] = {}
        for it in cleanup:
            acct = it.account_id
            by_acct[acct] = by_acct.get(acct, 0) + 1
            by_acct_type.setdefault(acct, {})
            by_acct_type[acct][it.type] = by_acct_type[acct].get(it.type, 0) + 1
            by_acct_risk.setdefault(acct, {})
            by_acct_risk[acct][it.risk_level] = by_acct_risk[acct].get(it.risk_level, 0) + 1
        lines.append(f"\nAction items (조치 필요 항목) — total {len(cleanup)} across all accounts:")
        for acct in sorted(by_acct):
            types = ", ".join(f"{t}={n}" for t, n in sorted(by_acct_type[acct].items()))
            risks = ", ".join(f"{r}={n}" for r, n in sorted(by_acct_risk[acct].items()))
            lines.append(f"- account {acct}: {by_acct[acct]} items · by type: {types} · by risk: {risks}")

    # 3) persona → 계정별 멤버 수 집계(persona 가 어느 계정에 얼마나 걸치는지). '575 계정 persona
    #    몇 개?' 류 질문에 답하려면 persona 마다 소속 계정을 명시해야 한다. 멤버 ARN 에서 계정 파싱.
    persona_accounts: dict[str, set[str]] = {}
    for e in catalog:
        accts = {m.split(":")[4] for m in e.members if len(m.split(":")) > 4}
        persona_accounts[e.persona] = accts

    # 계정별 persona 수 요약(집계 질문 대비 — 수치 확정).
    acct_persona_count: dict[str, int] = {}
    for accts in persona_accounts.values():
        for a in accts:
            acct_persona_count[a] = acct_persona_count.get(a, 0) + 1
    if acct_persona_count:
        lines.append("\nPersona count per account:")
        for a in sorted(acct_persona_count):
            lines.append(f"- account {a}: {acct_persona_count[a]} personas")

    # 4) persona 카탈로그(persona·소속 계정·멤버수·대표 action)
    catalog_lines: list[str] = ["Persona catalog:"]
    for e in catalog[:30]:  # 프롬프트 길이 제한
        acts = ", ".join(a.action for a in e.actions[:15])
        accts = ", ".join(sorted(persona_accounts.get(e.persona, set()))) or "-"
        catalog_lines.append(
            f"- persona {e.persona} (accounts: {accts}; {e.member_count} members): {acts}"
        )
    if split:
        return "\n".join(lines), "\n".join(catalog_lines)
    return "\n".join(lines) + "\n\n" + "\n".join(catalog_lines)


def _unavailable(msg: str) -> AssistantAnswer:
    return AssistantAnswer(answer=msg, grounded=False, citations=[])


def _ai_config() -> dict:
    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if not inline:
        return {"enabled": False}
    return json.loads(inline).get("ai", {"enabled": False})
