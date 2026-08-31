"""M7 Policy Synth — persona 별 최소권한 IAM 정책 합성.

catalog 의 각 persona 에 대해, 멤버들이 **실사용한 action 합집합**으로 최소권한 IAM 정책 JSON 을
`policies/<persona>.json` 에 만든다. `synthesis_source` 를 정책에 라벨링한다:
- last_accessed_evidence: Access Advisor(서비스별 최종 사용) 또는 IAM Access Analyzer 미사용 발견이
  근거에 기여함 → 고신뢰(catalog 에서 승계). CloudTrail 은 이 등급 판정에 들어가지 않는다.
- fallback_used_actions: 위 소스 없이 관측된 used action 합집합만 → 저신뢰

Access Analyzer Policy Generation(StartPolicyGeneration)은 계정별·비동기라 로컬 파이프라인에서는
catalog 의 used action(이미 수집됨)으로 합성한다 — StartPolicyGeneration 은 allowlist(계정 미변경)이나
M7 통합은 추후. included=false 로 사람이 토글한 action 은 제외(PolicyReview 편집 반영).

불변식 ②(결정론): action 정렬·안정 직렬화. 불변식 ③: AI 미사용.
정책은 리소스 '*' 로 두되(스코핑은 사람/Access Analyzer 후속), action 최소화가 핵심 산출.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import CatalogEntry

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

POLICIES_DIR = "policies"


def synth_policies(storage: "Storage", run: "RunContext") -> dict[str, dict]:
    """catalog.json → policies/<persona>.json 다수. 반환 = {persona: policy_doc}."""
    catalog = _load_catalog(storage)
    out: dict[str, dict] = {}

    for entry in catalog:
        policy = _policy_for(entry)
        key = f"{POLICIES_DIR}/{entry.persona}.json"
        storage.write_json(key, policy)
        out[entry.persona] = policy
    return out


def _policy_for(entry: CatalogEntry) -> dict:
    """persona 의 included action → 최소권한 정책 문서(IAM policy JSON)."""
    actions = sorted({a.action for a in entry.actions if a.included})

    statements = []
    if actions:
        statements.append(
            {
                "Sid": _sid(entry.persona),
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",  # 리소스 스코핑은 후속(Access Analyzer/사람). action 최소화가 M7 핵심.
            }
        )

    return {
        "Version": "2012-10-17",
        # 메타는 별도 키(정책 문서 표준 밖) — synthesis_source 추적용. IaC emitter 가 벗겨낸다.
        "_lp2ps": {
            "persona": entry.persona,
            "synthesis_source": entry.synthesis_source,
            "member_count": entry.member_count,
            "action_count": len(actions),
        },
        "Statement": statements,
    }


def _sid(persona: str) -> str:
    """정책 Sid 는 영숫자만 허용 → persona 명 정제."""
    return "".join(ch for ch in persona if ch.isalnum()) or "Lp2psPersona"


def _load_catalog(storage: "Storage") -> list[CatalogEntry]:
    raw = storage.read_json("catalog.json")
    return [CatalogEntry.model_validate(e) for e in raw]  # type: ignore[union-attr]
