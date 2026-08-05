"""M4 Risk Scorer — 결정론 위험 점수 + 감사 로그.

각 principal 의 위험을 config `risk_rules` 가중치의 **합**으로 계산한다(0-100 클램프). 점수를 만든
규칙·가중치·기여도를 `risk_audit.jsonl` 에 남겨 **완전 재현·설명 가능**하게 한다(감사 요건).

규칙(가중치는 config):
- long_lived_key: access_key_age_days ≥ long_lived_key_days
- no_mfa: user 인데 mfa=false (role/service 는 MFA 개념 없음 → 제외)
- unused_permission: unused_findings 건수 × 가중치(상한)
- escalation_path: escalation_paths 건수 × 가중치(상한)
- wildcard_action: granted 에 '*' 또는 'svc:*'
- admin_like: granted 가 관리자급('*' 단독 또는 'iam:*'+대량)

불변식 ②(결정론): 가중치 합·안정 정렬만, wall-clock/random 없음. 같은 입력 → 같은 점수·같은 audit.
불변식 ③: AI 미사용(순수 결정론). count_90d=0 모호성(#7): Access Advisor 가 used 로 넣은 이상
"사용됨"으로 보고 미사용에서 제외한다(m2 에서 이미 unused_findings 에 안 들어감) — 여기선 재판정 안 함.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .models import PrincipalRecord, RiskLevel

if TYPE_CHECKING:  # pragma: no cover
    from .config import RiskRules
    from .runctx import RunContext
    from .storage import Storage

AUDIT_NAME = "risk_audit.jsonl"

# 결정론 JSONL 직렬화(정렬된 키).
_JSON_KW = {"sort_keys": True, "ensure_ascii": False, "separators": (",", ":")}


def score_risks(storage: "Storage", run: "RunContext", rules: "RiskRules") -> list[PrincipalRecord]:
    """normalized.parquet 을 읽어 risk_* 를 채우고 다시 기록 + risk_audit.jsonl."""
    records = storage.read_normalized()
    audit_lines: list[str] = []

    for rec in records:
        score, reasons, contributions = _score_one(rec, rules)
        rec.risk_score = score
        rec.risk_level = _level(score, rules)
        rec.risk_reasons = reasons
        audit_lines.append(
            json.dumps(
                {
                    "run_id": run.run_id,
                    "principal": rec.principal,
                    "account_id": rec.account_id,
                    "risk_score": score,
                    "risk_level": rec.risk_level,
                    "contributions": contributions,  # [{rule, weight, contribution}]
                },
                **_JSON_KW,
            )
        )

    records.sort(key=lambda r: (r.account_id, r.principal))
    storage.write_normalized(records)

    # audit 도 principal 순 안정 정렬(결정론).
    audit_lines.sort()
    storage.write_text(AUDIT_NAME, "\n".join(audit_lines) + ("\n" if audit_lines else ""))
    return records


def _score_one(rec: PrincipalRecord, rules: "RiskRules") -> tuple[int, list[str], list[dict]]:
    """(clamp 점수, 사람이 읽는 reasons, audit contributions) 반환."""
    contributions: list[dict] = []
    reasons: list[str] = []

    def _add(rule: str, weight: int, hit: bool, reason: str) -> None:
        contribution = weight if hit else 0
        if hit:
            reasons.append(reason)
        contributions.append({"rule": rule, "weight": weight, "contribution": contribution})

    # long_lived_key
    age = rec.access_key_age_days
    hit_key = age is not None and age >= rules.long_lived_key_days
    _add("long_lived_key", rules.weight_long_lived_key, hit_key,
         f"장기 액세스키({age}일 ≥ {rules.long_lived_key_days})")

    # no_mfa (콘솔 로그인 가능한 user 한정 — 서비스 계정은 MFA 무관이라 제외)
    hit_mfa = rec.identity_type == "user" and rec.console_login and not rec.mfa
    _add("no_mfa", rules.weight_no_mfa, hit_mfa, "MFA 미설정 콘솔 사용자")

    # unused_permission (건수 × 가중치, 상한)
    n_unused = len(rec.unused_findings)
    unused_contribution = min(n_unused * rules.weight_unused_permission, rules.weight_unused_permission_cap)
    if n_unused:
        reasons.append(f"미사용 권한/발견 {n_unused}건")
    contributions.append({"rule": "unused_permission", "weight": rules.weight_unused_permission,
                          "contribution": unused_contribution, "count": n_unused,
                          "cap": rules.weight_unused_permission_cap})

    # escalation_path (건수 × 가중치, 상한)
    n_esc = len(rec.escalation_paths)
    esc_contribution = min(n_esc * rules.weight_escalation_path, rules.weight_escalation_cap)
    if n_esc:
        reasons.append(f"권한 상승 경로 {n_esc}건")
    contributions.append({"rule": "escalation_path", "weight": rules.weight_escalation_path,
                          "contribution": esc_contribution, "count": n_esc,
                          "cap": rules.weight_escalation_cap})

    # wildcard_action
    has_wildcard = any("*" in a for a in rec.granted_actions)
    _add("wildcard_action", rules.weight_wildcard_action, has_wildcard, "와일드카드 action 부여('*')")

    # admin_like
    is_admin = _is_admin_like(rec.granted_actions)
    _add("admin_like", rules.weight_admin_like, is_admin, "관리자급 광범위 권한")

    total = sum(c["contribution"] for c in contributions)
    score = max(0, min(100, total))
    reasons.sort()
    return score, reasons, contributions


def _is_admin_like(granted: list[str]) -> bool:
    """관리자급 판정: 전체 와일드카드 단독, 또는 iam 전체 제어."""
    gset = set(granted)
    if "*" in gset:
        return True
    return "iam:*" in gset


def _level(score: int, rules: "RiskRules") -> RiskLevel:
    if score >= rules.level_critical:
        return "critical"
    if score >= rules.level_high:
        return "high"
    if score >= rules.level_medium:
        return "medium"
    return "low"
