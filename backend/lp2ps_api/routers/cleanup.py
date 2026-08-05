"""GET /cleanup-backlog — 5유형 cleanup 항목(UI 가 카테고리 요약→드릴다운).

GET /cleanup-backlog/risk-criteria — 위험도 산정 기준(가중치·레벨 경계). 운영자가 "왜 이 항목이
critical/high 인지" 이해하도록 규칙을 노출한다. 임계치는 전부 config(risk_rules)에서 읽는다(불변식④).
"""

from __future__ import annotations

import json
import os

from fastapi import APIRouter
from pydantic import BaseModel

from lp2ps.config import RiskRules
from lp2ps.models import CleanupItem

from . import get_repos

router = APIRouter(tags=["cleanup"])


@router.get("/cleanup-backlog")
def get_cleanup() -> list[CleanupItem]:
    return get_repos().get_cleanup()


class RiskRuleInfo(BaseModel):
    key: str
    label: str
    weight: int
    detail: str


class RiskCriteria(BaseModel):
    """위험도 산정 기준 — 레벨 경계 + 규칙별 가중치. 점수 = hit 한 규칙 가중치 합(0-100)."""

    level_critical: int
    level_high: int
    level_medium: int
    rules: list[RiskRuleInfo]


def _risk_rules() -> RiskRules:
    """api Lambda 의 config(env inline)에서 risk_rules 로드. 없으면 기본값(모델 디폴트)."""
    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if inline:
        data = json.loads(inline).get("risk_rules", {})
        return RiskRules.model_validate(data)
    return RiskRules()


@router.get("/cleanup-backlog/risk-criteria")
def get_risk_criteria() -> RiskCriteria:
    r = _risk_rules()
    rules = [
        RiskRuleInfo(key="long_lived_key", label="장기 액세스키", weight=r.weight_long_lived_key,
                     detail=f"액세스키 사용연수 ≥ {r.long_lived_key_days}일"),
        RiskRuleInfo(key="no_mfa", label="MFA 미설정", weight=r.weight_no_mfa,
                     detail="콘솔 로그인 가능 IAM User 인데 MFA 없음"),
        RiskRuleInfo(key="unused_permission", label="미사용 권한", weight=r.weight_unused_permission,
                     detail=f"미사용 발견 1건당 +{r.weight_unused_permission}(상한 {r.weight_unused_permission_cap})"),
        RiskRuleInfo(key="escalation_path", label="권한 상승 경로", weight=r.weight_escalation_path,
                     detail=f"상승 경로 1건당 +{r.weight_escalation_path}(상한 {r.weight_escalation_cap})"),
        RiskRuleInfo(key="wildcard_action", label="와일드카드 권한", weight=r.weight_wildcard_action,
                     detail="granted 에 '*' 와일드카드 존재"),
        RiskRuleInfo(key="admin_like", label="관리자급 권한", weight=r.weight_admin_like,
                     detail="AdministratorAccess 급 광범위 권한('*' 단독 또는 iam:*)"),
    ]
    return RiskCriteria(
        level_critical=r.level_critical, level_high=r.level_high, level_medium=r.level_medium,
        rules=rules,
    )
