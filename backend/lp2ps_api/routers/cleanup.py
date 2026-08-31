"""GET /cleanup-backlog — 5유형 cleanup 항목(UI 가 카테고리 요약→드릴다운).

GET /cleanup-backlog/risk-criteria — 위험도 산정 기준(가중치·레벨 경계). 운영자가 "왜 이 항목이
critical/high 인지" 이해하도록 규칙을 노출한다. 임계치는 전부 config(risk_rules)에서 읽는다(불변식④).

PUT /cleanup-backlog/{finding_key}/status — 조치 상태 표시(미조치/조치완료/보류). 실제 조치는 사람이
AWS 콘솔·Terraform 으로 수행하고(이 도구는 대상 계정에 쓰지 않는다), 여기엔 **그 사실을 기록**만 한다.
그래서 상태는 도구 소유 DynamoDB(findings)에 있고 엔진 산출물에는 없다(불변식 ②).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from lp2ps.config import RiskRules
from lp2ps.models import CleanupItem, CleanupStatus

from ..audit import audit_event
from ..auth import require_auth
from ..repositories import FindingsUnavailable
from . import get_repos

router = APIRouter(tags=["cleanup"])

# finding_key 는 엔진이 만드는 sha256 hex 다(m6_reporter.cleanup_finding_key). 경로 파라미터로
# 오므로 형식을 고정해 임의 문자열이 DynamoDB 키로 들어가는 것을 막는다.
FINDING_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


@router.get("/cleanup-backlog")
def get_cleanup() -> list[CleanupItem]:
    return get_repos().get_cleanup()


class SetStatusRequest(BaseModel):
    status: CleanupStatus
    # 조치 근거 메모. IdC 없이 IAM 정책만 다듬어 적용한 경우처럼 "권장 조치와 다른 방법으로
    # 해결했다" 를 남기는 자리다. 길이를 제한해 무한 쓰기를 막는다.
    note: str = Field(default="", max_length=500)


class StatusRecord(BaseModel):
    finding_key: str
    status: CleanupStatus
    note: str
    updated_at: str
    updated_by: str


@router.put("/cleanup-backlog/{finding_key}/status")
def set_cleanup_status(
    finding_key: str, req: SetStatusRequest, claims: dict = Depends(require_auth)
) -> StatusRecord:
    """조치 상태 표시. 대상 계정에는 아무 것도 하지 않는다(기록 전용)."""
    if not FINDING_KEY_RE.match(finding_key):
        raise HTTPException(status_code=400, detail="잘못된 finding_key 형식")
    # 표시 시각은 서버 시각(감사 기록). 엔진 결정론 제약(불변식 ②)은 산출물에만 적용되고, 이건
    # 사람의 행위 기록이라 wall-clock 이 맞다.
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    actor = claims.get("email") or claims.get("sub") or ""
    try:
        rec = get_repos().put_finding_status(
            finding_key, req.status, req.note, updated_by=actor, updated_at=now
        )
    except FindingsUnavailable as e:
        audit_event(action="cleanup_status", resource=finding_key, result="failure",
                    claims=claims, reason="findings_table_unset")
        raise HTTPException(status_code=503, detail="조치 상태 저장소가 배선되지 않았습니다") from e
    audit_event(action="cleanup_status", resource=finding_key, result="success",
                claims=claims, status=req.status)
    return StatusRecord(
        finding_key=rec["id"], status=rec["status"], note=rec["note"],
        updated_at=rec["updated_at"], updated_by=rec["updated_by"],
    )


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
        # 아래 두 문구는 engine `m4_risk_scorer._score_one`/`_is_admin_like` 의 판정식을 그대로
        # 옮긴 것이다. 조건을 바꾸려면 두 곳을 같이 바꿔야 한다 — 화면의 "판정 기준" 이 실제 채점과
        # 어긋나면 사용자는 점수를 재현할 수 없다.
        RiskRuleInfo(key="wildcard_action", label="와일드카드 권한", weight=r.weight_wildcard_action,
                     detail="granted action 에 '*' 가 포함됨(`s3:Get*` 같은 접두 와일드카드도 해당)"),
        RiskRuleInfo(key="admin_like", label="관리자급 권한", weight=r.weight_admin_like,
                     detail="granted 에 '*'(전체 허용) 또는 'iam:*' 가 있음 "
                            "— AdministratorAccess 등 관리형 정책 연결로 들어온 경우 포함"),
    ]
    return RiskCriteria(
        level_critical=r.level_critical, level_high=r.level_high, level_medium=r.level_medium,
        rules=rules,
    )
