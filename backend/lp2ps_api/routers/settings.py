"""GET /settings/deployment — 화면 구성을 가르는 배포 성격(읽기 전용).

GET /settings/ai · PUT /settings/ai — AI 개입 기능 런타임 ON/OFF.

AI(어시스턴트 Q&A, 향후 persona 제안)는 Bedrock 비용이 발생하므로 운영 중 즉시 켜고 끌 수 있어야
한다. config yaml(`ai.enabled`)은 재배포가 필요해 런타임 토글에 부적합하므로, 상태를 **SSM
Parameter Store**(`/lp2ps/<customer>/ai_enabled`)에 저장한다. 파라미터가 없으면 config 값으로 폴백.

쓰기 대상은 도구 소유 SSM 파라미터 하나뿐 — 멤버계정 무관(불변식①). AI 자체는 순수 가산(불변식③):
이 토글이 꺼지면 어시스턴트는 안내만 반환하고, 결정론 산출물은 영향 없다.
"""

from __future__ import annotations

import json
import os

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..audit import audit_event
from ..auth import require_auth
from ..customer_config import uses_identity_center
from ..deps import get_settings

router = APIRouter(tags=["settings"])


class DeploymentSettings(BaseModel):
    """이 배포의 성격 — 화면이 무엇을 보여줄지 가른다.

    uses_identity_center=false 인 고객에게 'PS 마이그레이션 12%' 같은 지표를 보여주면 영구히 달성할
    수 없는 목표를 띄우는 것이 된다(IdC 인스턴스가 없어 분자가 구조적으로 0). 그런 배포에서는
    지표를 '해당 없음' 으로 표시한다. 값의 출처는 config 이며 데이터 추론이 아니다.
    """

    uses_identity_center: bool = True


@router.get("/settings/deployment")
def get_deployment_settings() -> DeploymentSettings:
    """config 유래 배포 성격. 인증 없이 읽는다(AI 토글 GET 과 동일 — 비밀이 아니다)."""
    return DeploymentSettings(uses_identity_center=uses_identity_center())


class AiSettings(BaseModel):
    """AI 개입 기능 활성 상태(GET 응답 / PUT 요청 공통)."""

    enabled: bool = False


def _param_name() -> str:
    return f"/lp2ps/{get_settings().customer}/ai_enabled"


def _ssm():
    return boto3.client("ssm", region_name=get_settings().region)


def _config_default() -> bool:
    """SSM 파라미터가 없을 때의 초기값 — config yaml 의 ai.enabled."""
    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if not inline:
        return False
    return bool(json.loads(inline).get("ai", {}).get("enabled", False))


@router.get("/settings/ai")
def get_ai_settings() -> AiSettings:
    """현재 AI 활성 상태. SSM 우선, 없으면 config 기본값."""
    try:
        p = _ssm().get_parameter(Name=_param_name())
        return AiSettings(enabled=p["Parameter"]["Value"] == "true")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return AiSettings(enabled=_config_default())
        # SSM 조회 실패 시 안전하게 config 기본값(장애가 AI 를 무단 활성화하지 않게).
        return AiSettings(enabled=_config_default())


@router.put("/settings/ai")
def put_ai_settings(state: AiSettings, claims: dict = Depends(require_auth)) -> AiSettings:
    """AI 활성 상태 갱신 — 도구 소유 SSM 파라미터에 저장. 즉시 반영(재배포 불필요)."""
    _ssm().put_parameter(
        Name=_param_name(),
        Value="true" if state.enabled else "false",
        Type="String",
        Overwrite=True,
    )
    # AI 토글 변경(write) 감사.
    audit_event(action="put_ai_settings", resource="ai_enabled",
                result="success", claims=claims, enabled=state.enabled)
    return AiSettings(enabled=state.enabled)


def ai_enabled() -> bool:
    """다른 라우터(assistant 등)가 참조하는 단일 진입점 — SSM 우선, config 폴백."""
    return get_ai_settings().enabled
