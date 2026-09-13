"""GET /schedule · PUT /schedule — 주기적 전체 조회 실행 예약(EventBridge).

도구 소유 EventBridge 규칙(engine-stack 이 생성) 하나를 읽고/갱신한다. 규칙 타깃은 이미 Step
Functions 파이프라인으로 배선돼 있으므로, 여기서는 **cron 식과 활성/비활성만** 바꾼다. 멤버계정은
전혀 건드리지 않는다(불변식① — 쓰기는 도구 소유 EventBridge 규칙 한정).

프론트는 빈도 프리셋(daily/weekly/…)을 보내고, 백엔드가 결정론적으로 cron 식으로 변환한다.
🔴 **조회는 그 변환을 되돌린다**(`_from_cron`). 예전에는 `frequency="custom"` 을 무조건 돌려줘서
"매일 02:00 KST" 로 저장한 예약을 다시 열면 프리셋이 사라지고 UTC cron 원문이 떠 있었다 —
고급 기능이 아니라 왕복(save→reload) 결함이었다. `_to_cron` 이 만드는 형태는 결정론적이므로
역매핑도 결정론적이다. 우리 형태와 안 맞는 cron(손으로 만든 규칙)만 `custom` 으로 남긴다 —
API 는 읽기 호환을 위해 `custom` 을 계속 받아들이고, 화면에서만 감춘다.
"""

from __future__ import annotations

import logging
import re
from typing import Literal

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..audit import audit_event
from ..auth import require_auth
from ..deps import get_settings

router = APIRouter(tags=["schedule"])
_log = logging.getLogger("lp2ps.api")

# EventBridge cron 식: 6개 필드 `cron(분 시 일 월 요일 연)`. 여기 저장/반환은 괄호 안 6필드만.
_CRON_FIELDS_RE = re.compile(r"^\S+ \S+ \S+ \S+ \S+ \S+$")


class ScheduleState(BaseModel):
    """현재 예약 상태(GET) / 갱신 요청(PUT) 공통."""

    enabled: bool = False
    # 표시·편집용 빈도 프리셋. custom 이면 cron 을 그대로 사용.
    # Literal 로 경계 검증(잘못된 값은 422) — 에러 메시지에 원값을 에코하지 않는다.
    frequency: Literal["daily", "weekly", "monthly", "custom"] = "daily"
    hour_utc: int = Field(default=2, ge=0, le=23)  # daily/weekly/monthly 기준 실행 시각(UTC)
    day_of_week: int = Field(default=2, ge=1, le=7)  # weekly: 1=일 … 7=토(EventBridge)
    day_of_month: int = Field(default=1, ge=1, le=28)  # monthly: 1~28(월말 회피)
    cron: str = ""  # EventBridge 6필드(괄호 제외). custom 이거나 조회 결과.


def _to_cron(s: ScheduleState) -> str:
    """빈도 프리셋 → EventBridge cron 6필드(결정론). custom 이면 입력 cron 검증 후 그대로."""
    if s.frequency == "custom":
        cron = s.cron.strip()
        if not _CRON_FIELDS_RE.match(cron):
            raise HTTPException(422, "cron 은 6개 필드여야 합니다: `분 시 일 월 요일 연`")
        return cron
    h = s.hour_utc
    if s.frequency == "daily":
        return f"0 {h} * * ? *"
    if s.frequency == "weekly":
        return f"0 {h} ? * {s.day_of_week} *"
    if s.frequency == "monthly":
        return f"0 {h} {s.day_of_month} * ? *"
    # frequency 는 Literal 이라 여기 도달 불가(방어) — 원값 에코 없이 정적 메시지.
    raise HTTPException(422, "지원하지 않는 frequency 입니다.")


def _from_cron(cron: str) -> ScheduleState:
    """cron 6필드 → 프리셋 복원(`_to_cron` 의 역함수). 우리 형태가 아니면 `custom`.

    우리가 만드는 형태는 세 가지뿐이다:
      daily   `0 {h} * * ? *`
      weekly  `0 {h} ? * {dow} *`
      monthly `0 {h} {dom} * ? *`
    분이 0 이 아니거나 월/연이 `*` 가 아니면 우리 것이 아니다 → `custom` 으로 둔다(422 를 내지
    않는다. 손으로 만든 규칙을 조회만 하다가 화면이 깨지면 예약을 고칠 방법이 없어진다).
    """
    base = ScheduleState(enabled=False, frequency="custom", cron=cron)
    parts = cron.split()
    if len(parts) != 6:
        return base
    minute, hour, dom, month, dow, year = parts
    if minute != "0" or month != "*" or year != "*" or not hour.isdigit():
        return base
    h = int(hour)
    if not 0 <= h <= 23:
        return base
    if dom == "*" and dow == "?":
        return ScheduleState(enabled=False, frequency="daily", hour_utc=h, cron=cron)
    if dom == "?" and dow.isdigit() and 1 <= int(dow) <= 7:
        return ScheduleState(enabled=False, frequency="weekly", hour_utc=h,
                             day_of_week=int(dow), cron=cron)
    if dow == "?" and dom.isdigit() and 1 <= int(dom) <= 28:
        return ScheduleState(enabled=False, frequency="monthly", hour_utc=h,
                             day_of_month=int(dom), cron=cron)
    return base


def _events_client():
    return boto3.client("events", region_name=get_settings().region)


@router.get("/schedule")
def get_schedule() -> ScheduleState:
    """EventBridge 규칙 조회 → 현재 예약 상태. 규칙 미설정이면 비활성 기본값."""
    s = get_settings()
    if not s.schedule_rule_name:
        return ScheduleState(enabled=False)
    try:
        r = _events_client().describe_rule(Name=s.schedule_rule_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return ScheduleState(enabled=False)
        # AWS 오류 코드를 응답에 노출하지 않는다(정적 메시지 + 내부는 서버 로그).
        _log.exception("EventBridge describe_rule 실패")
        raise HTTPException(502, "스케줄 조회에 실패했습니다.") from e
    # `cron(...)` → 안쪽 6필드만.
    expr = r.get("ScheduleExpression", "")
    cron = expr[5:-1] if expr.startswith("cron(") and expr.endswith(")") else ""
    state = _from_cron(cron)
    state.enabled = r.get("State") == "ENABLED"
    return state


@router.put("/schedule")
def put_schedule(state: ScheduleState, claims: dict = Depends(require_auth)) -> ScheduleState:
    """예약 갱신 — cron 식 + 활성/비활성. 도구 소유 EventBridge 규칙만 쓴다(멤버계정 무관)."""
    s = get_settings()
    if not s.schedule_rule_name:
        raise HTTPException(409, "스케줄 규칙이 배포되지 않았습니다(infra 재배포 필요).")

    cron = _to_cron(state)
    events = _events_client()
    try:
        # ScheduleExpression 은 규칙 생성 시 이미 있으나, cron 을 바꾸려면 put_rule 로 갱신.
        events.put_rule(
            Name=s.schedule_rule_name,
            ScheduleExpression=f"cron({cron})",
            State="ENABLED" if state.enabled else "DISABLED",
        )
    except ClientError as e:
        # AWS 오류 코드 미노출(정적 메시지 + 서버 로그).
        _log.exception("EventBridge put_rule 실패")
        audit_event(action="put_schedule", resource=s.schedule_rule_name, result="failure", claims=claims)
        raise HTTPException(502, "스케줄 갱신에 실패했습니다.") from e

    # 스케줄 변경(write) 감사.
    audit_event(action="put_schedule", resource=s.schedule_rule_name,
                result="success", claims=claims, enabled=state.enabled)
    return ScheduleState(
        enabled=state.enabled,
        frequency=state.frequency,
        hour_utc=state.hour_utc,
        day_of_week=state.day_of_week,
        day_of_month=state.day_of_month,
        cron=cron,
    )
