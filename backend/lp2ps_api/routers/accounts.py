"""GET /accounts — 이번 run 에서 수집된 계정 목록·상태(계정 선택기·필터용).

collection_manifest.json 의 accounts[] 를 노출한다. 관제(tooling) 계정은 is_tooling=True 로 표기
(env LP2PS_TOOLING_ACCOUNT 로 식별). 대시보드 상단 계정 선택기가 이 목록으로 "전체/개별"을 구성한다.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from . import get_repos

router = APIRouter(tags=["accounts"])


class AccountInfo(BaseModel):
    account_id: str
    status: str  # ok | degraded | skipped
    is_tooling: bool = False


@router.get("/accounts")
def list_accounts() -> list[AccountInfo]:
    return [AccountInfo(**a) for a in get_repos().list_accounts()]
