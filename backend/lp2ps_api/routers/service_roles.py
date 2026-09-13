"""GET /service-roles — 트랙② (기계가 쓰는 현역 역할)의 서비스 단위 접기 산출물.

트랙② 는 persona 로 **묶지 않는다**. Lambda 실행 역할 둘을 한 정책으로 묶으면 서로의 권한을 얻어
최소권한의 반대가 되기 때문이다(`m5_service_roles` 참조). 그래서 이 라우터는 카탈로그처럼 묶음을
내지 않고 역할별 항목을 그대로 낸다 — `group_key` 는 **표시만** 접기 위한 값이다.

접기·판단 필요 서비스 수(`decision_count`) 계산은 전부 엔진(M5, 결정론 코어)에서 끝난다. 여기서 다시 세지 않는다: 같은 권한이
화면과 산출물에서 다르게 읽히는 순간 어느 쪽이 맞는지 아무도 모른다.

쓰기 없음(순수 read). 조치는 사람이 AWS 에서 하고, 이 도구는 대상 계정에 쓰지 않는다.
"""

from __future__ import annotations

from fastapi import APIRouter

from lp2ps.models import ServiceRoleEntry

from . import get_repos

router = APIRouter(tags=["service-roles"])


@router.get("/service-roles")
def get_service_roles() -> list[ServiceRoleEntry]:
    """트랙② 대상 목록. 대상이 0 이면 빈 목록이다(404 아님 — 0 은 정상 상태다)."""
    return get_repos().get_service_roles()
