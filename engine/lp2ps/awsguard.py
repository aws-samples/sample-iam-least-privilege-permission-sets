"""읽기 전용 강제 (보안 핵심 불변식 ①).

분석 대상(멤버) 계정 세션의 모든 boto3 클라이언트에 botocore `before-call` 훅을 등록해,
allowlist에 없는 오퍼레이션이 호출되면 실제 API 요청이 나가기 전에 `ReadOnlyViolation`을
던진다(fail-closed). 새 수집 코드가 실수로 쓰기 API를 부르더라도 대상 계정은 변경되지 않는다.

완화 예외(불변식 ① 참조): tooling 계정 IdC의 Permission Set '정의 생성'은 이 가드를 **적용하지
않는** 별도 클라이언트(`unguarded`)로만 수행한다. 멤버계정 세션에는 이 예외가 없다.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session
    from botocore.client import BaseClient


class ReadOnlyViolation(RuntimeError):
    """멤버 계정 세션에서 allowlist 밖(=쓰기 가능성) 오퍼레이션을 시도했을 때."""


# 허용 동사(오퍼레이션 이름 접두). botocore 오퍼레이션명은 PascalCase (예: "ListRoles").
_ALLOWED_PREFIXES: tuple[str, ...] = (
    "Get",
    "List",
    "Describe",
    "Generate",  # GenerateCredentialReport, GenerateServiceLastAccessedDetails 등
    "BatchGet",
    "Simulate",  # SimulatePrincipalPolicy
    "Lookup",  # LookupEvents (CloudTrail)
    "Select",  # SelectObjectContent (S3)
)

# 접두 규칙만으로는 애매한, 계정 미변경이 확인된 개별 허용 오퍼레이션.
# 참고: CloudTrail Lake/Athena 쿼리 오퍼레이션(StartQuery/GetQueryResults/…)은 Lake 를 폐기하고
# LookupEvents 단일 소스로 전환하면서 제거했다(사용 안 하는 권한을 allowlist 에 두지 않는다 — 최소권한 원칙).
_ALLOWED_EXACT: frozenset[str] = frozenset(
    {
        "StartPolicyGeneration",  # Access Analyzer — create-shaped 이나 계정 IAM 미변경
    }
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _operation_name_from_event(event_name: str) -> str:
    """'before-call.iam.ListRoles' → 'ListRoles'."""
    return event_name.rsplit(".", 1)[-1]


def is_read_only_operation(operation_name: str) -> bool:
    """오퍼레이션이 읽기 전용 allowlist를 통과하는지."""
    if operation_name in _ALLOWED_EXACT:
        return True
    return operation_name.startswith(_ALLOWED_PREFIXES)


def _before_call_handler(model, params, **kwargs):  # noqa: ANN001 (botocore 시그니처)
    """botocore before-call 훅. allowlist 밖이면 ReadOnlyViolation."""
    op = model.name  # PascalCase 오퍼레이션명
    if not is_read_only_operation(op):
        raise ReadOnlyViolation(
            f"읽기 전용 위반: '{op}' 는 허용된 조회 오퍼레이션이 아닙니다 "
            f"(분석 대상 계정에는 allowlist verb 만 허용)."
        )
    return None


def attach_readonly_guard(client: "BaseClient") -> "BaseClient":
    """단일 boto3 클라이언트에 읽기 전용 훅을 등록해 반환한다."""
    # 모든 서비스의 모든 오퍼레이션에 대해 before-call 이벤트를 가로챈다.
    client.meta.events.register("before-call", _before_call_handler)
    return client


def guarded_client(session: "Session", service_name: str, **kwargs) -> "BaseClient":
    """읽기 전용 가드가 붙은 클라이언트 생성 — 멤버 계정 접근에 사용."""
    client = session.client(service_name, **kwargs)
    return attach_readonly_guard(client)


def unguarded_idc_client(session: "Session", service_name: str, **kwargs) -> "BaseClient":
    """가드 없는 클라이언트 — **tooling 계정 IdC PS 정의 생성 전용**.

    호출부(provisioning)에서 approved 상태 + UI 2차·최종 확인을 이미 통과했다는 전제로만 사용한다.
    멤버 계정 세션에는 절대 이 함수를 쓰지 않는다.
    """
    if service_name not in {"sso-admin", "identitystore", "sso"}:
        raise ValueError(
            f"unguarded_idc_client 는 IdC 서비스 전용입니다 (요청: {service_name})."
        )
    return session.client(service_name, **kwargs)
