"""읽기 전용 강제 테스트 (불변식 ①). moto 로 실제 boto3 클라이언트를 띄워 검증한다."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from lp2ps.awsguard import (
    ReadOnlyViolation,
    guarded_client,
    is_read_only_operation,
    unguarded_idc_client,
)


# ---- 순수 단위: allowlist 판정 ----
@pytest.mark.parametrize(
    "op",
    [
        "ListRoles",
        "GetAccountAuthorizationDetails",
        "DescribeInstances",
        "GenerateCredentialReport",
        "BatchGetTraces",
        "SimulatePrincipalPolicy",
        "LookupEvents",
        "SelectObjectContent",
        "StartPolicyGeneration",  # create-shaped 이나 명시 허용
    ],
)
def test_allowed_operations(op: str) -> None:
    assert is_read_only_operation(op) is True


@pytest.mark.parametrize(
    "op",
    [
        # CloudTrail Lake/Athena 쿼리 실행 오퍼레이션 — Lake 폐기로 _ALLOWED_EXACT 에서 제거됨.
        # Start/Stop 접두는 read 접두가 아니므로 이제 차단된다(Get* 는 일반 read 접두라 별개로 허용).
        "StartQuery",
        "StartQueryExecution",
        "StopQuery",
    ],
)
def test_removed_lake_query_ops_denied(op: str) -> None:
    assert is_read_only_operation(op) is False


@pytest.mark.parametrize(
    "op",
    [
        "CreateRole",
        "DeleteUser",
        "PutRolePolicy",
        "AttachRolePolicy",
        "CreatePermissionSet",
        "UpdateAccessKey",
        "TagRole",  # 쓰기
        "RemoveUserFromGroup",
    ],
)
def test_denied_operations(op: str) -> None:
    assert is_read_only_operation(op) is False


# ---- 통합: 가드가 붙은 클라이언트는 쓰기 API 에서 예외 ----
@mock_aws
def test_guarded_client_blocks_write() -> None:
    session = boto3.Session(region_name="us-west-2")
    iam = guarded_client(session, "iam")
    with pytest.raises(ReadOnlyViolation):
        iam.create_role(RoleName="x", AssumeRolePolicyDocument="{}")


@mock_aws
def test_guarded_client_allows_read() -> None:
    session = boto3.Session(region_name="us-west-2")
    iam = guarded_client(session, "iam")
    # 조회는 통과해야 한다 (moto 빈 계정이라 결과는 빈 목록).
    resp = iam.list_roles()
    assert "Roles" in resp


@mock_aws
def test_guarded_client_blocks_delete() -> None:
    session = boto3.Session(region_name="us-west-2")
    s3 = guarded_client(session, "s3")
    with pytest.raises(ReadOnlyViolation):
        s3.create_bucket(Bucket="should-not-be-created")


# ---- 완화 예외: IdC unguarded 클라이언트는 IdC 서비스에만 허용 ----
@mock_aws
def test_unguarded_idc_only_for_idc_services() -> None:
    session = boto3.Session(region_name="us-west-2")
    # 비-IdC 서비스로는 unguarded 클라이언트를 못 만든다 (실수로 멤버계정 쓰기 방지).
    with pytest.raises(ValueError):
        unguarded_idc_client(session, "iam")


@mock_aws
def test_unguarded_idc_client_created_for_sso_admin() -> None:
    session = boto3.Session(region_name="us-west-2")
    client = unguarded_idc_client(session, "sso-admin")
    assert client is not None
