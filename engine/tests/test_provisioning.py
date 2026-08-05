"""provisioning 완화 예외 테스트 — PS 정의 생성, account assignment 절대 안 함(불변식 ①)."""

from __future__ import annotations

import boto3
from moto import mock_aws

from lp2ps.provisioning import provision_permission_set

INSTANCE = "arn:aws:sso:::instance/ssoins-123"


@mock_aws
def test_provision_creates_ps_with_inline_policy() -> None:
    result = provision_permission_set(
        session=boto3.Session(region_name="us-west-2"),
        instance_arn=INSTANCE,
        persona="DataPersona",
        inline_policy_json='{"Version":"2012-10-17","Statement":[]}',
        provisioned_at="2026-07-16T00:00:00Z",
    )
    assert result.created is True
    assert result.assignment_skipped is True  # 불변식①: 멤버계정 권한부여 안 함
    assert result.permission_set_arn.startswith("arn:aws:sso:::")

    # inline policy 가 실제로 붙었는지.
    sso = boto3.client("sso-admin", region_name="us-west-2")
    pol = sso.get_inline_policy_for_permission_set(
        InstanceArn=INSTANCE, PermissionSetArn=result.permission_set_arn
    )
    assert "Version" in pol["InlinePolicy"]


@mock_aws
def test_provision_is_idempotent() -> None:
    """같은 persona 재프로비저닝 시 기존 PS 재사용(created=False)."""
    kw = dict(
        session=boto3.Session(region_name="us-west-2"),
        instance_arn=INSTANCE,
        persona="DataPersona",
        inline_policy_json='{"Version":"2012-10-17","Statement":[]}',
        provisioned_at="2026-07-16T00:00:00Z",
    )
    first = provision_permission_set(**kw)
    second = provision_permission_set(**kw)
    assert first.created is True
    assert second.created is False
    assert first.permission_set_arn == second.permission_set_arn


@mock_aws
def test_provision_does_not_create_account_assignment() -> None:
    """account assignment 이 생성되지 않았는지 확인(멤버계정 권한 부여 없음)."""
    result = provision_permission_set(
        session=boto3.Session(region_name="us-west-2"),
        instance_arn=INSTANCE,
        persona="DataPersona",
        inline_policy_json='{"Version":"2012-10-17","Statement":[]}',
        provisioned_at="2026-07-16T00:00:00Z",
    )
    sso = boto3.client("sso-admin", region_name="us-west-2")
    # 이 PS 에 대한 account assignment 이 하나도 없어야 한다.
    accts = sso.list_accounts_for_provisioned_permission_set(
        InstanceArn=INSTANCE, PermissionSetArn=result.permission_set_arn
    )
    assert accts.get("AccountIds", []) == []
