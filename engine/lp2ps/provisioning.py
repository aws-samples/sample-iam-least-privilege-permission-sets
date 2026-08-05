"""Permission Set '정의' 생성 — 읽기전용 불변식의 **유일한 완화 예외**(불변식 ① — CONTRIBUTING.md 참조).

tooling 계정 IdC 에 한해 persona 승인 후 Permission Set 정의(CreatePermissionSet +
PutInlinePolicyToPermissionSet)를 생성한다. 강제 가드:
- (i) **approved 상태**의 persona 만 — 호출부(provision-ps)가 확인.
- (ii) UI 2차+최종 확인 필수 — provision-ps 엔드포인트 호출 자체가 확인 후 액션.
- (iii) **account assignment 는 절대 안 함** — 멤버계정 권한 부여는 사람이 수동(assignment_skipped=True).
- (iv) 이 write 는 **unguarded_idc_client(sso-admin 전용)** 으로만 — 멤버계정 세션엔 read-only 훅 유지.

멤버계정 assume 세션은 이 모듈을 절대 쓰지 않는다(awsguard 가드가 그대로).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .awsguard import unguarded_idc_client
from .models import ProvisionResult

if TYPE_CHECKING:  # pragma: no cover
    import boto3


def provision_permission_set(
    session: "boto3.Session",
    instance_arn: str,
    persona: str,
    inline_policy_json: str,
    provisioned_at: str,
    *,
    region: str = "us-west-2",
    session_duration: str = "PT8H",
) -> ProvisionResult:
    """tooling IdC 에 Permission Set 정의 생성(+inline policy). account assignment 은 안 함.

    이미 존재하면 재사용(멱등). 실패는 예외로 전파(호출부가 처리).
    """
    sso = unguarded_idc_client(session, "sso-admin", region_name=region)

    ps_name = _ps_name(persona)
    ps_arn = _find_existing(sso, instance_arn, ps_name)
    created = False
    if ps_arn is None:
        resp = sso.create_permission_set(
            Name=ps_name,
            InstanceArn=instance_arn,
            # IdC description 은 ASCII/Latin-1( -~,¡-ÿ)만 허용 — em-dash 등 금지.
            Description=f"LP2PS least-privilege - {persona}",
            SessionDuration=session_duration,
            Tags=[{"Key": "ManagedBy", "Value": "lp2ps"}, {"Key": "Persona", "Value": persona}],
        )
        ps_arn = resp["PermissionSet"]["PermissionSetArn"]
        created = True

    # inline policy 주입(최소권한 합성 결과). account assignment 은 여기 없음(불변식 ①).
    sso.put_inline_policy_to_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=ps_arn,
        InlinePolicy=inline_policy_json,
    )

    return ProvisionResult(
        persona=persona,
        permission_set_arn=ps_arn,
        created=created,
        provisioned_at=provisioned_at,
    )


def _ps_name(persona: str) -> str:
    """Permission Set 이름(영숫자·하이픈, 32자 제한 고려)."""
    cleaned = "".join(ch if (ch.isalnum() or ch in "-_") else "" for ch in persona)
    return (cleaned or "Lp2psPersona")[:32]


def _find_existing(sso, instance_arn: str, ps_name: str) -> str | None:
    """이름이 같은 Permission Set 이 이미 있으면 그 ARN(멱등 재프로비저닝)."""
    paginator = sso.get_paginator("list_permission_sets")
    for page in paginator.paginate(InstanceArn=instance_arn):
        for arn in page.get("PermissionSets", []):
            desc = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=arn)
            if desc["PermissionSet"]["Name"] == ps_name:
                return arn
    return None
