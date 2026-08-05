"""IAM Identity Center(IdC) Permission Set 할당 수집 (읽기 전용).

이 계정에 할당된 Permission Set(=사람이 PS 기반으로 접근하는 경로, identity_type='sso_ps')를
나열한다: `ListInstances` → `ListPermissionSets` → 각 PS 별 `ListAccountAssignments`(이 계정 대상).

용도: PS 마이그레이션 **스냅샷 비율** 산출(현재 IAM User 수 vs PS 기반 접근 수). "User→PS 전환을
삭제 추적"하는 것이 아니라(원천 불가), 현재 상태에서 사람 접근이 얼마나 PS 기반인지 본다.

IdC 미설정(list_instances 빈 배열)이면 `skipped` 로 degrade — 대다수 소스처럼 crash 없이 완주.
IdC 는 위임 관리 계정에서만 조회 가능하므로, 멤버 계정 assume 세션에선 보통 skipped 가 정상.

read-only: List*/Describe* 만 사용(awsguard allowlist 통과). 쓰기 없음.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from . import Collector, CollectorResult

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

SOURCE = "idc_permission_sets"


class IdcPermissionSetsCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        # IdC 는 config.region 과 다른 리전일 수 있음(계정당 단일 리전) → idc_region 으로 조회.
        idc_region = context.get("idc_region")
        sso = account.client("sso-admin", region=idc_region)

        try:
            instance = _first_instance(sso)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return _skip(account, f"IdC 조회 실패({code}) — sso_ps 없음으로 처리")

        if instance is None:
            return _skip(account, "IdC instance 미설정 — 이 계정에 Permission Set 접근 없음")

        instance_arn = instance["arn"]
        try:
            assignments = _collect_assignments(sso, instance_arn, account.account_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return _skip(account, f"account assignment 조회 실패({code})")

        return CollectorResult(
            source=SOURCE,
            status="ok",
            data={
                "account_id": account.account_id,
                "instance_arn": instance_arn,
                "identity_store_id": instance.get("identity_store_id", ""),
                "permission_set_assignments": assignments,
            },
            note="" if assignments else "IdC 있으나 이 계정에 할당된 Permission Set 없음",
        )


def _skip(account: "AccountSession", note: str) -> CollectorResult:
    return CollectorResult(
        source=SOURCE,
        status="skipped",
        data={"account_id": account.account_id, "instance_arn": None, "permission_set_assignments": []},
        note=note,
    )


def _first_instance(sso) -> dict | None:
    """IdC instance(ARN·store) 첫 번째. 없으면 None(ID 정렬로 결정론)."""
    instances: list[dict] = []
    paginator = sso.get_paginator("list_instances")
    for page in paginator.paginate():
        for inst in page.get("Instances", []):
            instances.append(
                {"arn": inst["InstanceArn"], "identity_store_id": inst.get("IdentityStoreId", "")}
            )
    instances.sort(key=lambda i: i["arn"])
    return instances[0] if instances else None


def _collect_assignments(sso, instance_arn: str, account_id: str) -> list[dict]:
    """이 계정에 할당된 (permission_set, principal) 목록(안정 정렬).

    각 PS 이름·할당된 principal(USER/GROUP)을 평탄화. principal 하나가 곧 'sso_ps' 접근 1건.
    """
    out: list[dict] = []
    ps_paginator = sso.get_paginator("list_permission_sets")
    ps_arns: list[str] = []
    for page in ps_paginator.paginate(InstanceArn=instance_arn):
        ps_arns.extend(page.get("PermissionSets", []))
    ps_arns.sort()

    for ps_arn in ps_arns:
        ps_name = _ps_name(sso, instance_arn, ps_arn)
        aa_paginator = sso.get_paginator("list_account_assignments")
        for page in aa_paginator.paginate(
            InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn
        ):
            for a in page.get("AccountAssignments", []):
                out.append(
                    {
                        "permission_set_arn": ps_arn,
                        "permission_set_name": ps_name,
                        "principal_id": a.get("PrincipalId", ""),
                        "principal_type": a.get("PrincipalType", ""),  # USER | GROUP
                    }
                )
    out.sort(key=lambda x: (x["permission_set_name"], x["principal_type"], x["principal_id"]))
    return out


def _ps_name(sso, instance_arn: str, ps_arn: str) -> str:
    try:
        desc = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)
        return desc["PermissionSet"].get("Name", ps_arn.rsplit("/", 1)[-1])
    except ClientError:
        return ps_arn.rsplit("/", 1)[-1]
