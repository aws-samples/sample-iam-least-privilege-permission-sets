"""Credential Report + Account Authorization Details 수집.

두 native 소스를 묶어 principal 인벤토리의 뼈대를 만든다:
- `GetAccountAuthorizationDetails`(페이지네이션) — 모든 role/user 와 attach/inline 정책
  → granted actions 의 원천. principal 인벤토리를 `context["principals"]` 에 넣어 뒤 collector 가 재사용.
- `GenerateCredentialReport` + `GetCredentialReport` — user 별 MFA·액세스키 나이·마지막 사용
  (CSV). `GenerateCredentialReport` 는 계정 IAM 을 변경하지 않는 report 생성이라 allowlist(Generate) 통과.

미프로비저닝은 아니지만 권한 부족 등으로 실패하면 degraded 로 기록하고 빈 인벤토리로 진행한다.
"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from . import Collector, CollectorResult

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

SOURCE = "credential_report"


class CredentialReportCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        iam = account.client("iam")

        principals = _account_authorization_details(iam)
        cred_rows, cred_note = _credential_report(iam)

        # 뒤 collector(access_advisor, analyzer_unused)가 재조회 없이 쓰도록 공유.
        context["principals"] = principals

        data = {
            "account_id": account.account_id,
            "principals": principals,
            "credential_report": cred_rows,
        }
        # credential report 가 비면 MFA·장기 액세스키 근거가 **전부** 사라진다 — 그런데 인벤토리는
        # 살아 있으니 예전엔 ok 로 보고했다. 그 결과 대시보드는 "장기 액세스키 0" 을 보여주는데,
        # 그건 0건이라는 뜻이 아니라 근거가 없었다는 뜻이다(575 첫 실행에서 실제로 그랬다). 실패는
        # 실패로 말한다 → degraded.
        status = "ok" if principals and not cred_note else "degraded"
        note = cred_note if cred_note else ("" if principals else "principal 인벤토리가 비어 있음")
        return CollectorResult(source=SOURCE, status=status, data=data, note=note)


def _account_authorization_details(iam) -> list[dict]:
    """role + user 인벤토리(정책 포함)를 결정론 순서로 수집.

    반환 각 항목: {principal(ARN), name, identity_type, inline_policies[], attached_policies[],
    path, tags{}, (role 만)trust_policy{}}.
    granted actions 추출과 신뢰정책 해석은 M2(normalizer)에서 수행한다.
    """
    principals: list[dict] = []
    paginator = iam.get_paginator("get_account_authorization_details")
    # User/Role 만 — Group/LocalManagedPolicy 는 정책 문서 참조로 M2 에서 필요 시 확장.
    for page in paginator.paginate(Filter=["User", "Role"]):
        for role in page.get("RoleDetailList", []):
            principals.append(_role_record(role))
        for user in page.get("UserDetailList", []):
            principals.append(_user_record(user))
    principals.sort(key=lambda p: p["principal"])
    return principals


def _role_record(role: dict) -> dict:
    # trust_policy/tags 는 같은 GetAccountAuthorizationDetails 응답에 이미 들어 있다 —
    # 추가 API 호출도 추가 IAM 권한도 없다. botocore 가 AssumeRolePolicyDocument 를 dict 로
    # 디코드해 주므로(URL 인코딩 해제) 그대로 저장한다. M2 가 사용 주체(사람/서비스)를 가르는 근거.
    return {
        "principal": role["Arn"],
        "name": role["RoleName"],
        "identity_type": "role",
        "inline_policies": _inline(role.get("RolePolicyList", [])),
        "attached_policies": _attached(role.get("AttachedManagedPolicies", [])),
        "path": role.get("Path", "/"),
        "trust_policy": role.get("AssumeRolePolicyDocument") or {},
        "tags": _tags(role.get("Tags", [])),
    }


def _user_record(user: dict) -> dict:
    return {
        "principal": user["Arn"],
        "name": user["UserName"],
        "identity_type": "user",
        "inline_policies": _inline(user.get("UserPolicyList", [])),
        "attached_policies": _attached(user.get("AttachedManagedPolicies", [])),
        "path": user.get("Path", "/"),
        # user 는 신뢰정책이 없다(자기 자격으로 직접 로그인) → trust_policy 없음.
        "tags": _tags(user.get("Tags", [])),
    }


def _tags(tag_list: list[dict]) -> dict[str, str]:
    """IAM Tags([{Key,Value}]) → {키: 값}. 키 정렬로 결정론 유지(불변식 ②)."""
    return {t["Key"]: t.get("Value", "") for t in sorted(tag_list, key=lambda t: t.get("Key", "")) if t.get("Key")}


def _inline(policy_list: list[dict]) -> list[dict]:
    out = [
        {"name": p.get("PolicyName", ""), "document": p.get("PolicyDocument", {})}
        for p in policy_list
    ]
    out.sort(key=lambda p: p["name"])
    return out


def _attached(managed: list[dict]) -> list[dict]:
    out = [
        {"name": p.get("PolicyName", ""), "arn": p.get("PolicyArn", "")} for p in managed
    ]
    out.sort(key=lambda p: p["arn"])
    return out


# credential report 생성은 **비동기**다. 그 계정에서 처음 만드는(또는 만료된) 경우
# GetCredentialReport 가 즉시 ReportInProgress 로 실패한다 — 575 첫 실행에서 실제로 그랬고,
# MFA·액세스키 근거가 통째로 빠진 채 run 은 '성공' 으로 보였다. 생성은 보통 수 초라 짧게 기다린다.
_REPORT_WAIT_SECONDS = (2, 3, 5, 5, 5, 5, 5)  # 누적 30초


def _credential_report(iam) -> tuple[list[dict], str]:
    """credential report CSV → user 별 dict 목록(안정 정렬). 실패 시 ([], note)."""
    import time

    try:
        iam.generate_credential_report()  # 비동기 생성 트리거 (계정 미변경)
        resp = None
        for i, wait in enumerate((0, *_REPORT_WAIT_SECONDS)):
            if wait:
                time.sleep(wait)  # 대기는 시간 소모일 뿐 산출물에 wall-clock 을 남기지 않는다(불변식②)
            try:
                resp = iam.get_credential_report()
                break
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                if code not in ("ReportInProgress", "ReportNotPresent"):
                    raise
                if i == len(_REPORT_WAIT_SECONDS):
                    return [], (f"credential report 생성 대기 시간 초과({code}) — MFA·액세스키 근거 없음"
                                f"(다음 실행에서 채워집니다)")
        if resp is None:  # pragma: no cover - 방어(루프는 위에서 반드시 반환/탈출한다)
            return [], "credential report 조회 실패: Unknown"
    except ClientError as e:  # 권한 부족 등 — 완주 위해 degraded
        return [], f"credential report 조회 실패: {e.response.get('Error', {}).get('Code', 'Unknown')}"

    content = resp.get("Content", b"")
    text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
    reader = csv.DictReader(io.StringIO(text))
    rows = [dict(row) for row in reader]
    rows.sort(key=lambda r: r.get("arn", r.get("user", "")))
    return rows, ""
