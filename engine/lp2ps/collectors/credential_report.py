"""Credential Report + Account Authorization Details 수집.

두 native 소스를 묶어 principal 인벤토리의 뼈대를 만든다:
- `GetAccountAuthorizationDetails`(페이지네이션) — 모든 role/user/group, attach/inline 정책,
  그리고 **연결된 관리형 정책의 문서 본문**
  → granted actions 의 원천. principal 인벤토리를 `context["principals"]` 에 넣어 뒤 collector 가 재사용.
- `GenerateCredentialReport` + `GetCredentialReport` — user 별 MFA·액세스키 나이·마지막 사용
  (CSV). `GenerateCredentialReport` 는 계정 IAM 을 변경하지 않는 report 생성이라 allowlist(Generate) 통과.

**Filter 에 정책·그룹을 넣는 이유.** 예전엔 `Filter=["User","Role"]` 이라 관리형 정책은 이름·ARN 만
수집됐고 문서 본문이 없었다. 그러면 granted_actions 가 inline 정책만 담아, 관리형 정책만 붙은
principal 은 부여 권한 0으로 보인다 — 라이브 계정에서 142개 중 62개(44%)가 그랬고, 그중 8개는
AdministratorAccess/PowerUserAccess 를 들고도 risk=low·score=0·권한상승경로 0으로 표시됐다.
같은 응답에 `AWSManagedPolicy`/`LocalManagedPolicy`/`Group` 을 얹으면 **추가 API 호출도 추가 IAM
권한도 없이**(같은 GetAccountAuthorizationDetails 한 번) 문서 본문이 함께 온다.

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

        principals, managed_policies, groups, auth_note = _account_authorization_details(iam)
        cred_rows, cred_note = _credential_report(iam)

        # 뒤 collector(access_advisor, analyzer_unused)가 재조회 없이 쓰도록 공유.
        context["principals"] = principals

        data = {
            "account_id": account.account_id,
            "principals": principals,
            "credential_report": cred_rows,
            # 연결된 관리형 정책의 문서 본문(ARN 정렬). M2 가 attached_policies[].arn 으로 조회해
            # granted_actions 에 합친다.
            "managed_policies": managed_policies,
            # 그룹의 inline/attached 정책. user 의 부여 권한은 그룹 경유분을 포함한다.
            "groups": groups,
        }
        # credential report 가 비면 MFA·장기 액세스키 근거가 **전부** 사라진다 — 그런데 인벤토리는
        # 살아 있으니 예전엔 ok 로 보고했다. 그 결과 대시보드는 "장기 액세스키 0" 을 보여주는데,
        # 그건 0건이라는 뜻이 아니라 근거가 없었다는 뜻이다(575 첫 실행에서 실제로 그랬다). 실패는
        # 실패로 말한다 → degraded.
        notes = [n for n in (cred_note, auth_note) if n]
        if not principals:
            notes.append("principal 인벤토리가 비어 있음")
        # auth_note 가 있으면 관리형 정책 문서를 일부 못 받은 것 → 그 principal 의 부여 권한이
        # 과소 계상된다. 부여 권한 과소 계상은 "미사용 0" 이라는 조용한 거짓말로 이어지므로
        # ok 로 말하지 않는다.
        status = "ok" if principals and not notes else "degraded"
        return CollectorResult(source=SOURCE, status=status, data=data, note="; ".join(notes))


# GetAccountAuthorizationDetails 의 Filter. 정책·그룹까지 넣으면 같은 응답에 정책 문서 본문과
# 그룹 정책이 함께 실려 온다(추가 호출·추가 권한 없음).
_AUTH_FILTER = ["User", "Role", "Group", "AWSManagedPolicy", "LocalManagedPolicy"]


def _account_authorization_details(iam) -> tuple[list[dict], list[dict], list[dict], str]:
    """role/user 인벤토리 + 관리형 정책 문서 + 그룹을 결정론 순서로 수집.

    반환: (principals, managed_policies, groups, note).
    - principals 각 항목: {principal(ARN), name, identity_type, create_date, inline_policies[],
      attached_policies[], path, tags{}, (role 만)trust_policy{}, (user 만)groups[]}
    - managed_policies 각 항목: {arn, name, document{}} — **기본 버전** 문서만.
    - groups 각 항목: {name, path, inline_policies[], attached_policies[]}
    - note: 연결됐는데 문서를 못 받은 정책이 있으면 그 사실(부여 권한 과소 계상 경고).

    granted actions 추출(inline ∪ 관리형 ∪ 그룹)과 신뢰정책 해석은 M2(normalizer)에서 수행한다.
    """
    principals: list[dict] = []
    policies: list[dict] = []
    groups: list[dict] = []
    no_default: list[str] = []
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=_AUTH_FILTER):
        for role in page.get("RoleDetailList", []):
            principals.append(_role_record(role))
        for user in page.get("UserDetailList", []):
            principals.append(_user_record(user))
        for group in page.get("GroupDetailList", []):
            groups.append(_group_record(group))
        for pol in page.get("Policies", []):
            doc = _default_version_document(pol)
            if doc is None:
                # 기본 버전 표시가 없으면 어느 문서가 유효한지 알 수 없다 — 임의로 한 개를 고르면
                # 실제와 다른 권한을 부여 권한이라 주장하게 된다. 못 읽었다고 말한다.
                no_default.append(pol.get("Arn", pol.get("PolicyName", "?")))
                continue
            policies.append({"arn": pol.get("Arn", ""), "name": pol.get("PolicyName", ""), "document": doc})
    principals.sort(key=lambda p: p["principal"])
    policies.sort(key=lambda p: p["arn"])
    groups.sort(key=lambda g: g["name"])

    # 연결됐는데 문서가 없는 정책 = 그 principal 의 부여 권한이 과소 계상된다.
    collected = {p["arn"] for p in policies}
    referenced = {
        a["arn"]
        for holder in (*principals, *groups)
        for a in holder.get("attached_policies", [])
        if a.get("arn")
    }
    missing = sorted(referenced - collected)
    note = ""
    if missing:
        note = (
            f"관리형 정책 문서 {len(missing)}건 미수집 — 해당 principal 의 부여 권한이 과소 계상됨"
            f"(대표: {missing[0]})"
        )
        if no_default:
            note += f"; 기본 버전 미표시 {len(no_default)}건"
    return principals, policies, groups, note


def _default_version_document(policy: dict) -> dict | None:
    """관리형 정책의 **기본 버전** 문서. 기본 버전을 특정할 수 없으면 None."""
    for version in policy.get("PolicyVersionList", []) or []:
        if version.get("IsDefaultVersion"):
            return version.get("Document") or {}
    return None


def _role_record(role: dict) -> dict:
    # trust_policy/tags 는 같은 GetAccountAuthorizationDetails 응답에 이미 들어 있다 —
    # 추가 API 호출도 추가 IAM 권한도 없다. botocore 가 AssumeRolePolicyDocument 를 dict 로
    # 디코드해 주므로(URL 인코딩 해제) 그대로 저장한다. M2 가 사용 주체(사람/서비스)를 가르는 근거.
    return {
        "principal": role["Arn"],
        "name": role["RoleName"],
        "identity_type": "role",
        # 생성일. "실사용 기록 없음" 을 "안 쓰는 역할이라 삭제하라" 로 읽으려면 관측 가능 기간이
        # 있어야 한다 — 어제 만든 역할에 기록이 없는 건 당연하고, 삭제 근거가 아니다.
        "create_date": _iso(role.get("CreateDate")),
        # IAM 자신이 추적하는 역할 활동 시각(`RoleLastUsed`). 같은 응답에 이미 들어 있어 추가 호출도
        # 추가 권한도 없는데 그동안 버리고 있었다. 이 값이 우리가 가진 가장 넓은 사용 근거다:
        # **전 리전**을 아우르고(CloudTrail LookupEvents 는 리전별·페이지 상한), 콘솔의
        # "Last activity" 가 바로 이 값이다. 없으면 추적 창 안에 활동이 없었다는 뜻이므로
        # "얼마나 안 쓰였나" 의 하한을 준다 — 값 부재 자체가 정보다.
        "role_last_used": _iso((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
        "role_last_used_region": (role.get("RoleLastUsed") or {}).get("Region") or None,
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
        "create_date": _iso(user.get("CreateDate")),
        "inline_policies": _inline(user.get("UserPolicyList", [])),
        "attached_policies": _attached(user.get("AttachedManagedPolicies", [])),
        "path": user.get("Path", "/"),
        # user 는 신뢰정책이 없다(자기 자격으로 직접 로그인) → trust_policy 없음.
        "tags": _tags(user.get("Tags", [])),
        # 소속 그룹명(정렬). user 의 부여 권한은 그룹의 inline/attached 정책도 포함한다.
        "groups": sorted(user.get("GroupList", []) or []),
    }


def _group_record(group: dict) -> dict:
    return {
        "name": group["GroupName"],
        "path": group.get("Path", "/"),
        "inline_policies": _inline(group.get("GroupPolicyList", [])),
        "attached_policies": _attached(group.get("AttachedManagedPolicies", [])),
    }


def _iso(dt) -> str | None:
    """boto3 datetime → ISO8601 문자열. None 은 그대로(값 없음을 값으로 꾸미지 않는다)."""
    if dt is None:
        return None
    return dt if isinstance(dt, str) else dt.isoformat()


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
