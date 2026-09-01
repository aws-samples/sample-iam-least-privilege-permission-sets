"""credential report 수집 단위 테스트.

`GenerateCredentialReport` 는 **비동기**다. 그 계정에서 처음 만드는(또는 만료된) 경우 곧바로 부른
`GetCredentialReport` 는 ReportInProgress 로 실패한다. 575 계정 첫 라이브 실행에서 실제로 그랬고,
결과는 조용했다: 인벤토리는 살아 있어서 소스 상태는 ok, run 은 '성공', 그런데 MFA·장기 액세스키
근거는 통째로 없어 대시보드가 "장기 액세스키 0" 을 보여줬다 — 0건이 아니라 근거가 0이었다.

그래서 두 가지를 잠근다: (a) 진행 중이면 짧게 기다렸다 재조회한다, (b) 끝까지 못 받으면 ok 가
아니라 degraded 로 말한다.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from lp2ps.collectors.credential_report import CredentialReportCollector

_CSV = (
    "user,arn,mfa_active,password_enabled,access_key_1_active,access_key_1_last_rotated\n"
    "alice,arn:aws:iam::111122223333:user/alice,false,true,true,2020-01-01T00:00:00+00:00\n"
)

_AUTH_PAGE = {
    "RoleDetailList": [],
    "UserDetailList": [
        {"Arn": "arn:aws:iam::111122223333:user/alice", "UserName": "alice",
         "UserPolicyList": [], "AttachedManagedPolicies": [], "Path": "/", "Tags": []},
    ],
}


class _Paginator:
    def paginate(self, **kwargs):  # noqa: ANN001, ANN201
        return [_AUTH_PAGE]


class _FakeIAM:
    """get_credential_report 가 in_progress 번 ReportInProgress 를 던진 뒤 성공하는 fake."""

    def __init__(self, in_progress: int, always_fail: bool = False) -> None:
        self._left = in_progress
        self._always_fail = always_fail
        self.get_calls = 0

    def get_paginator(self, name):  # noqa: ANN001, ANN201
        return _Paginator()

    def generate_credential_report(self):  # noqa: ANN201
        return {"State": "STARTED"}

    def get_credential_report(self):  # noqa: ANN201
        self.get_calls += 1
        if self._always_fail or self._left > 0:
            self._left -= 1
            raise ClientError(
                {"Error": {"Code": "ReportInProgress", "Message": "in progress"}},
                "GetCredentialReport",
            )
        return {"Content": base64.b64decode(base64.b64encode(_CSV.encode()))}


class _Account:
    account_id = "111122223333"

    def __init__(self, iam) -> None:  # noqa: ANN001
        self._iam = iam

    def client(self, service_name, region=None, **kwargs):  # noqa: ANN001, ANN201
        return self._iam


def _collect(iam, monkeypatch):  # noqa: ANN001, ANN201
    # 대기는 동작 검증에 불필요한 실시간이므로 잘라낸다(테스트 30초 금지).
    import time as _t

    monkeypatch.setattr(_t, "sleep", lambda s: None)
    return CredentialReportCollector().collect(_Account(iam), {})


def test_report_in_progress_is_retried_then_collected(monkeypatch) -> None:
    """생성 중이면 재조회해서 결국 받아낸다 → ok + 액세스키 근거 존재."""
    iam = _FakeIAM(in_progress=3)
    r = _collect(iam, monkeypatch)
    assert r.status == "ok"
    assert r.note == ""
    assert iam.get_calls == 4  # 3번 실패 후 성공(재시도가 실제로 일어났다)
    rows = r.data["credential_report"]
    assert [row["user"] for row in rows] == ["alice"]


def test_report_never_ready_is_degraded_not_ok(monkeypatch) -> None:
    """끝까지 못 받으면 degraded — 인벤토리가 있어도 ok 라고 말하면 안 된다.

    ok 로 보고하면 run 은 '성공' 이 되고, MFA·장기키 지표가 0 인 이유가 화면에서 사라진다.
    """
    iam = _FakeIAM(in_progress=0, always_fail=True)
    r = _collect(iam, monkeypatch)
    assert r.status == "degraded"
    assert "ReportInProgress" in r.note
    assert r.data["credential_report"] == []
    # 인벤토리는 그래도 살아 있어야 한다(뒤 단계가 principal 을 잃지 않게).
    assert [p["name"] for p in r.data["principals"]] == ["alice"]
    assert iam.get_calls > 1  # 즉시 포기하지 않았다


def test_permission_error_is_degraded(monkeypatch) -> None:
    """ReportInProgress 가 아닌 오류(AccessDenied 등)는 재시도 없이 degraded."""

    class _Denied(_FakeIAM):
        def get_credential_report(self):  # noqa: ANN201
            self.get_calls += 1
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetCredentialReport")

    iam = _Denied(in_progress=0)
    r = _collect(iam, monkeypatch)
    assert r.status == "degraded"
    assert "AccessDenied" in r.note
    assert iam.get_calls == 1


# ---- GetAccountAuthorizationDetails: 관리형 정책 문서 · 그룹 · 생성일 ----
#
# 예전 Filter 는 ["User","Role"] 이었다. 그러면 관리형 정책은 이름·ARN 만 오고 문서 본문이 없어
# granted_actions 가 inline 정책만 담는다 — 라이브 계정에서 142개 중 62개(44%)가 부여 권한 0으로
# 보였고, 그중 8개는 AdministratorAccess 를 들고도 risk=low·상승경로 0 이었다. 같은 응답에
# 정책·그룹을 얹으면 추가 호출도 추가 IAM 권한도 없이 문서가 함께 온다.


class _RecordingPaginator:
    """paginate() 인자를 기록하는 paginator(고정 페이지 1장)."""

    def __init__(self, page: dict, seen: dict) -> None:
        self._page = page
        self._seen = seen

    def paginate(self, **kwargs):  # noqa: ANN001, ANN201
        self._seen.update(kwargs)
        return [self._page]


class _AuthIAM(_FakeIAM):
    """auth details 페이지를 지정할 수 있는 fake. credential report 는 즉시 성공."""

    def __init__(self, page: dict) -> None:
        super().__init__(in_progress=0)
        self._page = page
        self.paginate_kwargs: dict = {}

    def get_paginator(self, name):  # noqa: ANN001, ANN201
        return _RecordingPaginator(self._page, self.paginate_kwargs)


_ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_LOCAL_ARN = "arn:aws:iam::111122223333:policy/team-write"
_ROLE_ARN = "arn:aws:iam::111122223333:role/managed-only"


def _role(**over) -> dict:
    role = {
        "Arn": _ROLE_ARN,
        "RoleName": "managed-only",
        "CreateDate": datetime(2026, 8, 28, 8, 1, 0, tzinfo=timezone.utc),
        "RolePolicyList": [],
        "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": _ADMIN_ARN}],
        "Path": "/",
        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow",
                                                   "Principal": {"Service": "lambda.amazonaws.com"},
                                                   "Action": "sts:AssumeRole"}]},
        "Tags": [],
    }
    role.update(over)
    return role


def _admin_policy(default_version: str | None = "v2") -> dict:
    """AdministratorAccess 흉내 — 버전 2개 중 하나만 기본. default_version=None 이면 기본 표시 없음."""
    return {
        "Arn": _ADMIN_ARN,
        "PolicyName": "AdministratorAccess",
        "PolicyVersionList": [
            {"VersionId": "v1", "IsDefaultVersion": default_version == "v1",
             "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                         "Resource": "*"}]}},
            {"VersionId": "v2", "IsDefaultVersion": default_version == "v2",
             "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
        ],
    }


def test_auth_filter_requests_policies_and_groups(monkeypatch) -> None:
    """Filter 에 정책·그룹이 없으면 문서 본문이 오지 않는다 — 요청 자체를 계약으로 잠근다."""
    iam = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [],
                    "Policies": [_admin_policy()]})
    _collect(iam, monkeypatch)
    assert set(iam.paginate_kwargs["Filter"]) == {
        "User", "Role", "Group", "AWSManagedPolicy", "LocalManagedPolicy"
    }


def test_managed_policy_default_version_document_collected(monkeypatch) -> None:
    """관리형 정책은 **기본 버전** 문서만 싣는다(비기본 버전을 쓰면 없는 권한을 주장한다)."""
    iam = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [],
                    "Policies": [_admin_policy(default_version="v2")]})
    r = _collect(iam, monkeypatch)
    assert r.status == "ok"
    assert r.note == ""
    docs = {p["arn"]: p["document"] for p in r.data["managed_policies"]}
    assert docs[_ADMIN_ARN]["Statement"][0]["Action"] == "*", "기본 버전(v2) 문서여야 한다"

    # 대조: 기본 버전이 v1 이면 v1 문서가 온다(무조건 마지막 버전을 고르는 게 아니다).
    iam2 = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [],
                     "Policies": [_admin_policy(default_version="v1")]})
    docs2 = {p["arn"]: p["document"] for p in _collect(iam2, monkeypatch).data["managed_policies"]}
    assert docs2[_ADMIN_ARN]["Statement"][0]["Action"] == "s3:GetObject"


def test_policy_without_default_version_is_reported_not_guessed(monkeypatch) -> None:
    """기본 버전 표시가 없으면 임의로 고르지 않고 degraded + note 로 말한다.

    임의로 한 버전을 고르면 실제와 다른 권한을 '부여 권한' 이라고 주장한다. 반대로 조용히
    버리면 관리형만 붙은 principal 이 부여 권한 0 으로 보인다 — 그래서 못 읽었다고 말해야 한다.
    """
    iam = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [],
                    "Policies": [_admin_policy(default_version=None)]})
    r = _collect(iam, monkeypatch)
    assert r.data["managed_policies"] == [], "기본 버전을 특정할 수 없으면 싣지 않는다"
    assert r.status == "degraded"
    assert "과소 계상" in r.note and _ADMIN_ARN in r.note
    assert "기본 버전 미표시" in r.note


def test_attached_policy_missing_from_response_is_reported(monkeypatch) -> None:
    """연결됐는데 응답에 문서가 아예 없는 정책도 note 로 드러낸다(권한 과소 계상 경고)."""
    iam = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [], "Policies": []})
    r = _collect(iam, monkeypatch)
    assert r.status == "degraded"
    assert _ADMIN_ARN in r.note
    # 기본 버전 미표시는 이 경로의 사유가 아니다 — 두 사유를 섞어 말하지 않는다.
    assert "기본 버전 미표시" not in r.note


def test_groups_and_membership_collected(monkeypatch) -> None:
    """user 의 부여 권한은 그룹 경유분을 포함한다 → 그룹 정책과 소속을 함께 싣는다."""
    iam = _AuthIAM({
        "RoleDetailList": [],
        "UserDetailList": [{
            "Arn": "arn:aws:iam::111122223333:user/alice", "UserName": "alice",
            "UserPolicyList": [], "AttachedManagedPolicies": [], "Path": "/", "Tags": [],
            "GroupList": ["devs", "admins"],
        }],
        "GroupDetailList": [{
            "GroupName": "devs", "Path": "/",
            "GroupPolicyList": [{"PolicyName": "g", "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}}],
            "AttachedManagedPolicies": [{"PolicyName": "team-write", "PolicyArn": _LOCAL_ARN}],
        }],
        "Policies": [{"Arn": _LOCAL_ARN, "PolicyName": "team-write", "PolicyVersionList": [
            {"VersionId": "v1", "IsDefaultVersion": True, "Document": {
                "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]}}]}],
    })
    r = _collect(iam, monkeypatch)
    assert r.status == "ok"
    # 소속은 정렬해 싣는다(결정론).
    assert r.data["principals"][0]["groups"] == ["admins", "devs"]
    group = r.data["groups"][0]
    assert group["name"] == "devs"
    assert group["inline_policies"][0]["document"]["Statement"][0]["Action"] == "sqs:SendMessage"
    assert group["attached_policies"][0]["arn"] == _LOCAL_ARN
    # 그룹이 연결한 관리형 정책도 참조 대조에 들어간다 → 문서가 왔으니 note 없음.
    assert r.note == ""


def test_create_date_is_collected_as_iso(monkeypatch) -> None:
    """생성일이 없으면 '기록 없음' 을 '삭제하라' 로 읽는 것을 막을 근거가 사라진다."""
    iam = _AuthIAM({"RoleDetailList": [_role()], "UserDetailList": [],
                    "Policies": [_admin_policy()]})
    r = _collect(iam, monkeypatch)
    assert r.data["principals"][0]["create_date"] == "2026-08-28T08:01:00+00:00"


def test_missing_create_date_stays_none(monkeypatch) -> None:
    """대조군 — CreateDate 가 없으면 None. 값 없음을 값으로 꾸미지 않는다(예: 에폭 0)."""
    role = _role()
    del role["CreateDate"]
    iam = _AuthIAM({"RoleDetailList": [role], "UserDetailList": [],
                    "Policies": [_admin_policy()]})
    r = _collect(iam, monkeypatch)
    assert r.data["principals"][0]["create_date"] is None


def test_role_last_used_is_collected(monkeypatch) -> None:
    """RoleLastUsed 는 같은 응답에 이미 온다 — 버리면 미사용 기간을 말할 근거가 사라진다.

    이 값이 IAM 콘솔의 "Last activity" 이고 **전 리전**을 아우른다(CloudTrail 수집은 리전별).
    """
    role = _role(RoleLastUsed={"LastUsedDate": datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc),
                               "Region": "ap-northeast-1"})
    iam = _AuthIAM({"RoleDetailList": [role], "UserDetailList": [],
                    "Policies": [_admin_policy()]})
    p = _collect(iam, monkeypatch).data["principals"][0]
    assert p["role_last_used"] == "2026-08-30T12:00:00+00:00"
    assert p["role_last_used_region"] == "ap-northeast-1"


def test_missing_role_last_used_stays_none(monkeypatch) -> None:
    """대조군 — 활동 기록이 없으면 None. **부재가 정보다**(미사용 기간의 하한).

    IAM 은 활동이 없던 역할에 RoleLastUsed 를 아예 안 실어 보내거나 빈 dict 로 보낸다. 어느
    쪽이든 생성일 같은 다른 값으로 메꾸면 "이 날 썼다" 는 거짓을 화면이 주장한다.
    """
    iam = _AuthIAM({"RoleDetailList": [_role(), _role(RoleLastUsed={})], "UserDetailList": [],
                    "Policies": [_admin_policy()]})
    for p in _collect(iam, monkeypatch).data["principals"]:
        assert p["role_last_used"] is None
        assert p["role_last_used_region"] is None
