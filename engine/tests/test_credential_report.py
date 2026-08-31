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
