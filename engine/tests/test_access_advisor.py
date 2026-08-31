"""Access Advisor collector — 페이지네이션 회귀 테스트.

GetServiceLastAccessedDetails 는 IsTruncated/Marker 로 페이지네이션된다. 첫 페이지만 읽으면
서비스 많은 principal 의 used-action 이 잘려 미사용 갭이 과대 계상된다.
"""

from __future__ import annotations

from lp2ps.collectors.access_advisor import _retrieve


class _FakeIAM:
    """Marker 로 2페이지를 돌려주는 fake."""

    def __init__(self) -> None:
        self.calls = 0

    def get_service_last_accessed_details(self, JobId, Marker=None):  # noqa: N803
        self.calls += 1
        if Marker is None:
            return {
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [
                    {"ServiceNamespace": "s3", "TrackedActionsLastAccessed": []}
                ],
                "IsTruncated": True,
                "Marker": "page2",
            }
        return {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {"ServiceNamespace": "ec2", "TrackedActionsLastAccessed": []}
            ],
            "IsTruncated": False,
        }


def test_retrieve_follows_marker_pagination() -> None:
    iam = _FakeIAM()
    services = _retrieve(iam, "job-1")
    names = {s["service"] for s in services}
    # 두 페이지의 서비스가 모두 잡혀야 한다(첫 페이지만이면 ec2 누락 → 과대 갭).
    assert names == {"s3", "ec2"}
    assert iam.calls == 2


# ---- 미완료 잡을 성공으로 세지 않는다 ----
#
# _poll 은 IN_PROGRESS 가 계속되면 상한(_MAX_POLLS) 에서 포기하고 그 응답을 그대로 돌려준다 →
# ServicesLastAccessed 가 비어 온다. 그걸 entry 로 실으면 M2 는 "이 principal 은 어떤 서비스도
# 인증한 적 없다" 로 읽고 granted 전 권한에 삭제 권고를 붙인다. 빈 결과는 실패로 센다.


class _NeverReadyIAM:
    def __init__(self) -> None:
        self.arns: list[str] = []

    def generate_service_last_accessed_details(self, Arn, Granularity):  # noqa: N803
        self.arns.append(Arn)
        return {"JobId": f"job-{len(self.arns)}"}

    def get_service_last_accessed_details(self, JobId, Marker=None):  # noqa: N803
        # 계속 IN_PROGRESS — 상한 소진 후 빈 결과가 반환되는 상황.
        return {"JobStatus": "IN_PROGRESS", "ServicesLastAccessed": []}


class _Account:
    account_id = "111122223333"

    def __init__(self, iam) -> None:  # noqa: ANN001
        self._iam = iam

    def client(self, service_name, region=None, **kwargs):  # noqa: ANN001, ANN201
        return self._iam


def test_unfinished_job_is_not_reported_as_evidence(monkeypatch) -> None:
    import lp2ps.collectors.access_advisor as aa

    monkeypatch.setattr(aa.time, "sleep", lambda s: None)
    iam = _NeverReadyIAM()
    ctx = {"principals": [{"principal": "arn:aws:iam::111122223333:role/r1"}]}
    r = aa.AccessAdvisorCollector().collect(_Account(iam), ctx)
    # 근거를 하나도 못 받았으므로 degraded 이고 last_accessed 는 비어야 한다
    # (빈 services 를 실으면 M2 가 '미사용 확정' 으로 오독한다).
    assert r.data["last_accessed"] == []
    assert r.status == "degraded"


def test_completed_job_with_services_is_reported() -> None:
    """대조군 — 정상 완료 잡은 그대로 근거로 실린다(위 테스트가 전부 버리는 게 아니다)."""

    class _OkIAM(_NeverReadyIAM):
        def get_service_last_accessed_details(self, JobId, Marker=None):  # noqa: N803
            return {"JobStatus": "COMPLETED",
                    "ServicesLastAccessed": [{"ServiceNamespace": "s3", "TrackedActionsLastAccessed": []}],
                    "IsTruncated": False}

    import lp2ps.collectors.access_advisor as aa

    iam = _OkIAM()
    ctx = {"principals": [{"principal": "arn:aws:iam::111122223333:role/r1"}]}
    r = aa.AccessAdvisorCollector().collect(_Account(iam), ctx)
    assert r.status == "ok" and r.note == ""
    assert [e["principal"] for e in r.data["last_accessed"]] == ["arn:aws:iam::111122223333:role/r1"]
