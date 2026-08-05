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
