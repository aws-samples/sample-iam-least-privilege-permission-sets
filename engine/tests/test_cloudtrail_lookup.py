"""CloudTrail LookupEvents 폴백의 principal ARN 추출 테스트.

버그 회귀 방지: LookupEvents 의 얕은 `Username` 은 principal ARN 이 아니라 세션명/역할명이라
정규화 인벤토리(IAM ARN)와 매칭되지 않았다(실계정에서 CloudTrail 기여분 0/14). 이제 각 이벤트의
`CloudTrailEvent` JSON 을 파싱해 userIdentity 에서 진짜 IAM ARN 을 뽑는다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from lp2ps.collectors.cloudtrail import (
    _lookup_events,
    _principal_from_event,
    _principal_from_identity,
    _role_arn_from_sts,
)

AS_OF = datetime(2026, 7, 15, tzinfo=timezone.utc)

# 실계정에서 관측한 실제 userIdentity 모양.
ASSUMED_ROLE = {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_abc/alice",
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc",
        }
    },
}
AWS_SERVICE = {"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"}
IAM_USER = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"}


def test_assumed_role_uses_session_issuer_arn() -> None:
    # 임시 sts ARN 이 아니라 발급 역할의 IAM ARN 을 써야 인벤토리와 매칭된다.
    assert _principal_from_identity(ASSUMED_ROLE) == (
        "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
    )


def test_aws_service_has_no_principal() -> None:
    assert _principal_from_identity(AWS_SERVICE) == ""


def test_iam_user_uses_arn() -> None:
    assert _principal_from_identity(IAM_USER) == "arn:aws:iam::111122223333:user/alice"


def test_assumed_role_without_issuer_falls_back_to_sts_normalization() -> None:
    ui = {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/MyRole/sess-1"}
    assert _principal_from_identity(ui) == "arn:aws:iam::111122223333:role/MyRole"


def test_role_arn_from_sts() -> None:
    assert (
        _role_arn_from_sts("arn:aws:sts::123456789012:assumed-role/Foo/bar")
        == "arn:aws:iam::123456789012:role/Foo"
    )
    assert _role_arn_from_sts("not-an-arn") == ""


def test_principal_from_event_parses_json() -> None:
    ev = json.dumps({"userIdentity": ASSUMED_ROLE})
    assert _principal_from_event(ev).startswith("arn:aws:iam::111122223333:role/")
    assert _principal_from_event(None) == ""
    assert _principal_from_event("{bad json") == ""


class _FakeCT:
    """LookupEvents 수동 페이지네이션 fake — 단일 페이지(NextToken 없음)."""

    def __init__(self, events: list[dict]) -> None:
        self._events = events

    def lookup_events(self, **kwargs):
        return {"Events": self._events}  # 단일 페이지 → NextToken 없음


def _event(ui: dict, source: str, name: str, when: str) -> dict:
    return {
        "EventSource": source,
        "EventName": name,
        "EventTime": datetime.fromisoformat(when),
        "CloudTrailEvent": json.dumps({"userIdentity": ui}),
    }


def test_lookup_events_aggregates_by_real_arn() -> None:
    role_arn = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
    events = [
        _event(ASSUMED_ROLE, "s3.amazonaws.com", "GetObject", "2026-07-10T00:00:00+00:00"),
        _event(ASSUMED_ROLE, "s3.amazonaws.com", "GetObject", "2026-07-11T00:00:00+00:00"),
        _event(AWS_SERVICE, "kms.amazonaws.com", "GenerateDataKey", "2026-07-09T00:00:00+00:00"),
    ]
    rows, truncated = _lookup_events(_FakeCT(events), AS_OF)

    assert truncated is False  # 단일 페이지 → 상한 미도달
    # AWSService 이벤트는 principal 없음 → 제외. AssumedRole 2건은 같은 IAM ARN 으로 집계.
    assert len(rows) == 1
    r = rows[0]
    assert r["principal"] == role_arn
    assert r["event_name"] == "GetObject"
    assert r["count"] == 2
    assert r["last_used"] == "2026-07-11T00:00:00+00:00"
