"""CloudTrail LookupEvents 수집 단위 테스트.

CloudTrail Lake 경로는 제거됐다(비용 부담 회피 — 기본 CloudTrail LookupEvents 단일 소스).
여기서는 fake 클라이언트로 collector 상태 판정(ok/degraded/skipped)과 principal ARN 추출,
페이지 상한 truncation 을 검증한다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from lp2ps.collectors.cloudtrail import (
    CloudTrailCollector,
    _principal_from_identity,
    _role_arn_from_sts,
)

AS_OF = datetime(2026, 7, 15, tzinfo=timezone.utc)


def _event(principal_type: str, arn: str, source: str, name: str) -> dict:
    """LookupEvents Event 한 건(전체 CloudTrailEvent JSON 포함)."""
    ui: dict = {"type": principal_type, "arn": arn}
    if principal_type == "AssumedRole":
        ui = {"type": "AssumedRole", "arn": arn,
              "sessionContext": {"sessionIssuer": {"arn": arn}}}
    return {
        "EventSource": source, "EventName": name,
        "EventTime": datetime(2026, 7, 10, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({"userIdentity": ui}),
    }


class FakeCloudTrail:
    """lookup_events(수동 페이지네이션) 를 모사하는 최소 fake.

    pages 는 페이지별 이벤트 목록. throttle_before 만큼 처음 호출을 ThrottlingException 으로
    돌려보내 backoff 재시도를 검증할 수 있다. error 는 첫 호출부터 계속 나는 치명 오류.
    """

    def __init__(self, pages, error=None, throttle_before=0):  # noqa: ANN001
        self._pages = pages
        self._error = error
        self._throttle_before = throttle_before
        self._calls = 0

    def lookup_events(self, **kwargs):
        if self._error:
            raise self._error
        if self._calls < self._throttle_before:
            self._calls += 1
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "LookupEvents")
        # NextToken 으로 페이지 인덱스 추적(없으면 0).
        idx = int(kwargs.get("NextToken", "0"))
        evs = self._pages[idx] if idx < len(self._pages) else []
        out = {"Events": evs}
        if idx + 1 < len(self._pages):
            out["NextToken"] = str(idx + 1)
        return out


class _Account:
    account_id = "111122223333"

    def __init__(self, ct):
        self._ct = ct

    def client(self, service_name, region=None, **kwargs):  # noqa: ANN001
        return self._ct


def _collect(pages, error=None, throttle_before=0, **context):
    ctx = {"as_of": AS_OF.isoformat()}
    ctx.update(context)
    return CloudTrailCollector().collect(
        _Account(FakeCloudTrail(pages, error, throttle_before)), ctx
    )


def test_lookup_ok_when_collected() -> None:
    """정상 수집(상한 미도달) → ok."""
    r = _collect([[_event("IAMUser", "arn:aws:iam::111122223333:user/u", "s3.amazonaws.com", "GetBucketPolicy")]])
    assert r.status == "ok"
    assert r.data["mode"] == "lookup_events"
    assert r.data["truncated"] is False
    assert r.data["usage"][0]["principal"] == "arn:aws:iam::111122223333:user/u"


_TWO_PAGES = [
    [_event("IAMUser", "arn:aws:iam::111122223333:user/a", "s3.amazonaws.com", "ListBuckets")],
    [_event("IAMUser", "arn:aws:iam::111122223333:user/b", "ec2.amazonaws.com", "DescribeInstances")],
]


def test_lookup_ok_even_when_truncated() -> None:
    """페이지 상한 도달로 잘려도 ok(부분 소스 + Access Advisor 보완). note 로만 알림."""
    r = _collect(_TWO_PAGES, cloudtrail_max_pages=1)
    assert r.status == "ok"
    assert r.data["truncated"] is True
    assert r.data["max_pages"] == 1
    assert "상한" in r.note


# ---- 상한은 config 값이다(코드 상수가 아니라) ----
#
# 고객의 계정 수에 따라 안전한 페이지 예산이 다르다. 상한이 코드에 박혀 있으면 계정이 3개인
# 고객과 200개인 고객이 같은 예산을 쓴다(불변식 ④).


def test_max_pages_comes_from_context() -> None:
    """대조군 — 같은 입력에 상한만 올리면 절단되지 않고 두 페이지를 모두 읽는다.

    이 대조가 없으면 위 테스트는 collector 가 상한을 항상 1처럼 취급해도 통과한다.
    """
    r = _collect(_TWO_PAGES, cloudtrail_max_pages=2)
    assert r.data["truncated"] is False
    assert {u["principal"].rsplit("/", 1)[-1] for u in r.data["usage"]} == {"a", "b"}


def test_missing_context_falls_back_to_module_default() -> None:
    """context 에 예산이 없으면(구 호출 경로) 모듈 기본값으로 동작한다 — 수집이 멈추지 않게."""
    import lp2ps.collectors.cloudtrail as ct

    r = _collect(_TWO_PAGES)
    assert ct._LOOKUP_MAX_PAGES >= 2
    assert r.data["truncated"] is False


# ---- 근거 창의 실제 길이를 말한다 ----
#
# "일부 미수집" 만으로는 그게 89일분인지 하루분인지 알 수 없다. 활동이 많은 계정에서는 실제로
# 며칠 수준으로 좁아진다(실측: 1,200페이지·60,000건으로 4일) → 90일이라 사칭하면 안 된다.


def test_coverage_start_reports_oldest_observed_event() -> None:
    r = _collect(_TWO_PAGES, cloudtrail_max_pages=1)
    # fake 이벤트는 모두 2026-07-10, as_of=2026-07-15 → 최근 5일분.
    assert r.data["coverage_start"].startswith("2026-07-10")
    assert "최근 5일분" in r.note


def test_coverage_under_one_day_is_reported_in_hours() -> None:
    """반나절도 못 덮으면 '0일분' 이 아니라 시간으로 말한다.

    라이브 실행에서 실제로 "최근 0일분" 이 나왔다 — 활동이 많은 계정은 200페이지로 몇 시간분밖에
    못 읽는다. 정수 일 단위만 쓰면 문구가 무의미해진다.
    """
    ev = _event("IAMUser", "arn:aws:iam::111122223333:user/a", "s3.amazonaws.com", "ListBuckets")
    ev["EventTime"] = datetime(2026, 7, 14, 5, tzinfo=timezone.utc)  # as_of - 19h
    r = _collect([[ev], _TWO_PAGES[1]], cloudtrail_max_pages=1)
    assert r.data["truncated"] is True
    assert "최근 19시간분" in r.note


def test_coverage_counts_events_without_iam_principal() -> None:
    """principal 을 못 뽑는 이벤트(AWSService)도 커버 기간 계산에는 넣는다.

    집계 대상만 보면 훑은 범위를 실제보다 짧게 말한다 — 근거 창은 '무엇을 읽었나'의 문제다.
    """
    svc = {"EventSource": "s3.amazonaws.com", "EventName": "PutObject",
           "EventTime": datetime(2026, 5, 1, tzinfo=timezone.utc),
           "CloudTrailEvent": json.dumps({"userIdentity": {"type": "AWSService"}})}
    r = _collect([[*_TWO_PAGES[0], svc], _TWO_PAGES[1]], cloudtrail_max_pages=1)
    assert r.data["coverage_start"].startswith("2026-05-01")
    assert "최근 75일분" in r.note
    # 집계에는 여전히 안 들어간다(사용실태 대상 아님).
    assert all("PutObject" != u["event_name"] for u in r.data["usage"])


def test_lookup_throttle_backoff_then_succeeds(monkeypatch) -> None:
    """throttle 이 나도 backoff 재시도로 성공 → ok(skipped 아님). sleep 은 모킹."""
    import lp2ps.collectors.cloudtrail as ct

    monkeypatch.setattr(ct.time, "sleep", lambda s: None) if hasattr(ct, "time") else None
    # collector 내부는 지연 import(import time) 이므로 time.sleep 을 전역 패치.
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda s: None)
    # 처음 2번 throttle 후 성공.
    r = _collect(
        [[_event("IAMUser", "arn:aws:iam::111122223333:user/u", "s3.amazonaws.com", "GetObject")]],
        throttle_before=2,
    )
    assert r.status == "ok"
    assert r.data["usage"][0]["principal"] == "arn:aws:iam::111122223333:user/u"


def test_lookup_skipped_on_client_error() -> None:
    """throttle 아닌 치명 오류(AccessDenied 등) → skipped(Access Advisor 로 대체)."""
    err = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "LookupEvents")
    r = _collect([[]], error=err)
    assert r.status == "skipped"
    assert r.data["usage"] == []


def test_assumed_role_uses_session_issuer_arn() -> None:
    """AssumedRole 은 임시 sts ARN 이 아니라 발급 role IAM ARN(sessionIssuer)을 principal 로."""
    ui = {"type": "AssumedRole", "arn": "x",
          "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/App"}}}
    assert _principal_from_identity(ui) == "arn:aws:iam::111122223333:role/App"


def test_sts_arn_normalized_to_role_arn() -> None:
    sts = "arn:aws:sts::111122223333:assumed-role/App/session-1"
    assert _role_arn_from_sts(sts) == "arn:aws:iam::111122223333:role/App"


def test_awsservice_identity_skipped() -> None:
    """AWSService 등 IAM principal 아닌 이벤트는 사용실태 대상 아님(빈 문자열)."""
    assert _principal_from_identity({"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}) == ""
