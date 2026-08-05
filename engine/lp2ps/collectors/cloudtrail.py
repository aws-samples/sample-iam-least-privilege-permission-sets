"""CloudTrail 수집 — 실제 사용 이벤트(누가 어떤 API 를 언제).

**LookupEvents(90d) 단일 소스.** 기본 CloudTrail 의 LookupEvents 로 관리 이벤트(management events)를
집계한다. CloudTrail Lake(Event Data Store)는 **사용하지 않는다** — Lake 는 수집·저장·조회 비용이
추가되고, 이 도구는 실시간이 아니라 배치 분석이라 무료 LookupEvents 로 충분하다(고객 비용 부담 회피).

한계(설계상 수용): LookupEvents 는 **관리 이벤트만** 반환한다(데이터 이벤트 S3 GetObject 등은 미포함
— AWS API 제약). 데이터 이벤트 기반 사용 횟수는 Access Advisor(last_used)로 보완한다. 이 조합이면
최소권한 분석에 충분하므로 LookupEvents 정상 수집을 **ok** 로 본다(Lake 없음은 더 이상 저하 아님).

read-only: `LookupEvents` 는 allowlist 접두(가드 통과). 계정 미변경.
결정론: 90일 창은 `context["as_of"]`(run.started_at 파생) 기준 — collector 는 `datetime.now()`
를 호출하지 않는다(불변식 ②). as_of 미제공 시 시간 필터 없이 최근 이벤트만.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from . import Collector, CollectorResult

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

SOURCE = "cloudtrail"

_WINDOW_DAYS = 90
# LookupEvents 페이지 상한(계정당). 1페이지=최대 50개 → 최대 1만 이벤트/계정. LookupEvents 는 초당
# 요청 제한이 빡빡해(≈2회/초) 상한을 크게 잡으면 throttle·시간초과가 난다. 200 은 90일 관리 이벤트를
# 대부분 커버하면서 throttle backoff·Lambda 15분 안에 완주 가능한 현실적 값. 상한 도달해도 ok
# (LookupEvents 는 원래 관리 이벤트만 주는 부분 소스이고 Access Advisor 가 보완 — '가능한 만큼=정상').
_LOOKUP_MAX_PAGES = 200
# throttle 재시도: 실시간 불필요하므로 backoff 로 천천히 넘긴다(수집 지연만, 산출물 불변식② 영향 없음).
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException"}
_MAX_THROTTLE_RETRIES = 6  # 페이지당 재시도 횟수(지수 backoff 상한)


class CloudTrailCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        as_of = _parse_as_of(context.get("as_of"))

        try:
            ct = account.client("cloudtrail")
            events, truncated = _lookup_events(ct, as_of)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return CollectorResult(
                source=SOURCE,
                status="skipped",
                data={"account_id": account.account_id, "mode": "none", "usage": []},
                note=f"CloudTrail LookupEvents 사용 불가({code}) — 정규화 단계는 Access Advisor 에만 의존",
            )

        # 수집되면 항상 ok — LookupEvents 는 관리 이벤트만 주는 부분 소스이고 Access Advisor 가
        # 보완하므로 '가능한 만큼=정상'. 상한 도달(truncated)은 note 로만 알림(상태는 ok).
        note = "LookupEvents(90d) 관리 이벤트 기반. 데이터 이벤트는 미포함(Access Advisor 로 보완)."
        if truncated:
            note += f" 페이지 상한({_LOOKUP_MAX_PAGES}) 도달로 더 과거 일부는 미수집."
        return CollectorResult(
            source=SOURCE,
            status="ok",
            data={"account_id": account.account_id, "mode": "lookup_events",
                  "truncated": truncated, "usage": events},
            note=note,
        )


def _parse_as_of(as_of) -> datetime | None:
    if as_of is None:
        return None
    if isinstance(as_of, datetime):
        return as_of
    try:
        return datetime.fromisoformat(str(as_of).replace("Z", "+00:00"))
    except ValueError:
        return None


def _window_start(as_of: datetime | None) -> datetime | None:
    if as_of is None:
        return None
    return as_of - timedelta(days=_WINDOW_DAYS)


def _lookup_events(ct, as_of: datetime | None) -> tuple[list[dict], bool]:
    """LookupEvents — (집계 행 목록, 페이지 상한 도달 여부) 반환.

    (principal, event_name) 별 카운트/최근시각 집계.

    중요: 얕은 `Event.Username` 은 principal ARN 이 아니라 세션명/역할명이라 정규화 인벤토리
    (전부 IAM ARN)와 매칭되지 않는다. 각 이벤트의 `CloudTrailEvent`(전체 JSON) 를 파싱해
    `userIdentity` 에서 **진짜 IAM principal ARN** 을 뽑는다:
      - AssumedRole → sessionContext.sessionIssuer.arn (임시 sts ARN 이 아니라 IAM role ARN)
      - IAMUser/Root → userIdentity.arn
      - AWSService 등 → principal 없음(스킵)
    """
    start = _window_start(as_of)
    kwargs: dict = {}
    if start is not None:
        kwargs["StartTime"] = start
        if as_of is not None:
            kwargs["EndTime"] = as_of

    agg: dict[tuple[str, str, str], dict] = {}
    # 수동 페이지네이션(paginator 대신) — throttle 시 페이지 단위 backoff 재시도가 필요하기 때문.
    next_token = None
    pages = 0
    truncated = False
    while True:
        page_kwargs = dict(kwargs)
        if next_token:
            page_kwargs["NextToken"] = next_token
        try:
            page = _lookup_page_with_backoff(ct, page_kwargs)
        except _ThrottleExhausted:
            # 재시도 소진 — 조용히 자르지 않고 그때까지 모은 것으로 완주(부분 수집, ok).
            truncated = True
            break
        for ev in page.get("Events", []):
            src = ev.get("EventSource", "")
            name = ev.get("EventName", "")
            principal = _principal_from_event(ev.get("CloudTrailEvent"))
            if not principal:
                continue  # AWSService 등 IAM principal 없는 이벤트는 사용실태 대상 아님
            event_time = ev.get("EventTime")
            key = (principal, src, name)
            rec = agg.setdefault(
                key,
                {
                    "principal": principal,
                    "event_source": src,
                    "event_name": name,
                    "count": 0,
                    "last_used": None,
                },
            )
            rec["count"] += 1
            iso = _iso(event_time)
            if iso and (rec["last_used"] is None or iso > rec["last_used"]):
                rec["last_used"] = iso
        pages += 1
        next_token = page.get("NextToken")
        if not next_token:
            break  # 마지막 페이지 — 90일 창 전체 수집 완료.
        if pages >= _LOOKUP_MAX_PAGES:
            truncated = True  # 상한 도달, 후속 토큰 남음 → 더 과거 일부 미수집.
            break

    rows = list(agg.values())
    rows.sort(key=lambda r: (r["principal"], r["event_source"], r["event_name"]))
    return rows, truncated


class _ThrottleExhausted(Exception):
    """throttle 재시도를 모두 소진 — 부분 수집으로 완주하기 위한 내부 신호."""


def _lookup_page_with_backoff(ct, page_kwargs: dict) -> dict:
    """LookupEvents 한 페이지 조회 — throttle 이면 지수 backoff 재시도.

    실시간이 필요 없으므로 throttle 을 예외로 흘리지 않고 천천히 재시도한다(수집 지연만 발생,
    산출물 결정론 불변식②엔 영향 없음 — 최종 수집 데이터는 동일). backoff sleep 은 시간 대기일 뿐
    산출물에 wall-clock 을 쓰지 않는다. 재시도 소진 시 _ThrottleExhausted 로 부분 수집 완주.
    """
    import time

    for attempt in range(_MAX_THROTTLE_RETRIES + 1):
        try:
            return ct.lookup_events(**page_kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES:
                raise  # throttle 이 아닌 오류(권한 등)는 상위에서 skipped 처리.
            if attempt >= _MAX_THROTTLE_RETRIES:
                raise _ThrottleExhausted from e
            time.sleep(min(2 ** attempt, 30))  # 1,2,4,8,16,30… 초 backoff(상한 30s)
    raise _ThrottleExhausted  # 도달 불가(방어)


def _principal_from_event(cloudtrail_event: str | None) -> str:
    """CloudTrailEvent JSON 문자열 → IAM principal ARN(없으면 '')."""
    if not cloudtrail_event:
        return ""
    try:
        full = json.loads(cloudtrail_event)
    except (ValueError, TypeError):
        return ""
    return _principal_from_identity(full.get("userIdentity") or {})


def _principal_from_identity(ui: dict) -> str:
    """userIdentity 에서 안정적인 IAM principal ARN 추출.

    AssumedRole 은 임시 sts ARN(`assumed-role/Role/session`) 대신 발급 역할의 IAM ARN
    (`sessionIssuer.arn`)을 쓴다 — 세션마다 바뀌지 않아 인벤토리와 매칭되고 결정론적이다.
    """
    itype = ui.get("type", "")
    if itype == "AssumedRole":
        issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
        arn = issuer.get("arn", "")
        if arn:
            return arn
        # sessionIssuer 부재 시 sts ARN 을 role ARN 으로 정규화 시도.
        return _role_arn_from_sts(ui.get("arn", ""))
    if itype in ("IAMUser", "Root"):
        return ui.get("arn", "")
    # AWSService, FederatedUser, AWSAccount, Unknown 등은 IAM principal 인벤토리 대상 아님.
    return ""


def _role_arn_from_sts(sts_arn: str) -> str:
    """`arn:aws:sts::acct:assumed-role/RoleName/session` → `arn:aws:iam::acct:role/RoleName`."""
    m = re.match(r"^arn:aws[\w-]*:sts::(\d{12}):assumed-role/([^/]+)/", sts_arn)
    if not m:
        return ""
    account_id, role_name = m.group(1), m.group(2)
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if isinstance(dt, datetime):
        return dt.astimezone(timezone.utc).isoformat()
    return None
