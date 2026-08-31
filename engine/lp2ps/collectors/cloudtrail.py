"""CloudTrail 수집 — 실제 사용 이벤트(누가 어떤 API 를 언제).

**LookupEvents 단일 소스.** 기본 CloudTrail 의 LookupEvents 로 관리 이벤트(management events)를
집계한다. CloudTrail Lake(Event Data Store)는 **사용하지 않는다** — Lake 는 수집·저장·조회 비용이
추가되고, 이 도구는 실시간이 아니라 배치 분석이라 무료 LookupEvents 로 충분하다(고객 비용 부담 회피).

한계(설계상 수용): LookupEvents 는 **관리 이벤트만** 반환한다(데이터 이벤트 S3 GetObject 등은 미포함
— AWS API 제약). 데이터 이벤트 기반 사용 횟수는 Access Advisor(last_used)로 보완한다. 이 조합이면
최소권한 분석에 충분하므로 LookupEvents 정상 수집을 **ok** 로 본다(Lake 없음은 더 이상 저하 아님).

read-only: `LookupEvents` 는 allowlist 접두(가드 통과). 계정 미변경.
결정론: 소급 창은 `context["as_of"]`(run.started_at 파생) 기준 — collector 는 `datetime.now()`
를 호출하지 않는다(불변식 ②). as_of 미제공 시 시간 필터 없이 최근 이벤트만.

**요청한 창 ≠ 덮은 창.** `collection.cloudtrail_window_days`(기본 90) 를 StartTime 으로 요청하지만
페이지 상한에 걸리면 실제로 덮는 구간은 며칠로 줄어든다(라이브 575: 400페이지 = 2.5일). raw 는
요청값(`window_days`)과 실측값(`coverage_start`·`truncated`)을 **둘 다** 싣는다 — 하류가 요청값을
관측값처럼 표시하면 화면이 측정하지 않은 숫자를 주장하게 된다.
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

# 소급 창 기본값(일). 실제 값은 `config.collection.cloudtrail_window_days` 에서 오고
# 이 상수는 context 에 값이 없을 때의 폴백일 뿐이다(불변식 ④ — 임계치는 config).
_WINDOW_DAYS = 90
# 페이지 상한 기본값(계정·리전당). 실제 값은 `config.collection.cloudtrail_max_pages` 에서 오고
# 이 상수는 context 에 값이 없을 때의 폴백일 뿐이다(불변식 ④ — 임계치는 config).
#
# 상한을 올려도 90일을 덮을 수 없다(실측): 페이지당 최대 50건·≈0.5초라 활동이 많은 계정은
# 1,200페이지(60,000건, 약 10분)로도 며칠분밖에 못 읽는다. 90일 완주엔 수만 페이지·수 시간이
# 필요해 15분 Lambda 와 양립하지 않는다. 그래서 이 값은 "받아낼 양"이 아니라 "쓸 시간"의 상한이고,
# 상한 도달은 결함이 아니라 정상(부분 소스)이다 — 미사용 판정의 근거는 90일 이상을 보는 Access
# Advisor 이며 CloudTrail 은 그 위에 최근 사용을 덧붙이는 역할이다.
_LOOKUP_MAX_PAGES = 200
# throttle 재시도: 실시간 불필요하므로 backoff 로 천천히 넘긴다(수집 지연만, 산출물 불변식② 영향 없음).
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException"}
_MAX_THROTTLE_RETRIES = 6  # 페이지당 재시도 횟수(지수 backoff 상한)


class CloudTrailCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        as_of = _parse_as_of(context.get("as_of"))
        max_pages = int(context.get("cloudtrail_max_pages") or _LOOKUP_MAX_PAGES)
        window_days = int(context.get("cloudtrail_window_days") or _WINDOW_DAYS)

        try:
            ct = account.client("cloudtrail")
            events, truncated, coverage_start = _lookup_events(ct, as_of, max_pages, window_days)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return CollectorResult(
                source=SOURCE,
                status="skipped",
                data={"account_id": account.account_id, "mode": "none", "usage": [],
                      "truncated": False, "coverage_start": None,
                      "window_days": window_days, "max_pages": max_pages},
                note=f"CloudTrail LookupEvents 사용 불가({code}) — 정규화 단계는 Access Advisor 에만 의존",
            )

        # 수집되면 항상 ok — LookupEvents 는 관리 이벤트만 주는 부분 소스이고 Access Advisor 가
        # 보완하므로 '가능한 만큼=정상'. 상한 도달(truncated)은 note 로만 알림(상태는 ok).
        note = (f"LookupEvents({window_days}일 요청) 관리 이벤트 기반. "
                f"데이터 이벤트는 미포함(Access Advisor 로 보완).")
        if truncated:
            # 실제로 덮은 기간을 말한다 — "일부 미수집" 만으로는 그게 89일인지 하루인지 알 수 없고,
            # 활동이 많은 계정에서는 실제로 하루 수준이 된다. 최신순 수집이라 잘린 쪽은 과거다.
            span = _coverage_span(coverage_start, as_of)
            note += (f" 페이지 상한({max_pages}) 도달 — 이 계정의 CloudTrail 근거는 {span}이다"
                     f"(더 긴 기간의 미사용 판정은 Access Advisor 가 담당).")
        return CollectorResult(
            source=SOURCE,
            status="ok",
            data={"account_id": account.account_id, "mode": "lookup_events",
                  "truncated": truncated,
                  # 관측한 가장 오래된 이벤트 시각. 이벤트에서 파생된 값이라 wall-clock 이 아니다
                  # (불변식 ②). 소비자는 이걸로 CloudTrail 근거의 유효 창을 알 수 있다.
                  "coverage_start": coverage_start,
                  # 요청한 창. truncated=False 면 이 창을 끝까지 훑었다는 뜻이므로 하류가
                  # 관측 구간으로 쓸 수 있다. truncated=True 면 coverage_start 가 실측값이다.
                  "window_days": window_days,
                  "max_pages": max_pages,
                  "usage": events},
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


def _window_start(as_of: datetime | None, window_days: int) -> datetime | None:
    if as_of is None:
        return None
    return as_of - timedelta(days=window_days)


def _coverage_span(coverage_start: str | None, as_of: datetime | None) -> str:
    """근거 창의 실제 길이를 사람이 읽는 문구로.

    일 단위로만 쓰면 활동이 아주 많은 계정에서 "최근 0일분" 이 나온다 — 실측에서 실제로 그랬다
    (200페이지가 반나절도 못 덮는 계정). 24시간 미만은 시간으로 말한다.
    """
    if not coverage_start or as_of is None:
        return "일부 기간만"
    try:
        start = datetime.fromisoformat(coverage_start.replace("Z", "+00:00"))
    except ValueError:
        return "일부 기간만"
    hours = max((as_of - start).total_seconds() / 3600, 0)
    if hours < 24:
        return f"최근 {hours:.0f}시간분"
    return f"최근 {int(hours // 24)}일분"


def _lookup_events(
    ct, as_of: datetime | None, max_pages: int, window_days: int = _WINDOW_DAYS
) -> tuple[list[dict], bool, str | None]:
    """LookupEvents — (집계 행 목록, 페이지 상한 도달 여부, 관측 최고(最古) 시각) 반환.

    (principal, event_name) 별 카운트/최근시각 집계.

    중요: 얕은 `Event.Username` 은 principal ARN 이 아니라 세션명/역할명이라 정규화 인벤토리
    (전부 IAM ARN)와 매칭되지 않는다. 각 이벤트의 `CloudTrailEvent`(전체 JSON) 를 파싱해
    `userIdentity` 에서 **진짜 IAM principal ARN** 을 뽑는다:
      - AssumedRole → sessionContext.sessionIssuer.arn (임시 sts ARN 이 아니라 IAM role ARN)
      - IAMUser/Root → userIdentity.arn
      - AWSService 등 → principal 없음(스킵)
    """
    start = _window_start(as_of, window_days)
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
    # 커버 기간은 '훑은 범위'이므로 principal 을 못 뽑은 이벤트(AWSService 등)도 포함해 잰다 —
    # 집계 대상만 보면 근거 창을 실제보다 짧게 말하게 된다.
    coverage_start: str | None = None
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
            event_time = ev.get("EventTime")
            ev_iso = _iso(event_time)
            if ev_iso and (coverage_start is None or ev_iso < coverage_start):
                coverage_start = ev_iso
            principal = _principal_from_event(ev.get("CloudTrailEvent"))
            if not principal:
                continue  # AWSService 등 IAM principal 없는 이벤트는 사용실태 대상 아님
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
            if ev_iso and (rec["last_used"] is None or ev_iso > rec["last_used"]):
                rec["last_used"] = ev_iso
        pages += 1
        next_token = page.get("NextToken")
        if not next_token:
            break  # 마지막 페이지 — 요청한 창 전체 수집 완료.
        if pages >= max_pages:
            truncated = True  # 상한 도달, 후속 토큰 남음 → 더 과거 일부 미수집.
            break

    rows = list(agg.values())
    rows.sort(key=lambda r: (r["principal"], r["event_source"], r["event_name"]))
    return rows, truncated, coverage_start


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
