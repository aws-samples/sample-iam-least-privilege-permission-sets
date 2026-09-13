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

# ---- 사용 주체 신호(R1) ----
#
# 이벤트에는 "누가 이 역할을 집었나" 가 들어 있지만 종전 집계는 그것을 버리고 (principal, event,
# count, last_used) 만 남겼다. 그래서 사람이 쓰는 역할이 화면에서 전부 '판별 불가' 로 떴다.
# 이 신호들은 **이미 파싱한 이벤트**에서 뽑는다 — 추가 API 호출 0, 추가 권한 0.
#
# 🔴 원문은 남기지 않는다. 세션 이름에는 SSO 사용자 **이메일**이, 자동화 세션 이름에는 계정 ID 가
#    들어간다(개인정보). 호출자 ARN 도 남기지 않는다. 남기는 것은 **분류 라벨과 서비스명**뿐이다.

# 세션 이름 → 분류 라벨. 판정 순서가 곧 우선순위다(개인정보성이 강한 것부터).
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+")
_ACCOUNT_IN_NAME_RE = re.compile(r"\d{12}")
# 자동화가 붙이는 임의 접미: UUID, 또는 8자 이상의 hex/숫자 덩어리(Lambda·Step Functions·SDK 기본값).
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RANDOM_SUFFIX_RE = re.compile(r"(^|[^0-9a-fA-F])[0-9a-fA-F]{8,}$")
# IdC 콘솔 세션이 쓰는 역할 이름 접두(사람 접근의 강한 근거). AWS 예약 접두이므로 고객 값이 아니다.
_SSO_ROLE_PREFIX = "AWSReservedSSO_"

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
            events, truncated, coverage_start, subjects = _lookup_events(
                ct, as_of, max_pages, window_days
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return CollectorResult(
                source=SOURCE,
                status="skipped",
                data={"account_id": account.account_id, "mode": "none", "usage": [],
                      # 빈 목록 = "이 소스가 아무 주체 근거도 못 줬다". 키를 아예 빼면 하류가
                      # KeyError 대신 조용히 기본값을 쓰게 되어 판정 부재와 구분되지 않는다.
                      "subjects": [],
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
                  "usage": events,
                  # principal → 사용 주체 신호(R1). usage 행과 분리한 이유는 역할당 수천 행에
                  # 같은 4개 값이 중복되는 것을 피하기 위해서다. **원문 세션명·호출자 ARN 없음.**
                  "subjects": subjects},
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
) -> tuple[list[dict], bool, str | None, list[dict]]:
    """LookupEvents — (집계 행, 상한 도달 여부, 관측 최고(最古) 시각, 주체 신호 행) 반환.

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
    # principal → 사용 주체 신호(R1). action 행에 실으면 역할당 수천 번 중복되므로 별 집계다.
    subjects: dict[str, dict] = {}
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
            full = _parse_event(ev.get("CloudTrailEvent"))
            principal = _principal_from_identity(full.get("userIdentity") or {}) if full else ""
            # 주체 신호는 principal 을 못 뽑은 이벤트에서도 필요하다 — AssumeRole 의 호출자가
            # AWSService 면 principal 이 "" 지만, 그 사실이 **대상 역할**의 판정 근거다.
            if full:
                _collect_subject_signals(subjects, principal, full)
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
    return rows, truncated, coverage_start, _subject_rows(subjects)


def _empty_subject(principal: str) -> dict:
    return {
        "principal": principal,
        "mfa_seen": False,
        "invoked_by": set(),
        "session_name_shapes": set(),
        "assume_caller_kinds": set(),
    }


def _subject_rows(subjects: dict[str, dict]) -> list[dict]:
    """집계 → 결정론 정렬된 raw 행. 집합은 정렬 목록으로(불변식 ②)."""
    out = []
    for principal in sorted(subjects):
        s = subjects[principal]
        out.append({
            "principal": principal,
            "mfa_seen": s["mfa_seen"],
            "invoked_by": sorted(s["invoked_by"]),
            "session_name_shapes": sorted(s["session_name_shapes"]),
            "assume_caller_kinds": sorted(s["assume_caller_kinds"]),
        })
    return out


def _collect_subject_signals(subjects: dict[str, dict], principal: str, full: dict) -> None:
    """이벤트 1건 → 주체 신호 누적. **원문은 담지 않는다**(라벨·서비스명만).

    양성 근거만 모은다 — MFA 표시가 **없는 것**은 사람이 아니라는 근거가 못 된다(IdC 콘솔 세션도
    표시가 없을 수 있다). 그래서 mfa_seen 은 True 로만 올라가고 False 는 "못 봤다" 일 뿐이다.
    """
    ui = full.get("userIdentity") or {}
    if principal:
        s = subjects.setdefault(principal, _empty_subject(principal))
        attrs = (ui.get("sessionContext") or {}).get("attributes") or {}
        if str(attrs.get("mfaAuthenticated", "")).lower() == "true":
            s["mfa_seen"] = True
        invoked_by = ui.get("invokedBy")
        if isinstance(invoked_by, str) and invoked_by:
            s["invoked_by"].add(invoked_by)  # 서비스 principal 명(예: lambda.amazonaws.com)
        shape = _session_name_shape(ui)
        if shape:
            s["session_name_shapes"].add(shape)

    # AssumeRole: 호출자 성격을 **대상 역할**에 귀속한다. 이 역할을 집은 것이 사람인지 서비스인지는
    # 역할 자신의 이벤트에는 안 나온다 — 신뢰정책만 보면 사람이 쓰는 역할이 전부 unknown 이 되는
    # 이유가 이것이다.
    if full.get("eventName") == "AssumeRole" and full.get("eventSource") == "sts.amazonaws.com":
        params = full.get("requestParameters") or {}
        target = params.get("roleArn")
        if isinstance(target, str) and target.startswith("arn:"):
            t = subjects.setdefault(target, _empty_subject(target))
            t["assume_caller_kinds"].add(_caller_kind(ui))
            # 🔴 요청의 `roleSessionName` 도 대상 역할의 근거다. 예전에는 **행위자 자신의 이벤트**에서만
            # 세션명을 봤기 때문에(위 `_session_name_shape(ui)`), 크로스계정 assume 으로만 쓰이는 역할은
            # 세션명 근거가 0 이었다. 원문은 담지 않는다 — 닫힌 라벨만(R1-a).
            rsn = params.get("roleSessionName")
            if isinstance(rsn, str) and rsn:
                t["session_name_shapes"].add(_shape_of_name(rsn))


def _caller_kind(ui: dict) -> str:
    """AssumeRole 호출자 성격 라벨. **ARN 원문은 남기지 않는다.**

    사람: iam_user / federated / sso / root. 기계: service.
    role·unknown 은 근거로 쓰지 않는다 — 역할이 역할을 집는 것은 사람 자동화 양쪽 다 있다.
    """
    itype = ui.get("type", "")
    if itype == "AWSService":
        return "service"
    if itype == "IAMUser":
        return "iam_user"
    if itype == "Root":
        return "root"
    if itype in ("FederatedUser", "SAMLUser", "WebIdentityUser"):
        return "federated"
    if itype == "AssumedRole":
        arn = ui.get("arn", "")
        # IdC 콘솔 세션이 다른 역할을 집은 경우 = 사람이 한 일이다.
        return "sso" if _SSO_ROLE_PREFIX in arn else "role"
    # 🔴 크로스계정 AssumeRole 은 `AWSAccount` 로 온다 — ARN 도 호출자 종류도 없고 `accountId` 와
    # `principalId` 만 담긴다. 예전에는 여기서 곧바로 `unknown` 을 돌려줬고, 그래서 다른 계정 사람이
    # 매일 쓰는 역할이 "판별 불가" 가 됐다(실측: 관측 창을 57.8시간까지 늘려도 안 풀렸다 —
    # 커버리지 문제가 아니라 분류 누락이었다).
    # `principalId` 의 앞 4글자가 AWS 의 고정 식별자 접두라서 종류를 그대로 알려 준다.
    if itype == "AWSAccount":
        return _kind_from_principal_id(ui.get("principalId", ""))
    return "unknown"


# AWS 고유 ID 접두 → 호출자 종류. 접두 4글자만 보고 **원문은 버린다**(R1-a).
# ASIA(임시 자격증명)는 뒤에 무엇이 있는지 알 수 없어 근거로 쓰지 않는다.
_PRINCIPAL_ID_PREFIX_KIND = {
    "AIDA": "iam_user",       # IAM 사용자 → 사람
    "AROA": "role",           # 역할(사람·자동화 양쪽) → 근거로 쓰지 않는다
    "AIPA": "service",        # EC2 인스턴스 프로파일 → 기계
    "ASIA": "unknown",        # STS 임시 자격증명 → 원 주체를 알 수 없다
}


def _kind_from_principal_id(pid: str) -> str:
    """`principalId` → 호출자 종류 라벨. 판별 못 하면 `unknown`(추측하지 않는다)."""
    if not isinstance(pid, str) or not pid:
        return "unknown"
    # 루트 사용자로 온 크로스계정 호출은 principalId 가 12자리 계정 ID 그대로다.
    head = pid.split(":", 1)[0]
    if head.isdigit() and len(head) == 12:
        return "root"
    return _PRINCIPAL_ID_PREFIX_KIND.get(head[:4], "unknown")


def _session_name_shape(ui: dict) -> str | None:
    """세션 이름 → 분류 라벨(원문 반환 금지). 세션이 없으면 None.

    라벨만 남기는 이유: SSO 는 세션 이름에 사용자 이메일을 쓰고 자동화는 계정 ID 를 박는다.
    사람 판정의 가장 강한 근거가 개인정보라는 뜻이다 — 판정에만 쓰고 원문은 버린다.
    """
    if ui.get("type") != "AssumedRole":
        return None
    arn = ui.get("arn", "")
    m = re.match(r"^arn:aws[\w-]*:sts::\d{12}:assumed-role/[^/]+/(.+)$", arn)
    if not m:
        return None
    return _shape_of_name(m.group(1))


def _shape_of_name(name: str) -> str:
    """세션 이름 원문 → 라벨. `_session_name_shape`(ARN 경로)과 AssumeRole 요청 경로가 **같은 규칙**을
    쓰도록 갈라 놓은 것이다. 두 경로가 라벨을 다르게 매기면 같은 세션이 화면에서 두 성격으로 읽힌다.
    """
    if _EMAIL_RE.search(name):
        return "email_like"
    # UUID 를 계정 ID 보다 먼저 본다 — UUID 의 마지막 그룹은 12자리라 `\d{12}` 에 걸린다
    # (전부 숫자인 그룹이 실제로 나온다). 더 구체적인 패턴이 이겨야 라벨이 사실과 맞는다.
    if _UUID_RE.search(name):
        return "uuid_suffix"
    if _ACCOUNT_IN_NAME_RE.search(name):
        return "account_id_embedded"
    if _RANDOM_SUFFIX_RE.search(name):
        return "uuid_suffix"
    # 서비스·워크로드 이름 형태. **판정 근거로는 쓰지 않는다** — 사람의 사용자명도 이 형태다.
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9._=,@-]*", name):
        return "service_name"
    return "other"


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


def _parse_event(cloudtrail_event: str | None) -> dict:
    """CloudTrailEvent JSON 문자열 → dict(파싱 실패·부재는 빈 dict).

    이벤트당 한 번만 파싱한다 — principal 과 주체 신호가 같은 JSON 에서 나오므로 두 번 파싱하면
    큰 계정에서 그대로 두 배 비용이다.
    """
    if not cloudtrail_event:
        return {}
    try:
        full = json.loads(cloudtrail_event)
    except (ValueError, TypeError):
        return {}
    return full if isinstance(full, dict) else {}


def _principal_from_event(cloudtrail_event: str | None) -> str:
    """CloudTrailEvent JSON 문자열 → IAM principal ARN(없으면 '')."""
    return _principal_from_identity(_parse_event(cloudtrail_event).get("userIdentity") or {})


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
