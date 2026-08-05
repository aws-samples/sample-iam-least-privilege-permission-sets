"""Access Advisor (Service Last Accessed) 수집.

각 principal 에 대해 `GenerateServiceLastAccessedDetails`(action-level) → `GetServiceLastAccessedDetails`
로 "어떤 서비스/액션을 마지막으로 언제 썼는지"를 얻는다. granted-vs-used 갭(미사용 권한)의 핵심 소스다.

- `Generate*` 는 report 생성이라 allowlist(Generate) 통과. 계정 IAM 미변경.
- action-level 세부는 지원 서비스에서만 나온다 → 서비스 단위 last-accessed 로 폴백(미지원은 note).
- credential_report collector 가 채운 `context["principals"]` 를 재사용(재조회 없음).
- principal 이 없거나 조회 실패면 degraded 로 완주.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from . import Collector, CollectorResult

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

SOURCE = "access_advisor"

# GetServiceLastAccessedDetails 가 아직 생성 중이면 잠깐 폴링. 결정론 코어이므로
# wall-clock 을 산출물에 넣지 않는다 — 여기 sleep 은 폴링 지연일 뿐 데이터에 안 들어간다.
_MAX_POLLS = 10
_POLL_SLEEP_S = 1.0


class AccessAdvisorCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        principals = context.get("principals") or []
        if not principals:
            return CollectorResult(
                source=SOURCE,
                status="degraded",
                data={"account_id": account.account_id, "last_accessed": []},
                note="principal 인벤토리가 없어 Access Advisor 를 건너뜀",
            )

        iam = account.client("iam")

        # 2단계 수집: (1) 모든 principal 의 generate 잡을 먼저 발사(AWS 측 비동기 실행),
        # (2) 그 다음 결과를 회수. principal 당 순차 generate→poll→get 을 하면 principal 수에
        # 비례해 대기가 누적된다(347개 계정에서 수 분+). 먼저 전부 발사하면 회수 시점엔
        # 대부분 완료돼 대기가 거의 사라진다.
        jobs: list[tuple[str, str]] = []  # (arn, job_id)
        failures = 0
        for p in principals:
            arn = p["principal"]
            try:
                job = iam.generate_service_last_accessed_details(
                    Arn=arn, Granularity="ACTION_LEVEL"
                )
                jobs.append((arn, job["JobId"]))
            except ClientError:
                failures += 1

        entries: list[dict] = []
        for arn, job_id in jobs:
            try:
                services = _retrieve(iam, job_id)
                entries.append({"principal": arn, "services": services})
            except ClientError:
                failures += 1
        entries.sort(key=lambda e: e["principal"])

        status = "ok"
        note = ""
        if failures and not entries:
            status = "degraded"
            note = "모든 principal 의 Access Advisor 조회 실패"
        elif failures:
            note = f"{failures}개 principal 의 Access Advisor 조회 실패(부분 수집)"

        return CollectorResult(
            source=SOURCE,
            status=status,
            data={"account_id": account.account_id, "last_accessed": entries},
            note=note,
        )


def _retrieve(iam, job_id: str) -> list[dict]:
    """이미 발사된 generate 잡의 결과를 회수(안정 정렬).

    GetServiceLastAccessedDetails 는 IsTruncated/Marker 로 페이지네이션된다. 첫 페이지만 읽으면
    서비스가 많은 principal 의 사용 실태가 잘려 granted-vs-used 갭이 과대 계상된다 → 모든 페이지를
    Marker 로 이어 받는다.
    """
    services: list[dict] = []
    resp = _poll(iam, job_id)
    while True:
        for svc in resp.get("ServicesLastAccessed", []):
            services.append(
                {
                    "service": svc.get("ServiceNamespace", ""),
                    "last_authenticated": _iso(svc.get("LastAuthenticated")),
                    "total_authenticated_entities": svc.get("TotalAuthenticatedEntities", 0),
                    "actions": _actions(svc.get("TrackedActionsLastAccessed", [])),
                }
            )
        if not resp.get("IsTruncated") or not resp.get("Marker"):
            break
        resp = iam.get_service_last_accessed_details(JobId=job_id, Marker=resp["Marker"])
    services.sort(key=lambda s: s["service"])
    return services


def _poll(iam, job_id: str, marker: str | None = None) -> dict:
    """job 이 COMPLETED 될 때까지 폴링 후 (첫) 응답을 반환."""
    kwargs = {"JobId": job_id}
    if marker:
        kwargs["Marker"] = marker
    resp = iam.get_service_last_accessed_details(**kwargs)
    polls = 0
    while resp.get("JobStatus") == "IN_PROGRESS" and polls < _MAX_POLLS:
        time.sleep(_POLL_SLEEP_S)
        resp = iam.get_service_last_accessed_details(**kwargs)
        polls += 1
    return resp


def _actions(tracked: list[dict]) -> list[dict]:
    out = [
        {
            "action": a.get("ActionName", ""),
            "last_accessed": _iso(a.get("LastAccessedTime")),
        }
        for a in tracked
    ]
    out.sort(key=lambda a: a["action"])
    return out


def _iso(dt) -> str | None:
    """boto3 datetime → ISO8601 문자열. None 은 그대로."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.isoformat()
