"""수집기(collector) 계약 — M1.

각 collector 는 **읽기 전용 가드가 붙은** 대상 계정 클라이언트로 IAM 사용 실태 한 조각을
수집한다. 공통 규칙(불변식 + graceful degradation):

- 소스가 미프로비저닝이거나 권한이 없으면 **crash 하지 않고** `degraded`/`skipped` 로 기록한다
  (bare 계정 첫 run 도 완주해야 한다 — self-mode).
- 반환 `data` 는 `raw/<account_id>/<source>.json` 에 그대로 기록될 결정론 payload 다.
- 어떤 collector 도 쓰기 API 를 부르지 않는다. allowlist 밖 호출은 `ReadOnlyViolation` 으로 즉시 실패.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

CollectorStatus = Literal["ok", "degraded", "skipped"]


@dataclass
class CollectorResult:
    """collector 하나의 산출물 + 상태(manifest 에 요약된다)."""

    source: str
    status: CollectorStatus
    data: dict = field(default_factory=dict)
    note: str = ""


class Collector:
    """collector 인터페이스. `source` 는 raw 파일명(`raw/<acct>/<source>.json`)이 된다.

    `context` 는 같은 계정의 앞선 collector 들이 채운 공유 dict 다(고정 순서 실행이므로 안전).
    예: `credential_report` 가 principal 인벤토리를 넣으면 `access_advisor`/`analyzer_unused` 가
    재조회 없이 재사용한다.
    """

    source: str = ""

    def collect(
        self, account: "AccountSession", context: dict
    ) -> CollectorResult:  # pragma: no cover - abstract
        raise NotImplementedError


def all_collectors() -> "list[Collector]":
    """수집기(고정 순서 — 결정론)."""
    from .access_advisor import AccessAdvisorCollector
    from .analyzer_unused import UnusedAccessCollector
    from .cloudtrail import CloudTrailCollector
    from .credential_report import CredentialReportCollector
    from .idc_permission_sets import IdcPermissionSetsCollector

    return [
        CredentialReportCollector(),
        AccessAdvisorCollector(),
        UnusedAccessCollector(),
        CloudTrailCollector(),
        IdcPermissionSetsCollector(),
    ]


__all__ = [
    "Collector",
    "CollectorResult",
    "CollectorStatus",
    "all_collectors",
]
