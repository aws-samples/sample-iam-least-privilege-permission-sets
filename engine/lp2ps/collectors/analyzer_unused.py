"""IAM Access Analyzer — Unused Access 수집 (읽기 전용).

기존 unused-access analyzer 의 findings(미사용 role/키/권한)를 나열한다:
`ListAnalyzers` → unused-access 타입 필터 → `ListFindingsV2` → `GetFindingV2`.

**읽기 전용 불변식(①) 준수 — analyzer 를 생성하지 않는다.**
analyzer 를 코드가 생성하는 설계도 가능하나, analyzer 생성(`CreateAnalyzer`)은
분석 대상 계정에 대한 **쓰기**이며 read-only 가드(allowlist)에 없다. 따라서 M1 은 analyzer 가
존재할 때만 findings 를 읽고, **없으면 `skipped` 로 degrade** 한다(그 계정의 미사용 판정은 M2 가
Access Advisor + 키 수명으로 대체 산출). analyzer 자동 생성 여부는 별도 정책 결정 사항으로 남긴다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from . import Collector, CollectorResult

if TYPE_CHECKING:  # pragma: no cover
    from ..session import AccountSession

SOURCE = "analyzer_unused"

_UNUSED_TYPES = {"ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"}


class UnusedAccessCollector(Collector):
    source = SOURCE

    def collect(self, account: "AccountSession", context: dict) -> CollectorResult:
        aa = account.client("accessanalyzer")

        try:
            analyzer_arn = _find_unused_analyzer(aa)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return _skip(account, f"Access Analyzer 조회 실패({code}) — Access Advisor 로 대체")

        if not analyzer_arn:
            return _skip(
                account,
                "unused-access analyzer 미존재 — 생성하지 않음(읽기전용). 정규화 단계가 Access Advisor 로 대체",
            )

        try:
            findings = _list_findings(aa, analyzer_arn)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return _skip(account, f"findings 조회 실패({code}) — Access Advisor 로 대체")

        return CollectorResult(
            source=SOURCE,
            status="ok",
            data={
                "account_id": account.account_id,
                "analyzer_arn": analyzer_arn,
                "findings": findings,
            },
            note="",
        )


def _skip(account: "AccountSession", note: str) -> CollectorResult:
    return CollectorResult(
        source=SOURCE,
        status="skipped",
        data={"account_id": account.account_id, "analyzer_arn": None, "findings": []},
        note=note,
    )


def _find_unused_analyzer(aa) -> str | None:
    """unused-access 타입 analyzer 중 첫 번째 ARN(이름 정렬로 결정론)."""
    matches: list[str] = []
    paginator = aa.get_paginator("list_analyzers")
    for page in paginator.paginate():
        for a in page.get("analyzers", []):
            if a.get("type") in _UNUSED_TYPES:
                matches.append(a["arn"])
    matches.sort()
    return matches[0] if matches else None


def _list_findings(aa, analyzer_arn: str) -> list[dict]:
    """**ACTIVE** unused-access findings(안정 정렬). 결정에 쓰는 필드만 평탄화.

    RESOLVED/ARCHIVED 는 더 이상 유효한 미사용 findings 가 아니므로 제외한다(그렇지 않으면
    이미 해소된 finding 이 현재 미사용으로 잘못 보고된다). 서버측 filter 로 status=ACTIVE 만 요청.
    """
    out: list[dict] = []
    paginator = aa.get_paginator("list_findings_v2")
    status_filter = {"status": {"eq": ["ACTIVE"]}}
    for page in paginator.paginate(analyzerArn=analyzer_arn, filter=status_filter):
        for f in page.get("findings", []):
            if f.get("status", "ACTIVE") != "ACTIVE":  # 방어: 서버 필터 외 이중 확인
                continue
            out.append(
                {
                    "id": f.get("id", ""),
                    "finding_type": f.get("findingType", ""),
                    "resource": f.get("resource", ""),
                    "resource_type": f.get("resourceType", ""),
                    "status": f.get("status", ""),
                }
            )
    out.sort(key=lambda x: (x["resource"], x["id"]))
    return out
