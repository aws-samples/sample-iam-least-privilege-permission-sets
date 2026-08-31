"""M1 Collector — 오케스트레이션.

`resolve_sessions` 로 대상 계정 세션(항상 read-only 가드)을 얻고, 계정마다 고정 순서 collector 4종을
실행해 `raw/<account_id>/<source>.json` 을 기록한다. 계정·소스별 상태(ok/degraded/skipped)를
`collection_manifest.json` 으로 요약한다(수집 단계 계약 — `storage.py` 레이아웃 참조).

graceful degradation: 개별 collector 가 예외를 던져도 run 은 계속된다 — 해당 소스만 degraded 로
기록하고 다음 계정/소스로 진행(bare 계정 첫 run 완주).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .collectors import CollectorResult, all_collectors
from .session import resolve_sessions

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session

    from .config import Config
    from .runctx import RunContext
    from .storage import Storage


def collect(
    config: "Config",
    storage: "Storage",
    run: "RunContext",
    base_session: "Session | None" = None,
) -> dict:
    """전체 수집 실행 → manifest dict 반환(storage 에도 기록됨).

    반환 manifest 구조:
        {
          "run_id", "customer", "started_at", "account_scope",
          "status": "succeeded" | "degraded",   # degraded 는 실제 저품질 소스가 있을 때만.
                                                 # skipped(선택적 소스 미존재)는 정상 → succeeded.
          "status_summary": {"degraded_sources", "skipped_sources", "has_skipped"},
          "accounts": [
            {"account_id", "sources": [{"source","status","note","raw_key"}]}
          ]
        }
    """
    # run_id 는 assume-role 감사 이벤트의 correlation_id 로 쓰인다(감사 요건). 이 호출은
    # `_run_one` 의 예외 포획 **밖**이므로 assume 실패는 지금과 동일하게 run 을 실패시킨다 —
    # 달라진 것은 실패가 구조화 감사 라인으로 먼저 기록된다는 점뿐이다.
    sessions = resolve_sessions(config, base_session=base_session, run_id=run.run_id)

    account_entries: list[dict] = []
    any_degraded = False
    any_skipped = False

    # IdC 는 config.region 과 다른 리전일 수 있음(계정당 단일 리전). collector 가 참조.
    idc_region = config.provisioning.idc_region or config.region

    for account in sessions:
        # collector 간 공유 컨텍스트. as_of = run.started_at → 소급 창 결정론.
        context: dict = {
            "as_of": run.started_at,
            "idc_region": idc_region,
            # 수집 예산·창(계정 수에 맞춰 고객이 조정) — collector 가 코드 상수 대신 이 값을 쓴다.
            "cloudtrail_max_pages": config.collection.cloudtrail_max_pages,
            "cloudtrail_window_days": config.collection.cloudtrail_window_days,
        }
        source_entries: list[dict] = []

        for collector in all_collectors():
            result = _run_one(collector, account, context)
            raw_key = storage.write_raw(account.account_id, result.source, result.data)
            source_entries.append(
                {
                    "source": result.source,
                    "status": result.status,
                    "note": result.note,
                    "raw_key": storage.raw_key(account.account_id, result.source),
                }
            )
            # 상태 판정(정직): degraded 만 run 을 degraded 로 낮춘다. skipped 는 선택적 소스
            # 미존재/미프로비저닝(unused-access analyzer 없음, IdC 권한 없음 등)이라 **정상**이며
            # Access Advisor 등 다른 소스가 보완한다 → succeeded 유지(리포트·문서와 동일 원칙).
            if result.status == "degraded":
                any_degraded = True
            elif result.status == "skipped":
                any_skipped = True

        source_entries.sort(key=lambda s: s["source"])
        account_entries.append(
            {"account_id": account.account_id, "sources": source_entries}
        )

    account_entries.sort(key=lambda a: a["account_id"])

    manifest = {
        "run_id": run.run_id,
        "customer": run.customer,
        "started_at": run.started_at,
        "account_scope": len(sessions),
        "status": "degraded" if any_degraded else "succeeded",
        # 상태 근거 요약(UI 실행 이력 상세용). skipped 는 정상(선택적 소스 미존재)임을 명시.
        "status_summary": {
            "degraded_sources": sorted({
                s["source"] for a in account_entries for s in a["sources"] if s["status"] == "degraded"
            }),
            "skipped_sources": sorted({
                s["source"] for a in account_entries for s in a["sources"] if s["status"] == "skipped"
            }),
            "has_skipped": any_skipped,
        },
        "accounts": account_entries,
    }
    storage.write_manifest(manifest)
    return manifest


def _run_one(collector, account, context: dict) -> CollectorResult:
    """collector 하나를 실행하되, 예상 못 한 예외도 삼켜 degraded 로 완주시킨다.

    단, `ReadOnlyViolation` 은 **삼키지 않고 전파**한다 — 읽기전용 불변식 위반은 버그이지
    degradation 이 아니므로 run 을 즉시 실패시켜 드러낸다.
    """
    import logging

    from .awsguard import ReadOnlyViolation

    try:
        return collector.collect(account, context)
    except ReadOnlyViolation:
        raise
    except Exception as e:  # noqa: BLE001 — 완주 목적의 광범위 포획(불변식 위반 제외)
        # 예외 메시지·traceback 은 고객 노출 산출물(manifest note)에 넣지 않는다.
        # 계정ID·정책ARN 등 민감정보가 예외 텍스트에 섞일 수 있으므로 note 엔 예외 **타입명만** 남기고,
        # 전체 메시지·traceback 은 서버(CloudWatch) 로그에만 기록한다.
        logging.getLogger("lp2ps.engine").exception(
            "collector 예외 (source=%s account=%s)", collector.source, account.account_id
        )
        return CollectorResult(
            source=collector.source,
            status="degraded",
            data={"account_id": account.account_id, "error": True},
            note=f"수집 중 예외: {type(e).__name__}",
        )
