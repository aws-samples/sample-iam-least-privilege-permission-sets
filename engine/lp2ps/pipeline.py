"""파이프라인 오케스트레이션 — stage barrier + 멱등.

각 stage 는 이전 stage 산출물을 storage 에서 읽어 진행하기 전에 **존재를 assert**한다(하네스 §4b
stage barrier). 코어 stage 는 모두 결정론이며 lp2ps.ai 를 import 하지 않는다(불변식 ③).

stage 그룹:
- analyze: normalize(M2) → escalation(M3) → risk(M4) → catalog(M5). normalized.parquet 을 순차 enrich.
- synth:   policy_synth(M7) → iac_emit(M7).
- report:  reports(M6) → snapshot.
- run:     collect(M1) → analyze → synth → report (전체).

collect 는 AWS 자격증명이 필요하므로 여기서 직접 부르지 않고 run() 이 m1_collector 로 위임한다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .storage import MANIFEST_NAME, NORMALIZED_NAME

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session

    from .config import Config
    from .runctx import RunContext
    from .storage import Storage


class StageBarrierError(RuntimeError):
    """upstream 산출물이 없어 다음 stage 를 진행할 수 없을 때(fail-closed)."""


def _require(storage: "Storage", relpath: str, stage: str) -> None:
    if not storage.exists(relpath):
        raise StageBarrierError(
            f"stage '{stage}' 진행 불가: 선행 산출물 '{relpath}' 없음 "
            f"({storage.location(relpath)}). 선행 stage 를 같은 --out/--run-id 로 먼저 실행하세요."
        )


def run_analyze(storage: "Storage", run: "RunContext", cfg: "Config") -> dict:
    """normalize → escalation → risk → tracks → catalog → service_roles. 반환 요약 dict."""
    from .m2_normalizer import normalize
    from .m3_escalation import detect_escalations
    from .m4_risk_scorer import score_risks
    from .m5_catalog import build_catalog
    from .m5_service_roles import build_service_roles
    from .m5_tracks import assign_tracks

    _require(storage, MANIFEST_NAME, "analyze")  # collect 산출물 필요
    records = normalize(
        storage, run, cfg.risk_rules,
        account_groups=_tenancy_of(storage, cfg),
        tooling_account_id=_tooling_account_id(storage),
    )

    _require(storage, NORMALIZED_NAME, "escalation")
    detect_escalations(storage, run)
    score_risks(storage, run, cfg.risk_rules)
    # 트랙 배정은 **카탈로그보다 먼저**다. M5·M6 은 대상 선별을 각자 다시 하지 않고 이 결과를 읽는다
    # (두 곳이 각자 조건을 갖게 되면 화면이 "제외" 라고 말한 대상이 persona 에 들어 있게 된다).
    tracks = assign_tracks(storage, run, cfg)
    catalog = build_catalog(storage, run, cfg.catalog)
    service_roles = build_service_roles(storage, run, cfg)

    return {
        "principals": len(records),
        "personas": len(catalog),
        "service_roles": len(service_roles),
        "tracks": tracks,
    }


def _tenancy_of(storage: "Storage", cfg: "Config") -> dict[str, str]:
    """이번 run 이 **실제로 수집한** 계정의 테넌트 그룹 맵(R5).

    config 선언이 아니라 산출물 기준이어야 한다. `cross_account=false` 모드의 `accounts` 는
    `["self"]` 라서 config 만 보면 자기 계정조차 맵에 없고, 그러면 자기 계정을 신뢰하는 모든 역할이
    `unconfirmed`(소유자 확인)로 밀린다. 반대로 맵에 없는 계정을 기본 그룹으로 채워 주지도 않는다 —
    들여다본 적 없는 계정을 내부라고 말하면 fail-safe 가 뒤집힌다(`Config.tenant_group_of` 가 범위 밖
    계정에 `""` 를 주는 것과 같은 이유다).
    """
    from .config import DEFAULT_TENANT_GROUP

    return {
        account_id: cfg.tenant_group_of(account_id) or DEFAULT_TENANT_GROUP
        for account_id in storage.list_accounts()
    }


def _tooling_account_id(storage: "Storage") -> str:
    """manifest 에 M1 이 기록한 호출자(관제) 계정 ID. 없으면 빈 문자열(모른다).

    config 키로 두지 않는 이유: 관제 계정은 `accounts` 에 없을 수 있고(권장 구성), 선언은 배포가
    옮겨지면 조용히 틀린 값이 된다. M1 이 `sts:GetCallerIdentity` 로 **측정한** 사실을 쓴다.
    """
    manifest = storage.read_manifest()
    if isinstance(manifest, dict):
        value = manifest.get("tooling_account_id")
        if isinstance(value, str):
            return value
    return ""


def run_synth(storage: "Storage", run: "RunContext", cfg: "Config") -> dict:
    """policy_synth → iac_emit. analyze(catalog) 선행 필요."""
    from .m7_iac_emitter import emit_iac
    from .m7_policy_synth import synth_policies

    _require(storage, "catalog.json", "synth")
    policies = synth_policies(storage, run)
    iac = emit_iac(storage, run, cfg)
    return {"policies": len(policies), "iac_files": len(iac)}


def run_report(storage: "Storage", run: "RunContext", cfg: "Config", account_scope: int, status: str) -> dict:
    """reports(M6) → snapshot. analyze 선행 필요."""
    from .m6_reporter import build_reports
    from .snapshot import write_snapshot

    _require(storage, NORMALIZED_NAME, "report")
    _require(storage, "catalog.json", "report")
    summary = build_reports(storage, run, cfg)
    point = write_snapshot(storage, run, account_scope=account_scope, status=status,
                           risk_rules=cfg.risk_rules, cfg=cfg)
    return {
        "personas": summary.personas,
        "unused_permission_principals": summary.unused_permission_principals,
        "unused_permission_actions": summary.unused_permission_actions,
        "metrics_run_id": point.run_id,
    }


def run_full(
    storage: "Storage", run: "RunContext", cfg: "Config", base_session: "Session | None" = None
) -> dict:
    """collect → analyze → synth → report 전체. 반환 = 단계별 요약."""
    from .m1_collector import collect

    manifest = collect(cfg, storage, run, base_session=base_session)
    analyze = run_analyze(storage, run, cfg)
    synth = run_synth(storage, run, cfg)
    report = run_report(
        storage, run, cfg,
        account_scope=manifest["account_scope"],
        status=manifest["status"],
    )
    return {"manifest_status": manifest["status"], **analyze, **synth, **report}
