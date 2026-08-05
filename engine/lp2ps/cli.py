"""lp2ps CLI 진입점.

배선: `collect`(M1 → raw/** + manifest), `analyze`(M2 normalize + M3 escalation + M4 risk +
M5 catalog → normalized.parquet·catalog.json 등), `synth`(M7 정책+IaC), `report`(M6 백로그·리포트 +
snapshot), `run`(collect→analyze→synth→report 전체). 파이프라인 오케스트레이션은 pipeline.py.
"""

from __future__ import annotations

import argparse
import sys

from .config import Config, load_config
from .runctx import RunContext, new_run_context
from .storage import resolve_storage


def _add_common_args(p: argparse.ArgumentParser, *, with_run: bool = False) -> None:
    p.add_argument("-c", "--config", required=True, help="config/<customer>.yaml 경로")
    if with_run:
        p.add_argument(
            "--out",
            default="out",
            help="산출물 base 경로(LocalFS 루트 또는 s3:// URI). 기본 'out'",
        )
        p.add_argument(
            "--run-id",
            default=None,
            help="run 식별자 고정(재현·결정론 테스트용). 미지정 시 started-at 에서 파생",
        )
        p.add_argument(
            "--started-at",
            default=None,
            help="run 시작 시각 ISO8601(결정론 재현용). 미지정 시 현재 UTC",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lp2ps", description="IAM 최소권한 → Permission Set 도구 (읽기 전용)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [
        ("collect", "대상 계정에서 IAM 사용 실태 수집 (읽기 전용)"),
        ("analyze", "정규화 + 상승경로 + 위험점수 + persona 카탈로그"),
        ("synth", "최소권한 정책 + Permission Set Terraform 합성"),
        ("report", "cleanup 백로그·리포트·지표 스냅샷 산출"),
        ("run", "collect→analyze→synth→report 전체 실행"),
    ]:
        _add_common_args(sub.add_parser(name, help=help_text), with_run=True)

    _add_common_args(sub.add_parser("validate-config", help="config 파일 로드·검증만"))

    return parser


def _resolve_run(cfg: Config, args: argparse.Namespace) -> RunContext:
    run = new_run_context(cfg.customer, started_at=args.started_at)
    if args.run_id:
        run = RunContext(run_id=args.run_id, customer=cfg.customer, started_at=run.started_at)
    return run


def _cmd_collect(cfg: Config, args: argparse.Namespace) -> int:
    from .m1_collector import collect

    run = _resolve_run(cfg, args)
    storage = resolve_storage(args.out, cfg.customer, run.run_id)
    manifest = collect(cfg, storage, run)

    print(f"[collect] run_id={run.run_id} status={manifest['status']} "
          f"accounts={manifest['account_scope']}")
    for acct in manifest["accounts"]:
        summary = ", ".join(f"{s['source']}={s['status']}" for s in acct["sources"])
        print(f"  {acct['account_id']}: {summary}")
    print(f"  출력: {storage.location()}")
    # degraded 도 성공(완주)으로 본다 — 미프로비저닝은 실패가 아님.
    return 0


def _cmd_analyze(cfg: Config, args: argparse.Namespace) -> int:
    from .pipeline import StageBarrierError, run_analyze

    run = _resolve_run(cfg, args)
    storage = resolve_storage(args.out, cfg.customer, run.run_id)
    try:
        result = run_analyze(storage, run, cfg)
    except StageBarrierError as e:
        print(f"[analyze] {e}", file=sys.stderr)
        return 2
    print(f"[analyze] run_id={run.run_id} principals={result['principals']} "
          f"personas={result['personas']} → {storage.location()}")
    return 0


def _cmd_synth(cfg: Config, args: argparse.Namespace) -> int:
    from .pipeline import StageBarrierError, run_synth

    run = _resolve_run(cfg, args)
    storage = resolve_storage(args.out, cfg.customer, run.run_id)
    try:
        result = run_synth(storage, run, cfg)
    except StageBarrierError as e:
        print(f"[synth] {e}", file=sys.stderr)
        return 2
    print(f"[synth] run_id={run.run_id} policies={result['policies']} "
          f"iac_files={result['iac_files']} → {storage.location('iac')}")
    return 0


def _cmd_report(cfg: Config, args: argparse.Namespace) -> int:
    from .pipeline import StageBarrierError, run_report

    run = _resolve_run(cfg, args)
    storage = resolve_storage(args.out, cfg.customer, run.run_id)
    # account_scope/status 는 manifest 에서 읽는다(report 단독 실행 지원).
    scope, status = _scope_status_from_manifest(storage)
    try:
        result = run_report(storage, run, cfg, account_scope=scope, status=status)
    except StageBarrierError as e:
        print(f"[report] {e}", file=sys.stderr)
        return 2
    print(f"[report] run_id={run.run_id} personas={result['personas']} "
          f"cleanup(unused_perm)={result['unused_permissions_removed']} → {storage.location()}")
    return 0


def _cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    from .pipeline import run_full

    run = _resolve_run(cfg, args)
    storage = resolve_storage(args.out, cfg.customer, run.run_id)
    result = run_full(storage, run, cfg)
    print(f"[run] run_id={run.run_id} status={result['manifest_status']} "
          f"principals={result['principals']} personas={result['personas']} "
          f"policies={result['policies']} iac_files={result['iac_files']}")
    print(f"  출력: {storage.location()}")
    return 0


def _scope_status_from_manifest(storage) -> tuple[int, str]:  # noqa: ANN001
    """report 단독 실행 시 manifest 에서 account_scope/status 복원(없으면 기본값)."""
    if storage.exists("collection_manifest.json"):
        m = storage.read_manifest()
        if isinstance(m, dict):
            return int(m.get("account_scope", 1)), str(m.get("status", "succeeded"))
    return 1, "succeeded"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)

    if args.command == "validate-config":
        print(f"config OK: customer={cfg.customer} region={cfg.region} "
              f"cross_account={cfg.cross_account} accounts={cfg.accounts}")
        return 0

    handlers = {
        "collect": _cmd_collect,
        "analyze": _cmd_analyze,
        "synth": _cmd_synth,
        "report": _cmd_report,
        "run": _cmd_run,
    }
    return handlers[args.command](cfg, args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
