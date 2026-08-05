"""Lambda 진입점 (zip 소스 패키징).

Step Functions 가 stage 별로 이 핸들러를 호출한다. 로컬 CLI(`python -m lp2ps.handler`, env LP2PS_*)
로도 같은 로직을 돌릴 수 있다. stage 파라미터로 파이프라인 일부/전체 실행:
  collect | analyze | synth | report | run

config 는 (1) event/env 의 인라인 dict, 또는 (2) 배포 패키지에 포함된 경로에서 로드. out 은 s3:// 또는
로컬 경로. run_id/started_at 은 Step Functions 실행에서 주입(결정론 재현).
"""

from __future__ import annotations

import json
import os
from typing import Any

from .config import Config, load_config
from .runctx import RunContext, new_run_context
from .storage import resolve_storage


def _resolve_config(params: dict) -> Config:
    """config 를 인라인 dict / 파일 경로 중 하나로 로드."""
    if "config_inline" in params and params["config_inline"]:
        return Config.model_validate(params["config_inline"])
    config_path = params.get("config_path") or os.environ.get("LP2PS_CONFIG")
    if not config_path:
        raise ValueError("config_inline 또는 config_path(LP2PS_CONFIG) 가 필요합니다.")
    return load_config(config_path)


def _run_stage(stage: str, cfg: Config, run: RunContext, out: str) -> dict:
    """단일 stage 실행. Step Functions 가 stage 별로 이 핸들러를 호출한다."""
    from . import pipeline

    storage = resolve_storage(out, cfg.customer, run.run_id)

    if stage == "collect":
        from .m1_collector import collect

        manifest = collect(cfg, storage, run)
        return {"stage": "collect", "status": manifest["status"],
                "account_scope": manifest["account_scope"]}
    if stage == "analyze":
        return {"stage": "analyze", **pipeline.run_analyze(storage, run, cfg)}
    if stage == "synth":
        return {"stage": "synth", **pipeline.run_synth(storage, run, cfg)}
    if stage == "report":
        scope, status = _scope_status(storage)
        return {"stage": "report",
                **pipeline.run_report(storage, run, cfg, account_scope=scope, status=status)}
    if stage == "run":
        return {"stage": "run", **pipeline.run_full(storage, run, cfg)}
    raise ValueError(f"알 수 없는 stage: {stage}")


def _scope_status(storage) -> tuple[int, str]:  # noqa: ANN001
    if storage.exists("collection_manifest.json"):
        m = storage.read_manifest()
        if isinstance(m, dict):
            return int(m.get("account_scope", 1)), str(m.get("status", "succeeded"))
    return 1, "succeeded"


def _params_from(event: dict | None) -> dict:
    """event(Lambda) 또는 환경변수(로컬 CLI)에서 파라미터 병합. event 우선."""
    params: dict[str, Any] = {
        "stage": os.environ.get("LP2PS_STAGE", "run"),
        "out": os.environ.get("LP2PS_OUT", "out"),
        "run_id": os.environ.get("LP2PS_RUN_ID") or None,
        "started_at": os.environ.get("LP2PS_STARTED_AT") or None,
        "config_path": os.environ.get("LP2PS_CONFIG") or None,
    }
    # CDK 가 config 를 인라인 JSON 환경변수로 주입(LP2PS_CONFIG_INLINE).
    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if inline:
        params["config_inline"] = json.loads(inline)
    if event:
        params.update({k: v for k, v in event.items() if v is not None})
    return params


def handler(event: dict | None = None, context: Any = None) -> dict:  # noqa: ANN401
    """Lambda 핸들러 겸 공용 진입. event/env 에서 파라미터를 읽어 stage 실행."""
    params = _params_from(event)
    cfg = _resolve_config(params)
    run = new_run_context(cfg.customer, started_at=params.get("started_at"))
    if params.get("run_id"):
        run = RunContext(run_id=params["run_id"], customer=cfg.customer, started_at=run.started_at)
    result = _run_stage(params.get("stage", "run"), cfg, run, params.get("out", "out"))
    result["run_id"] = run.run_id
    return result


def main() -> int:
    """로컬 CLI 진입: `python -m lp2ps.handler`. 결과를 stdout 에 JSON 으로."""
    result = handler(event=None, context=None)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
