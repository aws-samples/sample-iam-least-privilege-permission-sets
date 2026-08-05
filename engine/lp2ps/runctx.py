"""Run 식별자 — run_id + started_at.

`started_at` 은 불변식 ②의 **유일한 wall-clock 예외**(models.Run.started_at). 산출물의 다른
어떤 값도 실행 시각에 의존하면 안 된다. 결정론 테스트(2회 run 바이트 동일)를 위해 run 식별자를
**주입 가능**하게 한다 — CLI 는 기본값을 생성하고, 테스트/재현은 고정 값을 넘긴다.

run_id 형식: `run-<YYYYMMDDTHHMMSSZ>-<rand8>` (started_at 파생 시각 + 랜덤 접미사).
랜덤 접미사로 동시/근접 실행의 run_id 충돌·예측을 방지한다. 테스트·재현은 run_id 를
직접 주입하므로(결정론) 이 랜덤은 자동생성 경로(new_run_context)에만 적용된다.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class RunContext:
    run_id: str
    customer: str
    started_at: str  # ISO8601 UTC

    @property
    def started_dt(self) -> datetime:
        return datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))


def new_run_context(customer: str, started_at: str | None = None) -> RunContext:
    """run 컨텍스트 생성. started_at 미지정 시 현재 UTC(유일 허용 wall-clock)."""
    if started_at is None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        started_at = now.isoformat().replace("+00:00", "Z")
    dt = datetime.fromisoformat(started_at.replace("Z", "+00:00")).astimezone(timezone.utc)
    # 시각 파생 run_id 에 랜덤 접미사를 붙여 충돌·예측 방지.
    run_id = "run-" + dt.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    return RunContext(run_id=run_id, customer=customer, started_at=started_at)
