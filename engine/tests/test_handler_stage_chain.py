"""핸들러가 **다음 stage 로 넘길 run 컨텍스트**를 응답에 담는가.

Step Functions 의 collect 단계는 이 응답의 `run_id`/`started_at` 을 상태 루트로 승격해 이후
stage(analyze·synth·report)에 넘긴다(`infra/lib/engine-stack.ts`). 스케줄 트리거는 run 컨텍스트를
주지 않으므로(`{"run_id": null, "started_at": null}`) **이 응답이 유일한 전달 경로**다. 둘 중 하나라도
빠지면 stage 마다 각자 새 run 이 생기고 analyze 가 선행 산출물을 못 찾아 죽는다 — 라이브 스케줄
실행 2건이 실제로 그렇게 실패했다(2026-09-12·09-13).

`_run_stage` 는 대체한다. 여기서 검증하는 계약은 파이프라인 결과가 아니라 **응답의 run 컨텍스트**다.
"""

from __future__ import annotations

import pytest

from lp2ps import handler as H

CFG_INLINE = {
    "customer": "test",
    "region": "us-west-2",
    "accounts": ["self"],
    "cross_account": False,
}


@pytest.fixture()
def stub_stage(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """stage 실행을 대체하고, 호출된 run_id 를 기록한다."""
    seen: list[str] = []

    def fake(stage: str, cfg: object, run: object, out: str) -> dict:
        seen.append(run.run_id)  # type: ignore[attr-defined]
        return {"stage": stage, "status": "succeeded"}

    monkeypatch.setattr(H, "_run_stage", fake)
    return seen


def test_response_carries_run_context(stub_stage: list[str]) -> None:
    """트리거가 run 컨텍스트를 주지 않아도 응답이 run_id·started_at 을 갖는다."""
    result = H.handler({"stage": "collect", "run_id": None, "started_at": None,
                        "config_inline": CFG_INLINE, "out": "out"})
    assert result["run_id"], "run_id 가 응답에 없다 — 다음 stage 가 새 run 을 만든다"
    assert result["started_at"], "started_at 이 응답에 없다"
    # 실제로 그 run 으로 stage 를 돌렸는지(응답만 그럴싸한 값이면 안 된다).
    assert stub_stage == [result["run_id"]]


def test_injected_run_id_round_trips(stub_stage: list[str]) -> None:
    """승격된 run_id 를 다음 stage 가 받으면 그것을 그대로 쓴다(새로 만들지 않는다)."""
    rid = "run-20260914T000000Z-deadbeef"
    result = H.handler({"stage": "analyze", "run_id": rid, "started_at": None,
                        "config_inline": CFG_INLINE, "out": "out"})
    assert result["run_id"] == rid
    assert stub_stage == [rid]


def test_stage_chain_shares_one_run(stub_stage: list[str]) -> None:
    """collect 응답을 그대로 이후 stage 입력으로 넘기면 4개 stage 가 한 run 을 공유한다.

    이것이 Step Functions 가 하는 일의 축소판이다. 승격이 없으면(= run_id 를 넘기지 않으면)
    아래 `assert len(set(...)) == 1` 이 4개 서로 다른 값으로 깨진다.
    """
    state = {"run_id": None, "started_at": None}
    for stage in ("collect", "analyze", "synth", "report"):
        out = H.handler({"stage": stage, **state, "config_inline": CFG_INLINE, "out": "out"})
        state = {"run_id": out["run_id"], "started_at": out["started_at"]}
    assert len(set(stub_stage)) == 1, f"stage 들이 서로 다른 run 을 썼다: {set(stub_stage)}"
    assert len(stub_stage) == 4


def test_no_promotion_breaks_the_chain(stub_stage: list[str]) -> None:
    """대조군 — run_id 를 넘기지 않으면 stage 마다 다른 run 이 된다(결함 상태 재현)."""
    for stage in ("collect", "analyze", "synth", "report"):
        H.handler({"stage": stage, "run_id": None, "started_at": None,
                   "config_inline": CFG_INLINE, "out": "out"})
    assert len(set(stub_stage)) == 4, "결함 상태가 재현되지 않았다 — 이 테스트의 판별력이 없다"
