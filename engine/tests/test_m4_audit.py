"""M4 Risk Scorer — 점수=가중치 합, 근거 재현, risk_audit.jsonl."""

from __future__ import annotations

import json

from lp2ps.config import RiskRules
from lp2ps.m4_risk_scorer import AUDIT_NAME, score_risks
from lp2ps.models import EscalationPath, PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-15T00:00:00Z")


def _seed(storage, records):
    storage.write_normalized(records)


def _rec(**kw) -> PrincipalRecord:
    base = dict(account_id="111122223333", principal="arn:aws:iam::111122223333:role/r",
                identity_type="role", run_id="run-x")
    base.update(kw)
    return PrincipalRecord(**base)


def test_score_is_sum_of_weights(tmp_path):
    rules = RiskRules()
    st = LocalFSStorage(tmp_path, "test", "run-x")
    # long_lived_key(20) + wildcard(20) + escalation 1건(30) = 70 → high(>=50).
    rec = _rec(
        principal="arn:aws:iam::111122223333:user/u", identity_type="user", mfa=True,
        access_key_age_days=100, granted_actions=["s3:*"],
        escalation_paths=[EscalationPath(via="x", to="y", mitre="TA0004")],
    )
    _seed(st, [rec])
    out = score_risks(st, RUN, rules)
    r = out[0]
    assert r.risk_score == 20 + 20 + 30
    assert r.risk_level == "high"


def test_reasons_are_ordered_by_contribution_and_carry_points(tmp_path):
    """근거는 **기여도 내림차순**이고 각 문장에 그 규칙의 점수가 붙는다.

    화면이 첫 줄을 "왜 이 등급인지" 한 줄 요약으로 쓴다(사용자 피드백 2026-09-11). 예전에는
    `reasons.sort()` 알파벳 정렬이라 첫 줄이 최대 기여라는 보장이 없었다.

    🔴 이 픽스처는 **알파벳 1위 ≠ 기여 1위** 로 잡았다 — 옛 코드에서 첫 줄은 "관리자급…"(+25)이고
    기여 1위는 "권한 상승 경로 2건"(+40, 상한)이다. 그래야 어서션이 정렬을 실제로 잰다.
    """
    rules = RiskRules()
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _rec(
        granted_actions=["*"],  # admin_like(25) + wildcard_action(20)
        escalation_paths=[EscalationPath(via="a", to="b", mitre="TA0004"),
                          EscalationPath(via="c", to="d", mitre="TA0004")],  # 2건 → 60이나 상한 40
        unused_findings=["s3:a", "s3:b"],  # 2건 × 1 = 2
    )
    _seed(st, [rec])
    reasons = score_risks(st, RUN, rules)[0].risk_reasons

    points = [int(r.rsplit("(+", 1)[1].removesuffix("점)")) for r in reasons]
    assert points == sorted(points, reverse=True), reasons
    assert reasons[0].startswith("권한 상승 경로 2건")
    # 상한에 걸린 사실을 말한다 — 2건인데 60이 아니라 40인 이유가 화면에서 설명돼야 한다.
    assert "상한" in reasons[0]
    assert reasons[0].endswith("(+40점)")
    # 알파벳 정렬이었다면 "관리자급…" 이 첫 줄이었다(대조군: 이 문장은 존재하고 1위가 아니다).
    assert any(r.startswith("관리자급 광범위 권한") for r in reasons)
    assert not reasons[0].startswith("관리자급")
    # 근거 점수 합 == 총점(클램프 전) — 문장에 실린 숫자가 실제 기여도다.
    assert sum(points) == 40 + 25 + 20 + 2


def test_audit_contributions_reproduce_score(tmp_path):
    rules = RiskRules()
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _rec(identity_type="user", mfa=False, console_login=True, access_key_age_days=200,
               unused_findings=["s3:x", "s3:y", "s3:z"])
    _seed(st, [rec])
    score_risks(st, RUN, rules)

    lines = st.read_bytes(AUDIT_NAME).decode().strip().splitlines()
    audit = json.loads(lines[0])
    # 감사로그 기여도 합 == 기록된 risk_score (완전 재현).
    total = sum(c["contribution"] for c in audit["contributions"])
    assert total == audit["risk_score"]
    # no_mfa(15, 콘솔 로그인) + long_lived_key(20) + unused 3건*1=3 = 38.
    assert audit["risk_score"] == 15 + 20 + 3


def test_no_mfa_only_for_console_users(tmp_path):
    """서비스 계정(console_login=false)은 mfa=false 여도 no_mfa 위험 아님(#4)."""
    rules = RiskRules()
    st = LocalFSStorage(tmp_path, "test", "run-x")
    svc = _rec(principal="arn:aws:iam::111122223333:user/ci", identity_type="user",
               mfa=False, console_login=False)
    human = _rec(principal="arn:aws:iam::111122223333:user/alice", identity_type="user",
                 mfa=False, console_login=True)
    _seed(st, [svc, human])
    out = {r.principal: r for r in score_risks(st, RUN, rules)}
    # 서비스 계정: no_mfa 가중치 0.
    assert out["arn:aws:iam::111122223333:user/ci"].risk_score == 0
    # 콘솔 사용자: no_mfa 15.
    assert out["arn:aws:iam::111122223333:user/alice"].risk_score == 15


def test_unused_contribution_capped(tmp_path):
    rules = RiskRules()  # cap=25
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _rec(unused_findings=[f"s3:a{i}" for i in range(100)])  # 100 > cap
    _seed(st, [rec])
    out = score_risks(st, RUN, rules)
    # 100*1 이지만 cap 25.
    assert out[0].risk_score == 25


def test_determinism_audit_sorted(tmp_path):
    rules = RiskRules()
    st = LocalFSStorage(tmp_path, "test", "run-x")
    recs = [_rec(principal=f"arn:aws:iam::111122223333:role/r{i}") for i in (3, 1, 2)]
    _seed(st, recs)
    score_risks(st, RUN, rules)
    a = st.read_bytes(AUDIT_NAME)
    score_risks(st, RUN, rules)
    b = st.read_bytes(AUDIT_NAME)
    assert a == b  # 안정 정렬 → 바이트 동일
