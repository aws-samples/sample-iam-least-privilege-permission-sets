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
