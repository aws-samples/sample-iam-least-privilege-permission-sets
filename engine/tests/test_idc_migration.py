"""IdC collector + sso_ps 정규화 + 마이그레이션 스냅샷 비율."""

from __future__ import annotations

from lp2ps.m2_normalizer import _sso_ps_records
from lp2ps.models import PrincipalRecord
from lp2ps.snapshot import _metrics
from lp2ps.runctx import RunContext

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-17T00:00:00Z")


def test_sso_ps_records_from_idc_raw() -> None:
    idc_raw = {
        "permission_set_assignments": [
            {"permission_set_name": "Admin", "principal_id": "u1", "principal_type": "USER"},
            {"permission_set_name": "Admin", "principal_id": "u2", "principal_type": "USER"},
            # 중복(같은 PS+principal) → 1건으로.
            {"permission_set_name": "Admin", "principal_id": "u1", "principal_type": "USER"},
        ]
    }
    recs = _sso_ps_records("111122223333", idc_raw, "run-x")
    assert len(recs) == 2  # u1, u2 (중복 제거)
    assert all(r.identity_type == "sso_ps" for r in recs)


def test_migration_pct_snapshot_ratio() -> None:
    # 사람 접근 = IAM user 3 + sso_ps 2 = 5. PS 기반 2 → 40%.
    records = [
        *[PrincipalRecord(account_id="a", principal=f"arn:...:user/u{i}", identity_type="user",
                          console_login=True, run_id="run-x") for i in range(3)],
        *[PrincipalRecord(account_id="a", principal=f"sso_ps::a::Admin::p{i}", identity_type="sso_ps",
                          run_id="run-x") for i in range(2)],
    ]
    pt = _metrics(records, [], RUN)
    assert pt.ps_migration_pct == 40  # round(100*2/5)
    assert pt.iam_users_pending_migration == 3


def test_migration_pct_zero_when_no_idc() -> None:
    # sso_ps 없음(IdC 미설정) → 0%.
    records = [PrincipalRecord(account_id="a", principal="arn:...:user/u", identity_type="user",
                               console_login=True, run_id="run-x")]
    pt = _metrics(records, [], RUN)
    assert pt.ps_migration_pct == 0


def test_migration_pct_no_human_access() -> None:
    # 사람 접근이 전혀 없음(role 만) → 분모 0 → 0% (0 나눗셈 방지).
    records = [PrincipalRecord(account_id="a", principal="arn:...:role/r", identity_type="role",
                               granted_actions=["s3:GetObject"], run_id="run-x")]
    pt = _metrics(records, [], RUN)
    assert pt.ps_migration_pct == 0
