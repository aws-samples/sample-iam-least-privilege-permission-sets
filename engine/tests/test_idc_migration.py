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
    recs = _sso_ps_records("111122223333", idc_raw, "run-x", [])
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


# ---- AWSReservedSSO_* 역할의 실사용을 PS 레코드로 귀속 ----

from lp2ps.m2_normalizer import _reserved_sso_usage  # noqa: E402
from lp2ps.models import PrincipalRecord, UsedAction  # noqa: E402

_ACCT = "111122223333"


def _reserved(ps_suffix: str, actions: list[tuple[str, int, str]]) -> PrincipalRecord:
    return PrincipalRecord(
        account_id=_ACCT,
        principal=f"arn:aws:iam::{_ACCT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_{ps_suffix}",
        identity_type="role",
        used_actions=[UsedAction(action=a, count_90d=c, last_used=t) for a, c, t in actions],
        run_id="run-x",
    )


def test_reserved_sso_usage_attributed_to_ps() -> None:
    """AWSReservedSSO_<PS>_<hex> 의 실사용이 PS 이름으로 귀속된다."""
    recs = [_reserved("Admin_bb706f225dcfee54", [("s3:GetObject", 3, "2026-07-10T00:00:00Z")])]
    usage = _reserved_sso_usage(recs)
    assert set(usage) == {"Admin"}
    assert [u.action for u in usage["Admin"]] == ["s3:GetObject"]


def test_ps_name_with_underscore_preserved() -> None:
    """PS 이름에 '_' 가 있어도 마지막 '_' 만 suffix 로 떼어낸다."""
    recs = [_reserved("Security_Read_Only_edff522ebd48d8e3", [("iam:ListRoles", 1, "2026-07-01T00:00:00Z")])]
    assert set(_reserved_sso_usage(recs)) == {"Security_Read_Only"}


def test_usage_merged_across_reserved_roles() -> None:
    """같은 PS 의 예약 역할이 여러 개면 호출수 합·최근 시각 채택(결정론)."""
    recs = [
        _reserved("Admin_aaaaaaaaaaaaaaaa", [("s3:GetObject", 2, "2026-07-01T00:00:00Z")]),
        _reserved("Admin_bbbbbbbbbbbbbbbb", [("s3:GetObject", 5, "2026-07-20T00:00:00Z")]),
    ]
    merged = _reserved_sso_usage(recs)["Admin"]
    assert len(merged) == 1
    assert merged[0].count_90d == 7
    assert merged[0].last_used == "2026-07-20T00:00:00Z"


def test_ordinary_role_not_attributed() -> None:
    """대조군 — 일반 역할은 PS 귀속 대상이 아니다."""
    r = PrincipalRecord(
        account_id=_ACCT, principal=f"arn:aws:iam::{_ACCT}:role/data-eng", identity_type="role",
        used_actions=[UsedAction(action="s3:GetObject", count_90d=1, last_used="2026-07-01T00:00:00Z")],
        run_id="run-x",
    )
    assert _reserved_sso_usage([r]) == {}


def test_sso_ps_record_carries_used_actions() -> None:
    """PS 할당 레코드에 실사용이 실린다 — 이전에는 항상 비어 있어 과다권한 판정이 불가했다."""
    idc_raw = {"permission_set_assignments": [
        {"permission_set_name": "Admin", "principal_id": "u1", "principal_type": "USER"},
        {"permission_set_name": "Unused", "principal_id": "u2", "principal_type": "USER"},
    ]}
    iam = [_reserved("Admin_bb706f225dcfee54", [("s3:GetObject", 4, "2026-07-10T00:00:00Z")])]
    recs = _sso_ps_records(_ACCT, idc_raw, "run-x", iam)
    by_ps = {r.principal.split("::")[2]: r for r in recs}
    assert [u.action for u in by_ps["Admin"].used_actions] == ["s3:GetObject"]
    # 대조군: 대응 예약 역할이 없는 PS 는 비어 있어야(실제로 안 쓰인 PS).
    assert by_ps["Unused"].used_actions == []


def test_sso_ps_excluded_from_persona_clustering() -> None:
    """sso_ps 는 합성 레코드 → persona 군집 대상이 아니다(is_exception).

    회귀 방지: used_actions 를 채우자 M5 의 active 필터(used_actions 존재)를 통과해 persona 멤버가 되고,
    UI 가 `sso_ps::<account>::<PS>::<id>` 키를 ARN 으로 파싱해 PS 이름을 계정으로 오인했다.
    """
    from lp2ps.m2_normalizer import EXC_SSO_PS

    idc_raw = {"permission_set_assignments": [
        {"permission_set_name": "Admin", "principal_id": "u1", "principal_type": "USER"},
    ]}
    iam = [_reserved("Admin_bb706f225dcfee54", [("s3:GetObject", 4, "2026-07-10T00:00:00Z")])]
    (rec,) = _sso_ps_records(_ACCT, idc_raw, "run-x", iam)
    assert rec.used_actions, "전제: 실사용이 실려 있어야 이 테스트가 의미를 가진다"
    assert rec.is_exception is True
    assert rec.exception_type == EXC_SSO_PS


def test_sso_ps_still_counted_in_migration_pct() -> None:
    """대조군 — 제외해도 PS 마이그레이션 비율 분자에는 계속 잡힌다(`is_exception` 미참조)."""
    records = [
        PrincipalRecord(account_id="a", principal="arn:...:user/u", identity_type="user",
                        console_login=True, run_id="run-x"),
        PrincipalRecord(account_id="a", principal="sso_ps::a::Admin::p1", identity_type="sso_ps",
                        is_exception=True, exception_type="sso_ps_synthetic", run_id="run-x"),
    ]
    assert _metrics(records, [], RUN).ps_migration_pct == 50
