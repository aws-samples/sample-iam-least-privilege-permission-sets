"""M6 Reporter + snapshot — 백로그·exec summary·지표."""

from __future__ import annotations

import csv
import io
import json
import re

from lp2ps.config import Config
from lp2ps.m6_reporter import BACKLOG_NAME, EXEC_SUMMARY_NAME, build_reports
from lp2ps.models import CatalogEntry, EscalationPath, PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.snapshot import write_snapshot
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-15T00:00:00Z")


def _cfg() -> Config:
    return Config.model_validate({"customer": "test", "region": "us-west-2",
                                  "cross_account": False, "accounts": ["self"]})


def _seed(st) -> None:
    recs = [
        # 미사용 role + 미사용 권한 + escalation.
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:role/idle",
                        identity_type="role", granted_actions=["s3:DeleteBucket"],
                        unused_findings=["s3:DeleteBucket"], risk_level="high",
                        escalation_paths=[EscalationPath(via="iam:*", to="x", mitre="TA0004")],
                        run_id="run-x"),
        # no_mfa 콘솔 user + long-lived key.
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:user/u",
                        identity_type="user", mfa=False, console_login=True, access_key_age_days=200,
                        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z", count_90d=1)],
                        risk_level="medium", run_id="run-x"),
    ]
    st.write_normalized(recs)
    st.write_json("catalog.json", [CatalogEntry(persona="DataPersona", description="d",
                                                members=["arn:aws:iam::111122223333:user/u"],
                                                member_count=1, policy_ref="policies/DataPersona.json").model_dump()])


def test_backlog_has_five_types(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg())
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    types = {r["type"] for r in rows}
    # idle role → unused_role + unused_permission + escalation_path; user → no_mfa + long_lived_key.
    assert {"unused_role", "unused_permission", "escalation_path", "no_mfa", "long_lived_key"} <= types
    # 결정론 id: c1..cN 순서.
    ids = [r["id"] for r in rows]
    assert ids == [f"c{i}" for i in range(1, len(rows) + 1)]


# ---- 사용 흔적이 있는 역할을 '미사용' 이라 부르지 않는다 ----
#
# Access Advisor 의 action-level 추적 범위는 서비스별로 달라, 실제로 쓰이는 역할도 action 세부가
# 안 나와 used_actions 가 빌 수 있다. 서비스 단위 인증 기록(used_services)만 있어도 그 역할은
# 쓰이는 중이다 — "90일간 미사용, 삭제 검토" 를 내면 운영 중인 역할을 지우게 된다.


def _role_rec(**kw) -> PrincipalRecord:
    base = dict(account_id="111122223333", principal="arn:aws:iam::111122223333:role/repl",
                identity_type="role", granted_actions=["s3:ReplicateObject"],
                risk_level="low", run_id="run-x")
    base.update(kw)
    return PrincipalRecord(**base)


def _backlog_types(st, recs) -> set[str]:
    st.write_normalized(recs)
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    return {r["type"] for r in rows}


def test_role_with_service_level_usage_is_not_unused(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    types = _backlog_types(st, [_role_rec(used_actions=[], used_services=["s3"])])
    assert "unused_role" not in types, "서비스 인증 기록이 있으면 미사용 역할이 아니다"


def test_role_with_no_usage_at_any_level_is_unused(tmp_path):
    """대조: used_services 까지 비면 미사용 역할로 잡혀야 한다.

    이 대조가 없으면 위 테스트는 unused_role 을 아예 못 만들게 망가뜨려도 통과한다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    types = _backlog_types(st, [_role_rec(used_actions=[], used_services=[])])
    assert "unused_role" in types


def test_unused_permission_evidence_reports_undetermined_count(tmp_path):
    """판정 불가 건수를 증거에 실어, 백로그가 부여 권한 전체를 설명하는 것으로 오해받지 않게 한다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_role_rec(unused_findings=["s3:DeleteBucket"],
                                   undetermined_findings=["s3:ReplicateObject", "s3:PutObjectAcl"],
                                   used_services=["s3"])])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    rows = [r for r in csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode()))
            if r["type"] == "unused_permission"]
    assert len(rows) == 1
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["미사용 action 수"] == "1"
    assert evidence["근거 불명 action 수"] == "2"


def test_exec_summary_counts(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    summary = build_reports(st, RUN, _cfg())
    data = json.loads(st.read_bytes(EXEC_SUMMARY_NAME).decode())
    assert data["principals"] == 2
    assert data["accounts"] == 1
    assert data["personas"] == 1
    assert data["generated_at"] == "2026-07-15T00:00:00Z"  # run.started_at


def test_snapshot_metrics(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg())
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded")
    assert point.no_mfa == 1
    assert point.long_lived_keys == 1
    assert point.escalation_paths == 1
    assert point.unused_roles == 1
    assert point.over_privileged_principals == 1  # high 1건
    assert point.risk_dist.high == 1
    assert point.risk_dist.medium == 1
    # run.json 기록 확인.
    run_row = json.loads(st.read_bytes("run.json").decode())
    assert run_row["run_id"] == "run-x"
    assert run_row["status"] == "succeeded"


def test_snapshot_separates_undetermined_permissions(tmp_path):
    """판정 불가는 unused_permissions 에서 빠지고 별도 지표로 센다.

    두 지표가 분리돼 있지 않으면, 근거 배선이 좋아져 미사용 수가 줄어든 것을
    "권한이 정리됐다" 로 오독한다(시계열 그래프가 그렇게 보인다).
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_role_rec(unused_findings=["s3:DeleteBucket"],
                                   undetermined_findings=["s3:ReplicateObject", "s3:PutObjectAcl"],
                                   used_services=["s3"])])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded")
    assert point.unused_permissions == 1
    assert point.undetermined_permissions == 2
    assert point.unused_roles == 0, "서비스 인증 기록이 있으면 지표도 미사용으로 세지 않는다"


def test_unused_role_detected_via_managed_only(tmp_path):
    """inline 권한 없이 managed 정책만 붙은 미사용 role 도 unused_role 로 잡힌다(#3)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:role/mgd",
                        identity_type="role", granted_actions=[], has_managed_policies=True,
                        risk_level="low", run_id="run-x"),
    ])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    assert any(r["type"] == "unused_role" for r in rows)


def test_timeseries_accumulates_across_runs(tmp_path):
    """metrics_timeseries 는 customer 레벨에 누적된다(#1) — 서로 다른 run 이 같은 시계열에 쌓임."""
    from lp2ps.runctx import RunContext

    base = tmp_path / "out"
    for rid, ts in [("run-1", "2026-07-01T00:00:00Z"), ("run-2", "2026-07-15T00:00:00Z")]:
        run = RunContext(run_id=rid, customer="test", started_at=ts)
        st = LocalFSStorage(base, "test", rid)
        _seed(st)
        build_reports(st, run, _cfg())
        write_snapshot(st, run, account_scope=1, status="succeeded")

    # customer 레벨 시계열에 2개 run 이 누적.
    shared = json.loads((base / "test" / "metrics_timeseries.json").read_text())
    run_ids = {m["run_id"] for m in shared}
    assert run_ids == {"run-1", "run-2"}


def test_reports_deterministic(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg())
    a = st.read_bytes(BACKLOG_NAME)
    build_reports(st, RUN, _cfg())
    b = st.read_bytes(BACKLOG_NAME)
    assert a == b


def _cfg_no_idc() -> Config:
    return Config.model_validate({"customer": "test", "region": "us-west-2",
                                  "cross_account": False, "accounts": ["self"],
                                  "provisioning": {"uses_identity_center": False}})


# ---- finding_key: 조치 상태가 run 을 넘어 살아남는 근거 ----

def test_finding_key_stable_when_volatile_detail_changes(tmp_path):
    """detail 의 변하는 수치(액세스키 age)가 바뀌어도 finding_key 는 같다.

    detail 을 키에 넣었다면 매일 새 항목이 되어 "조치완료" 표시가 하루 만에 사라진다."""
    keys = []
    for age in (612, 613):
        st = LocalFSStorage(tmp_path / str(age), "test", "run-x")
        st.write_normalized([
            PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:user/u",
                            identity_type="user", access_key_age_days=age, risk_level="high",
                            run_id="run-x"),
        ])
        st.write_json("catalog.json", [])
        build_reports(st, RUN, _cfg())
        rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
        row = next(r for r in rows if r["type"] == "long_lived_key")
        assert str(age) in row["detail"], "detail 은 실제로 달라야 함(대조 전제)"
        keys.append(row["finding_key"])
    assert keys[0] == keys[1], "detail 만 달라졌는데 finding_key 가 바뀌면 상태가 유실된다"


def test_finding_key_survives_id_shift(tmp_path):
    """항목이 하나 늘어 `id` 순번이 밀려도 기존 항목의 finding_key 는 그대로다."""
    target = "arn:aws:iam::111122223333:user/u"
    base = PrincipalRecord(account_id="111122223333", principal=target, identity_type="user",
                           mfa=False, console_login=True, risk_level="medium", run_id="run-x")
    # 정렬키(type, ...)는 유형명 사전순이라 long_lived_key < no_mfa — 이 항목을 추가하면 no_mfa 의
    # 순번이 밀린다(unused_* 는 no_mfa 뒤라 밀어내지 못한다).
    extra = PrincipalRecord(account_id="111122223333",
                            principal="arn:aws:iam::111122223333:user/aaa", identity_type="user",
                            mfa=True, console_login=False, access_key_age_days=400,
                            risk_level="low", run_id="run-x")

    def _row(recs):
        st = LocalFSStorage(tmp_path / str(len(recs)), "test", "run-x")
        st.write_normalized(recs)
        st.write_json("catalog.json", [])
        build_reports(st, RUN, _cfg())
        rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
        return next(r for r in rows if r["type"] == "no_mfa" and r["principal"] == target)

    before, after = _row([base]), _row([base, extra])
    assert before["id"] != after["id"], "순번이 실제로 밀려야 함(대조 전제 — 안 밀리면 이 테스트는 무의미)"
    assert before["finding_key"] == after["finding_key"]


def test_finding_key_distinct_per_escalation_path(tmp_path):
    """한 principal 의 상승 경로가 여러 건이면 건마다 다른 키(키 하나로 뭉치면 개별 조치 불가)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:role/r",
                        identity_type="role", granted_actions=["iam:*"], risk_level="high",
                        used_actions=[UsedAction(action="iam:ListRoles", last_used=None, count_90d=1)],
                        escalation_paths=[
                            EscalationPath(via="iam:PassRole", to="lambda", mitre="TA0004"),
                            EscalationPath(via="iam:AttachRolePolicy", to="admin", mitre="TA0004"),
                        ], run_id="run-x"),
    ])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    rows = [r for r in csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode()))
            if r["type"] == "escalation_path"]
    assert len(rows) == 2
    assert len({r["finding_key"] for r in rows}) == 2


def test_backlog_csv_has_finding_key_column(tmp_path):
    """CSV 헤더에 finding_key 가 있고, 각 행이 64자 hex 다(API 가 이 컬럼으로 상태를 병합)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg())
    text = st.read_bytes(BACKLOG_NAME).decode()
    header = next(csv.reader(io.StringIO(text)))
    assert header[:3] == ["id", "finding_key", "type"]
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows and all(re.fullmatch(r"[0-9a-f]{64}", r["finding_key"]) for r in rows)


# ---- 권장 조치 문구: IdC 미사용 고객은 조치 가능한 문구를 받아야 한다 ----

def test_recommendation_avoids_permission_set_when_no_idc(tmp_path):
    """uses_identity_center=false 면 어떤 항목도 Permission Set 를 권하지 않는다(조치 불가 조언 금지)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg_no_idc())
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    assert len(rows) >= 5
    for r in rows:
        assert "Permission Set" not in r["recommendation"], r
        assert "PS " not in r["recommendation"], r


def test_recommendation_mentions_permission_set_when_idc(tmp_path):
    """대조군 — IdC 고객에게는 기존대로 PS 문구가 나온다(위 테스트가 항상 통과하는 게 아님을 보장)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed(st)
    build_reports(st, RUN, _cfg())
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    assert any("Permission Set" in r["recommendation"] for r in rows)


def test_sec018_csv_formula_injection_neutralized():
    """CSV 셀 앞글자가 = + - @ tab CR 이면 ' 프리픽스로 무력화, 그 외는 그대로."""
    from lp2ps.m6_reporter import _csv_safe

    assert _csv_safe("=1+1") == "'=1+1"
    assert _csv_safe("+cmd") == "'+cmd"
    assert _csv_safe("-2") == "'-2"
    assert _csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert _csv_safe("\tTAB") == "'\tTAB"
    assert _csv_safe("\rCR") == "'\rCR"
    # 개행(\n)으로 시작하는 셀도 무력화.
    assert _csv_safe("\n=cmd") == "'\n=cmd"
    # 정상 값은 변형 없음.
    assert _csv_safe("arn:aws:iam::111122223333:role/x") == "arn:aws:iam::111122223333:role/x"
    assert _csv_safe("no_mfa") == "no_mfa"
    assert _csv_safe(None) == ""


def test_sec018_backlog_escapes_injection(tmp_path):
    """엔진이 실제로 formula-injection 셀을 무력화해 CSV 를 쓰는지(백로그 경로)."""
    from lp2ps.models import CleanupItem

    st = LocalFSStorage(tmp_path, "test", "run-x")
    # detail 이 '=' 로 시작하는 악성 유사 값.
    items = [CleanupItem(id="=HYPERLINK(1)", type="no_mfa", account_id="111122223333",
                         principal="arn:aws:iam::111122223333:user/u", risk_level="medium",
                         detail="=cmd|calc", recommendation="fix", risk_score=10,
                         risk_reasons=["r"], evidence={})]
    from lp2ps.m6_reporter import _write_backlog
    _write_backlog(st, items)
    rows = list(csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    assert rows[0]["id"].startswith("'="), "= 로 시작하는 id 는 ' 로 무력화돼야 함"
    assert rows[0]["detail"].startswith("'="), "= 로 시작하는 detail 은 ' 로 무력화돼야 함"
