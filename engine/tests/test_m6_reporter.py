"""M6 Reporter + snapshot — 백로그·exec summary·지표."""

from __future__ import annotations

import csv
import io
import json
import re

from lp2ps.config import Config
from lp2ps.m6_reporter import BACKLOG_NAME, EXEC_SUMMARY_NAME, _unused_period, build_reports
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
                        # 신뢰 대상이 내부로 확인된 역할 → 삭제 검토(`unused_role`). 명시하지 않으면
                        # 모델 기본값 `unconfirmed` 라 유형이 `unconfirmed_trust_role` 로 갈린다(R5).
                        trust_scope="internal",
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
    # `trust_scope="internal"` 을 기본값으로 둔다: 이 파일의 미사용 역할 테스트는 **일수·문구**를
    # 검증하는 것이고, 신뢰 축은 유형을 `unused_role` / `unconfirmed_trust_role` 로 가른다(R5).
    # 모델 기본값은 fail-safe 인 `unconfirmed` 이므로 명시하지 않으면 전부 삭제 권고가 없는 쪽으로
    # 가고, 그러면 "삭제 권고" 를 검증하는 대조군이 통째로 죽는다. 신뢰 축 자체의 검증은
    # test_tracks_and_tenancy.py 가 담당한다.
    base = dict(account_id="111122223333", principal="arn:aws:iam::111122223333:role/repl",
                identity_type="role", granted_actions=["s3:ReplicateObject"],
                trust_scope="internal", risk_level="low", run_id="run-x")
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
                        trust_scope="internal", risk_level="low", run_id="run-x"),
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


# ---- 신규 역할은 '미사용 역할' 이 아니다 ----
#
# 라이브 575 에서 미사용 판정 59건 중 16건이 생성 90일 미만, 3건은 **당일 생성**이었다. 그런데
# 백로그는 "미사용 역할 — 역할 삭제" 를 권했고 화면은 "90일 사용 action 0" 이라고 적었다. 그 90일은
# 어디서도 측정되지 않았고, 어제 만든 역할에 사용 기록이 없는 건 당연하다. 배포 중인 역할을
# 지우라고 권하는 것이라 유형을 갈라 둔다(new_role_unused, 삭제 권고 없음).


def _rows_of_type(st, recs, ctype: str) -> list[dict]:
    st.write_normalized(recs)
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    return [r for r in csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode()))
            if r["type"] == ctype]


def test_new_role_is_not_recommended_for_deletion(tmp_path):
    """생성 후 unused_action_days 미만인 미사용 역할 → new_role_unused + 삭제 권고 없음."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[],
                    create_date="2026-07-12T00:00:00+00:00", age_days=3)
    rows = _rows_of_type(st, [rec], "new_role_unused")
    assert len(rows) == 1, "3일 된 역할이 '미사용 역할' 로 분류되면 안 된다"
    assert "삭제 권고 아님" in rows[0]["recommendation"]
    assert "관측 기간" in rows[0]["detail"]
    # 같은 레코드가 unused_role 로도 나오면 안 된다(이중 계상).
    assert _rows_of_type(st, [rec], "unused_role") == []


def test_old_unused_role_still_recommends_deletion(tmp_path):
    """대조군 — 충분히 오래된 미사용 역할은 그대로 삭제 후보다.

    이 대조가 없으면 위 테스트는 '전부 new_role_unused 로 밀어버려도' 통과한다. 그러면 이 도구의
    본래 산출물(미사용 역할 정리)이 통째로 사라진다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[],
                    create_date="2025-01-01T00:00:00+00:00", age_days=560)
    rows = _rows_of_type(st, [rec], "unused_role")
    assert len(rows) == 1
    assert "역할 삭제" in rows[0]["recommendation"]
    assert _rows_of_type(st, [rec], "new_role_unused") == []


def test_unknown_age_does_not_change_judgment(tmp_path):
    """나이를 모르면(구버전 raw) 판정을 바꾸지 않고 증거에 '확인 불가' 로 남긴다.

    모른다는 이유로 조치 대상을 늘리거나 줄이면, 근거가 없는 쪽으로 결론이 흔들린다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rows = _rows_of_type(st, [_role_rec(used_actions=[], used_services=[])], "unused_role")
    assert len(rows) == 1
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["생성 후 경과"] == "확인 불가"
    assert evidence["역할 생성일"] == "미수집"


def test_unused_role_evidence_states_measured_window(tmp_path):
    """증거는 '90일' 이라고 쓰지 않는다 — CloudTrail 실측 일수 + Advisor 는 AWS 사양임을 밝힌다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=560,
                    create_date="2025-01-01T00:00:00+00:00", observed_days=2,
                    observed_from="2026-07-13T00:00:00+00:00",
                    unused_days=560, unused_days_basis="create_date")
    rows = _rows_of_type(st, [rec], "unused_role")
    evidence = json.loads(rows[0]["evidence"])
    assert "CloudTrail 2일" in evidence["수집된 사용 흔적"]
    assert "AWS 사양" in evidence["수집된 사용 흔적"], "측정하지 않은 400일을 실측처럼 적으면 안 된다"
    # 임계치는 config(risk_rules.unused_role_days)에서 온다 — 리터럴이 아니다.
    assert evidence["삭제 검토 임계"] == "미사용 90일 이상"
    # detail 은 판정 창이 아니라 **미사용 기간**을 말한다(사용자가 목록에서 먼저 보는 값).
    # 판정 창은 위 '수집된 사용 흔적' 이 이미 싣고 있어, 한 줄에 둘을 겹쳐 쓰면 둘 다 안 읽힌다.
    assert "생성 후 560일" in rows[0]["detail"]


def test_unused_role_evidence_says_no_cloudtrail_when_absent(tmp_path):
    """대조군 — CloudTrail 근거가 없으면 일수를 말하지 않고 '근거 없음' 이라고 쓴다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=560,
                    create_date="2025-01-01T00:00:00+00:00")
    rows = _rows_of_type(st, [rec], "unused_role")
    evidence = json.loads(rows[0]["evidence"])
    # CloudTrail 부분은 일수를 포함하지 않아야 한다 — "CloudTrail None일" 같은 값이 새면 안 된다.
    ct_part = evidence["수집된 사용 흔적"].split(" + Access Advisor")[0]
    assert ct_part == "없음(CloudTrail 근거 없음", ct_part


# ---- 미사용 기간 표기 ----
#
# "90일간 미사용" 리터럴을 지운 뒤 실제 값을 채우지 않아 기간 표기가 **아예 사라졌다**(사용자 지적).
# 실제 값은 이미 받아오던 GetAccountAuthorizationDetails 응답의 RoleLastUsed 에 있었다.


def test_period_from_create_date_says_what_it_counted(tmp_path):
    """IAM 활동 기록이 없으면 **무엇부터 센 일수인지**를 문구에 담는다(R2 ②).

    예전엔 "최소 200일 이상" 이라고 썼다. 그 값이 IAM 이 측정한 미사용 기간인지 우리가 생성일부터
    센 것인지 구분되지 않아, 둘 다 같은 문장으로 읽혔다. 추적 창(400일)을 그대로 쓰는 것도
    금지다 — 200일 된 역할에 "최소 400일" 이면 존재하지도 않던 기간을 주장한다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=200,
                    create_date="2026-02-13T00:00:00+00:00",
                    unused_days=200, unused_days_basis="create_date")
    rows = _rows_of_type(st, [rec], "unused_role")
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["마지막 활동"] == "IAM 활동 기록 없음"
    assert evidence["미사용 기간"] == "생성 후 200일 · 사용 기록 없음(AWS 추적 보장 400일)"
    assert "400일" not in evidence["미사용 기간"].split("(")[0], "경과일 자리에 추적 창이 새면 안 된다"
    assert evidence["일수 근거"] == "생성일(활동 기록 없음)"
    assert "생성 후 200일" in rows[0]["detail"]


def test_new_role_does_not_get_a_period_lower_bound(tmp_path):
    """관측 기간이 부족한 역할은 기간을 말하지 않는다 — 라이브에서 '최소 0일 이상' 이 나왔다.

    참이지만 아무 정보가 없고, 숫자가 판단처럼 읽힌다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=0,
                    create_date="2026-07-15T00:00:00+00:00")
    evidence = json.loads(_rows_of_type(st, [rec], "new_role_unused")[0]["evidence"])
    assert "일 이상" not in evidence["미사용 기간"], evidence["미사용 기간"]
    assert evidence["미사용 기간"].startswith("판단 보류")


def test_period_from_create_date_is_not_capped_but_flags_tracking_window(tmp_path):
    """대조군 — 추적 창으로 **자르지 않는다**. 대신 그 창을 문구로 밝힌다.

    예전엔 min(생성 후 경과, 400)으로 잘랐다. 자르면 5년 된 역할과 400일 된 역할이 같은 문장이
    되어 정리 우선순위가 사라진다. 생성 후 1800일은 사실이므로 그대로 말하고, 그 안에 IAM 이
    보장하는 추적 범위가 400일뿐이라는 한계를 같은 줄에 붙인다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=1800,
                    create_date="2021-09-01T00:00:00+00:00",
                    unused_days=1800, unused_days_basis="create_date")
    evidence = json.loads(_rows_of_type(st, [rec], "unused_role")[0]["evidence"])
    assert evidence["미사용 기간"] == "생성 후 1800일 · 사용 기록 없음(AWS 추적 보장 400일)"


def test_unknown_age_does_not_invent_a_period(tmp_path):
    """나이를 모르면 하한도 말하지 않는다 — 숫자를 만들지 않는다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    evidence = json.loads(
        _rows_of_type(st, [_role_rec(used_actions=[], used_services=[])], "unused_role")[0]["evidence"])
    assert re.search(r"\d+일 이상", evidence["미사용 기간"]) is None, evidence["미사용 기간"]
    assert "확인 불가" in evidence["미사용 기간"]


def test_role_with_iam_last_used_is_not_unused(tmp_path):
    """IAM 이 활동을 기록한 역할은 미사용이 아니다 — 다른 층위 근거가 비어 있어도 그렇다.

    RoleLastUsed 는 **전 리전**을 아우른다. CloudTrail 은 리전별·페이지 상한이고 Access Advisor
    는 action 세부를 안 줄 수 있어, 다른 리전에서만 쓰이는 역할은 두 층위 모두 빈다. 그때
    "사용 기록 없음, 삭제" 라고 권하면 IAM 이 반대로 말하는 것을 화면이 주장한다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(used_actions=[], used_services=[], age_days=560,
                    create_date="2025-01-01T00:00:00+00:00",
                    role_last_used="2026-08-20T01:02:03+00:00", role_last_used_region="ap-northeast-1",
                    unused_days=12)
    types = _backlog_types(st, [rec])
    assert "unused_role" not in types
    assert "new_role_unused" not in types
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded")
    assert point.unused_roles == 0, "지표도 같은 판정식을 써야 백로그와 어긋나지 않는다"


def test_measured_period_uses_iam_record(tmp_path):
    """기록이 있으면 정확한 경과일과 **활동 리전**을 그대로 쓴다(하한 문구 아님).

    `is_unused_role` 가드가 이 경우를 백로그에서 제외하므로 헬퍼를 직접 부른다 — 표기 로직은
    unused_permission 증거와, 판정 규칙이 '미사용 N일 이상' 으로 바뀔 때 살아 있는 경로다.
    """
    rec = _role_rec(role_last_used="2026-08-20T01:02:03+00:00",
                    role_last_used_region="ap-northeast-1", unused_days=12)
    assert _unused_period(rec) == ("2026-08-20T01:02:03+00:00 (ap-northeast-1)", "12일")
    # 리전을 모르면 괄호를 만들지 않는다(빈 괄호는 값이 있다고 오해시킨다).
    assert _unused_period(_role_rec(role_last_used="2026-08-20T01:02:03+00:00",
                                    unused_days=12))[0] == "2026-08-20T01:02:03+00:00"


def test_unused_permission_evidence_carries_last_activity(tmp_path):
    """역할의 미사용 권한 항목에도 마지막 활동을 싣는다 — user 에는 싣지 않는다.

    user 는 RoleLastUsed 가 애초에 없어서, '기록 없음' 을 함께 적으면 '안 쓰였다' 로 읽힌다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    role = _role_rec(used_actions=[UsedAction(action="s3:GetObject")],
                     unused_findings=["s3:DeleteObject"],
                     role_last_used="2026-08-20T01:02:03+00:00",
                     role_last_used_region="us-east-1", unused_days=12)
    evidence = json.loads(_rows_of_type(st, [role], "unused_permission")[0]["evidence"])
    assert evidence["마지막 활동"] == "2026-08-20T01:02:03+00:00 (us-east-1)"
    assert "미사용 기간" not in evidence, "실사용 action 이 있는 항목에 미사용 기간을 적으면 자기모순이다"

    user = PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:user/u",
                           identity_type="user", granted_actions=["s3:DeleteObject"],
                           unused_findings=["s3:DeleteObject"], risk_level="low", run_id="run-x")
    st2 = LocalFSStorage(tmp_path / "u", "test", "run-x")
    ev_user = json.loads(_rows_of_type(st2, [user], "unused_permission")[0]["evidence"])
    assert "마지막 활동" not in ev_user


def test_snapshot_splits_new_roles_out_of_unused_roles(tmp_path):
    """대시보드 지표도 같은 기준으로 갈라야 한다 — 백로그와 어긋나면 사용자가 수를 재현할 수 없다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    old = _role_rec(principal="arn:aws:iam::111122223333:role/old", used_actions=[],
                    used_services=[], create_date="2025-01-01T00:00:00+00:00", age_days=560)
    new = _role_rec(principal="arn:aws:iam::111122223333:role/new", used_actions=[],
                    used_services=[], create_date="2026-07-12T00:00:00+00:00", age_days=3)
    st.write_normalized([old, new])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded")
    assert point.unused_roles == 1, "신규 역할이 섞이면 조치 가능 건수가 부풀려진다"
    assert point.new_unused_roles == 1


# ---------------------------------------------------------------------------
# 고객이 읽는 문구 — 계약값(cleanup/TA0004/rule id)을 그대로 노출하지 않는다.
#
# 라이브에서 실제로 났던 일이다: 증거 모달에 `미사용 등급: cleanup` 과
# `iam:PassRole + lambda:CreateFunction → lambda-exec-role (TA0004)` 이 원문으로 떠 있었다.
# 우리에겐 규칙 식별자지만 고객에겐 해독 대상이고, `cleanup` 은 "지워도 되는 것" 으로 읽힌다.
# ---------------------------------------------------------------------------


def _row_of_type(st, recs, ctype: str, cfg: Config | None = None) -> dict:
    st.write_normalized(recs)
    st.write_json("catalog.json", [])
    build_reports(st, RUN, cfg or _cfg())
    rows = [r for r in csv.DictReader(io.StringIO(st.read_bytes(BACKLOG_NAME).decode()))
            if r["type"] == ctype]
    assert len(rows) == 1, f"{ctype} 행이 {len(rows)}개다(전제 실패 — 문구를 측정할 수 없다)"
    return rows[0]


def _idle_role(**kw):
    base = dict(used_actions=[], used_services=[], age_days=560,
                create_date="2025-01-01T00:00:00+00:00", unused_days=147,
                unused_days_basis="role_last_used", unused_tier="cleanup")
    base.update(kw)
    return _role_rec(**base)


def test_tier_evidence_is_a_sentence_not_the_contract_value(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    ev = json.loads(_row_of_type(st, [_idle_role()], "unused_role")["evidence"])
    assert ev["미사용 등급"] == "90일 이상 미사용"
    for raw in ("cleanup", "watch", "review", "active"):
        assert raw not in ev["미사용 등급"]


def test_tier_evidence_follows_config_boundaries(tmp_path):
    """경계를 조정한 고객(불변식 ④)의 증거가 90 을 말하면 안 된다.

    문구에 숫자를 박으면 이 테스트가 FAIL 한다 — 그것이 이 테스트의 존재 이유다.
    """
    cfg = Config.model_validate({
        "customer": "test", "region": "us-west-2", "cross_account": False, "accounts": ["self"],
        "risk_rules": {"unused_tier_days": [10, 20, 45], "unused_role_days": 45},
    })
    st = LocalFSStorage(tmp_path, "test", "run-x")
    ev = json.loads(_row_of_type(st, [_idle_role()], "unused_role", cfg)["evidence"])
    assert ev["미사용 등급"] == "45일 이상 미사용"


def test_ungraded_tier_says_unmeasured_not_zero(tmp_path):
    """등급 없음은 0 이 아니라 미측정이다 — 문구에서도 그 구분을 잃지 않는다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    ev = json.loads(_row_of_type(st, [_idle_role(unused_tier=None)], "unused_role")["evidence"])
    assert ev["미사용 등급"].startswith("미측정")


def test_escalation_labels_cover_every_rule():
    """규칙을 추가하고 문구를 안 붙이면 화면이 조용히 원문 폴백으로 돌아간다 — 여기서 잡는다."""
    from lp2ps.m3_escalation import _RULES
    from lp2ps.m6_reporter import _ESCALATION_LABEL, _MITRE_LABEL

    missing = [(via, to) for _needed, via, to, _mitre in _RULES if (via, to) not in _ESCALATION_LABEL]
    assert not missing, f"상승 경로 문구가 없는 규칙: {missing}"
    tactics = {mitre for _needed, _via, _to, mitre in _RULES}
    assert tactics <= set(_MITRE_LABEL), f"뜻을 안 붙인 MITRE 코드: {tactics - set(_MITRE_LABEL)}"


def test_escalation_evidence_explains_what_the_attacker_can_do(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(escalation_paths=[EscalationPath(
        via="iam:PassRole + lambda:CreateFunction", to="lambda-exec-role", mitre="TA0004")])
    row = _row_of_type(st, [rec], "escalation_path")
    ev = json.loads(row["evidence"])
    # 결론이 문장으로 있다.
    assert "Lambda 함수" in ev["무엇이 가능한가"] and ev["무엇이 가능한가"].endswith("다.")
    # 목록 행(detail)도 규칙 식별자가 아니다.
    assert "iam:PassRole" not in row["detail"] and "TA0004" not in row["detail"]
    # 🔴 그러면서 원문 추적은 끊기지 않는다 — 고객이 정책에서 찾을 문자열과 규칙 식별자·코드가 남아 있다.
    assert ev["필요한 권한(정책에서 찾을 문자열)"] == "iam:PassRole + lambda:CreateFunction"
    assert "lambda-exec-role" in ev["도달 대상"]
    assert ev["MITRE ATT&CK"].startswith("TA0004") and "권한 상승" in ev["MITRE ATT&CK"]


def test_unlabeled_escalation_rule_falls_back_to_the_raw_rule(tmp_path):
    """문구가 없는 조합은 항목을 빠뜨리지 않고 원문으로 낸다(설명이 없다고 감추면 더 나쁘다)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    rec = _role_rec(escalation_paths=[EscalationPath(via="iam:*", to="x", mitre="TA0004")])
    row = _row_of_type(st, [rec], "escalation_path")
    assert row["detail"] == "iam:* → x"
    assert json.loads(row["evidence"])["도달 대상"] == "x (x)"


def test_every_recommendation_stays_a_short_verb_phrase() -> None:
    """🔴 권고문 **전 조합**(유형 × 그룹 × IdC 사용여부)이 짧은 동사구다 — F18 의 요구는 길이다.

    이 전수 검사가 없던 동안 `needs_confirmation` 접두문이 문장으로 남아 라이브 백로그 42행이
    **76~83자 두 문장**이었다(2026-09-11 CSV 전수 실측). 유형별 문구는 단위 테스트가 봤지만 **접두문이
    붙은 합성문**은 아무도 재지 않았다 — 그래서 개별 문구만 압축하고 합성문은 그대로 통과했다.
    바(60자)는 라이브 하네스(`live-check.mjs` F18 스텝)와 같은 값이다.
    """
    from typing import get_args

    from lp2ps.m6_reporter import _recommendation
    from lp2ps.models import CleanupGroup, CleanupType

    bad = []
    for ctype in get_args(CleanupType):
        for group in (*get_args(CleanupGroup), None):
            for uses_idc in (True, False):
                text = _recommendation(ctype, uses_idc, group)
                if len(text) > 60 or "—" in text or "\n" in text:
                    bad.append((ctype, group, uses_idc, len(text), text))
    assert not bad, bad
