"""M5 Catalog — persona 2축 군집(도메인×접근성격), 결정론."""

from __future__ import annotations

import json

from lp2ps.config import CatalogConfig
from lp2ps.m5_catalog import (
    _access_profile,
    _cluster_key,
    _dominant_domain,
    build_catalog,
)
from lp2ps.models import PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-15T00:00:00Z")


def _rec(principal, actions, source=("access_advisor",), exception=False) -> PrincipalRecord:
    return PrincipalRecord(
        account_id="111122223333", principal=principal, identity_type="role",
        used_actions=[UsedAction(action=a, last_used="2026-07-10T00:00:00Z", count_90d=5) for a in actions],
        source=list(source), is_exception=exception, run_id="run-x",
    )


# ── 축2: 접근 성격 분류 ────────────────────────────────────────────────────

def test_profile_readonly_when_all_read_verbs():
    r = _rec("arn:...:role/v", ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"])
    assert _access_profile(r) == "ReadOnly"


def test_profile_write_when_change_verbs_present():
    # PutObject/CreateFunction 은 조회 동사가 아님 → 변경 비중 > 임계 → Write.
    r = _rec("arn:...:role/d", ["s3:GetObject", "s3:PutObject", "lambda:CreateFunction"])
    assert _access_profile(r) == "Write"


def test_profile_admin_when_identity_write_and_broad():
    # iam 쓰기 + 서비스 폭 20+ → Admin(관리자 성격, 도메인 무시).
    actions = ["iam:CreateRole", "iam:AttachRolePolicy"] + [f"svc{i}:DoThing" for i in range(25)]
    assert _access_profile(_rec("arn:...:role/admin", actions)) == "Admin"


# ── 축1: 지배 도메인(부수기능 디웨이팅) ─────────────────────────────────────

def test_dominant_domain_ignores_ambient_logs():
    # 로그(Observability)는 거의 모든 role 의 부수기능 → 디웨이팅. ec2 3개 > logs 4개*0.25.
    r = _rec("arn:...:role/c", [
        "logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup", "logs:DescribeLogStreams",
        "ec2:RunInstances", "ec2:DescribeInstances", "ec2:TerminateInstances",
    ])
    assert _dominant_domain(r) == "Compute"


def test_dominant_domain_merges_database_into_data():
    r = _rec("arn:...:role/db", ["dynamodb:GetItem", "dynamodb:PutItem", "rds:DescribeDBInstances"])
    assert _dominant_domain(r) == "Data"


# ── 2축 조합 군집 ──────────────────────────────────────────────────────────

def test_same_domain_and_profile_cluster_together(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    # 둘 다 Data 도메인 + 변경 성격 → 같은 persona(DataWritePersona).
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/a", ["s3:PutObject", "glue:StartJobRun"]),
        _rec("arn:aws:iam::111122223333:role/b", ["s3:PutObject", "glue:UpdateJob"]),
    ])
    cat = build_catalog(st, RUN, CatalogConfig())
    assert len(cat) == 1
    entry = cat[0]
    assert entry.persona == "DataWritePersona"
    assert entry.member_count == 2
    assert entry.approval_status == "draft"
    assert entry.ai_suggested is False


def test_contributing_sources_union(tmp_path):
    """기여 수집 소스를 멤버들의 source 합집합으로 노출(결정론 정렬)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    r1 = _rec("arn:aws:iam::111122223333:role/a", ["s3:PutObject"], source=("access_advisor", "credential_report"))
    r2 = _rec("arn:aws:iam::111122223333:role/b", ["s3:PutObject"], source=("cloudtrail", "credential_report"))
    st.write_normalized([r1, r2])
    cat = build_catalog(st, RUN, CatalogConfig())
    assert cat[0].contributing_sources == ["access_advisor", "cloudtrail", "credential_report"]


def test_same_domain_different_profile_split(tmp_path):
    """같은 Data 도메인이라도 접근 성격이 다르면(감사자 vs 개발자) 다른 persona 로 분리."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/r1", ["s3:GetObject", "s3:ListBucket"]),   # ReadOnly
        _rec("arn:aws:iam::111122223333:role/r2", ["s3:GetObject", "s3:GetBucketAcl"]),  # ReadOnly
        _rec("arn:aws:iam::111122223333:role/w1", ["s3:PutObject", "s3:DeleteObject"]),  # Write
        _rec("arn:aws:iam::111122223333:role/w2", ["s3:PutObject", "s3:CreateBucket"]),  # Write
    ])
    cat = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=2))
    personas = {e.persona for e in cat}
    assert personas == {"DataReadOnlyPersona", "DataWritePersona"}


def test_admin_clusters_regardless_of_domain(tmp_path):
    """광범위 관리자는 도메인과 무관하게 BroadAdminPersona 하나로 모인다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    a1 = ["iam:CreateRole"] + [f"svc{i}:Do" for i in range(25)]
    a2 = ["iam:AttachRolePolicy"] + [f"other{i}:Do" for i in range(25)]  # 서비스 집합이 달라도
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/admin1", a1),
        _rec("arn:aws:iam::111122223333:role/admin2", a2),
    ])
    cat = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=2))
    assert [e.persona for e in cat] == ["BroadAdminPersona"]
    assert cat[0].member_count == 2


def test_cluster_key_shapes():
    assert _cluster_key(_rec("arn:...:role/x", ["ec2:DescribeInstances"])) == "ComputeReadOnly"
    assert _cluster_key(_rec("arn:...:role/y", ["ec2:RunInstances", "ec2:StartInstances"])) == "ComputeWrite"


def test_exception_and_unused_excluded(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/a", ["s3:GetObject"]),
        _rec("arn:aws:iam::111122223333:role/exc", ["s3:GetObject"], exception=True),
        # used 없음 → 제외.
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:role/idle",
                        identity_type="role", granted_actions=["s3:*"], run_id="run-x"),
    ])
    cat = build_catalog(st, RUN, CatalogConfig())
    members = [m for e in cat for m in e.members]
    assert "arn:aws:iam::111122223333:role/exc" not in members
    assert "arn:aws:iam::111122223333:role/idle" not in members
    assert "arn:aws:iam::111122223333:role/a" in members


def test_actions_merged_and_included(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    # 같은 도메인·성격(둘 다 Data ReadOnly)이라야 한 persona 로 병합됨.
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/a", ["s3:GetObject"]),
        _rec("arn:aws:iam::111122223333:role/b", ["s3:GetObject", "s3:ListBucket"]),
    ])
    cat = build_catalog(st, RUN, CatalogConfig())
    assert len(cat) == 1
    actions = {a.action: a for a in cat[0].actions}
    assert set(actions) == {"s3:GetObject", "s3:ListBucket"}
    assert all(a.used and a.included for a in actions.values())
    assert actions["s3:GetObject"].count_90d == 10  # 5+5 병합


def test_permission_gap_included_disabled(tmp_path):
    """granted 이나 미사용(gap)도 catalog 에 담되 used=False·included=False(검토용)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    r1 = _rec("arn:aws:iam::111122223333:role/a", ["s3:GetObject"])
    r1.unused_findings = ["s3:DeleteBucket", "s3:GetObject"]  # DeleteBucket=gap, GetObject=used(우선)
    r2 = _rec("arn:aws:iam::111122223333:role/b", ["s3:GetObject", "s3:ListBucket"])
    r2.unused_findings = ["iam:PassRole", "role-not-action"]  # PassRole=gap, 비-action 은 제외
    st.write_normalized([r1, r2])
    cat = build_catalog(st, RUN, CatalogConfig())
    actions = {a.action: a for a in cat[0].actions}
    # used(2) + gap(2) = 4. 비-action('role-not-action')은 제외.
    assert set(actions) == {"s3:GetObject", "s3:ListBucket", "s3:DeleteBucket", "iam:PassRole"}
    # used action 은 포함, gap 은 기본 제외.
    assert actions["s3:GetObject"].used and actions["s3:GetObject"].included
    assert not actions["s3:DeleteBucket"].used and not actions["s3:DeleteBucket"].included
    assert not actions["iam:PassRole"].used and not actions["iam:PassRole"].included
    # used 가 gap 보다 우선(GetObject 는 양쪽에 있으나 used).
    assert actions["s3:GetObject"].used


def test_small_clusters_merge_into_general(tmp_path):
    """min_members_for_persona 미만 군집은 버리지 않고 General 로 합친다(#2)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    # 서로 다른 (도메인,성격) 1인 군집 2개 → 각각 min(2) 미만 → General 로 병합.
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/solo1", ["s3:GetObject"]),          # DataReadOnly
        _rec("arn:aws:iam::111122223333:role/solo2", ["ec2:RunInstances"]),       # ComputeWrite
    ])
    cfg = CatalogConfig(min_members_for_persona=2)
    cat = build_catalog(st, RUN, cfg)
    # 두 1인 군집이 GeneralPersona 하나로.
    personas = {e.persona: e for e in cat}
    assert "GeneralPersona" in personas
    assert personas["GeneralPersona"].member_count == 2
    # 아무 principal 도 유실되지 않음.
    all_members = {m for e in cat for m in e.members}
    assert all_members == {"arn:aws:iam::111122223333:role/solo1", "arn:aws:iam::111122223333:role/solo2"}


def test_catalog_deterministic(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _rec("arn:aws:iam::111122223333:role/z", ["ec2:DescribeInstances"]),
        _rec("arn:aws:iam::111122223333:role/a", ["s3:GetObject"]),
    ])
    build_catalog(st, RUN, CatalogConfig())
    a = st.read_bytes("catalog.json")
    build_catalog(st, RUN, CatalogConfig())
    b = st.read_bytes("catalog.json")
    assert a == b
    # persona 정렬 확인.
    cat = json.loads(a.decode())
    personas = [e["persona"] for e in cat]
    assert personas == sorted(personas)
