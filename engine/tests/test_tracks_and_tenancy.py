"""트랙 배정(R5-b) · 테넌트 판정(R5) · persona 격리(R8) · 서비스 접기(R7).

고친 결함 셋:

1. 서비스 역할이 persona 단계에서 **조용히 사라져**, 계정에서 과권한이 가장 큰 덩어리(실측 84 역할
   / 미사용 확정 14,732)가 화면에 아예 나오지 않았다.
2. `_cluster_key` 가 계정을 보지 않아, 여러 고객을 한 배포에서 관리하면 A 고객 정책이 B 고객 사용
   실태에서 파생되고 A 산출물에 B 계정 ARN 이 들어간다.
3. 90일 이상 미사용 역할의 다수가 벤더·다른 도구가 심어놓은 역할인데(안 쓰이는 게 정상) 삭제 권고에
   섞여 있었다. 이 목록의 가치는 개수가 아니라 신뢰다.

판정 방향에 주의: `trust_scope` 는 "외부인가?" 가 아니라 **"내부라고 확인됐나?"** 를 묻는다.
오판의 비대칭 때문이다 — 벤더 역할을 내부로 오판하면 고객이 연동을 끊고, 반대는 한 단계 밀릴 뿐이다.
"""

from __future__ import annotations

from lp2ps.config import DEFAULT_TENANT_GROUP, Config
from lp2ps.m2_normalizer import _trust_scope, normalize
from lp2ps.m5_catalog import build_catalog
from lp2ps.m5_service_roles import build_service_roles
from lp2ps.m5_tracks import _track_of, assign_tracks
from lp2ps.models import PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")
A1 = "111122223333"   # 그룹 alpha (우리 계정)
A2 = "444455556666"   # 그룹 alpha (같은 그룹의 다른 계정)
B1 = "777788889999"   # 그룹 beta  (다른 고객!)
TOOLING = "123456789012"  # 관제 계정(수집 대상 아님)
OUTSIDE = "999988887777"  # 어디에도 없는 계정(벤더)

GROUPS = {A1: "alpha", A2: "alpha", B1: "beta"}


def _cfg(accounts=None, **over) -> Config:
    payload: dict = {
        "customer": "test", "region": "us-west-2", "cross_account": False,
        "accounts": accounts or ["self"],
    }
    payload.update(over)
    return Config.model_validate(payload)


def _rec(**kw) -> PrincipalRecord:
    base = dict(account_id=A1, principal=f"arn:aws:iam::{A1}:role/r", identity_type="role",
                run_id="run-x", tenant_group="alpha", trust_scope="internal")
    base.update(kw)
    return PrincipalRecord(**base)


# ---- R5: trust_scope — "내부라고 확인됐나?" ----


def _scope(values, keys=(), *, own="alpha", identity_type="role", tooling=TOOLING) -> str:
    return _trust_scope(identity_type, set(keys), list(values), own, GROUPS, tooling)


def test_same_group_account_is_internal() -> None:
    assert _scope([f"arn:aws:iam::{A2}:root"]) == "internal"


def test_other_group_account_is_cross_tenant() -> None:
    """이 도구가 스스로 찾기 가장 어려운 문제다 — 수집 대상 계정이므로 '내부' 로 보이기 쉽다."""
    assert _scope([f"arn:aws:iam::{B1}:root"]) == "cross_tenant"


def test_cross_tenant_wins_over_internal() -> None:
    """같은 그룹 + 다른 그룹을 함께 신뢰하면 **위험한 결론이 이긴다**. 섞이면 경계 위반이 숨는다."""
    assert _scope([f"arn:aws:iam::{A2}:root", f"arn:aws:iam::{B1}:root"]) == "cross_tenant"


def test_unknown_account_is_unconfirmed_not_internal() -> None:
    """수집 범위 밖 계정은 **내부라고 말할 근거가 없다**. 벤더·다른 도구일 수 있다.

    여기서 기본 그룹을 주면 fail-safe 가 뒤집혀 벤더 역할이 삭제 권고 목록에 올라간다.
    """
    assert _scope([f"arn:aws:iam::{OUTSIDE}:root"]) == "unconfirmed"


def test_tooling_account_trust_is_labelled_not_actioned() -> None:
    """관제 계정만 신뢰하면 정상 운영 경로다(모든 대상 계정에 존재 → 계정 수만큼 노이즈가 된다)."""
    assert _scope([f"arn:aws:iam::{TOOLING}:root"]) == "tooling"


def test_tooling_plus_same_group_is_internal() -> None:
    """대조군 — 관제 계정 신뢰가 다른 판정을 **가리지 않는다**."""
    assert _scope([f"arn:aws:iam::{TOOLING}:root", f"arn:aws:iam::{A2}:root"]) == "internal"


def test_service_trust_is_service() -> None:
    assert _scope([], ["Service"]) == "service"


def test_account_trust_wins_over_service_trust() -> None:
    """계정 신뢰가 있으면 그게 경계 문제다 — 서비스 신뢰는 계정 경계와 무관하다.

    둘이 함께 있는 역할(서비스가 쓰지만 사람도 assume 가능)에서 서비스 판정이 이기면 다른 고객
    계정을 신뢰하는 사실이 트랙② 로 사라진다.
    """
    assert _scope([f"arn:aws:iam::{B1}:root"], ["Service", "AWS"]) == "cross_tenant"


def test_federated_trust_is_internal() -> None:
    """페더레이션은 계정이 아니라 **이 계정 안의** SAML/OIDC provider 를 가리킨다."""
    assert _scope([f"arn:aws:iam::{A1}:saml-provider/idp"], ["Federated"]) == "internal"


def test_iam_user_has_no_trust_policy_but_is_internal() -> None:
    """IAM 사용자·PS 할당에는 신뢰정책이 **없다**. 부재를 '확인 안 됨' 으로 읽으면 전 사용자가
    소유자 확인 트랙으로 밀린다 — 사용자는 우리가 수집한 계정 안에 사는 신원이다.
    """
    assert _scope([], identity_type="user") == "internal"
    assert _scope([], identity_type="sso_ps") == "internal"


def test_no_trust_evidence_at_all_is_unconfirmed() -> None:
    """대조군 — 역할인데 신뢰 근거가 아무것도 없으면 보수적으로 남긴다(추측하지 않는다)."""
    assert _scope([]) == "unconfirmed"
    assert _scope(["*"]) == "unconfirmed", "와일드카드는 계정 ID 가 아니다(별 유형이 다룬다)"


# ---- R5: normalize 가 그룹 맵을 실제로 쓴다 ----


def _seed(storage: LocalFSStorage, account_id: str, name: str, trust: dict, actions=("s3:Get*",)) -> None:
    storage.write_raw(account_id, "credential_report", {
        "account_id": account_id,
        "principals": [{
            "principal": f"arn:aws:iam::{account_id}:role/{name}", "name": name,
            "identity_type": "role", "create_date": "2026-01-01T00:00:00+00:00", "path": "/",
            "trust_policy": trust, "attached_policies": [],
            "inline_policies": [{"name": "i", "document": {"Statement": [
                {"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}}],
        }],
        "credential_report": [],
    })


def _trust_of(*arns) -> dict:
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": list(arns)}, "Action": "sts:AssumeRole"}]}


def test_normalize_fills_tenant_group_and_scope(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(st, A1, "peer", _trust_of(f"arn:aws:iam::{A2}:root"))
    _seed(st, B1, "crosser", _trust_of(f"arn:aws:iam::{A1}:root"))
    by_arn = {r.principal: r for r in normalize(
        st, RUN, account_groups=GROUPS, tooling_account_id=TOOLING)}
    peer = by_arn[f"arn:aws:iam::{A1}:role/peer"]
    crosser = by_arn[f"arn:aws:iam::{B1}:role/crosser"]
    assert (peer.tenant_group, peer.trust_scope) == ("alpha", "internal")
    assert (crosser.tenant_group, crosser.trust_scope) == ("beta", "cross_tenant")


def test_single_account_deployment_stays_internal(tmp_path) -> None:
    """대조군(회귀) — 단일 계정 배포에서 자기 계정을 신뢰하는 역할이 `unconfirmed` 가 되면
    **모든** 역할이 소유자 확인 트랙으로 밀린다. 그룹 맵 미지정 시 수집한 계정은 기본 그룹이다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(st, A1, "self-trusting", _trust_of(f"arn:aws:iam::{A1}:root"))
    rec = normalize(st, RUN)[0]
    assert rec.tenant_group == DEFAULT_TENANT_GROUP
    assert rec.trust_scope == "internal"


# ---- R5-b: 트랙 배정 우선순위 ----


def test_idle_beats_persona_and_service_role() -> None:
    """90일 이상 미사용이면 트랙③ 이 이긴다 — 지울 대상의 정책을 다듬는 것은 낭비다."""
    cfg = _cfg()
    idle_human = _rec(usage_subject="human", granted_actions=["s3:Get*"],
                      unused_days=400, unused_tier="cleanup", age_days=500,
                      role_last_used="2025-06-01T00:00:00+00:00")
    idle_machine = _rec(usage_subject="machine", principal_kind="service",
                        granted_actions=["s3:Get*"], unused_days=400, unused_tier="cleanup",
                        age_days=500, role_last_used="2025-06-01T00:00:00+00:00")
    assert _track_of(idle_human, cfg) == ("delete_review", None)
    assert _track_of(idle_machine, cfg) == ("delete_review", None)


def test_idle_with_unconfirmed_trust_goes_to_owner_review() -> None:
    """벤더·다른 도구가 심어놓은 역할은 안 쓰이는 게 정상이다 → 삭제 권고를 하지 않는다."""
    rec = _rec(trust_scope="unconfirmed", granted_actions=["s3:Get*"],
               unused_days=400, unused_tier="cleanup", age_days=500)
    assert _track_of(rec, _cfg()) == ("owner_review", None)


def test_idle_cross_tenant_never_gets_delete_recommendation() -> None:
    """대조군 — 경계 위반 의심 대상을 삭제 검토에 섞으면 그 자체가 별 문제를 덮는다."""
    rec = _rec(trust_scope="cross_tenant", granted_actions=["s3:Get*"],
               unused_days=400, unused_tier="cleanup", age_days=500)
    assert _track_of(rec, _cfg())[0] == "owner_review"


def test_idle_tooling_trust_is_not_deleted() -> None:
    """관제 계정 신뢰는 '조치 없음'(R5)이다. 형태가 벤더 교차계정 역할과 같아 구분할 수 없다."""
    rec = _rec(trust_scope="tooling", granted_actions=["s3:Get*"],
               unused_days=400, unused_tier="cleanup", age_days=500)
    assert _track_of(rec, _cfg())[0] == "owner_review"


def test_active_human_goes_to_persona() -> None:
    rec = _rec(usage_subject="human", used_actions=[UsedAction(action="s3:GetObject")],
               unused_days=3, unused_tier="active", age_days=500)
    assert _track_of(rec, _cfg()) == ("persona", None)


def test_active_machine_goes_to_service_role() -> None:
    rec = _rec(usage_subject="machine", used_actions=[UsedAction(action="s3:GetObject")],
               unused_days=3, unused_tier="active", age_days=500)
    assert _track_of(rec, _cfg()) == ("service_role", None)


def test_usage_subject_beats_trust_policy_kind() -> None:
    """두 축의 논리합에서 **실사용 축이 이긴다**. 반대로 두면 신뢰정책이 `Principal.AWS` 뿐인
    자동화 역할(실측 다수)이 계속 persona 로 올라온다.
    """
    machine_by_events = _rec(usage_subject="machine", principal_kind="unknown",
                             used_actions=[UsedAction(action="s3:GetObject")], age_days=500)
    human_by_events = _rec(usage_subject="human", principal_kind="service",
                           used_actions=[UsedAction(action="s3:GetObject")], age_days=500)
    assert _track_of(machine_by_events, _cfg())[0] == "service_role"
    assert _track_of(human_by_events, _cfg())[0] == "persona"


def test_unknown_subject_stays_in_persona() -> None:
    """대조군 — 추측으로 트랙② 에 보내면 사람이 쓰는 역할이 화면에서 사라진다. 남겨서 보게 한다."""
    rec = _rec(usage_subject="none", principal_kind="unknown",
               used_actions=[UsedAction(action="s3:GetObject")], age_days=500)
    assert _track_of(rec, _cfg())[0] == "persona"


def test_service_role_toggle_off_keeps_machines_in_persona() -> None:
    """`exclude_service_roles=false` 는 예전 뜻(버림) 이 아니라 '트랙② 로 보내지 않음' 이다."""
    rec = _rec(usage_subject="machine", used_actions=[UsedAction(action="s3:GetObject")],
               age_days=500)
    cfg = _cfg(catalog={"exclude_service_roles": False})
    assert _track_of(rec, cfg)[0] == "persona"


# ---- R6: 제외는 사유와 함께 남는다 ----


def test_exclusion_reasons() -> None:
    used = [UsedAction(action="s3:GetObject")]
    cfg = _cfg(readonly_role_name="Lp2psReadOnly",
               catalog={"exclude_principal_patterns": ["cdk-*-deploy-role"]})
    tool = _rec(principal=f"arn:aws:iam::{A1}:role/Lp2psReadOnly", used_actions=used, age_days=500)
    boot = _rec(principal=f"arn:aws:iam::{A1}:role/cdk-hnb-deploy-role", used_actions=used,
                age_days=500)
    fresh = _rec(used_actions=used, age_days=3, unused_tier="new")
    slr = _rec(used_actions=used, age_days=500, is_exception=True,
               exception_type="aws_service_linked")
    assert _track_of(tool, cfg) == ("excluded", "tool_readonly_role")
    assert _track_of(boot, cfg) == ("excluded", "iac_bootstrap_role")
    assert _track_of(fresh, cfg) == ("excluded", "too_new")
    assert _track_of(slr, cfg) == ("excluded", "aws_service_linked")


def test_default_patterns_exclude_cdk_cfn_exec_role() -> None:
    """🔴 `cdk bootstrap` 의 다섯 번째 역할(`cfn-exec-role`)도 **기본 패턴만으로** 빠져야 한다.

    라이브에서 이것이 빠져 있어 미사용 96일 · critical 로 '역할 삭제' 권고까지 올라왔다(리전별로
    하나씩). 지우면 그 리전으로의 CloudFormation 배포가 전부 실패한다. 나머지 넷과 달리 신뢰 대상이
    `cloudformation.amazonaws.com` 이어서 서비스 역할로 보이지만, 서비스 역할 제외는 트랙 배정에만
    쓰이고 미사용 판정을 막지 않는다 — 그래서 이름 패턴에 있어야 한다.
    """
    boot = _rec(principal=f"arn:aws:iam::{A1}:role/cdk-hnb659fds-cfn-exec-role-{A1}-ap-northeast-2",
                granted_actions=["*"], unused_days=96, unused_days_basis="role_last_used",
                unused_tier="cleanup", age_days=999)
    assert _track_of(boot, _cfg()) == ("excluded", "iac_bootstrap_role")


def test_cfn_exec_role_would_be_delete_review_without_the_pattern() -> None:
    """대조군 — 패턴을 지우면 **같은 레코드가 삭제 검토로 올라온다**. 위 어서션이 실패할 수 있음을
    증명한다(패턴이 없어도 통과하는 어서션은 아무것도 재지 않는다)."""
    boot = _rec(principal=f"arn:aws:iam::{A1}:role/cdk-hnb659fds-cfn-exec-role-{A1}-ap-northeast-2",
                granted_actions=["*"], unused_days=96, unused_days_basis="role_last_used",
                unused_tier="cleanup", age_days=999)
    assert _track_of(boot, _cfg(catalog={"exclude_principal_patterns": []}))[0] == "delete_review"


def test_exclusion_beats_idle() -> None:
    """제외가 미사용보다 먼저다 — 손댈 수 없는 대상(AWS 소유)을 삭제 권고에 올리면 목록 신뢰가 깨진다."""
    slr = _rec(is_exception=True, exception_type="aws_service_linked",
               granted_actions=["s3:Get*"], unused_days=900, unused_tier="cleanup", age_days=999)
    assert _track_of(slr, _cfg())[0] == "excluded"


def test_persona_without_used_actions_is_excluded_with_reason() -> None:
    """실사용이 없으면 묶을 것이 없다. 다만 **사유 없이** 사라지면 안 된다(R6)."""
    rec = _rec(granted_actions=["s3:Get*"], unused_days=3, unused_tier="active", age_days=500)
    assert _track_of(rec, _cfg()) == ("excluded", "no_used_actions")


def test_assign_tracks_writes_back_and_counts(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _rec(principal=f"arn:aws:iam::{A1}:role/h", usage_subject="human", age_days=500,
             used_actions=[UsedAction(action="s3:GetObject")]),
        _rec(principal=f"arn:aws:iam::{A1}:role/m", usage_subject="machine", age_days=500,
             used_actions=[UsedAction(action="s3:GetObject")]),
        _rec(principal=f"arn:aws:iam::{A1}:role/i", granted_actions=["s3:Get*"],
             unused_days=400, unused_tier="cleanup", age_days=500),
    ])
    counts = assign_tracks(st, RUN, _cfg())
    assert counts == {"delete_review": 1, "persona": 1, "service_role": 1}
    # 되쓰기 확인 — parquet 스키마에서 빠지면 조용히 기본값으로 돌아온다(allowlist).
    assert sorted(r.track or "" for r in st.read_normalized()) == [
        "delete_review", "persona", "service_role"]


# ---- R8: persona 격리 ----


def _persona_member(account_id: str, group: str, name: str) -> PrincipalRecord:
    return _rec(
        account_id=account_id, principal=f"arn:aws:iam::{account_id}:role/{name}",
        tenant_group=group, track="persona", usage_subject="human", age_days=500,
        used_actions=[UsedAction(action="s3:GetObject"), UsedAction(action="s3:ListBucket")],
        source=["credential_report"],
    )


def test_groups_never_share_a_persona(tmp_path) -> None:
    """R8 — 축이 없으면 A 고객 정책이 B 고객 실태에서 파생되고 A 산출물에 B 계정 ARN 이 들어간다."""
    from lp2ps.config import CatalogConfig

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _persona_member(A1, "alpha", "a1"), _persona_member(A2, "alpha", "a2"),
        _persona_member(B1, "beta", "b1"),
    ])
    entries = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=1))
    for entry in entries:
        accounts = {m.split(":")[4] for m in entry.members}
        assert len(accounts) == 1 or accounts == {A1, A2}, f"{entry.persona}: {accounts}"
        assert B1 not in str(entry.members) or entry.tenant_group == "beta"
    beta = [e for e in entries if e.tenant_group == "beta"]
    assert beta, "beta 그룹 persona 가 따로 나와야 한다"
    assert all(B1 not in m for e in entries if e.tenant_group == "alpha" for m in e.members)


def test_small_clusters_do_not_merge_across_groups(tmp_path) -> None:
    """'General'(기타) 묶음이 격리가 새는 가장 눈에 안 띄는 경로다 — 정상 군집만 분리되고 여기서 섞인다."""
    from lp2ps.config import CatalogConfig

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_persona_member(A1, "alpha", "a1"), _persona_member(B1, "beta", "b1")])
    entries = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=5))
    generals = [e for e in entries if e.persona.endswith("GeneralPersona")]
    assert len(generals) == 2, [e.persona for e in entries]
    assert {e.tenant_group for e in generals} == {"alpha", "beta"}


def test_default_group_persona_names_are_unchanged(tmp_path) -> None:
    """하위호환 — 단일 그룹 배포의 persona 명·정책 경로는 **바이트 동일**해야 한다.

    승인 상태와 Permission Set 이름이 persona 명으로 이어져 있어서 접두가 붙으면 기존 고객의
    승인이 전부 초기화된 것처럼 보인다.
    """
    from lp2ps.config import CatalogConfig

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_persona_member(A1, DEFAULT_TENANT_GROUP, "a1")])
    entry = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=1))[0]
    assert not entry.persona.startswith(DEFAULT_TENANT_GROUP)
    assert entry.policy_ref == f"policies/{entry.persona}.json"


def test_named_group_prefixes_persona_and_policy_path(tmp_path) -> None:
    from lp2ps.config import CatalogConfig

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_persona_member(B1, "beta", "b1")])
    entry = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=1))[0]
    assert entry.persona.startswith("beta_")
    # 경로를 persona 명에서 다시 만드는 호출부가 셋이다 — 이름과 경로가 어긋나면 조용히 깨진다.
    assert entry.policy_ref == f"policies/{entry.persona}.json"


def test_catalog_reads_track_and_does_not_re_derive(tmp_path) -> None:
    """대조군 — 배정된 트랙을 카탈로그가 무시하면 화면이 "제외" 라고 말한 대상이 persona 에 들어간다."""
    from lp2ps.config import CatalogConfig

    st = LocalFSStorage(tmp_path, "test", "run-x")
    member = _persona_member(A1, "alpha", "a1")
    excluded = _persona_member(A1, "alpha", "a2")
    excluded.track = "excluded"
    excluded.excluded_reason = "tool_readonly_role"
    st.write_normalized([member, excluded])
    entries = build_catalog(st, RUN, CatalogConfig(min_members_for_persona=1))
    assert [m for e in entries for m in e.members] == [member.principal]


# ---- R7: 서비스 단위 접기 ----


def _svc_rec(**kw) -> PrincipalRecord:
    base = dict(
        principal=f"arn:aws:iam::{A1}:role/svc", track="service_role", usage_subject="machine",
        age_days=500, role_last_used="2026-07-10T00:00:00+00:00", unused_days=5,
        unused_days_basis="role_last_used", unused_tier="active",
    )
    base.update(kw)
    return _rec(**base)


def test_rollup_folds_actions_into_namespaces(tmp_path) -> None:
    """실측 미사용 14,732개를 그대로 뿌리면 아무도 읽지 않는다 — 서비스 단위로 접는다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                         "dynamodb:Query", "dynamodb:Scan", "kms:Decrypt"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")],
        unused_findings=["s3:PutObject", "s3:DeleteObject", "dynamodb:Query", "dynamodb:Scan"],
        undetermined_findings=["kms:Decrypt"],
    )])
    entry = build_service_roles(st, RUN, _cfg())[0]
    by_ns = {r.namespace: r for r in entry.service_rollups}
    assert [r.namespace for r in entry.service_rollups] == ["dynamodb", "kms", "s3"], "정렬 결정론"
    assert (by_ns["s3"].verdict, by_ns["s3"].granted_count, by_ns["s3"].used_count) == ("keep", 3, 1)
    assert by_ns["dynamodb"].verdict == "remove", "인증 기록 없는 서비스는 통째로 제거 대상"
    assert by_ns["kms"].verdict == "undetermined", "안 썼다는 증거가 없으면 손대지 않는다"
    assert by_ns["dynamodb"].tier == "cleanup", "사용 기록이 아예 없으면 최상위 등급(R2)"
    assert by_ns["kms"].tier is None, "판정 불가는 등급도 없다 — 0 이 아니라 미측정이다"


def test_service_wildcard_does_not_block_the_verdict(tmp_path) -> None:
    """`acm:Get*` 는 M2 갭 계산에서 빠져 미사용 확정에 들어올 수 없다 → 개수에 세면 열거 가능한 권한이
    전부 미사용인 서비스까지 '판정 불가' 가 된다(실측 판정 불가 대부분이 이 형태였다).

    세지 않되 **버리지도 않는다** — 정리를 실행할 때 고쳐야 하는 문이 바로 이것이다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["acm:Get*", "acm:List*", "acm:SearchCertificates"],
        wildcard_grants=["acm:Get*", "acm:List*"],
        unused_findings=["acm:SearchCertificates"],
    )])
    entry = build_service_roles(st, RUN, _cfg())[0]
    rollup = entry.service_rollups[0]
    assert (rollup.namespace, rollup.verdict) == ("acm", "remove")
    assert rollup.granted_count == 1, "와일드카드는 셀 수 없다(R4)"
    assert rollup.wildcard_grants == ["acm:Get*", "acm:List*"], "행에서 사라지면 안 된다"
    # keep 이 없으므로 판단 필요 서비스는 0 — 제거 판정 자체는 위에서 확인했다(F15-2).
    assert entry.decision_count == 0


def test_wildcard_only_service_stays_undetermined(tmp_path) -> None:
    """대조군 — 셀 수 있는 권한이 하나도 없으면 제거 근거도 없다. 행은 남지만 판정 불가다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(granted_actions=["acm:Get*"], wildcard_grants=["acm:Get*"])])
    entry = build_service_roles(st, RUN, _cfg())[0]
    rollup = entry.service_rollups[0]
    assert (rollup.namespace, rollup.verdict, rollup.granted_count) == ("acm", "undetermined", 0)
    assert rollup.wildcard_grants == ["acm:Get*"]
    assert entry.decision_count == 0, "판정 불가는 사람이 내릴 결정이 아니다"


def test_service_authenticated_without_action_evidence_is_keep(tmp_path) -> None:
    """M2 케이스 ③ — Advisor 가 서비스 인증을 확인했지만 action 단위 근거가 없는 경우.

    이 서비스를 `undetermined` 로 두면 화면이 **아는 것을 모른다고** 말한다(실측: 접기 행의 절반
    이상이 판정 불가로 나왔다). 어느 action 인지 모르는 것과 서비스를 쓰는지 모르는 것은 다르다.
    등급은 없다 — 서비스 단위 인증 날짜는 레코드에 남지 않아 일수를 셀 근거가 없다(추정 금지).
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["kms:Decrypt", "kms:Encrypt"],
        used_services=["kms"],
        undetermined_findings=["kms:Decrypt", "kms:Encrypt"],
    )])
    rollup = build_service_roles(st, RUN, _cfg())[0].service_rollups[0]
    assert (rollup.namespace, rollup.verdict, rollup.used_count) == ("kms", "keep", 0)
    assert rollup.tier is None


def test_unauthenticated_service_is_still_removable(tmp_path) -> None:
    """대조군 — 인증 기록이 **없는** 서비스는 그대로 제거 대상이다(위 완화가 전부를 keep 으로 만들면
    트랙② 가 아무 것도 제안하지 못한다)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["kms:Decrypt", "sqs:SendMessage"], used_services=["kms"],
        unused_findings=["sqs:SendMessage"], undetermined_findings=["kms:Decrypt"],
    )])
    by_ns = {r.namespace: r for r in build_service_roles(st, RUN, _cfg())[0].service_rollups}
    assert by_ns["sqs"].verdict == "remove"
    assert by_ns["kms"].verdict == "keep"


def test_recently_used_service_stays_undetermined_tier(tmp_path) -> None:
    """R2 하한선 — 서비스를 어제 썼으면 그 안의 미사용 권한에 대해 아무 말도 못 한다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["s3:GetObject", "s3:PutObject"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-14T00:00:00Z")],
        unused_findings=["s3:PutObject"],
    )])
    rollup = build_service_roles(st, RUN, _cfg())[0].service_rollups[0]
    assert rollup.tier == "active", "1일 전 사용 → 등급으로 정리를 주장할 수 없다"


def test_stale_service_gets_cleanup_tier(tmp_path) -> None:
    """대조군 — 오래 안 쓴 서비스는 등급이 올라간다(경계는 config, 기본 90)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["s3:GetObject", "s3:PutObject"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2025-07-14T00:00:00Z")],
        unused_findings=["s3:PutObject"],
    )])
    assert build_service_roles(st, RUN, _cfg())[0].service_rollups[0].tier == "cleanup"


def test_decision_count_excludes_bulk_removal(tmp_path) -> None:
    """`decision_count` 는 **`keep` 서비스 수**다 — 제거 묶음을 세지 않는다(F15-2).

    화면 라벨이 `판단 필요 서비스` 이므로 값도 서비스 개수여야 한다. 예전에는 "인증 이력 없는
    서비스 일괄 제거" 를 작업 1건으로 더했는데, 그건 서비스가 아니라 작업이어서 서비스 수를 세는
    칼럼에 단위가 다른 값이 섞였다. 제거 쪽 개수는 `사용하지 않는 서비스` 컬럼이 따로 말한다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=[f"svc{i}:Do" for i in range(50)],
        unused_findings=[f"svc{i}:Do" for i in range(50)],
    )])
    entry = build_service_roles(st, RUN, _cfg())[0]
    assert len(entry.service_rollups) == 50
    # 제거만 50건이고 keep 이 없다 → 판단할 서비스는 0. 제거 대상은 rollup 으로 그대로 남는다.
    assert entry.decision_count == 0
    assert sum(1 for r in entry.service_rollups if r.verdict == "remove") == 50


def test_decision_count_counts_only_keep_services(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(
        granted_actions=["s3:GetObject", "dynamodb:Query", "sqs:SendMessage", "kms:Decrypt"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z"),
                      UsedAction(action="dynamodb:Query", last_used="2026-07-10T00:00:00Z")],
        unused_findings=["sqs:SendMessage"],
        undetermined_findings=["kms:Decrypt"],
    )])
    entry = build_service_roles(st, RUN, _cfg())[0]
    # keep 2(s3·dynamodb)뿐이다. remove(sqs)는 세지 않고, undetermined(kms)도 '손대지 않는다'.
    assert entry.decision_count == 2
    # 대조군 — 세지 않은 두 판정이 실제로 존재한다(어서션이 빈 rollup 을 통과한 게 아니다).
    verdicts = {r.namespace: r.verdict for r in entry.service_rollups}
    assert verdicts["sqs"] == "remove"
    assert verdicts["kms"] == "undetermined"


def test_group_key_folds_identical_granted_sets(tmp_path) -> None:
    """부여 집합이 같은 역할을 한 행으로 접기 위한 키(실측 84 역할 → 49 그룹). 순서에 흔들리면 안 된다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/x", granted_actions=["s3:Get", "s3:Put"]),
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/y", granted_actions=["s3:Put", "s3:Get"]),
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/z", granted_actions=["s3:Get"]),
    ])
    entries = {e.principal.rsplit("/", 1)[-1]: e for e in build_service_roles(st, RUN, _cfg())}
    assert entries["x"].group_key == entries["y"].group_key
    assert entries["z"].group_key not in ("", entries["x"].group_key)


def test_only_service_role_track_is_emitted(tmp_path) -> None:
    """대조군 — persona·삭제 검토 대상이 트랙② 산출물에 섞이면 정책이 역할별로 나가지 않는다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/m"),
        _persona_member(A1, "alpha", "h"),
        _rec(principal=f"arn:aws:iam::{A1}:role/i", track="delete_review"),
    ])
    assert [e.principal for e in build_service_roles(st, RUN, _cfg())] == [
        f"arn:aws:iam::{A1}:role/m"]


def test_wildcard_is_not_folded_into_a_namespace(tmp_path) -> None:
    """`*` 는 어느 서비스에도 접히지 않는다 — 부여 범위에 상한이 없어 개수를 셀 수 없다(R4)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_svc_rec(granted_actions=["*", "s3:GetObject"], wildcard_grants=["*"],
                                 unused_findings=["s3:GetObject"])])
    entry = build_service_roles(st, RUN, _cfg())[0]
    assert [r.namespace for r in entry.service_rollups] == ["s3"]
    assert entry.wildcard_grants == ["*"], "보유 사실은 별 항목으로 이어져야 한다"


# ---- 지표 ----


def test_metrics_count_tracks_and_cross_tenant(tmp_path) -> None:
    """이 지표가 없으면 과권한의 가장 큰 덩어리와 경계 위반이 대시보드에서 사라진다."""
    from lp2ps.m6_reporter import build_reports
    from lp2ps.snapshot import write_snapshot

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/m1",
                 granted_actions=["s3:Get", "s3:Put"], unused_findings=["s3:Put"]),
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/m2",
                 granted_actions=["sqs:Send"], unused_findings=["sqs:Send"]),
        _rec(principal=f"arn:aws:iam::{A1}:role/x", track="owner_review",
             trust_scope="cross_tenant"),
    ])
    st.write_json("catalog.json", [])
    cfg = _cfg()
    build_reports(st, RUN, cfg)
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded", risk_rules=cfg.risk_rules)
    assert point.service_role_targets == 2
    assert point.service_role_unused_actions == 2
    assert point.cross_tenant_trust_roles == 1


def test_observed_window_is_passed_through_not_invented(tmp_path) -> None:
    """관측 구간을 그대로 내려보낸다 — 화면 경고 강도의 근거다.

    기계 역할의 권한 축소는 장애 직결이라 화면이 상시 경고를 띄우고, 구간이 짧으면 경고를 승격한다.
    여기서 값을 만들어 내거나(기본 90) 없는 것을 0 으로 채우면 화면이 **측정하지 않은 숫자**로
    경고 강도를 정하게 된다.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/short", observed_days=12,
                 granted_actions=["s3:GetObject"], used_actions=[
                     UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")]),
        # CloudTrail 근거가 아예 없는 역할 — None 이 0 이나 기본값으로 바뀌면 안 된다.
        _svc_rec(principal=f"arn:aws:iam::{A1}:role/nowindow", observed_days=None,
                 granted_actions=["s3:GetObject"], used_actions=[
                     UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")]),
    ])
    entries = {e.principal.rsplit("/", 1)[1]: e for e in build_service_roles(st, RUN, _cfg())}
    assert entries["short"].observed_days == 12
    assert entries["nowindow"].observed_days is None


# ---- R5 / 트랙③·③-b: 백로그 문구 (P7) ----
#
# 배정은 P4 에서 했지만 백로그 문구는 없었다. 배정만 하고 문구를 예전 것으로 두면 화면이
# "소유자 확인" 이라고 분류한 대상의 권고가 "역할 삭제" 인 상태가 되고, 그게 정확히 이 목록의
# 신뢰를 깨는 경로다. 그래서 갈라지는 지점을 **양쪽 다** 고정한다.


def _idle_role(**kw) -> PrincipalRecord:
    """90일 이상 미사용으로 잡히는 역할(사용 근거 0 · 부여 권한 있음)."""
    base = dict(granted_actions=["s3:DeleteBucket"], unused_days=200,
                unused_days_basis="role_last_used", unused_tier="cleanup", age_days=400)
    base.update(kw)
    return _rec(**base)


def _items(records):
    from lp2ps.m6_reporter import _cleanup_items
    return _cleanup_items(records, _cfg())


def _of_type(records, ctype):
    return [i for i in _items(records) if i.type == ctype]


def _recommends_deletion(item) -> bool:
    """권고가 실제로 삭제를 지시하는가.

    `"삭제" in recommendation` 으로 보면 안 된다 — 삭제하지 말라는 문구("삭제 권고 아님")가
    그 검사를 통과한다. 실제로 그렇게 써서 이 테스트가 잘못 FAIL 했다.
    """
    return item.recommendation.startswith("역할 삭제")


def test_unconfirmed_trust_does_not_recommend_deletion() -> None:
    """신뢰 미확인 + 미사용 → `unconfirmed_trust_role`, 권고에 '삭제' 가 없다."""
    items = _of_type([_idle_role(trust_scope="unconfirmed")], "unconfirmed_trust_role")
    assert len(items) == 1
    assert "삭제 권고 아님" in items[0].recommendation
    assert "역할 삭제" not in items[0].recommendation
    # 왜 확인이 안 됐는지 소유자에게 물으려면 신뢰 대상이 증거에 있어야 한다.
    assert "신뢰 범위 판정" in items[0].evidence
    # detail 이 미사용만 말하면 화면에서 unused_role 과 구별되지 않는다.
    assert "신뢰 대상 미확인" in items[0].detail


def test_confirmed_internal_still_recommends_deletion() -> None:
    """대조군 — 내부로 확인된 미사용 역할은 그대로 삭제 검토다.

    이 대조가 없으면 위 테스트는 '모든 미사용 역할의 삭제 권고를 없애도' 통과한다. 그러면 이
    도구의 본래 산출물이 통째로 사라진다.
    """
    items = _of_type([_idle_role(trust_scope="internal")], "unused_role")
    assert len(items) == 1
    assert "역할 삭제" in items[0].recommendation
    assert _of_type([_idle_role(trust_scope="internal")], "unconfirmed_trust_role") == []


def test_tooling_trust_is_not_a_deletion_candidate() -> None:
    """관제 계정 신뢰는 정상 운영 경로지 '내부 확인' 이 아니다 — 삭제 권고로 가지 않는다(R5)."""
    types = {i.type for i in _items([_idle_role(trust_scope="tooling")])}
    assert "unconfirmed_trust_role" in types
    assert "unused_role" not in types


def test_cross_tenant_trust_is_emitted_regardless_of_usage() -> None:
    """경계 위반 의심은 **미사용 여부와 무관**하다 — 활발히 쓰이는 위반이 조용히 빠지면 안 된다."""
    active = _rec(principal=f"arn:aws:iam::{A1}:role/live", trust_scope="cross_tenant",
                  granted_actions=["s3:GetObject"],
                  used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-14T00:00:00Z")],
                  trust_principals=[f"arn:aws:iam::{B1}:root"])
    items = _of_type([active], "cross_tenant_trust")
    assert len(items) == 1, "사용 중인 역할도 경계 위반 의심으로 올라와야 한다"
    assert not _recommends_deletion(items[0])
    assert "삭제 권고 아님" in items[0].recommendation
    assert B1 in items[0].detail
    # 대조군: 같은 역할의 신뢰가 내부면 이 유형은 나오지 않는다.
    assert _of_type([_rec(**{**active.model_dump(), "trust_scope": "internal"})],
                    "cross_tenant_trust") == []


def test_cross_tenant_and_unconfirmed_coexist() -> None:
    """미사용 + 경계 위반이면 두 유형이 함께 나온다 — 서로를 가리지 않는다.

    한쪽이 다른 쪽을 가리면(예: cross_tenant 면 미사용 항목을 안 냄) 화면에서 그 역할의 미사용
    사실이 사라지거나, 반대로 경계 위반이 사라진다. 둘은 다른 사실이다.
    """
    types = {i.type for i in _items([_idle_role(trust_scope="cross_tenant",
                                                trust_principals=[f"arn:aws:iam::{B1}:root"])])}
    assert {"cross_tenant_trust", "unconfirmed_trust_role"} <= types
    assert "unused_role" not in types


def test_no_owner_review_target_ever_gets_a_deletion_recommendation() -> None:
    """P7 완료 기준을 그대로 고정: `owner_review` 로 배정된 대상의 권고에 삭제가 섞이지 않는다.

    유형별로 확인하는 대신 **배정 결과(track)** 를 기준으로 전수 확인한다. 새 유형이 늘거나
    분기가 바뀌어도 이 어서션은 유지돼야 한다.
    """
    recs = [
        _idle_role(principal=f"arn:aws:iam::{A1}:role/vendor", trust_scope="unconfirmed"),
        _idle_role(principal=f"arn:aws:iam::{A1}:role/tool", trust_scope="tooling"),
        _idle_role(principal=f"arn:aws:iam::{A1}:role/other", trust_scope="cross_tenant",
                   trust_principals=[f"arn:aws:iam::{B1}:root"]),
        _idle_role(principal=f"arn:aws:iam::{A1}:role/ours", trust_scope="internal"),
    ]
    cfg = _cfg()
    for rec in recs:
        rec.track, rec.excluded_reason = _track_of(rec, cfg)  # type: ignore[assignment]
    assert {r.track for r in recs} == {"owner_review", "delete_review"}, "양쪽이 다 나와야 대조가 성립"

    by_arn = {r.principal: r for r in recs}
    deleted = [i.principal for i in _items(recs) if _recommends_deletion(i)]
    for arn in deleted:
        assert by_arn[arn].track == "delete_review", f"{arn} 은 {by_arn[arn].track} 인데 삭제 권고를 받았다"
    assert deleted, "delete_review 대상은 삭제 권고를 받아야 한다(대조군)"


def test_track_beats_a_stale_trust_scope() -> None:
    """배정 결과가 있으면 그것이 정본이다 — 백로그가 신뢰 축을 다시 판정하지 않는다.

    두 곳이 각자 판정하면 화면 배정과 백로그 문구가 어긋나고, 그 어긋남은 '숫자가 틀렸다' 로만
    보인다(대시보드 40 vs 백로그 59 를 이미 한 번 겪었다).
    """
    rec = _idle_role(trust_scope="internal", track="owner_review")
    assert {i.type for i in _items([rec])} >= {"unconfirmed_trust_role"}
    assert _of_type([rec], "unused_role") == []


def test_owner_review_metric_reconciles_with_the_backlog(tmp_path) -> None:
    """지표와 백로그가 같은 판정식을 쓰는지 산수로 고정한다.

    `unused_roles`(미사용 90일 이상)는 정의가 바뀌지 않았고, 백로그만 두 유형으로 갈렸다.
    `owner_review_roles` 가 그 몫을 정확히 설명하지 못하면 대시보드와 목록이 어긋나 보인다.
    """
    from lp2ps.m6_reporter import build_reports
    from lp2ps.snapshot import write_snapshot

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _idle_role(principal=f"arn:aws:iam::{A1}:role/vendor", trust_scope="unconfirmed"),
        _idle_role(principal=f"arn:aws:iam::{A1}:role/tool", trust_scope="tooling"),
        _idle_role(principal=f"arn:aws:iam::{A1}:role/ours", trust_scope="internal"),
    ])
    st.write_json("catalog.json", [])
    cfg = _cfg()
    items = build_reports(st, RUN, cfg) and None
    del items
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded", risk_rules=cfg.risk_rules)
    import csv as _csv
    import io as _io

    from lp2ps.m6_reporter import BACKLOG_NAME
    rows = list(_csv.DictReader(_io.StringIO(st.read_bytes(BACKLOG_NAME).decode())))
    unused_rows = [r for r in rows if r["type"] == "unused_role"]
    owner_rows = [r for r in rows if r["type"] == "unconfirmed_trust_role"]
    assert point.unused_roles == 3
    assert point.owner_review_roles == 2
    assert len(owner_rows) == point.owner_review_roles
    assert len(unused_rows) == point.unused_roles - point.owner_review_roles
