"""와일드카드 승격(R4) — 보유 사실을 findings 로 올린다.

고친 결함: `*` 는 부여 범위에 상한이 없어 (granted − used) 갭 계산에서 빠진다. 그 판단 자체는
맞다 — "미사용 3개" 처럼 셀 수가 없다. 문제는 빠진 뒤 **아무 데도 남지 않아서** 전 권한 보유자가
findings 0 으로 목록에서 가장 깨끗해 보였다는 것이다. 세는 것을 포기하는 것과 보고하지 않는 것은
다르다.

신뢰정책 와일드카드는 **별 유형**이다: granted 와일드카드는 "이 역할이 무엇을 할 수 있나",
신뢰 와일드카드는 "누가 이 역할을 집을 수 있나" 다.
"""

from __future__ import annotations

import json

from lp2ps.config import Config, RiskRules
from lp2ps.m2_normalizer import _trust_wildcard, normalize
from lp2ps.m4_risk_scorer import _score_one
from lp2ps.m6_reporter import _cleanup_items
from lp2ps.models import PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")
ACCOUNT = "111122223333"
ARN = f"arn:aws:iam::{ACCOUNT}:role/admin-ish"


def _cfg(**risk) -> Config:
    return Config.model_validate({
        "customer": "test", "region": "us-west-2", "cross_account": False,
        "accounts": ["self"], **({"risk_rules": risk} if risk else {}),
    })


def _rec(**kw) -> PrincipalRecord:
    # 신뢰는 내부로 확인된 것으로 둔다 — 이 파일이 검증하는 것은 와일드카드 승격이고, 신뢰 축은
    # 미사용 유형을 `unused_role` / `unconfirmed_trust_role` 로 가른다(R5, test_tracks_and_tenancy).
    base = dict(account_id=ACCOUNT, principal=ARN, identity_type="role",
                trust_scope="internal", risk_level="critical", run_id="run-x")
    base.update(kw)
    return PrincipalRecord(**base)


def _types(records: list[PrincipalRecord], cfg: Config | None = None) -> list[str]:
    return [i.type for i in _cleanup_items(records, cfg or _cfg())]


def _item_of(records: list[PrincipalRecord], ctype: str, cfg: Config | None = None):
    return next(i for i in _cleanup_items(records, cfg or _cfg()) if i.type == ctype)


# ---- M2: 갭에서 뺀 와일드카드를 보존한다 ----


def _seed(storage: LocalFSStorage, actions, trust: dict | None = None) -> None:
    principal: dict = {
        "principal": ARN, "name": "admin-ish", "identity_type": "role",
        "create_date": "2026-01-01T00:00:00+00:00",
        "inline_policies": [{"name": "inline", "document": {
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}}],
        "attached_policies": [], "path": "/",
    }
    if trust is not None:
        principal["trust_policy"] = trust
    storage.write_raw(ACCOUNT, "credential_report", {
        "account_id": ACCOUNT, "principals": [principal], "credential_report": [],
    })


def test_wildcards_are_kept_out_of_gap_but_recorded(tmp_path) -> None:
    """와일드카드는 미사용 판정에서 **빠지고**, `wildcard_grants` 에 **남는다**.

    두 어서션이 함께 있어야 의미가 있다. 빠지는 것만 확인하면 예전 결함(빠진 뒤 소실)이 통과하고,
    남는 것만 확인하면 "미사용 1건" 같은 셀 수 없는 숫자가 다시 생겨도 통과한다.
    """
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, ["*", "s3:*", "s3:GetObject"])
    r = normalize(storage, RUN, RiskRules())[0]
    assert r.wildcard_grants == ["*", "s3:*"], "정렬된 원문이 보존돼야 한다"
    # advisor 근거가 없는 principal 이라 갭은 전부 '판정 불가' 로 간다(ⓞ). 여기서 확인하는 것은
    # **어느 쪽 목록에도 와일드카드가 없다**는 것이다 — 셀 수 없는 것을 세면 안 된다.
    assert r.undetermined_findings == ["s3:GetObject"]
    assert r.unused_findings == []
    assert not any(f in ("*", "s3:*") for f in r.unused_findings + r.undetermined_findings)


def test_no_wildcard_leaves_field_empty(tmp_path) -> None:
    """대조군 — 와일드카드가 없으면 빈 리스트다(전 역할에 배너가 뜨면 배너가 무의미해진다)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, ["s3:GetObject", "s3:PutObject"])
    assert normalize(storage, RUN, RiskRules())[0].wildcard_grants == []


# ---- M2: 신뢰정책 와일드카드 ----


def _trust(principal, condition: dict | None = None, effect: str = "Allow") -> dict:
    stmt: dict = {"Effect": effect, "Principal": principal, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def test_trust_wildcard_forms_that_count() -> None:
    """세 형태를 잡는다: 문자열 `"*"`, `AWS: "*"`, 계정 자리가 `*` 인 ARN."""
    assert _trust_wildcard(_trust("*")) is True
    assert _trust_wildcard(_trust({"AWS": "*"})) is True
    assert _trust_wildcard(_trust({"AWS": ["arn:aws:iam::*:root"]})) is True


def test_specific_account_trust_is_not_wildcard() -> None:
    """대조군 — 특정 계정 신뢰는 와일드카드가 아니다.

    교차계정 신뢰는 범위 문제이고 `trust_scope` 가 다룬다. 여기서 잡으면 정상적인 교차계정
    연동 전부가 '보안 결함' 으로 올라간다.
    """
    assert _trust_wildcard(_trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})) is False
    assert _trust_wildcard(_trust({"Service": "lambda.amazonaws.com"})) is False
    assert _trust_wildcard({}) is False


def test_conditioned_wildcard_is_not_flagged() -> None:
    """`Principal:"*"` + Condition 은 잡지 않는다 — IAM Access Analyzer 와 같은 기준이다.

    `aws:PrincipalOrgID` 로 조직 범위를 묶는 것은 정상 패턴이고, AWS 콘솔이 '외부 접근 없음'
    이라고 말하는 것을 이 도구가 '보안 결함' 이라고 주장하면 고객이 어느 쪽을 믿을지 알 수 없다.
    🔴 한계: 조건의 **강도**는 보지 않는다(약한 조건으로 열린 신뢰는 여기서 안 잡힌다).
    """
    conditioned = _trust("*", {"StringEquals": {"aws:PrincipalOrgID": "o-example"}})
    assert _trust_wildcard(conditioned) is False


def test_deny_statement_wildcard_is_not_a_grant() -> None:
    """대조군 — Deny 의 와일드카드는 신뢰를 **주지 않는다**. 잡으면 방어책이 결함으로 뒤집힌다."""
    assert _trust_wildcard(_trust("*", effect="Deny")) is False


def test_normalize_fills_trust_wildcard(tmp_path) -> None:
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, ["s3:GetObject"], trust=_trust("*"))
    assert normalize(storage, RUN, RiskRules())[0].trust_wildcard is True


# ---- M6: findings 0 이 아니게 된다 ----


def test_wildcard_holder_is_no_longer_findings_zero() -> None:
    """이 테스트가 곧 결함의 재현이다 — 전 권한 보유자가 목록에서 가장 깨끗해 보였다.

    `unused_findings` 가 비어 있어(셀 수 없어서) `unused_permission` 항목이 안 나오는 것은 맞다.
    그 상태에서 항목이 **하나도** 없으면 안 된다.
    """
    rec = _rec(granted_actions=["*"], wildcard_grants=["*"],
               used_actions=[UsedAction(action="s3:GetObject")])
    types = _types([rec])
    assert "unused_permission" not in types, "셀 수 없는 개수를 만들어내면 안 된다"
    assert "wildcard_grant" in types, "가장 위험한 대상이 findings 0 으로 보이던 결함"


def test_wildcard_item_recommends_rewrite_not_removal() -> None:
    """권고는 "미사용 N개 제거" 가 아니라 실사용 기반 **재작성**이다.

    개수를 말하면 그만큼 지우면 최소권한이 된다는 뜻이 되는데, `*` 는 그대로 남는다.
    """
    item = _item_of([_rec(granted_actions=["*"], wildcard_grants=["*"])], "wildcard_grant")
    assert "재작성" in item.recommendation
    assert "제거" not in item.recommendation.replace("제거 개수 산정 불가", "")
    assert item.evidence["미사용 개수 산정"] == "불가(부여 범위에 상한이 없음)"
    assert item.evidence["보유 와일드카드"] == "*"


def test_wildcard_item_is_emitted_regardless_of_usage() -> None:
    """미사용 여부·트랙과 무관하게 올린다 — 현역 역할의 `*` 도 결함이다."""
    active = _rec(principal=f"{ARN}-a", granted_actions=["*"], wildcard_grants=["*"],
                  used_actions=[UsedAction(action="s3:GetObject")], used_services=["s3"],
                  unused_days=1, unused_tier="active", age_days=500)
    idle = _rec(principal=f"{ARN}-b", granted_actions=["*"], wildcard_grants=["*"],
                unused_days=1076, unused_tier="cleanup", age_days=1500,
                role_last_used="2023-08-04T00:00:00+00:00")
    types = [(i.principal, i.type) for i in _cleanup_items([active, idle], _cfg())]
    assert (active.principal, "wildcard_grant") in types
    assert (idle.principal, "wildcard_grant") in types
    # 미사용 쪽은 삭제 검토도 함께 받는다 — 두 유형은 서로를 가리지 않는다.
    assert (idle.principal, "unused_role") in types


def test_trust_policy_wildcard_is_a_separate_item() -> None:
    """신뢰 와일드카드는 granted 와일드카드와 별 항목이고, 권고도 다르다."""
    rec = _rec(granted_actions=["s3:GetObject"], trust_wildcard=True,
               trust_principals=["*"], used_actions=[UsedAction(action="s3:GetObject")])
    item = _item_of([rec], "trust_policy_wildcard")
    assert "wildcard_grant" not in _types([rec]), "granted 와일드카드가 없으면 그 유형은 안 나온다"
    assert "Principal" in item.recommendation and "좁히" in item.recommendation
    assert item.evidence["판정 기준"].startswith("Condition 없는")


def test_both_wildcard_types_can_coexist() -> None:
    """대조군 — 둘 다 있으면 둘 다 나온다(한쪽이 다른 쪽을 삼키지 않는다)."""
    rec = _rec(granted_actions=["*"], wildcard_grants=["*"], trust_wildcard=True)
    types = _types([rec])
    assert types.count("wildcard_grant") == 1
    assert types.count("trust_policy_wildcard") == 1


def test_backlog_csv_carries_new_types(tmp_path) -> None:
    """백로그 CSV·라벨까지 이어져야 한다 — 유형만 늘리고 표기를 빼면 화면에 원문 문자열이 뜬다."""
    from lp2ps.m6_reporter import build_reports

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(granted_actions=["*"], wildcard_grants=["*"], trust_wildcard=True)])
    st.write_json("catalog.json", [])
    build_reports(st, RUN, _cfg())
    csv_text = st.read_bytes("cleanup_backlog.csv").decode("utf-8-sig")
    assert "wildcard_grant" in csv_text
    assert "trust_policy_wildcard" in csv_text
    html_text = st.read_bytes("report.html").decode()
    assert "와일드카드 권한" in html_text
    assert "신뢰정책 와일드카드" in html_text


# ---- M4: 두 결함이 서로 다른 가중치를 받는다 ----


def test_trust_wildcard_scores_separately_from_granted_wildcard() -> None:
    """신뢰 와일드카드와 granted 와일드카드를 한 가중치로 합치면 조치 우선순위가 사라진다."""
    rules = RiskRules()
    granted_only = _score_one(_rec(granted_actions=["s3:*"], wildcard_grants=["s3:*"]), rules)[0]
    trust_only = _score_one(_rec(granted_actions=["s3:GetObject"], trust_wildcard=True), rules)[0]
    both = _score_one(
        _rec(granted_actions=["s3:*"], wildcard_grants=["s3:*"], trust_wildcard=True), rules)[0]
    assert granted_only == rules.weight_wildcard_action
    assert trust_only == rules.weight_trust_policy_wildcard
    assert both == granted_only + trust_only, "두 결함은 더해져야 한다"


def test_trust_wildcard_weight_comes_from_config() -> None:
    """대조군 — 가중치가 config 에서 온다(불변식 ④)."""
    rec = _rec(granted_actions=["s3:GetObject"], trust_wildcard=True)
    assert _score_one(rec, RiskRules(weight_trust_policy_wildcard=7))[0] == 7


def test_wildcard_action_uses_m2_field_and_stays_monotone() -> None:
    """`wildcard_grants` 를 우선 쓰되, 이 필드가 없던 레코드에서도 점수가 떨어지지 않는다.

    폴백을 빼면 구 normalized 를 다시 읽을 때 가중치가 조용히 0 이 되어 등급이 내려간다.
    """
    rules = RiskRules()
    legacy = _rec(granted_actions=["s3:*"])  # wildcard_grants 미채움
    assert _score_one(legacy, rules)[0] == rules.weight_wildcard_action
    reason = _score_one(_rec(granted_actions=["*"], wildcard_grants=["*"]), rules)[1]
    assert any("와일드카드 action" in r for r in reason)


# ---- 지표 ----


def test_metrics_count_wildcard_holders(tmp_path) -> None:
    """이 지표가 없으면 가장 위험한 대상이 대시보드에서 사라진다(미사용 개수 0으로 잡히므로)."""
    from lp2ps.m6_reporter import build_reports
    from lp2ps.snapshot import write_snapshot

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([
        _rec(principal=f"{ARN}-a", granted_actions=["*"], wildcard_grants=["*"]),
        _rec(principal=f"{ARN}-b", granted_actions=["s3:*"], wildcard_grants=["s3:*"]),
        _rec(principal=f"{ARN}-c", granted_actions=["s3:GetObject"]),
    ])
    st.write_json("catalog.json", [])
    cfg = _cfg()
    build_reports(st, RUN, cfg)
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded",
                           risk_rules=cfg.risk_rules)
    assert point.wildcard_grant_principals == 2
    assert point.unused_permissions == 0, "와일드카드는 미사용 개수에 기여하지 않는다(대조)"


# ---- M7: 초안은 실사용만 ----


def test_policy_draft_for_wildcard_holder_contains_only_used_actions(tmp_path) -> None:
    """전 권한 보유자의 정책 초안에 `*` 가 새면 최소권한이 아니라 현상 유지가 된다."""
    from lp2ps.config import CatalogConfig
    from lp2ps.m5_catalog import build_catalog
    from lp2ps.m7_policy_synth import synth_policies

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(
        granted_actions=["*", "s3:GetObject"], wildcard_grants=["*"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")],
        principal_kind="human",
    )])
    build_catalog(st, RUN, CatalogConfig(min_members_for_persona=1))
    policies = synth_policies(st, RUN)
    assert policies, "persona 가 하나는 나와야 초안을 검사할 수 있다"
    for doc in policies.values():
        actions = [a for stmt in doc["Statement"] for a in stmt["Action"]]
        assert actions == ["s3:GetObject"], actions
        assert "*" not in actions
    # 초안 전문에도 action 와일드카드가 없어야 한다(Resource 의 "*" 는 M7 범위 밖 — 별도 후속).
    for doc in policies.values():
        for stmt in doc["Statement"]:
            assert all("*" not in a for a in stmt["Action"])
            assert stmt["Resource"] == "*", "리소스 스코핑은 M7 범위가 아니다(대조)"


def test_json_evidence_is_serializable(tmp_path) -> None:
    """증거 dict 는 CSV 에 JSON 으로 실린다 — 값이 전부 문자열이어야 한다."""
    item = _item_of([_rec(granted_actions=["*"], wildcard_grants=["*", "s3:*"])], "wildcard_grant")
    assert all(isinstance(v, str) for v in item.evidence.values())
    json.dumps(item.evidence, ensure_ascii=False)
