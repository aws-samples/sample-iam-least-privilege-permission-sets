"""신뢰정책 → 사용 주체 구분(principal_kind) + persona 군집에서 서비스 역할 분리.

배경: persona 는 **사람** 접근의 표준화 단위인데, 서비스 실행 역할(Lambda/EC2/SSM 등)이 섞여
들어와 사람용 정책에 서비스 전용 action 이 합성되고 실재하지 않는 persona 가 생겼다.
신뢰정책(AssumeRolePolicyDocument)은 `GetAccountAuthorizationDetails` 응답에 이미 들어 있어
추가 API 호출·추가 IAM 권한 없이 이 구분이 가능하다.

분류 규칙의 근거는 실측이다(role 398개): Service 353 / AWS 만 38 / AWS+Service 5 / Federated 2.
혼합은 1.3% 이고 전부 "서비스 + 배포 계정 root" 패턴 → Service 가 있으면 서비스로 본다.
"""

from __future__ import annotations

import pytest

from lp2ps.config import CatalogConfig
from lp2ps.m2_normalizer import normalize
from lp2ps.m5_catalog import build_catalog
from lp2ps.models import UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")
ACCOUNT = "111122223333"

_INLINE = [
    {
        "name": "inline",
        "document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
    }
]


def _trust(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(principal) -> dict:  # noqa: ANN001
    return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}


def _role(name: str, trust: dict | None, *, tags: dict | None = None) -> dict:
    return {
        "principal": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "name": name,
        "identity_type": "role",
        "inline_policies": _INLINE,
        "attached_policies": [],
        "path": "/",
        "trust_policy": trust or {},
        "tags": tags or {},
    }


def _user(name: str) -> dict:
    return {
        "principal": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "name": name,
        "identity_type": "user",
        "inline_policies": _INLINE,
        "attached_policies": [],
        "path": "/",
        "tags": {},
    }


def _seed(storage: LocalFSStorage, principals: list[dict]) -> None:
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {"account_id": ACCOUNT, "principals": principals, "credential_report": []},
    )


def _normalize(tmp_path, principals: list[dict]):  # noqa: ANN001
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, principals)
    records = normalize(storage, RUN)
    return storage, {r.principal.rsplit("/", 1)[-1]: r for r in records}


# ---- 분류 규칙 ----
@pytest.mark.parametrize(
    ("name", "trust", "expected_kind", "expected_principals"),
    [
        # 서비스 실행 역할 — 사람이 로그인할 수 없다.
        ("lambda-fn", _trust(_allow({"Service": "lambda.amazonaws.com"})), "service",
         ["lambda.amazonaws.com"]),
        # 서비스 principal 이 `.amazonaws.com` 이 아닌 실측 사례(`*.aws.internal`).
        # 도메인 접미로 판정하면 여기서 틀린다 → Principal 의 **키**로 판정해야 한다.
        ("internal-svc", _trust(_allow({"Service": "orchestrator.alpo.aws.internal"})), "service",
         ["orchestrator.alpo.aws.internal"]),
        # SAML/OIDC 연합 → 사람이 IdP 로 로그인해 assume 한다.
        ("saml-role", _trust(_allow({"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"})),
         "human", [f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"]),
        # Principal.AWS 만 — 사람이든 자동화든 권한만 있으면 쓸 수 있어 신뢰정책으로 갈릴 수 없다.
        ("cross-acct", _trust(_allow({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})), "unknown",
         [f"arn:aws:iam::{ACCOUNT}:root"]),
        # 혼합(실측 1.3%) — 전부 "서비스 + 배포 계정 root" 패턴이라 서비스로 본다.
        ("cfn-custom-resource",
         _trust(_allow({"Service": "lambda.amazonaws.com", "AWS": f"arn:aws:iam::{ACCOUNT}:root"})),
         "service", [f"arn:aws:iam::{ACCOUNT}:root", "lambda.amazonaws.com"]),
        # 신뢰정책 미수집(빈 dict) → 추측하지 않고 unknown.
        ("no-trust-doc", None, "unknown", []),
    ],
)
def test_kind_from_trust_policy(tmp_path, name, trust, expected_kind, expected_principals) -> None:
    _, by_name = _normalize(tmp_path, [_role(name, trust)])
    rec = by_name[name]
    assert rec.principal_kind == expected_kind
    # trust_principals 는 배지 근거로 UI 에 그대로 노출되므로 정렬(결정론)까지 확인.
    assert rec.trust_principals == expected_principals


def test_iam_user_is_human(tmp_path) -> None:
    """IAM 사용자는 신뢰정책이 없다(자기 자격으로 직접 로그인) → identity_type 으로 즉시 human."""
    _, by_name = _normalize(tmp_path, [_user("alice")])
    assert by_name["alice"].principal_kind == "human"
    assert by_name["alice"].trust_principals == []


def test_deny_statement_does_not_grant_trust(tmp_path) -> None:
    """Deny 는 신뢰를 부여하지 않는다 — Deny 만 있는 신뢰정책은 서비스로 분류되면 안 된다."""
    trust = {"Statement": [{"Effect": "Deny", "Principal": {"Service": "lambda.amazonaws.com"}}]}
    _, by_name = _normalize(tmp_path, [_role("deny-only", trust)])
    assert by_name["deny-only"].principal_kind == "unknown"
    assert by_name["deny-only"].trust_principals == []


def test_principal_as_bare_string(tmp_path) -> None:
    """`Principal: "*"` 처럼 dict 가 아닌 문자열 형태도 크래시 없이 AWS 신뢰로 처리."""
    _, by_name = _normalize(tmp_path, [_role("wide-open", _trust(_allow("*")))])
    assert by_name["wide-open"].principal_kind == "unknown"
    assert by_name["wide-open"].trust_principals == ["*"]


def test_tags_preserved(tmp_path) -> None:
    """태그는 같은 응답에 이미 있다 — 소유자 귀속 표시용으로 보존한다(분류 입력은 아님)."""
    _, by_name = _normalize(tmp_path, [_role("tagged", None, tags={"Team": "data", "Env": "prod"})])
    assert by_name["tagged"].tags == {"Team": "data", "Env": "prod"}


# ---- M5: persona 군집 분리 ----
def _catalog_members(storage, *, exclude: bool, patterns: list[str] | None = None) -> list[str]:  # noqa: ANN001
    records = storage.read_normalized()
    for r in records:
        r.used_actions = [UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")]
    storage.write_normalized(records)
    catalog = build_catalog(
        storage,
        RUN,
        CatalogConfig(
            min_members_for_persona=1,
            exclude_service_roles=exclude,
            exclude_principal_patterns=[] if patterns is None else patterns,
        ),
    )
    return [m.rsplit("/", 1)[-1] for e in catalog for m in e.members]


def test_service_role_excluded_from_persona_but_unknown_kept(tmp_path) -> None:
    """서비스 역할은 persona 멤버에서 빠지고, `unknown`·사람은 남는다.

    unknown 을 함께 버리지 않는 것이 핵심이다 — 신뢰정책만으로 갈릴 수 없는 역할을 추측으로
    제외하면 사람이 실제로 쓰는 역할이 조용히 사라진다.
    """
    storage, _ = _normalize(
        tmp_path,
        [
            _role("lambda-fn", _trust(_allow({"Service": "lambda.amazonaws.com"}))),
            _role("cross-acct", _trust(_allow({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}))),
            _user("alice"),
        ],
    )
    members = _catalog_members(storage, exclude=True)
    assert "lambda-fn" not in members, "서비스 실행 역할이 persona 멤버로 남으면 안 됨"
    assert "cross-acct" in members, "판별 불가(unknown)를 추측으로 버리면 안 됨"
    assert "alice" in members


def test_exclusion_is_config_gated(tmp_path) -> None:
    """대조군: exclude_service_roles=false 면 서비스 역할이 그대로 멤버로 남는다.

    위 테스트가 '실패할 수 없는 어서션'이 아님을 증명한다 — 플래그를 끄면 반대 결과가 나와야 한다.
    """
    storage, _ = _normalize(
        tmp_path, [_role("lambda-fn", _trust(_allow({"Service": "lambda.amazonaws.com"})))]
    )
    assert "lambda-fn" in _catalog_members(storage, exclude=False)


# ---- M5: IaC 배포 역할 이름 패턴 제외 ----
# CDK bootstrap 배포 역할은 신뢰정책이 `Principal.AWS`(배포 계정 root)뿐이라 principal_kind=unknown
# 으로 남아 서비스 역할 제외를 통과한다. 리전마다 3개씩 생겨 스스로 persona 를 만들어 버린다.
_CDK_TRUST = _trust(_allow({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}))


def test_default_patterns_exclude_cdk_bootstrap_roles(tmp_path) -> None:
    """기본 패턴만으로 CDK bootstrap 배포 역할 3종이 persona 멤버에서 빠져야 한다."""
    from lp2ps.config import CatalogConfig as _Cfg

    names = [
        "cdk-hnb659fds-deploy-role-111122223333-us-west-2",
        "cdk-hnb659fds-file-publishing-role-111122223333-us-west-2",
        "cdk-hnb659fds-lookup-role-111122223333-us-west-2",
    ]
    storage, _ = _normalize(tmp_path, [_role(n, _CDK_TRUST) for n in names] + [_user("alice")])
    members = _catalog_members(
        storage, exclude=True, patterns=_Cfg().exclude_principal_patterns
    )
    assert members == ["alice"], f"CDK 배포 역할이 persona 멤버로 남았다: {members}"


def test_pattern_exclusion_is_config_gated(tmp_path) -> None:
    """대조군: 패턴 목록이 비면 같은 역할이 그대로 멤버로 남는다(어서션이 실패할 수 있음을 증명)."""
    storage, _ = _normalize(
        tmp_path, [_role("cdk-hnb659fds-deploy-role-111122223333-us-west-2", _CDK_TRUST)]
    )
    assert _catalog_members(storage, exclude=True, patterns=[]) == [
        "cdk-hnb659fds-deploy-role-111122223333-us-west-2"
    ]


def test_pattern_matching_is_case_sensitive(tmp_path) -> None:
    """대소문자를 구분해야 한다 — `fnmatch` 는 macOS 에서 무시하고 Linux 에서 구분해 로컬과
    Lambda 결과가 갈린다(불변식 ② 위반). 대문자 이름은 소문자 패턴에 걸리지 않아야 한다.
    """
    storage, _ = _normalize(tmp_path, [_role("CDK-HNB659FDS-DEPLOY-ROLE-X", _CDK_TRUST)])
    assert _catalog_members(storage, exclude=True, patterns=["cdk-*-deploy-role-*"]) == [
        "CDK-HNB659FDS-DEPLOY-ROLE-X"
    ]


def test_pattern_matches_full_arn(tmp_path) -> None:
    """경로(path)까지 스코프하고 싶은 고객을 위해 전체 ARN 대조도 지원한다."""
    storage, _ = _normalize(tmp_path, [_role("deployer", _CDK_TRUST), _user("alice")])
    members = _catalog_members(storage, exclude=True, patterns=["arn:aws:iam::*:role/deployer"])
    assert members == ["alice"]


def test_pattern_exclusion_does_not_erase_cleanup_items(tmp_path) -> None:
    """패턴 제외도 조치 필요 항목을 지우면 안 된다 — 미사용 배포 역할은 여전히 정리 대상이다."""
    from lp2ps.config import Config
    from lp2ps.m6_reporter import _cleanup_items

    _, by_name = _normalize(
        tmp_path, [_role("cdk-hnb659fds-deploy-role-111122223333-us-west-2", _CDK_TRUST)]
    )
    rec = by_name["cdk-hnb659fds-deploy-role-111122223333-us-west-2"]
    rec.used_actions = []
    cfg = Config.model_validate(
        {"customer": "test", "region": "us-west-2", "cross_account": False, "accounts": ["self"]}
    )
    items = _cleanup_items([rec], cfg)
    assert any(i.type == "unused_role" and i.principal == rec.principal for i in items)


def test_exclusion_does_not_erase_cleanup_items(tmp_path) -> None:
    """persona 제외가 조치 항목까지 지우면 안 된다 — 미사용 서비스 역할도 정리 대상이다."""
    from lp2ps.config import Config
    from lp2ps.m6_reporter import _cleanup_items

    storage, by_name = _normalize(
        tmp_path, [_role("lambda-fn", _trust(_allow({"Service": "lambda.amazonaws.com"})))]
    )
    rec = by_name["lambda-fn"]
    assert rec.principal_kind == "service"
    rec.used_actions = []  # 미사용 상태
    cfg = Config.model_validate(
        {"customer": "test", "region": "us-west-2", "cross_account": False, "accounts": ["self"]}
    )
    items = _cleanup_items([rec], cfg)
    assert any(i.type == "unused_role" and i.principal == rec.principal for i in items)
