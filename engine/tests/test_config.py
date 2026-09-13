"""config 로더 테스트 (불변식 ④: 고객 값은 config 에만)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lp2ps.config import Config, load_config

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def test_load_example() -> None:
    cfg = load_config(CONFIG_DIR / "example.yaml")
    assert cfg.customer == "example"
    assert cfg.region == "us-west-2"
    assert cfg.cross_account is True  # 멀티계정 템플릿


def test_load_self() -> None:
    # self.yaml 은 멀티계정 검증 구성(관제 + 멤버)로 전환됨.
    cfg = load_config(CONFIG_DIR / "self.yaml")
    assert cfg.cross_account is True
    assert "111122223333" in cfg.accounts and "444455556666" in cfg.accounts
    assert cfg.readonly_role_name == "lp2ps-readonly"


# ---- 수집 예산(불변식 ④) ----
#
# LookupEvents 페이지 상한은 고객의 계정 수·활동량에 달렸다. 코드 상수로 두면 계정이 3개인
# 고객과 200개인 고객이 같은 예산으로 15분 Lambda 를 나눠 쓴다.


def test_collection_budget_defaults_and_is_overridable() -> None:
    assert Config.model_validate({"customer": "c"}).collection.cloudtrail_max_pages == 200
    # 계정이 많은 템플릿은 더 낮은/조정된 예산을 명시한다(예시 자체가 근거 문서다).
    assert load_config(CONFIG_DIR / "multi.yaml").collection.cloudtrail_max_pages == 300


def test_collection_budget_rejects_zero() -> None:
    """0 이면 CloudTrail 을 아예 안 읽는데 산출물은 '수집됨'으로 보인다 → 조용한 오해를 막는다."""
    with pytest.raises(ValueError):
        Config.model_validate({"customer": "c", "collection": {"cloudtrail_max_pages": 0}})


def test_single_account_requires_self_accounts() -> None:
    # cross_account=false(기본) 인데 실제 계정 ID → 거부.
    with pytest.raises(ValueError):
        Config.model_validate({"customer": "x", "cross_account": False, "accounts": ["111122223333"]})


def test_cross_account_rejects_self_literal() -> None:
    # cross_account=true 인데 "self" → 거부(실제 계정 ID 필요).
    with pytest.raises(ValueError):
        Config.model_validate(
            {"customer": "x", "cross_account": True, "accounts": ["self"],
             "readonly_role_name": "lp2ps-readonly"})


def test_cross_account_requires_readonly_role() -> None:
    with pytest.raises(ValueError):
        Config.model_validate(
            {"customer": "x", "cross_account": True, "accounts": ["111122223333"]})


def test_cross_account_valid() -> None:
    cfg = Config.model_validate(
        {"customer": "x", "cross_account": True, "accounts": ["111122223333"],
         "readonly_role_name": "lp2ps-readonly"})
    assert cfg.cross_account is True and cfg.accounts == ["111122223333"]


def test_default_is_single_account() -> None:
    # 아무것도 안 주면 cross_account=false, accounts=["self"].
    cfg = Config.model_validate({"customer": "x"})
    assert cfg.cross_account is False and cfg.accounts == ["self"]


def test_empty_accounts_rejected() -> None:
    with pytest.raises(ValueError):
        Config.model_validate({"customer": "x", "accounts": []})


# ---- 테넌트 그룹(R5) ----
#
# 이 도구는 여러 고객의 계정을 한 배포에서 관리하는 형태로 쓰인다. 그 경우 `config.accounts`
# 전체를 "우리" 로 볼 수 없다 — A 고객 역할이 B 고객 계정을 신뢰하면 안전이 아니라 경계 위반이다.


def test_tenant_group_defaults_for_plain_string_list() -> None:
    """하위호환 — 문자열 목록은 그대로 통과하고 전 계정이 기본 그룹이 된다.

    이게 깨지면 기존 고객 config 전부가 배포 시점에 실패한다.
    """
    cfg = Config.model_validate(
        {"customer": "x", "cross_account": True,
         "accounts": ["111122223333", "444455556666"],
         "readonly_role_name": "lp2ps-readonly"})
    assert cfg.accounts == ["111122223333", "444455556666"]
    assert cfg.tenant_group_of("111122223333") == "default"
    assert cfg.tenant_group_of("444455556666") == "default"


def test_tenant_group_dict_form_normalizes_to_id_list() -> None:
    """`{id, group}` 형태도 계정 ID 목록으로 정규화된다 → 수집 루프는 손대지 않는다."""
    cfg = Config.model_validate(
        {"customer": "x", "cross_account": True,
         "accounts": [
             {"id": "111122223333", "group": "customerA"},
             {"id": "444455556666", "group": "customerA"},
             {"id": "777788889999", "group": "customerB"},
         ],
         "readonly_role_name": "lp2ps-readonly"})
    assert cfg.accounts == ["111122223333", "444455556666", "777788889999"]
    assert cfg.tenant_group_of("777788889999") == "customerB"
    # 그룹이 다른 두 계정이 같은 그룹으로 뭉개지지 않아야 한다(R8 격리의 전제).
    assert cfg.tenant_group_of("111122223333") != cfg.tenant_group_of("777788889999")


def test_tenant_group_unknown_account_is_empty_not_default() -> None:
    """대조군 — 수집 범위 밖 계정은 "" (모른다) 다.

    기본 그룹을 돌려주면 신뢰정책이 가리키는 **남의 계정**까지 internal 로 판정돼 R5 의
    fail-safe 가 뒤집힌다("모르면 보수적으로" → "모르면 우리 것").
    """
    cfg = Config.model_validate(
        {"customer": "x", "cross_account": True,
         "accounts": [{"id": "111122223333", "group": "customerA"}],
         "readonly_role_name": "lp2ps-readonly"})
    assert cfg.tenant_group_of("999999999999") == ""


def test_tenant_group_rejects_typo_key_and_bad_name() -> None:
    """오탈자 키를 조용히 무시하면 그룹 선언이 누락된 채 전 계정이 한 그룹으로 합쳐진다."""
    with pytest.raises(ValueError, match="알 수 없는 키"):
        Config.model_validate(
            {"customer": "x", "cross_account": True,
             "accounts": [{"id": "111122223333", "gropu": "customerA"}],
             "readonly_role_name": "lp2ps-readonly"})
    # 그룹 이름은 산출물 파일명·경로가 된다 → 경로 조작 문자 거부.
    with pytest.raises(ValueError, match=r"group 형식"):
        Config.model_validate(
            {"customer": "x", "cross_account": True,
             "accounts": [{"id": "111122223333", "group": "../etc"}],
             "readonly_role_name": "lp2ps-readonly"})


def test_tenant_group_conflicting_declaration_rejected() -> None:
    with pytest.raises(ValueError, match="서로 다른 그룹"):
        Config.model_validate(
            {"customer": "x", "cross_account": True,
             "accounts": [
                 {"id": "111122223333", "group": "customerA"},
                 {"id": "111122223333", "group": "customerB"},
             ],
             "readonly_role_name": "lp2ps-readonly"})


def test_account_groups_is_derived_not_user_supplied() -> None:
    """yaml 에 직접 쓴 `account_groups` 는 정규화가 덮어쓴다(파생값이 SSOT 가 아니다)."""
    cfg = Config.model_validate(
        {"customer": "x", "cross_account": True,
         "accounts": [{"id": "111122223333", "group": "customerA"}],
         "account_groups": {"999999999999": "spoofed"},
         "readonly_role_name": "lp2ps-readonly"})
    assert cfg.account_groups == {"111122223333": "customerA"}


# ---- 미사용 등급 경계(R2, 불변식 ④) ----


def test_unused_tier_defaults() -> None:
    rules = Config.model_validate({"customer": "x"}).risk_rules
    assert rules.unused_tier_days == [30, 60, 90]
    assert rules.unused_role_days == 90 and rules.new_principal_days == 30


def test_unused_tier_rejects_non_ascending() -> None:
    """오름차순이 아니면 도달 불가 등급이 생긴다(예: [60,30,90] → watch 가 없다)."""
    with pytest.raises(ValueError, match="오름차순"):
        Config.model_validate(
            {"customer": "x", "risk_rules": {"unused_tier_days": [60, 30, 90]}})
    with pytest.raises(ValueError, match="오름차순"):
        Config.model_validate(
            {"customer": "x", "risk_rules": {"unused_tier_days": [30, 30, 90]}})


def test_unused_tier_rejects_wrong_length_and_zero() -> None:
    with pytest.raises(ValueError, match="3개 값"):
        Config.model_validate({"customer": "x", "risk_rules": {"unused_tier_days": [30, 90]}})
    with pytest.raises(ValueError, match="1 이상"):
        Config.model_validate({"customer": "x", "risk_rules": {"unused_tier_days": [0, 60, 90]}})


def test_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        load_config(CONFIG_DIR / "nonexistent.yaml")


# ---- account/region 형식 검증 ----

def test_sec029_bad_account_rejected() -> None:
    with pytest.raises(ValueError, match="account 형식"):
        Config.model_validate(
            {"customer": "x", "cross_account": True, "accounts": ["12345"],  # 12자리 아님
             "readonly_role_name": "lp2ps-readonly"})


def test_sec029_account_injection_rejected() -> None:
    # ARN 인젝션 시도(숫자 12자리가 아닌 값) → 거부.
    with pytest.raises(ValueError, match="account 형식"):
        Config.model_validate(
            {"customer": "x", "cross_account": True,
             "accounts": ["111122223333", "*:role/admin"],
             "readonly_role_name": "lp2ps-readonly"})


def test_sec029_bad_region_rejected() -> None:
    with pytest.raises(ValueError, match="region 형식"):
        Config.model_validate({"customer": "x", "region": "not_a_region"})


def test_sec029_valid_region_forms() -> None:
    for r in ("us-west-2", "ap-northeast-2", "us-gov-east-1", "eu-central-1"):
        cfg = Config.model_validate({"customer": "x", "region": r})
        assert cfg.region == r


# ---- run_id 랜덤 접미사 ----

def test_sec011_run_id_has_random_suffix() -> None:
    from lp2ps.runctx import new_run_context

    r1 = new_run_context("cust", started_at="2026-07-21T00:00:00Z")
    r2 = new_run_context("cust", started_at="2026-07-21T00:00:00Z")
    # 같은 started_at 이라도 run_id 는 랜덤 접미사로 서로 달라야 한다(충돌 방지).
    assert r1.run_id != r2.run_id
    assert r1.run_id.startswith("run-20260721T000000Z-")
    # started_at 은 입력 그대로(불변식②: 유일 wall-clock).
    assert r1.started_at == "2026-07-21T00:00:00Z"
