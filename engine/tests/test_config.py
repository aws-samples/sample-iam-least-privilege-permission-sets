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
