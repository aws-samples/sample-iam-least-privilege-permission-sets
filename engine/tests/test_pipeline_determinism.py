"""전체 파이프라인 결정론 + AI-off 완전동작 (불변식 ②③).

moto self-mode 로 collect→run 을 두 번 돌려 핵심 산출물 해시가 동일한지 검증한다.
AI 하네스가 off(기본)일 때 lp2ps.ai import 없이 완주하는지도 확인한다.
"""

from __future__ import annotations

import hashlib

import boto3
import pytest
from moto import mock_aws

from lp2ps.config import Config
from lp2ps.pipeline import run_full
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")

# 결정론 대상 산출물(run.json 은 wall-clock 없는 값만 담지만 started_at 고정이라 포함 가능).
_ARTIFACTS = [
    "normalized.parquet", "catalog.json", "risk_audit.jsonl", "escalation_status.json",
    "cleanup_backlog.csv", "exec_summary.json", "iac/permission_sets.tf",
    "iac/providers.tf", "iac/account_assignments.tf", "metrics_timeseries.json",
]


def _cfg() -> Config:
    return Config.model_validate({"customer": "test", "region": "us-west-2",
                                  "cross_account": False, "accounts": ["self"]})


def _seed_iam():
    iam = boto3.client("iam", region_name="us-west-2")
    iam.create_role(RoleName="data-eng", AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}')
    iam.put_role_policy(RoleName="data-eng", PolicyName="p",
                        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:DeleteObject","iam:CreateRole","iam:AttachRolePolicy"],"Resource":"*"}]}')
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")


def _hashes(storage) -> dict:
    out = {}
    for rel in _ARTIFACTS:
        if storage.exists(rel):
            out[rel] = hashlib.sha256(storage.read_bytes(rel)).hexdigest()
    return out


@mock_aws
def test_full_run_completes_ai_off(tmp_path):
    _seed_iam()
    st = LocalFSStorage(tmp_path, "test", "run-fixed")
    result = run_full(st, RUN, _cfg())
    assert result["principals"] >= 1
    # 핵심 산출물 존재.
    for rel in ("normalized.parquet", "catalog.json", "cleanup_backlog.csv",
                "iac/permission_sets.tf", "run.json", "report.html"):
        assert st.exists(rel), f"{rel} 산출 안 됨"


@mock_aws
def test_two_runs_identical_hashes(tmp_path):
    """같은 입력(moto 고정) → 두 번 run 의 산출물 해시 동일(불변식 ②)."""
    _seed_iam()
    st1 = LocalFSStorage(tmp_path / "a", "test", "run-fixed")
    st2 = LocalFSStorage(tmp_path / "b", "test", "run-fixed")
    run_full(st1, RUN, _cfg())
    run_full(st2, RUN, _cfg())
    h1, h2 = _hashes(st1), _hashes(st2)
    assert h1 == h2, f"결정론 위반: {[k for k in h1 if h1.get(k) != h2.get(k)]}"
    assert "normalized.parquet" in h1  # 실제로 뭔가 해시됨


def test_core_does_not_import_ai():
    """결정론 코어 모듈이 lp2ps.ai 를 import 하지 않는지(불변식 ③, 코드 레벨 경계)."""
    import ast
    import pathlib

    core = ["m1_collector", "m2_normalizer", "m3_escalation", "m4_risk_scorer",
            "m5_catalog", "m7_policy_synth", "m7_iac_emitter", "m6_reporter",
            "snapshot", "pipeline", "storage", "session", "awsguard", "audit"]
    root = pathlib.Path(__file__).resolve().parents[1] / "lp2ps"
    offenders = []
    for mod in core:
        src = (root / f"{mod}.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("lp2ps.ai"):
                offenders.append(mod)
            if isinstance(node, ast.Import):
                for n in node.names:
                    if n.name.startswith("lp2ps.ai"):
                        offenders.append(mod)
    assert not offenders, f"결정론 코어가 lp2ps.ai 를 import 함: {offenders}"
