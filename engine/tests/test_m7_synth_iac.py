"""M7 Policy Synth + IaC Emitter — 정책 합성·HCL 생성·파싱."""

from __future__ import annotations

import io
import json

import hcl2

from lp2ps.config import Config
from lp2ps.m5_catalog import build_catalog
from lp2ps.m7_iac_emitter import emit_iac
from lp2ps.m7_policy_synth import synth_policies
from lp2ps.models import PrincipalRecord, UsedAction
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-15T00:00:00Z")


def _cfg() -> Config:
    return Config.model_validate({"customer": "test", "region": "us-west-2",
                                  "cross_account": False, "accounts": ["self"]})


def _seed_catalog(st) -> None:
    recs = [
        PrincipalRecord(account_id="111122223333", principal="arn:aws:iam::111122223333:role/a",
                        identity_type="role", source=["access_advisor"],
                        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z", count_90d=5),
                                      UsedAction(action="glue:StartJobRun", last_used="2026-07-10T00:00:00Z", count_90d=2)],
                        run_id="run-x"),
    ]
    st.write_normalized(recs)
    build_catalog(st, RUN, _cfg().catalog)


def test_policy_has_used_actions_and_source(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    policies = synth_policies(st, RUN)
    assert len(policies) == 1
    doc = next(iter(policies.values()))
    stmt = doc["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert set(stmt["Action"]) == {"s3:GetObject", "glue:StartJobRun"}
    assert doc["_lp2ps"]["synthesis_source"] in ("access_analyzer", "fallback_used_actions")


def test_excluded_action_not_in_policy(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    # catalog 에서 한 action 을 included=false 로 토글.
    cat = json.loads(st.read_bytes("catalog.json").decode())
    cat[0]["actions"][0]["included"] = False
    excluded = cat[0]["actions"][0]["action"]
    st.write_json("catalog.json", cat)

    policies = synth_policies(st, RUN)
    doc = next(iter(policies.values()))
    assert excluded not in doc["Statement"][0]["Action"]


def test_iac_parses_and_has_permission_sets(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    synth_policies(st, RUN)
    outputs = emit_iac(st, RUN, _cfg())

    # 3개 파일 생성.
    assert set(k.split("/")[-1] for k in outputs) == {
        "providers.tf", "permission_sets.tf", "account_assignments.tf"
    }
    # permission_sets.tf 는 hcl2 로 파싱되고 permission set resource 를 포함.
    ps_hcl = outputs["iac/permission_sets.tf"]
    parsed = hcl2.load(io.StringIO(ps_hcl))
    # hcl2 버전에 따라 resource-type 키에 따옴표가 남을 수 있어 정규화.
    resource_types = {list(r.keys())[0].strip('"') for r in parsed.get("resource", [])}
    assert "aws_ssoadmin_permission_set" in resource_types
    assert "aws_ssoadmin_permission_set_inline_policy" in resource_types


def test_account_assignments_are_commented_out(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    synth_policies(st, RUN)
    outputs = emit_iac(st, RUN, _cfg())
    aa = outputs["iac/account_assignments.tf"]
    # 불변식 ①: account assignment 은 활성 resource 로 생성하지 않는다(주석 골격만).
    parsed = hcl2.load(io.StringIO(aa))
    assert parsed.get("resource", []) == []
    assert "aws_ssoadmin_account_assignment" in aa  # 주석 안엔 존재(참고용)


def test_empty_policy_persona_skipped_in_iac(tmp_path):
    """included action 이 0 인 persona 는 PS 를 생성하지 않는다(#5, 빈 Statement 방지)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    # catalog 의 모든 action 을 included=false 로 → 빈 정책.
    cat = json.loads(st.read_bytes("catalog.json").decode())
    for a in cat[0]["actions"]:
        a["included"] = False
    st.write_json("catalog.json", cat)

    synth_policies(st, RUN)
    outputs = emit_iac(st, RUN, _cfg())
    parsed = hcl2.load(io.StringIO(outputs["iac/permission_sets.tf"]))
    # 생성된 permission set resource 가 없어야(빈 정책 persona 제외).
    assert parsed.get("resource", []) == []


def test_iac_deterministic(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    _seed_catalog(st)
    synth_policies(st, RUN)
    a = emit_iac(st, RUN, _cfg())
    b = emit_iac(st, RUN, _cfg())
    assert a == b
