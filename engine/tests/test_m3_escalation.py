"""M3 Escalation — 규칙 기반 상승경로 탐지."""

from __future__ import annotations

import json

from lp2ps.m3_escalation import detect_escalations
from lp2ps.models import PrincipalRecord
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-x", customer="test", started_at="2026-07-15T00:00:00Z")


def _rec(granted, principal="arn:aws:iam::111122223333:role/r") -> PrincipalRecord:
    return PrincipalRecord(account_id="111122223333", principal=principal,
                           identity_type="role", granted_actions=granted, run_id="run-x")


def test_detects_create_role_attach(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:CreateRole", "iam:AttachRolePolicy", "s3:GetObject"])])
    out = detect_escalations(st, RUN)
    vias = {p.via for p in out[0].escalation_paths}
    assert "iam:CreateRole + AttachRolePolicy" in vias
    assert "iam:AttachRolePolicy (자기 역할에 정책 부착)" in vias
    assert all(p.mitre.startswith("TA") for p in out[0].escalation_paths)


def test_wildcard_satisfies_rules(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:*"])])  # iam 와일드카드 → iam 기반 규칙 다수 hit
    out = detect_escalations(st, RUN)
    assert len(out[0].escalation_paths) >= 3


def test_no_escalation_for_readonly(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["s3:GetObject", "ec2:DescribeInstances"])])
    out = detect_escalations(st, RUN)
    assert out[0].escalation_paths == []


def test_status_file_records_rule_mode(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:CreateRole", "iam:AttachRolePolicy"])])
    detect_escalations(st, RUN)
    status = json.loads(st.read_bytes("escalation_status.json").decode())
    assert status["mode"] == "rule_based"
    assert status["principals_with_escalation"] == 1


def test_deterministic_path_order(tmp_path):
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:*", "lambda:CreateFunction", "iam:PassRole"])])
    a = detect_escalations(st, RUN)
    paths1 = [(p.via, p.to) for p in a[0].escalation_paths]
    b = detect_escalations(st, RUN)
    paths2 = [(p.via, p.to) for p in b[0].escalation_paths]
    assert paths1 == paths2 == sorted(paths1)
