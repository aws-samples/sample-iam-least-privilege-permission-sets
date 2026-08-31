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


def test_prefix_wildcard_satisfies_rules(tmp_path):
    """접두 와일드카드('iam:Create*')도 규칙을 만족시켜야 한다.

    관리형 정책 문서를 수집하기 시작한 뒤 실제로 들어오는 모양이다(AWS 관리형 정책이 서비스 전체
    와일드카드보다 접두 와일드카드를 훨씬 많이 쓴다). 서비스 와일드카드만 확장하면 이런 정책을
    들고 있는 principal 의 상승경로가 0으로 보인다 — 조용한 과소 탐지.
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:Create*", "iam:Attach*"])])
    vias = {p.via for p in detect_escalations(st, RUN)[0].escalation_paths}
    assert "iam:CreateRole + AttachRolePolicy" in vias
    assert "iam:AttachRolePolicy (자기 역할에 정책 부착)" in vias


def test_wildcard_matching_is_case_insensitive(tmp_path):
    """IAM 은 action 매칭에서 대소문자를 구분하지 않는다 — 정책에 소문자로 써도 hit."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:createrole", "iam:attachrolepolicy"])])
    vias = {p.via for p in detect_escalations(st, RUN)[0].escalation_paths}
    assert "iam:CreateRole + AttachRolePolicy" in vias


def test_single_char_wildcard_matches_one_char(tmp_path):
    """'?' 는 1자 매칭이다 — 0자·2자에는 걸리지 않아야 한다(대조군 포함)."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:CreatePolicyVersio?"])])
    vias = {p.via for p in detect_escalations(st, RUN)[0].escalation_paths}
    assert "iam:CreatePolicyVersion (정책 재작성)" in vias

    # 대조: '?' 는 0자를 매칭하지 않는다 → 'iam:CreatePolicyVersion?' 는 hit 하면 안 된다.
    st.write_normalized([_rec(["iam:CreatePolicyVersion?"])])
    assert detect_escalations(st, RUN)[0].escalation_paths == []


def test_character_class_is_not_a_wildcard(tmp_path):
    """대조군 — IAM 문법에 '[seq]' 문자클래스는 없다. fnmatch 로 매칭하면 여기서 오탐이 난다.

    이 테스트가 없으면 `fnmatch` 로 되돌려도 다른 테스트가 전부 통과한다. 단 패턴에 `*`/`?` 가
    **함께 있어야** 판별력이 있다 — 둘 중 하나도 없는 action 은 와일드카드 매처를 거치지 않고
    정확 일치 집합으로 가므로, 구현을 fnmatch 로 바꿔도 결과가 같다(실측으로 확인했다).
    """
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:[CD]reatePolicyVersion*"])])
    assert detect_escalations(st, RUN)[0].escalation_paths == [], \
        "'[CD]' 는 리터럴이다 — 와일드카드로 해석하면 없는 권한을 있다고 주장한다"


def test_unrelated_prefix_wildcard_does_not_hit(tmp_path):
    """대조군 — 읽기 계열 접두 와일드카드는 어떤 상승 규칙도 만족시키지 않는다."""
    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(["iam:Get*", "iam:List*", "s3:*"])])
    assert detect_escalations(st, RUN)[0].escalation_paths == []


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
