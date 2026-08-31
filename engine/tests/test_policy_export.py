"""policy_export — 승인 정책의 반영 산출물(IAM 정책/역할/JSON/PS).

핵심 관심사:
- IdC 미사용 고객에게 **apply 할 수 있는 물건**이 나오는가(PS 만 있던 시절의 공백).
- 생성된 HCL 이 실제로 파싱되는가(문자열 조립이라 문법 오류가 조용히 나갈 수 있다).
- 불변식 ②(결정론): 같은 입력 → 바이트 동일.
- 불변식 ④: 산출물에 계정ID·ARN 리터럴이 없다(신뢰정책 주체는 변수).
"""

from __future__ import annotations

import io
import json

import hcl2
import pytest

from lp2ps.policy_export import (
    build_artifacts,
    build_bulk_iam_policies,
    iam_name,
    tf_name,
)

DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "glue:StartJobRun"], "Resource": "*"}
    ],
    # 메타 키 — 산출물에 새어나가면 apply 시 IAM 이 거부한다.
    "_lp2ps": {"synthesis_source": "access_analyzer"},
}
EMPTY_DOC = {"Version": "2012-10-17", "Statement": []}


def _parse(hcl: str) -> dict:
    return hcl2.load(io.StringIO(hcl))


def _resource_types(hcl: str) -> set[str]:
    # hcl2 버전에 따라 resource-type 키에 따옴표가 남을 수 있어 정규화(test_m7 과 동일).
    return {list(r.keys())[0].strip('"') for r in _parse(hcl).get("resource", [])}


# ---- 구성: 어떤 산출물이 나오는가 ----
def test_default_includes_all_four_targets():
    arts = build_artifacts("DataEngineer", "데이터 엔지니어", DOC)
    assert [a.target for a in arts] == [
        "iam_policy_tf", "policy_json", "iam_role_tf", "permission_set_tf"
    ]


def test_no_identity_center_omits_permission_set():
    """IdC 인스턴스가 없는 고객에게 apply 불가한 PS .tf 를 주지 않는다."""
    arts = build_artifacts("DataEngineer", "d", DOC, uses_identity_center=False)
    assert "permission_set_tf" not in {a.target for a in arts}
    # 그래도 반영할 물건은 남아야 한다(이게 이 기능의 존재 이유).
    assert {"iam_policy_tf", "iam_role_tf", "policy_json"} == {a.target for a in arts}


def test_filenames_unique_per_target():
    arts = build_artifacts("DataEngineer", "d", DOC)
    names = [a.filename for a in arts]
    assert len(set(names)) == len(names)


def test_every_artifact_carries_resource_star_note():
    """Resource "*" 경고는 파일을 열지 않고 다운로드만 하는 사람에게도 보여야 한다."""
    for a in build_artifacts("DataEngineer", "d", DOC):
        assert any('Resource 는 "*"' in n for n in a.notes), a.target


def test_role_artifact_warns_about_trust_policy():
    role = next(a for a in build_artifacts("P", "d", DOC) if a.target == "iam_role_tf")
    assert any("신뢰정책" in n for n in role.notes)


# ---- 생성물이 유효한가 ----
@pytest.mark.parametrize("target", ["iam_policy_tf", "iam_role_tf", "permission_set_tf"])
def test_hcl_parses(target):
    art = next(a for a in build_artifacts("DataEngineer", "데이터", DOC) if a.target == target)
    assert _parse(art.content)  # 문법 오류면 여기서 예외


def test_iam_policy_resources():
    art = next(a for a in build_artifacts("DataEngineer", "d", DOC) if a.target == "iam_policy_tf")
    assert _resource_types(art.content) == {"aws_iam_policy"}  # attach 는 하지 않는다


def test_iam_role_uses_inline_policy_not_managed():
    """역할 산출물이 관리형 정책을 만들면 IAM 정책 산출물과 이름이 충돌한다(EntityAlreadyExists)."""
    art = next(a for a in build_artifacts("DataEngineer", "d", DOC) if a.target == "iam_role_tf")
    assert _resource_types(art.content) == {"aws_iam_role", "aws_iam_role_policy"}


def test_iam_role_trust_principals_is_a_variable():
    """불변식 ④: 신뢰 주체(계정ID·ARN)를 리터럴로 박지 않는다."""
    art = next(a for a in build_artifacts("DataEngineer", "d", DOC) if a.target == "iam_role_tf")
    variables = {list(v.keys())[0].strip('"') for v in _parse(art.content).get("variable", [])}
    assert "dataengineer_trusted_principals" in variables
    assert "arn:aws:iam::1" not in art.content  # 예시 주석의 <계정ID> 플레이스홀더만 존재


def test_permission_set_uses_configured_session_duration():
    art = next(
        a for a in build_artifacts("P", "d", DOC, session_duration="PT4H")
        if a.target == "permission_set_tf"
    )
    assert 'session_duration = "PT4H"' in art.content


# ---- 메타 키 제거 ----
def test_meta_keys_stripped_from_all_artifacts():
    for a in build_artifacts("P", "d", DOC):
        assert "_lp2ps" not in a.content, a.target


def test_policy_json_is_the_policy_document():
    art = next(a for a in build_artifacts("P", "d", DOC) if a.target == "policy_json")
    assert json.loads(art.content) == {k: v for k, v in DOC.items() if k != "_lp2ps"}


# ---- 결정론 ----
def test_deterministic():
    a = build_artifacts("P", "d", DOC)
    b = build_artifacts("P", "d", DOC)
    assert [x.model_dump() for x in a] == [x.model_dump() for x in b]


def test_key_order_does_not_change_output():
    """dict 입력 순서가 달라도 바이트 동일(안정 정렬)."""
    reordered = {"_lp2ps": DOC["_lp2ps"], "Statement": DOC["Statement"], "Version": DOC["Version"]}
    assert [x.content for x in build_artifacts("P", "d", reordered)] == [
        x.content for x in build_artifacts("P", "d", DOC)
    ]


# ---- 이름 정제 ----
def test_tf_name_alnum_lower():
    assert tf_name("Data-Engineer.v2") == "data_engineer_v2"
    assert tf_name("---") == "persona"  # 전부 정제되면 폴백


def test_iam_name_replaces_illegal_chars():
    # IAM 이름 허용 문자는 [\w+=,.@-] — 공백·슬래시·한글은 '-' 로. 양끝 '-' 는 정리한다.
    assert iam_name("Data Engineer/한글") == "Data-Engineer-least-privilege"
    assert iam_name("A B") == "A-B-least-privilege"


def test_iam_name_length_capped():
    assert len(iam_name("A" * 200)) == 128


# ---- 일괄 파일(M7) ----
def test_bulk_contains_every_persona():
    hcl = build_bulk_iam_policies([("Alpha", DOC), ("Beta", DOC)])
    assert _parse(hcl)
    assert "alpha" in hcl and "beta" in hcl


def test_bulk_skips_empty_statement_persona():
    """빈 정책은 apply 시 IAM 이 거부하므로 리소스를 만들지 않는다."""
    hcl = build_bulk_iam_policies([("Alpha", DOC), ("Beta", EMPTY_DOC)])
    # resource 항목 = {"aws_iam_policy": {"<로컬명>": {...}}}
    names = {
        k.strip('"')
        for r in _parse(hcl).get("resource", [])
        for body in r.values()
        for k in body
    }
    assert names == {"alpha"}


def test_bulk_all_empty_is_parseable_and_says_so():
    hcl = build_bulk_iam_policies([("Beta", EMPTY_DOC)])
    assert _parse(hcl).get("resource", []) == []
    assert "반영할 정책이 없습니다" in hcl


def test_bulk_matches_single_artifact_body():
    """화면에서 개별 다운로드한 정책과 run 산출물의 정책이 같은 코드로 생성된다(드리프트 방지)."""
    single = next(a for a in build_artifacts("Alpha", "d", DOC) if a.target == "iam_policy_tf")
    bulk = build_bulk_iam_policies([("Alpha", DOC)])
    body = single.content.split("resource ", 1)[1]
    assert body in bulk
