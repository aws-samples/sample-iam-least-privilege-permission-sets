"""R1 — 사용 주체 판별(usage_subject) + R1-a 산출물 PII 부재.

배경: 신뢰정책만 보면 "누가 집을 수 **있나**" 밖에 알 수 없어, 사람이 실제로 쓰는 역할이 화면에서
전부 '판별 불가' 로 떴다(실측 141개 중 사람 판정 0건). CloudTrail 은 "실제로 누가 집었나" 를 이미
싣고 있었는데 수집 단계에서 버려졌다.

두 가지를 고정한다.
1. 7개 규칙 각각이 판정을 내리는지 + **대조군**(근거가 없으면 `none` 으로 남는지). 근거 부재를
   판정으로 꾸미면 안 된다 — MFA 표시 없음 ≠ 사람 아님, 이벤트 없음 ≠ 기계.
2. 판정의 가장 강한 근거(세션 이름)가 개인정보이므로 **산출물 전문에 원문이 없어야** 한다.
   S3 에 쓰인 다음에는 되돌릴 수 없다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from lp2ps.config import CatalogConfig
from lp2ps.m2_normalizer import normalize
from lp2ps.m5_catalog import build_catalog
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")
AS_OF = datetime(2026, 7, 15, tzinfo=timezone.utc)
ACCOUNT = "111122223333"
OTHER_ACCOUNT = "444455556666"

_INLINE = [
    {
        "name": "inline",
        "document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
    }
]


def _trust(principal) -> dict:  # noqa: ANN001
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}],
    }


def _role(name: str, trust: dict | None = None) -> dict:
    return {
        "principal": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "name": name,
        "identity_type": "role",
        "inline_policies": _INLINE,
        "attached_policies": [],
        "path": "/",
        "trust_policy": trust or {},
        "tags": {},
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


def _subject(
    name: str,
    *,
    kind: str = "role",
    mfa: bool = False,
    invoked_by: list[str] | None = None,
    shapes: list[str] | None = None,
    callers: list[str] | None = None,
) -> dict:
    """수집기(`_subject_rows`)가 내는 것과 동일한 모양의 주체 신호 행."""
    return {
        "principal": f"arn:aws:iam::{ACCOUNT}:{kind}/{name}",
        "mfa_seen": mfa,
        "invoked_by": sorted(invoked_by or []),
        "session_name_shapes": sorted(shapes or []),
        "assume_caller_kinds": sorted(callers or []),
    }


def _normalize(tmp_path, principals: list[dict], subjects: list[dict] | None = None):  # noqa: ANN001
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {"account_id": ACCOUNT, "principals": principals, "credential_report": []},
    )
    if subjects is not None:
        storage.write_raw(
            ACCOUNT,
            "cloudtrail",
            {"account_id": ACCOUNT, "mode": "lookup_events", "usage": [], "subjects": subjects,
             "truncated": False, "coverage_start": None, "window_days": 90, "max_pages": 200},
        )
    records = normalize(storage, RUN)
    return storage, {r.principal.rsplit("/", 1)[-1]: r for r in records}


# ---- 7개 규칙 각각 ----
@pytest.mark.parametrize(
    ("rule", "principals", "subjects", "expected"),
    [
        # 1. IAM 사용자 — 신뢰정책이 없고 자기 자격으로 직접 로그인한다.
        ("iam_user", [_user("alice")], None, ("human", "iam_user")),
        # 2. MFA 인증 표시 — 사람만 통과할 수 있는 관문이다.
        ("mfa_session", [_role("ops")], [_subject("ops", mfa=True)], ("human", "mfa_session")),
        # 3. 이 역할을 집은 호출자가 사람이었다(IdC 콘솔 세션).
        ("assume_caller_sso", [_role("ops")], [_subject("ops", callers=["sso"])],
         ("human", "assume_caller_human")),
        ("assume_caller_iam_user", [_role("ops")], [_subject("ops", callers=["iam_user"])],
         ("human", "assume_caller_human")),
        ("assume_caller_federated", [_role("ops")], [_subject("ops", callers=["federated"])],
         ("human", "assume_caller_human")),
        # 3-b. 세션 이름이 이메일 형태 — 자동화는 이메일을 세션명으로 쓰지 않는다.
        ("session_name_email", [_role("ops")], [_subject("ops", shapes=["email_like"])],
         ("human", "session_name_email")),
        # 3-b 대조군: `service_name` 은 사람의 사용자명도 같은 형태라 **판정하지 않는다**.
        ("session_name_service_is_not_evidence", [_role("ops")],
         [_subject("ops", shapes=["service_name"])], ("none", "events_without_subject_signal")),
        # 4. 신뢰정책이 IAM **사용자** ARN 을 직접 가리킨다.
        ("trust_iam_user", [_role("ops", _trust({"AWS": f"arn:aws:iam::{ACCOUNT}:user/alice"}))],
         None, ("human", "trust_iam_user")),
        # 5. 서비스가 이 역할로 호출했다.
        ("invoked_by", [_role("fn")], [_subject("fn", invoked_by=["lambda.amazonaws.com"])],
         ("machine", "invoked_by")),
        # 6. 세션 이름이 자동화 형식이다.
        ("session_account_id", [_role("fn")], [_subject("fn", shapes=["account_id_embedded"])],
         ("machine", "session_name_automation")),
        ("session_uuid", [_role("fn")], [_subject("fn", shapes=["uuid_suffix"])],
         ("machine", "session_name_automation")),
        # 7. 신뢰정책이 AWS 서비스를 가리킨다.
        ("trust_service", [_role("fn", _trust({"Service": "lambda.amazonaws.com"}))], None,
         ("machine", "trust_service")),
    ],
)
def test_each_rule_decides(tmp_path, rule, principals, subjects, expected) -> None:
    _, by_name = _normalize(tmp_path, principals, subjects)
    rec = next(iter(by_name.values()))
    assert (rec.usage_subject, rec.usage_subject_basis) == expected, rule


# ---- 대조군: 근거가 없으면 판정하지 않는다 ----
def test_no_evidence_stays_none_and_distinguishes_why(tmp_path) -> None:
    """근거 없음은 `none` 이고, "이벤트가 없었다" 와 "이벤트는 있었지만 못 갈랐다" 는 다른 사실이다.

    이 둘을 합치면 화면이 관측 범위 밖인 역할과 관측했지만 판정 못 한 역할을 같은 문장으로 설명한다.
    """
    # 신뢰정책은 Principal.AWS(계정 root)뿐 — 사람도 자동화도 쓸 수 있어 갈릴 수 없다.
    trust_root = _trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})
    _, by_name = _normalize(tmp_path, [_role("no-events", trust_root)], [])
    assert (by_name["no-events"].usage_subject, by_name["no-events"].usage_subject_basis) == (
        "none",
        "no_events",
    )

    _, by_name = _normalize(tmp_path, [_role("seen", trust_root)], [_subject("seen")])
    assert (by_name["seen"].usage_subject, by_name["seen"].usage_subject_basis) == (
        "none",
        "events_without_subject_signal",
    )


def test_mfa_absence_is_not_machine_evidence(tmp_path) -> None:
    """MFA 표시가 **없는 것**은 사람이 아니라는 근거가 못 된다(IdC 콘솔 세션도 없을 수 있다)."""
    _, by_name = _normalize(
        tmp_path,
        [_role("ops", _trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}))],
        [_subject("ops", mfa=False, callers=["role"])],
    )
    # 호출자가 일반 역할인 것도 근거가 아니다 — 역할이 역할을 집는 것은 양쪽 다 있다.
    assert by_name["ops"].usage_subject == "none"


def test_service_name_shape_is_not_machine_evidence(tmp_path) -> None:
    """`service_name` 형태 세션 이름은 근거가 아니다 — 사람의 SSO 사용자명도 그 형태다.

    이걸 기계 근거로 쓰면 사람이 쓰는 역할이 '기계' 로 오판되고, 그 역할은 persona(트랙①)에서
    빠져 사람용 최소권한 정책이 만들어지지 않는다.
    """
    _, by_name = _normalize(
        tmp_path,
        [_role("ops", _trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}))],
        [_subject("ops", shapes=["service_name"])],
    )
    assert by_name["ops"].usage_subject == "none"
    # 라벨 자체는 보존한다(판정에 쓰지 않을 뿐).
    assert by_name["ops"].session_name_shape == "service_name"


def test_human_evidence_beats_machine_evidence(tmp_path) -> None:
    """사람 근거가 기계 근거보다 우선한다(R1 우선순위 2 vs 5).

    서비스 실행 역할을 사람이 콘솔에서 디버깅용으로 집는 일이 있다. 그때 '기계' 로 확정하면
    그 역할이 persona 에서 빠져 실제 사람 접근이 표준화 대상에서 사라진다.
    """
    _, by_name = _normalize(
        tmp_path,
        [_role("shared", _trust({"Service": "lambda.amazonaws.com"}))],
        [_subject("shared", mfa=True, invoked_by=["lambda.amazonaws.com"])],
    )
    rec = by_name["shared"]
    assert (rec.usage_subject, rec.usage_subject_basis) == ("human", "mfa_session")
    # 신뢰정책 축은 그대로 남는다 — 두 값은 다른 사실이다("집을 수 있나" vs "실제로 집었나").
    assert rec.principal_kind == "service"


def test_session_shape_pick_is_deterministic(tmp_path) -> None:
    """여러 라벨이 관측되면 우선순위로 하나를 고른다(집합 순회 순서에 의존하면 불변식 ② 위반)."""
    _, by_name = _normalize(
        tmp_path,
        [_role("multi")],
        [_subject("multi", shapes=["other", "uuid_suffix", "email_like", "service_name"])],
    )
    assert by_name["multi"].session_name_shape == "email_like"


def test_missing_cloudtrail_subjects_key_does_not_guess(tmp_path) -> None:
    """구버전 raw(주체 신호 키 없음)에서도 동작하고, 없으면 추측하지 않는다."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {"account_id": ACCOUNT, "principals": [_role("ops")], "credential_report": []},
    )
    storage.write_raw(ACCOUNT, "cloudtrail", {"account_id": ACCOUNT, "usage": []})  # subjects 없음
    rec = normalize(storage, RUN)[0]
    assert (rec.usage_subject, rec.usage_subject_basis) == ("none", "no_events")


def test_assume_target_in_other_account_creates_no_record(tmp_path) -> None:
    """AssumeRole 대상이 수집 범위 밖 계정 역할이면 레코드를 만들지 않는다.

    호출자 신호가 있다는 이유로 레코드를 만들면 다른 계정의 역할이 이 계정 산출물에 나타난다.
    """
    foreign = {
        "principal": f"arn:aws:iam::{OTHER_ACCOUNT}:role/Foreign",
        "mfa_seen": False, "invoked_by": [], "session_name_shapes": [],
        "assume_caller_kinds": ["iam_user"],
    }
    _, by_name = _normalize(tmp_path, [_role("ops")], [foreign])
    assert "Foreign" not in by_name
    assert list(by_name) == ["ops"]


# ---- R1-a: 산출물 전문에 세션 이름 원문이 없어야 한다 ----
class _FakeCT:
    def __init__(self, events: list[dict]) -> None:
        self._events = events

    def lookup_events(self, **kwargs):  # noqa: ANN003
        return {"Events": self._events}


def test_pipeline_artifacts_contain_no_raw_session_name(tmp_path) -> None:
    """수집기 → 정규화 → 카탈로그 전 경로의 산출물 파일 전문에 이메일·세션 원문이 없어야 한다.

    사람 판정의 근거가 개인정보라 판정에만 쓰고 원문은 버린다. 수집기 단위 테스트만으로는 부족하다 —
    하류가 다시 원문을 실을 수 있는 경로(raw JSON 그대로 저장)가 있기 때문이다.
    """
    from lp2ps.collectors.cloudtrail import _lookup_events

    role_arn = f"arn:aws:iam::{ACCOUNT}:role/AWSReservedSSO_Admin_abc"
    ui = {
        "type": "AssumedRole",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_Admin_abc/alice@example.com",
        "sessionContext": {
            "sessionIssuer": {"arn": role_arn},
            "attributes": {"mfaAuthenticated": "true"},
        },
    }
    ev = {
        "EventSource": "s3.amazonaws.com",
        "EventName": "GetObject",
        "EventTime": datetime(2026, 7, 10, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps(
            {"userIdentity": ui, "eventSource": "s3.amazonaws.com", "eventName": "GetObject"}
        ),
    }
    usage, truncated, coverage_start, subjects = _lookup_events(_FakeCT([ev]), AS_OF, 200)

    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {
            "account_id": ACCOUNT,
            "principals": [_role("AWSReservedSSO_Admin_abc")],
            "credential_report": [],
        },
    )
    storage.write_raw(
        ACCOUNT,
        "cloudtrail",
        {"account_id": ACCOUNT, "mode": "lookup_events", "usage": usage, "subjects": subjects,
         "truncated": truncated, "coverage_start": coverage_start,
         "window_days": 90, "max_pages": 200},
    )
    records = normalize(storage, RUN)
    build_catalog(storage, RUN, CatalogConfig(min_members_for_persona=1, exclude_service_roles=False))

    # 판정은 실제로 이뤄졌다 — 아래 부재 어서션이 "아무것도 안 했다" 로 통과하는 것이 아니다.
    rec = records[0]
    assert (rec.usage_subject, rec.usage_subject_basis) == ("human", "mfa_session")
    assert rec.session_name_shape == "email_like"

    for path in sorted(p for p in (tmp_path / "test" / "run-fixed").rglob("*") if p.is_file()):
        blob = path.read_bytes()
        assert b"alice@example.com" not in blob, f"세션 이름 원문이 {path.name} 에 남았다"
        assert b"assumed-role" not in blob, f"임시 sts ARN(=세션 이름 포함)이 {path.name} 에 남았다"
