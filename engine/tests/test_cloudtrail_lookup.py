"""CloudTrail LookupEvents 폴백의 principal ARN 추출 테스트.

버그 회귀 방지: LookupEvents 의 얕은 `Username` 은 principal ARN 이 아니라 세션명/역할명이라
정규화 인벤토리(IAM ARN)와 매칭되지 않았다(실계정에서 CloudTrail 기여분 0/14). 이제 각 이벤트의
`CloudTrailEvent` JSON 을 파싱해 userIdentity 에서 진짜 IAM ARN 을 뽑는다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from lp2ps.collectors.cloudtrail import (
    _caller_kind,
    _lookup_events,
    _principal_from_event,
    _principal_from_identity,
    _role_arn_from_sts,
    _session_name_shape,
)

AS_OF = datetime(2026, 7, 15, tzinfo=timezone.utc)

# 실계정에서 관측한 실제 userIdentity 모양.
ASSUMED_ROLE = {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_abc/alice",
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "arn": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc",
        }
    },
}
AWS_SERVICE = {"type": "AWSService", "invokedBy": "cloudtrail.amazonaws.com"}
IAM_USER = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"}


def test_assumed_role_uses_session_issuer_arn() -> None:
    # 임시 sts ARN 이 아니라 발급 역할의 IAM ARN 을 써야 인벤토리와 매칭된다.
    assert _principal_from_identity(ASSUMED_ROLE) == (
        "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
    )


def test_aws_service_has_no_principal() -> None:
    assert _principal_from_identity(AWS_SERVICE) == ""


def test_iam_user_uses_arn() -> None:
    assert _principal_from_identity(IAM_USER) == "arn:aws:iam::111122223333:user/alice"


def test_assumed_role_without_issuer_falls_back_to_sts_normalization() -> None:
    ui = {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/MyRole/sess-1"}
    assert _principal_from_identity(ui) == "arn:aws:iam::111122223333:role/MyRole"


def test_role_arn_from_sts() -> None:
    assert (
        _role_arn_from_sts("arn:aws:sts::123456789012:assumed-role/Foo/bar")
        == "arn:aws:iam::123456789012:role/Foo"
    )
    assert _role_arn_from_sts("not-an-arn") == ""


def test_principal_from_event_parses_json() -> None:
    ev = json.dumps({"userIdentity": ASSUMED_ROLE})
    assert _principal_from_event(ev).startswith("arn:aws:iam::111122223333:role/")
    assert _principal_from_event(None) == ""
    assert _principal_from_event("{bad json") == ""


class _FakeCT:
    """LookupEvents 수동 페이지네이션 fake — 단일 페이지(NextToken 없음)."""

    def __init__(self, events: list[dict]) -> None:
        self._events = events

    def lookup_events(self, **kwargs):
        return {"Events": self._events}  # 단일 페이지 → NextToken 없음


def _event(ui: dict, source: str, name: str, when: str) -> dict:
    return {
        "EventSource": source,
        "EventName": name,
        "EventTime": datetime.fromisoformat(when),
        "CloudTrailEvent": json.dumps({"userIdentity": ui}),
    }


def test_lookup_events_aggregates_by_real_arn() -> None:
    role_arn = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc"
    events = [
        _event(ASSUMED_ROLE, "s3.amazonaws.com", "GetObject", "2026-07-10T00:00:00+00:00"),
        _event(ASSUMED_ROLE, "s3.amazonaws.com", "GetObject", "2026-07-11T00:00:00+00:00"),
        _event(AWS_SERVICE, "kms.amazonaws.com", "GenerateDataKey", "2026-07-09T00:00:00+00:00"),
    ]
    rows, truncated, coverage_start, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)

    assert truncated is False  # 단일 페이지 → 상한 미도달
    # 주체 신호는 별 집계다 — usage 행에 실으면 역할당 수천 번 중복된다.
    assert [s["principal"] for s in subjects] == [role_arn]
    # 커버 기간은 훑은 범위 — principal 없는 AWSService 이벤트(7/9)가 가장 오래된 것이다.
    assert coverage_start.startswith("2026-07-09")
    # AWSService 이벤트는 principal 없음 → 제외. AssumedRole 2건은 같은 IAM ARN 으로 집계.
    assert len(rows) == 1
    r = rows[0]
    assert r["principal"] == role_arn
    assert r["event_name"] == "GetObject"
    assert r["count"] == 2
    assert r["last_used"] == "2026-07-11T00:00:00+00:00"


# ---- 사용 주체 신호(R1) ----


def _sts_arn(session_name: str, role: str = "MyRole") -> str:
    return f"arn:aws:sts::111122223333:assumed-role/{role}/{session_name}"


def test_session_name_shape_classifies_without_returning_raw() -> None:
    """세션 이름 → 닫힌 라벨. 반환값에 원문 조각이 없어야 한다(R1-a)."""
    # SSO 는 세션 이름에 사용자 이메일을 쓴다 — 사람 판정의 가장 강한 근거가 개인정보다.
    assert _session_name_shape({"type": "AssumedRole", "arn": _sts_arn("alice@example.com")}) == "email_like"
    # 자동화는 계정 ID 를 박는다.
    assert _session_name_shape({"type": "AssumedRole", "arn": _sts_arn("finops-111122223333")}) == "account_id_embedded"
    assert _session_name_shape(
        {"type": "AssumedRole", "arn": _sts_arn("3f2b1c9d-1111-2222-3333-444455556666")}
    ) == "uuid_suffix"
    assert _session_name_shape({"type": "AssumedRole", "arn": _sts_arn("run-9f8e7d6c5b4a")}) == "uuid_suffix"
    # 사람의 SSO 사용자명도 이 형태다 → 라벨만 남기고 **판정 근거로는 쓰지 않는다**.
    assert _session_name_shape({"type": "AssumedRole", "arn": _sts_arn("alice")}) == "service_name"
    assert _session_name_shape({"type": "AssumedRole", "arn": _sts_arn("한글세션")}) == "other"
    # 대조군 — 세션이 없으면 라벨도 없다(부재를 라벨로 꾸미지 않는다).
    assert _session_name_shape(IAM_USER) is None
    assert _session_name_shape({"type": "AssumedRole", "arn": "not-an-arn"}) is None


def test_caller_kind_labels_only() -> None:
    """호출자 성격 라벨. ARN 원문은 반환하지 않는다."""
    assert _caller_kind(AWS_SERVICE) == "service"
    assert _caller_kind(IAM_USER) == "iam_user"
    assert _caller_kind({"type": "Root", "arn": "arn:aws:iam::111122223333:root"}) == "root"
    assert _caller_kind({"type": "SAMLUser"}) == "federated"
    # IdC 콘솔 세션이 다른 역할을 집었다 = 사람이 한 일.
    assert _caller_kind(ASSUMED_ROLE) == "sso"
    # 일반 역할이 역할을 집는 것은 사람·자동화 양쪽에 있다 → 근거 아님(라벨만).
    assert _caller_kind({"type": "AssumedRole", "arn": _sts_arn("x")}) == "role"
    assert _caller_kind({}) == "unknown"


def test_caller_kind_reads_cross_account_principal_id_prefix() -> None:
    """🔴 크로스계정 AssumeRole(`AWSAccount`)은 ARN 도 호출자 종류도 없다 — `principalId` 접두로 가른다.

    이것이 라이브에서 `admin` 이 '판별 불가' 였던 진짜 원인이다. 관측 창을 57.8시간까지 늘려도
    안 풀렸다(그 창 안에 assume 2건이 있었고 둘 다 `unknown` 이었다) — 커버리지가 아니라 분류 누락.
    R1-a: 접두 4글자 분류 결과만 쓰고 `principalId` 원문은 어디에도 남기지 않는다.
    """
    def aws_account(pid: str) -> dict:
        # 실제 이벤트에는 arn·userName 이 **없다**. 있는 것은 이 둘뿐이다.
        return {"type": "AWSAccount", "accountId": "444455556666", "principalId": pid}

    # 🔴 픽스처의 꼬리를 **짧게** 둔다(실물은 접두 4글자 + 17글자 = 21글자). 실물 길이로 쓰면
    # 시크릿 스캐너가 `(AIDA|AROA|AIPA|ASIA)[A-Z0-9]{16}` 를 액세스 키로 잡아 커밋이 막힌다
    # (Code Defender 가 실제로 막았다). 분류는 `head[:4]` 만 보므로(`_kind_from_principal_id`)
    # 길이는 판정에 무관하다 — 길게 되돌리지 말 것. 허용목록으로 덮는 것도 답이 아니다:
    # 공개 예정 리포에 키 모양 문자열을 남기게 된다.

    assert _caller_kind(aws_account("AIDAEXAMPLE1")) == "iam_user"   # IAM 사용자 → 사람
    assert _caller_kind(aws_account("AROAEXAMPLE1:sess")) == "role"  # 역할 → 근거 아님
    assert _caller_kind(aws_account("AIPAEXAMPLE1")) == "service"    # 인스턴스 프로파일
    assert _caller_kind(aws_account("ASIAEXAMPLE1")) == "unknown"    # 임시 자격증명 → 알 수 없음
    assert _caller_kind(aws_account("444455556666")) == "root"                # 루트 = 계정 ID 그대로
    # 대조군 — 모르는 접두·빈 값은 추측하지 않는다.
    assert _caller_kind(aws_account("ZZZZEXAMPLE1")) == "unknown"
    assert _caller_kind(aws_account("")) == "unknown"
    # 라벨은 닫힌 집합이고 원문 조각이 새지 않는다.
    assert "EXAMPLE" not in _caller_kind(aws_account("AIDAEXAMPLE1"))


def _full_event(ui: dict, source: str, name: str, when: str, request_params: dict | None = None) -> dict:
    """CloudTrailEvent 전문에 eventName/eventSource/requestParameters 까지 담은 이벤트."""
    full: dict = {"userIdentity": ui, "eventSource": source, "eventName": name}
    if request_params is not None:
        full["requestParameters"] = request_params
    return {
        "EventSource": source,
        "EventName": name,
        "EventTime": datetime.fromisoformat(when),
        "CloudTrailEvent": json.dumps(full),
    }


def test_subject_signals_attribute_assume_caller_to_target_role() -> None:
    """AssumeRole 호출자 성격은 **대상 역할**에 귀속한다.

    이 역할을 집은 것이 사람인지 서비스인지는 역할 자신의 이벤트에 안 나온다 — 신뢰정책만 보면
    사람이 쓰는 역할이 전부 '판별 불가' 로 떨어지는 이유가 이것이다.
    """
    target = "arn:aws:iam::111122223333:role/Target"
    events = [
        _full_event(IAM_USER, "sts.amazonaws.com", "AssumeRole", "2026-07-10T00:00:00+00:00",
                    {"roleArn": target}),
        _full_event(AWS_SERVICE, "sts.amazonaws.com", "AssumeRole", "2026-07-11T00:00:00+00:00",
                    {"roleArn": "arn:aws:iam::111122223333:role/Machine"}),
    ]
    _, _, _, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)
    by_principal = {s["principal"]: s for s in subjects}

    assert by_principal[target]["assume_caller_kinds"] == ["iam_user"]
    # 호출자가 서비스면 principal 은 "" 지만 그 사실이 대상 역할의 기계 판정 근거다.
    assert by_principal["arn:aws:iam::111122223333:role/Machine"]["assume_caller_kinds"] == ["service"]
    # 호출자 자신(IAM 사용자)도 주체 행을 갖는다.
    assert IAM_USER["arn"] in by_principal


def test_assume_role_session_name_shape_lands_on_target_role() -> None:
    """요청의 `roleSessionName` shape 를 **대상 역할**에 귀속한다(원문은 담지 않는다).

    예전에는 행위자 자신의 이벤트에서만 세션명을 봤다 → 크로스계정 assume 으로만 쓰이는 역할은
    세션명 근거가 0 이었다. 여기서는 `AWSAccount` 호출자(ARN 없음)를 쓰므로 **요청 경로가 아니면
    라벨이 나올 수 없다** — 어서션이 실제로 새 코드를 잰다.
    """
    human_target = "arn:aws:iam::111122223333:role/HumanUsed"
    bot_target = "arn:aws:iam::111122223333:role/BotUsed"
    caller = {"type": "AWSAccount", "accountId": "444455556666",
              "principalId": "AIDAEXAMPLE1"}
    events = [
        _full_event(caller, "sts.amazonaws.com", "AssumeRole", "2026-07-10T00:00:00+00:00",
                    {"roleArn": human_target, "roleSessionName": "alice@example.com"}),
        _full_event(caller, "sts.amazonaws.com", "AssumeRole", "2026-07-11T00:00:00+00:00",
                    {"roleArn": bot_target, "roleSessionName": "deploy-444455556666"}),
    ]
    _, _, _, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)
    by_principal = {s["principal"]: s for s in subjects}

    assert by_principal[human_target]["session_name_shapes"] == ["email_like"]
    assert by_principal[bot_target]["session_name_shapes"] == ["account_id_embedded"]
    # R1-a — 세션명 원문·이메일 조각이 산출 행에 없다.
    blob = json.dumps(subjects, default=str)
    assert "alice" not in blob
    assert "deploy-" not in blob


def test_subject_signals_collect_mfa_and_invoked_by() -> None:
    mfa_ui = {
        "type": "AssumedRole",
        "arn": _sts_arn("alice@example.com", "AWSReservedSSO_Admin_abc"),
        "sessionContext": {
            "sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/AWSReservedSSO_Admin_abc"},
            "attributes": {"mfaAuthenticated": "true"},
        },
    }
    lambda_ui = {
        "type": "AssumedRole",
        "arn": _sts_arn("fn-1", "LambdaExec"),
        "invokedBy": "lambda.amazonaws.com",
        "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/LambdaExec"}},
    }
    events = [
        _full_event(mfa_ui, "s3.amazonaws.com", "GetObject", "2026-07-10T00:00:00+00:00"),
        _full_event(lambda_ui, "s3.amazonaws.com", "GetObject", "2026-07-11T00:00:00+00:00"),
    ]
    _, _, _, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)
    by_principal = {s["principal"]: s for s in subjects}

    human = by_principal["arn:aws:iam::111122223333:role/AWSReservedSSO_Admin_abc"]
    assert human["mfa_seen"] is True
    assert human["session_name_shapes"] == ["email_like"]
    assert human["invoked_by"] == []

    machine = by_principal["arn:aws:iam::111122223333:role/LambdaExec"]
    # 대조군 — MFA 표시 부재는 "못 봤다" 일 뿐 사람이 아니라는 근거가 아니다.
    assert machine["mfa_seen"] is False
    assert machine["invoked_by"] == ["lambda.amazonaws.com"]


def test_subject_rows_carry_no_raw_session_name_or_caller_arn() -> None:
    """R1-a — 수집기 산출물 전문에 세션 이름 원문·호출자 ARN 이 없어야 한다.

    사람 판정의 근거가 개인정보이므로 판정에만 쓰고 원문은 버린다. S3 에 쓰인 다음에는 되돌릴 수 없다.
    """
    ui = {
        "type": "AssumedRole",
        "arn": _sts_arn("alice@example.com", "AWSReservedSSO_Admin_abc"),
        "sessionContext": {
            "sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/AWSReservedSSO_Admin_abc"},
            "attributes": {"mfaAuthenticated": "true"},
        },
    }
    events = [
        _full_event(ui, "sts.amazonaws.com", "AssumeRole", "2026-07-10T00:00:00+00:00",
                    {"roleArn": "arn:aws:iam::111122223333:role/Target"}),
    ]
    _, _, _, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)
    blob = json.dumps(subjects)

    assert "alice@example.com" not in blob
    assert "@" not in blob.replace("amazonaws.com", "")  # 이메일 형식 문자열 부재
    assert "assumed-role" not in blob  # 임시 sts ARN(=세션 이름 포함) 부재
    # 대조군 — 판정에 필요한 라벨은 실제로 담겨 있다(위 어서션이 빈 산출물을 통과한 게 아니다).
    assert "email_like" in blob and "sso" in blob


def test_malformed_event_json_does_not_break_collection() -> None:
    """전문 파싱 실패는 그 이벤트만 버리고 완주한다(부분 소스는 정상)."""
    events = [
        {"EventSource": "s3.amazonaws.com", "EventName": "GetObject",
         "EventTime": datetime.fromisoformat("2026-07-10T00:00:00+00:00"),
         "CloudTrailEvent": "{bad json"},
        _full_event(IAM_USER, "s3.amazonaws.com", "GetObject", "2026-07-11T00:00:00+00:00"),
    ]
    rows, truncated, coverage_start, subjects = _lookup_events(_FakeCT(events), AS_OF, 200)
    assert truncated is False
    assert [r["principal"] for r in rows] == [IAM_USER["arn"]]
    assert [s["principal"] for s in subjects] == [IAM_USER["arn"]]
    # 커버 기간은 파싱 실패 이벤트도 포함해 잰다(훑은 범위이므로).
    assert coverage_start.startswith("2026-07-10")
