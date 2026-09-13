"""미사용 일수·등급(R2) + `unused_role` 재정의(R3) + 추이 정의 경계.

이 파일이 지키는 것:
- 등급 **경계값**(29/30/59/60/89/90)이 config 값에서 나오고, 리터럴이 아니다.
- 같은 일수라도 **무엇부터 센 것인지**(`unused_days_basis`)가 구분된다 — ①IAM 활동 기록 /
  ②생성일. 추적 보장 창 문구는 ②에만 붙는다.
- ①은 **상한이 없다**(라이브에서 1,076일이 그대로 나왔다).
- 사용 중인 역할에는 일수를 아예 붙이지 않는다(케이스 ③) — "생성 후 N일 미사용" 오탐 차단.
- 정의가 바뀌었으므로 `MetricsPoint.definition_version` 이 추이에 경계선을 그린다.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from lp2ps.config import RiskRules
from lp2ps.m2_normalizer import _unused_days, _unused_tier, normalize
from lp2ps.m6_reporter import (
    _unused_period,
    is_deletion_reviewable,
    is_idle_beyond,
    is_new_unused_role,
    is_unused_role,
)
from lp2ps.models import MetricsPoint, PrincipalRecord
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")
AS_OF = "2026-07-15T00:00:00Z"
ACCOUNT = "111122223333"
ARN = f"arn:aws:iam::{ACCOUNT}:role/data-eng"
RULES = RiskRules()


_AS_OF_DT = datetime.fromisoformat(AS_OF.replace("Z", "+00:00"))


def _days_before(days: int) -> str:
    """as_of 기준 N일 전 ISO 날짜 — 경계 테스트가 as_of 를 손으로 계산하지 않게 한다."""
    return (_AS_OF_DT - timedelta(days=days)).isoformat()


def _seed(storage: LocalFSStorage, **overrides) -> None:
    """역할 1건 raw. `create_date`/`role_last_used` 만 바꿔가며 경계를 본다."""
    principal = {
        "principal": ARN,
        "name": "data-eng",
        "identity_type": "role",
        "create_date": _days_before(1000),
        "inline_policies": [{
            "name": "inline",
            "document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                        "Resource": "*"}]},
        }],
        "attached_policies": [],
        "path": "/",
    }
    principal.update(overrides)
    storage.write_raw(ACCOUNT, "credential_report", {
        "account_id": ACCOUNT, "principals": [principal], "credential_report": [],
    })


def _rec(**kw) -> PrincipalRecord:
    base = dict(account_id=ACCOUNT, principal=ARN, identity_type="role",
                granted_actions=["s3:GetObject"], risk_level="low", run_id="run-x")
    base.update(kw)
    return PrincipalRecord(**base)


# ---- 등급 경계 ----


@pytest.mark.parametrize(
    "unused_days,expected",
    [
        (0, "active"),
        (29, "active"),   # watch 경계 직전
        (30, "watch"),    # = unused_tier_days[0]
        (59, "watch"),
        (60, "review"),   # = unused_tier_days[1]
        (89, "review"),
        (90, "cleanup"),  # = unused_tier_days[2]
        (1076, "cleanup"),  # 라이브 실측 최댓값 — 상한이 없다
    ],
)
def test_tier_boundaries(unused_days: int, expected: str) -> None:
    """경계는 닫힘/열림이 뒤집히기 쉬운 자리다 — 양쪽 값을 모두 못박는다.

    나이는 충분히 크게 줘서 `new` 가 개입하지 않게 한다(그 우선순위는 별도 테스트).
    """
    tier = _unused_tier(unused_days, 1000, RULES.unused_tier_days, RULES.new_principal_days)
    assert tier == expected


def test_tier_boundaries_come_from_config_not_literals() -> None:
    """대조군 — config 를 바꾸면 경계도 따라 움직여야 한다(불변식 ④).

    이 대조가 없으면 위 테스트는 30/60/90 을 코드에 박아도 그대로 통과한다.
    """
    tight = [7, 14, 21]
    assert _unused_tier(7, 1000, tight, 1) == "watch"
    assert _unused_tier(6, 1000, tight, 1) == "active"
    assert _unused_tier(21, 1000, tight, 1) == "cleanup"
    # 기본 경계에서는 같은 7일이 active 다 — 두 결과가 다르다는 것이 config 의존의 증거다.
    assert _unused_tier(7, 1000, RULES.unused_tier_days, RULES.new_principal_days) == "active"


def test_new_wins_over_active() -> None:
    """생성 30일 미만은 `active` 가 아니라 `new` 다 — 등급을 **보류**한다.

    3일 전에 만들어 어제 한 번 쓴 역할을 `active` 로 물들이면 "쓰이고 있다" 는 판단을 관측
    기간 3일로 주장하게 된다. 반대로 안 쓴 역할이면 `cleanup` 으로 몰려 배포 중인 역할이
    삭제 후보가 된다(라이브: 575 에서 미사용 59건 중 3건이 당일 생성이었다).
    """
    assert _unused_tier(1, 3, RULES.unused_tier_days, RULES.new_principal_days) == "new"
    assert _unused_tier(200, 3, RULES.unused_tier_days, RULES.new_principal_days) == "new"
    # 경계: 30일째부터는 등급을 매긴다.
    assert _unused_tier(1, 30, RULES.unused_tier_days, RULES.new_principal_days) == "active"


def test_ungraded_when_nothing_to_count() -> None:
    """일수를 셀 근거가 없으면 등급도 없다 — 0 이나 active 로 메꾸지 않는다."""
    assert _unused_tier(None, None, RULES.unused_tier_days, RULES.new_principal_days) is None


# ---- 일수 근거 3경로 ----


def test_unused_days_basis_role_last_used_has_no_cap() -> None:
    """① IAM 활동 기록이 있으면 그 날짜부터 센다. **상한 없음.**"""
    assert _unused_days(_days_before(1076), _days_before(1500), False, _AS_OF_DT) == (
        1076, "role_last_used")


def test_unused_days_basis_create_date_when_no_record() -> None:
    """② 기록이 없고 양성 사용 근거도 없으면 생성일부터 센다."""
    assert _unused_days(None, _days_before(46), False, _AS_OF_DT) == (46, "create_date")


def test_no_day_count_when_usage_evidence_exists() -> None:
    """③ 기록이 없는데 **쓰인 근거는 있으면** 일수를 말하지 않는다.

    이 경로가 없으면 CloudTrail/Advisor 로 사용이 확인된 역할과 모든 IAM User(RoleLastUsed 가
    애초에 없다)가 "생성 후 N일 미사용" 으로 표기된다 — 정면으로 사실과 반대다.
    """
    assert _unused_days(None, _days_before(500), True, _AS_OF_DT) == (None, None)


def test_no_day_count_when_neither_date_exists() -> None:
    """대조군 — 날짜가 아예 없으면 숫자를 만들지 않는다."""
    assert _unused_days(None, None, False, _AS_OF_DT) == (None, None)


# ---- 문구: 같은 숫자를 다르게 말한다 ----


def test_tracking_window_caveat_only_on_create_date_basis() -> None:
    """추적 보장 400일 문구는 ②에만 붙는다.

    ①에 붙이면 AWS 가 기록한 사실을 우리가 못 믿는 것처럼 읽힌다. ②에서 빼면 생성 후 경과가
    측정된 미사용 기간처럼 읽힌다.
    """
    measured = _rec(role_last_used=_days_before(1076), role_last_used_region="ap-northeast-1",
                    unused_days=1076, unused_days_basis="role_last_used")
    last, period = _unused_period(measured)
    assert period == "1076일", period
    assert "추적 보장" not in period
    assert "(ap-northeast-1)" in last, "활동 리전이 빠지면 CloudTrail 에 왜 없는지 설명이 사라진다"

    inferred = _rec(unused_days=46, unused_days_basis="create_date", age_days=46,
                    create_date=_days_before(46))
    last2, period2 = _unused_period(inferred)
    assert last2 == "IAM 활동 기록 없음"
    assert period2 == "생성 후 46일 · 사용 기록 없음(AWS 추적 보장 400일)"


def test_period_says_unknown_instead_of_zero() -> None:
    """셀 근거가 없으면 '확인 불가' 다 — "0일" 은 '방금 쓰였다' 로 읽힌다."""
    _, period = _unused_period(_rec())
    assert "확인 불가" in period
    assert "0일" not in period


# ---- R3: `unused_role` 재정의 ----


def test_long_idle_role_is_now_unused_role() -> None:
    """3년 전에 마지막으로 쓰인 역할은 **이제 정리 대상이다.**

    구 정의("실사용 증거가 어느 층위에도 없다")에서는 `used_actions` 가 비어도 RoleLastUsed 가
    있으면 '쓰인 적 있음' 으로 빠졌다. 정리 대상 중 가장 확실한 것이 목록에서 사라진 셈이다.
    """
    rec = _rec(role_last_used=_days_before(1076), unused_days=1076,
               unused_days_basis="role_last_used", unused_tier="cleanup", age_days=1500)
    assert is_unused_role(rec, RULES.unused_role_days) is True
    assert is_new_unused_role(rec, RULES.new_principal_days) is False


def test_recently_used_role_is_not_unused_role() -> None:
    """대조군 — 12일 전에 쓰인 역할은 아니다. 이 대조가 없으면 위 테스트는
    "RoleLastUsed 가 있으면 무조건 미사용" 으로도 통과한다."""
    rec = _rec(role_last_used=_days_before(12), unused_days=12,
               unused_days_basis="role_last_used", unused_tier="active", age_days=1500)
    assert is_unused_role(rec, RULES.unused_role_days) is False


def test_mid_age_role_without_record_is_neither_type() -> None:
    """46일 된 기록 없는 역할은 `unused_role` 도 `new_role_unused` 도 아니다.

    90일 경계 아래이므로 삭제 검토가 아니고, 30일을 넘겼으므로 '너무 새것' 도 아니다. 두 유형
    사이의 이 구간이 존재한다는 것을 명시해 둔다 — 백로그에서 안 보이는 이유가 설명돼야 한다
    (등급 `watch` 로는 여전히 보인다).
    """
    rec = _rec(unused_days=46, unused_days_basis="create_date", age_days=46,
               unused_tier="watch")
    assert is_unused_role(rec, RULES.unused_role_days) is False
    assert is_new_unused_role(rec, RULES.new_principal_days) is False
    assert rec.unused_tier == "watch", "유형이 없어도 등급으로는 추적된다"


def test_new_role_without_record_stays_in_backlog_as_judgment_deferred() -> None:
    """생성 직후 역할은 `new_role_unused`(판단 보류)로 남는다 — 조용히 사라지면 안 된다(R6)."""
    rec = _rec(unused_days=3, unused_days_basis="create_date", age_days=3, unused_tier="new")
    assert is_unused_role(rec, RULES.unused_role_days) is False
    assert is_new_unused_role(rec, RULES.new_principal_days) is True


def test_old_usage_traces_do_not_rescue_a_long_idle_role() -> None:
    """🔴 오래된 사용 흔적은 미사용 판정을 **막지 못한다**(라이브 실측 결함 #9).

    예전 판정식은 `used_actions`/`used_services` 가 비어 있기를 요구했다. 두 필드는 "쓰였다" 만
    말하고 "언제" 를 말하지 않으므로, IAM 이 1,076일 미사용이라고 기록한 역할이 3년 전 흔적 때문에
    '쓰이는 중' 으로 판정돼 조치 목록에서 **통째로 빠졌다**(어느 카드에도 없었다 — 실측 26개).
    두 근거는 모순되지 않았다: 같은 날짜를 말하고 있었고 판정식이 그 날짜를 버렸다.

    `role_last_used` 는 IAM 이 기록한 활동 시각(전 리전)이라 우리 사용 근거가 그보다 새로울 수
    없다 → 이 근거로 임계를 넘겼으면 흔적이 있어도 미사용이다.
    """
    from lp2ps.models import UsedAction

    by_action = _rec(used_actions=[UsedAction(action="s3:GetObject",
                                              last_used=_days_before(1076))],
                     role_last_used=_days_before(1076), unused_days=1076,
                     unused_days_basis="role_last_used")
    by_service = _rec(used_services=["s3"], role_last_used=_days_before(1076),
                      unused_days=1076, unused_days_basis="role_last_used")
    assert is_unused_role(by_action, RULES.unused_role_days) is True
    assert is_unused_role(by_service, RULES.unused_role_days) is True


def test_usage_guard_still_holds_when_the_date_is_only_a_create_date() -> None:
    """🔴 대조군 — 일수 근거가 **생성일**이면 사용 근거의 존재가 판정을 막는다.

    `create_date` 는 "언제 마지막으로 썼나" 를 말하지 않는다. 이 가드가 없으면 10년 전에 만들어
    지금도 매일 쓰는 IAM 사용자가(사용자에는 `RoleLastUsed` 가 애초에 없다) 삭제 검토에 올라온다.
    위 테스트가 "일수만 크면 무조건 미사용" 으로도 통과하지 않게 하는 대조이기도 하다.
    """
    from lp2ps.models import UsedAction

    by_action = _rec(identity_type="user", used_actions=[UsedAction(action="s3:GetObject")],
                     unused_days=3650, unused_days_basis="create_date", age_days=3650)
    by_service = _rec(used_services=["s3"], unused_days=3650,
                      unused_days_basis="create_date", age_days=3650)
    assert is_idle_beyond(by_action, RULES.unused_role_days) is False
    assert is_idle_beyond(by_service, RULES.unused_role_days) is False
    # 흔적을 지우면 같은 레코드가 미사용이 된다 — 위 False 가 일수 때문이 아님을 보인다.
    by_service.used_services = []
    assert is_idle_beyond(by_service, RULES.unused_role_days) is True


def test_unused_role_evidence_does_not_claim_there_was_no_usage() -> None:
    """미사용 역할의 증거가 "사용 근거: 없음" 이라고 **거짓을 말하지 않는다.**

    신 판정식에서는 오래된 흔적이 있어도 미사용이 된다(실측 84개 중 58개는 미사용 권한·와일드카드
    항목까지 함께 들고 넘어왔다). 증거 줄이 리터럴 "없음" 이면, 고객이 콘솔에서 그 흔적을 보는
    순간 목록 전체를 안 믿는다.
    """
    from lp2ps.m6_reporter import _usage_evidence_phrase
    from lp2ps.models import UsedAction

    rec = _rec(used_actions=[UsedAction(action="s3:GetObject", last_used="2023-08-29T00:00:00Z")],
               used_services=["s3"], role_last_used=_days_before(1076), unused_days=1076,
               unused_days_basis="role_last_used")
    phrase = _usage_evidence_phrase(rec)
    # "없음" 만 금지하면 안 된다 — 창 설명("CloudTrail 근거 없음")에도 그 낱말이 들어간다.
    # 금지 대상은 **사용 근거 자체가 없다는 주장**, 즉 문장 머리다.
    assert not phrase.startswith("없음") and "2023-08-29" in phrase
    # 날짜 없는 흔적에는 날짜를 지어내지 않는다.
    rec.used_actions = [UsedAction(action="s3:GetObject")]
    assert "미수집" in _usage_evidence_phrase(rec)
    # 🔴 라이브 결함 A: action 근거는 없고 **서비스 단위 흔적만** 있는 경우. 예전 판은 여기서
    # "없음" 을 냈고, 같은 카드의 `사용 흔적 서비스: ec2` · `마지막 활동: 2022-12-19` 와 정면으로
    # 부딪쳤다. 어느 층위가 없는 것인지 밝혀야 모순이 사라진다.
    rec.used_actions = []
    svc_phrase = _usage_evidence_phrase(rec)
    assert not svc_phrase.startswith("없음"), svc_phrase
    assert "action 단위 근거 없음" in svc_phrase and "서비스 단위 흔적 1개" in svc_phrase
    # 대조군: 두 층위 모두 비어야 "없음" 이 맞는 말이다(이게 없으면 위 어서션은 "없음" 을 절대
    # 안 내는 코드로도 통과한다 — 실패할 수 없는 어서션 = 미측정).
    rec.used_services = []
    assert _usage_evidence_phrase(rec).startswith("없음")


def test_undated_role_with_no_evidence_stays_listed() -> None:
    """날짜가 아예 없는 무근거 역할은 목록에 **남는다**(구 정의의 '사용 근거 전무').

    일수 조건을 `>= N` 으로만 두면 증거가 가장 없는 역할이 오히려 빠진다(R6 위반).
    """
    rec = _rec()  # role_last_used·create_date·unused_days 전부 없음
    assert is_unused_role(rec, RULES.unused_role_days) is True
    assert _unused_period(rec)[1].startswith("확인 불가")


# ---- R6 제외가 미사용 판정보다 먼저 이긴다 (라이브 실측 결함) ----


def _idle_excluded(reason: str, **kw) -> PrincipalRecord:
    """90일 훨씬 넘게 미사용이고 권한도 있는데 **R6 로 제외된** 역할."""
    return _rec(track="excluded", excluded_reason=reason, unused_days=1500,
                unused_days_basis="create_date", age_days=1600, unused_tier="cleanup", **kw)


def test_service_linked_role_is_not_an_unused_role() -> None:
    """AWS service-linked 역할은 미사용이어도 정리 대상이 아니다.

    라이브(관제 계정 self-scan)에서 `AWSServiceRoleFor*` 7개가 "역할 삭제 (미사용 — PS 카탈로그에
    불필요)" 권고를 달고 백로그에 올라왔다. AWS 가 소유해 **정책을 수정할 수 없는** 역할이다
    (삭제 자체는 `DeleteServiceLinkedRole` 로 가능하다 — "지울 수 없다" 고 쓰면 틀린 말이 된다.
    문제는 지울 수 있느냐가 아니라 우리가 그 역할의 사용 실태를 판단할 근거가 없다는 것이다),
    삭제 권고 목록에 하나라도 그런 것이 섞이면 목록 전체를 안 믿는다. `m5_tracks` 계약("이후
    단계는 다시 판정하지 않고 track 을 읽는다")을 이 판정식이 안 지킨 것이 원인이었다.
    """
    rec = _idle_excluded("service_linked", trust_scope="service", is_exception=True,
                         exception_type="service_linked")
    assert is_unused_role(rec, RULES.unused_role_days) is False
    assert is_deletion_reviewable(rec) is False


def test_same_role_is_listed_once_r6_no_longer_excludes_it() -> None:
    """🔴 대조군 — 위 테스트가 판별력을 가지려면 `track` 만 바꿨을 때 **반드시 잡혀야** 한다.

    이 대조가 없으면 다른 필드(사용 근거·일수) 때문에 빠진 것과 구별되지 않는다.
    """
    rec = _idle_excluded("service_linked", trust_scope="service")
    rec.track = "delete_review"
    rec.excluded_reason = None
    assert is_unused_role(rec, RULES.unused_role_days) is True
    assert is_deletion_reviewable(rec) is True


def test_iac_bootstrap_role_does_not_become_owner_review() -> None:
    """config 패턴으로 제외한 CDK 부트스트랩 역할은 '외부 연동 의심' 으로도 올리지 않는다.

    라이브에서 `cdk-hnb659fds-image-publishing-role-*` 가 `trust_scope="tooling"` 이라 소유자 확인
    트랙으로 올라왔다 — 소유자가 우리인 역할에 "소유자를 확인하라" 고 말한 셈이다.
    """
    rec = _idle_excluded("iac_bootstrap_role", trust_scope="tooling")
    assert is_unused_role(rec, RULES.unused_role_days) is False
    assert is_deletion_reviewable(rec) is False


def test_unassigned_track_is_not_treated_as_excluded() -> None:
    """`track` 이 비어 있는 레코드(배정 전·구버전 parquet)는 게이트에 걸리지 않는다.

    미배정을 제외로 읽으면 배정 버그가 '정상적으로 제외됨' 으로 보인다 — `m5_tracks` 가
    `track=None` 을 기본값으로 둔 이유와 같은 이유다.
    """
    rec = _rec(unused_days=1500, unused_days_basis="create_date", age_days=1600,
               unused_tier="cleanup")
    assert rec.track is None
    assert is_unused_role(rec, RULES.unused_role_days) is True


def test_too_new_exclusion_still_reaches_judgment_deferred() -> None:
    """`too_new` 제외는 `new_role_unused`(판단 보류)와 같은 사실이므로 통과시킨다.

    여기서 함께 빼면 유형 자체가 비어버린다 — 라이브 8건이 전부 이 사유였다.
    """
    rec = _rec(track="excluded", excluded_reason="too_new", unused_days=3,
               unused_days_basis="create_date", age_days=3, unused_tier="new")
    assert is_new_unused_role(rec, RULES.new_principal_days) is True


def test_other_exclusions_do_not_reach_judgment_deferred() -> None:
    """반대로 다른 제외 사유는 판단 보류로도 올리지 않는다 — 우리가 손댈 대상이 아니다."""
    rec = _rec(track="excluded", excluded_reason="service_linked", unused_days=3,
               unused_days_basis="create_date", age_days=3, unused_tier="new")
    assert is_new_unused_role(rec, RULES.new_principal_days) is False


def test_legacy_record_falls_back_to_age_days() -> None:
    """`unused_days` 가 없던 시절의 normalized 를 다시 읽어도 판정이 유지된다.

    폴백이 없으면 나이와 무관하게 전부 '무근거' 로 묶여, 3일 된 역할이 삭제 검토로 올라간다.
    """
    old = _rec(age_days=560, create_date=_days_before(560))
    young = _rec(age_days=3, create_date=_days_before(3))
    assert is_unused_role(old, RULES.unused_role_days) is True
    assert is_unused_role(young, RULES.unused_role_days) is False


# ---- M2 통합: 등급이 실제 파이프라인에서 채워진다 ----


def test_normalize_fills_tier_from_role_last_used(tmp_path) -> None:
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, role_last_used=_days_before(1076), role_last_used_region="ap-northeast-1")
    r = normalize(storage, RUN, RULES)[0]
    assert (r.unused_days, r.unused_days_basis, r.unused_tier) == (
        1076, "role_last_used", "cleanup")


def test_normalize_withholds_tier_for_new_role(tmp_path) -> None:
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, create_date=_days_before(3), role_last_used=_days_before(1))
    r = normalize(storage, RUN, RULES)[0]
    assert r.unused_tier == "new", "관측 기간 3일로 'active' 를 주장할 수 없다"


def test_normalize_respects_config_boundaries(tmp_path) -> None:
    """대조군 — 같은 raw 에 다른 config 면 등급이 달라진다(임계치가 코드에 없다는 증거)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed(storage, role_last_used=_days_before(45))
    assert normalize(storage, RUN, RULES)[0].unused_tier == "watch"
    tight = RiskRules(unused_tier_days=[7, 14, 21], new_principal_days=1)
    assert normalize(storage, RUN, tight)[0].unused_tier == "cleanup"


# ---- 추이 정의 경계 ----


def test_metrics_carry_current_definition_version(tmp_path) -> None:
    """지표에 정의 버전이 실린다 — 없으면 정의 변경으로 줄어든 숫자를 '정리됐다' 로 읽는다."""
    from lp2ps.m6_reporter import build_reports
    from lp2ps.snapshot import DEFINITION_VERSION, write_snapshot

    st = LocalFSStorage(tmp_path, "test", "run-x")
    st.write_normalized([_rec(unused_days=1076, unused_days_basis="role_last_used",
                              unused_tier="cleanup", role_last_used=_days_before(1076),
                              age_days=1500)])
    st.write_json("catalog.json", [])
    from lp2ps.config import Config

    cfg = Config.model_validate({"customer": "test", "region": "us-west-2",
                                 "cross_account": False, "accounts": ["self"]})
    build_reports(st, RUN, cfg)
    point = write_snapshot(st, RUN, account_scope=1, status="succeeded",
                           risk_rules=cfg.risk_rules)
    assert point.definition_version == DEFINITION_VERSION
    assert DEFINITION_VERSION >= 2, "unused_role 재정의 이후 버전은 1 이 아니다"
    assert point.unused_roles == 1


def test_legacy_timeseries_entry_defaults_to_old_definition() -> None:
    """이 필드가 없던 시절의 시계열 항목은 **1(구 정의)** 로 읽힌다.

    기본값을 현재 버전으로 두면 구 정의 숫자가 신 정의라고 주장해 경계선이 사라진다 — 이 필드를
    만든 목적 자체가 무효화된다.
    """
    legacy = MetricsPoint.model_validate({"run_id": "run-old", "ts": "2026-06-01T00:00:00Z"})
    assert legacy.definition_version == 1


def test_tier_distribution_accounts_for_every_record(tmp_path) -> None:
    """등급 분포의 합 = 레코드 수. 근거 없는 것은 0 이 아니라 `ungraded` 로 센다."""
    from lp2ps.m6_reporter import build_reports
    from lp2ps.snapshot import write_snapshot

    st = LocalFSStorage(tmp_path, "test", "run-x")
    recs = [
        _rec(principal=f"{ARN}-a", unused_days=5, unused_tier="active", age_days=100),
        _rec(principal=f"{ARN}-b", unused_days=45, unused_tier="watch", age_days=100),
        _rec(principal=f"{ARN}-c", unused_days=70, unused_tier="review", age_days=100),
        _rec(principal=f"{ARN}-d", unused_days=1076, unused_tier="cleanup", age_days=1500),
        _rec(principal=f"{ARN}-e", unused_days=2, unused_tier="new", age_days=2),
        _rec(principal=f"{ARN}-f"),  # 근거 없음 → ungraded
    ]
    st.write_normalized(recs)
    st.write_json("catalog.json", [])
    from lp2ps.config import Config

    cfg = Config.model_validate({"customer": "test", "region": "us-west-2",
                                 "cross_account": False, "accounts": ["self"]})
    build_reports(st, RUN, cfg)
    dist = write_snapshot(st, RUN, account_scope=1, status="succeeded",
                          risk_rules=cfg.risk_rules).unused_tier_dist
    assert (dist.active, dist.watch, dist.review, dist.cleanup, dist.new, dist.ungraded) == (
        1, 1, 1, 1, 1, 1)
    assert sum(dist.model_dump().values()) == len(recs)
