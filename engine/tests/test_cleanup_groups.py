"""조치 필요 항목의 **3그룹**(삭제 검토 / 권한 축소 / 확인 필요) + 제외 게이트.

이 파일이 지키는 것 — 전부 라이브 실측에서 나온 결함이다:

- **결함 C**: 제외(R6)된 대상 87개가 164건의 조치 권고를 달고 목록에 올라와 있었다. AWS 소유
  역할에 "실사용 기반 정책으로 교체", CDK 부트스트랩 역할에 "와일드카드 재작성" — 할 수 없거나
  하면 배포가 깨지는 조치다. `is_unused_role` 만 게이트를 갖고 있었고 나머지 유형은 없었다.
- **결함 D**: 199일·1,066일 미사용인데 **권한이 하나도 없는** 역할 2개가 목록에서 빠졌다.
  권한이 없다는 것은 지우기 **가장 안전한** 근거인데 제외 사유로 쓰였고, 그래서 대시보드
  "삭제 검토 128" 과 목록 126행이 어긋났다.
- **어서션 1**: 카드의 큰 숫자 == 그 카드가 여는 목록의 행 수. 단위 불일치(KPI 는 action 41,451,
  목록은 principal 329행)가 같은 종류의 결함이었다.
- **어서션 2**: 세 그룹은 서로소이고 합이 목록 전체다. 유형(type)으로 묶던 시절에는 같은 역할이
  '미사용 역할' 과 '미사용 권한' 두 카드에 동시에 나왔다(126건 중 121건).
- 아무것도 **조용히 사라지지 않는다**(R6): 제외는 개수로 남고, 항목 유형이 하나도 안 걸리는
  대상(`no_used_actions`)은 `unverified_usage` 로 목록에 남는다.
"""

from __future__ import annotations

import itertools

from lp2ps.config import Config
from lp2ps.m6_reporter import (
    _RECOMMENDATION,
    cleanup_group,
    cleanup_items,
    summarize_exclusions,
    summarize_groups,
)
from lp2ps.models import EscalationPath, PrincipalRecord, UsedAction

CFG = Config(customer="test")
RULES = CFG.risk_rules
ACCOUNT = "111122223333"


def _role(name: str, **kw) -> PrincipalRecord:
    base = dict(
        account_id=ACCOUNT,
        principal=f"arn:aws:iam::{ACCOUNT}:role/{name}",
        identity_type="role",
        granted_actions=["s3:GetObject"],
        risk_level="low",
        run_id="run-x",
    )
    base.update(kw)
    return PrincipalRecord(**base)  # type: ignore[arg-type]


def _idle(name: str, days: int = 1500, **kw) -> PrincipalRecord:
    """미사용 N일 이상 + 신뢰 대상이 내부로 확인된 역할(= 삭제 검토 후보)."""
    base = dict(unused_days=days, unused_days_basis="role_last_used", unused_tier="cleanup",
                age_days=days + 100, trust_scope="internal", track="delete_review")
    base.update(kw)
    return _role(name, **base)


# ---- 결함 D: 권한이 없는 오래된 미사용 역할이 목록에서 빠졌다 ----


def test_idle_role_with_no_permissions_is_listed(tmp_path) -> None:
    """권한이 하나도 없는 199일 미사용 역할도 '삭제 검토' 로 올라온다.

    라이브에서 정확히 2건(199일·1,066일)이 이 조건으로 빠졌다. 둘 다 track 은 `delete_review` 라
    대시보드는 128 로 셌는데 목록은 126행이었다 — 카드를 눌러 열면 2건이 없다. 권한이 없다는
    사실은 제외 사유가 아니라 **삭제해도 아무것도 깨지지 않는다는 근거**다.
    """
    rec = _idle("no-perms", days=199, granted_actions=[], has_managed_policies=False)
    items = cleanup_items([rec], CFG)
    assert [i.type for i in items] == ["unused_role"], [i.type for i in items]
    assert items[0].group == "delete_review"


def test_idle_role_with_permissions_still_listed(tmp_path) -> None:
    """대조군 — 권한이 있는 쪽은 원래도 올라왔다. 위 테스트가 조건 제거를 재는 것이 맞는지 가른다."""
    items = cleanup_items([_idle("has-perms", days=199)], CFG)
    assert "unused_role" in {i.type for i in items}


# ---- 결함 C: 제외가 모든 유형보다 먼저 이긴다 ----

_EXCLUDED_ONLY = ("service_linked", "iac_bootstrap_role", "idc_reserved", "tool_readonly_role")


def _rich(name: str, **kw) -> PrincipalRecord:
    """조치 유형이 여러 개 걸리는 역할 — 미사용 권한 + 와일드카드 + 상승 경로."""
    base = dict(
        granted_actions=["s3:*", "iam:PassRole", "s3:GetObject"],
        used_actions=[UsedAction(action="s3:GetObject")],
        unused_findings=["s3:DeleteBucket", "s3:PutBucketPolicy"],
        wildcard_grants=["s3:*"],
        escalation_paths=[EscalationPath(via="iam:PassRole", to="admin-role", mitre="T1078")],
    )
    base.update(kw)
    return _role(name, **base)


def test_exclusion_suppresses_every_type() -> None:
    """제외된 대상은 미사용 권한·와일드카드·상승 경로 **어느 유형으로도** 올라오지 않는다.

    예전 코드는 이 세 유형을 "미사용 여부·트랙과 무관하게" 올렸다. 미사용 여부와 무관해야 한다는
    판단은 맞았고, **제외와도 무관하다**는 것이 틀렸다.
    """
    for reason in _EXCLUDED_ONLY:
        rec = _rich(f"x-{reason}", track="excluded", excluded_reason=reason)
        assert cleanup_group(rec, RULES) is None, reason
        assert cleanup_items([rec], CFG) == [], reason


def test_same_role_appears_when_not_excluded() -> None:
    """대조군 — track 만 바꾸면 같은 레코드가 3건으로 올라온다.

    이것이 없으면 위 테스트는 "제외를 걸렀다" 가 아니라 "레코드가 애초에 아무 유형에도 안 걸린다"
    로도 통과한다(실패할 수 없는 어서션 = 미측정).
    """
    rec = _rich("visible", track="service_role")
    types = {i.type for i in cleanup_items([rec], CFG)}
    assert types == {"unused_permission", "wildcard_grant", "escalation_path"}, types


def test_exclusion_entry_reports_what_it_hid() -> None:
    """제외는 **개수로 남는다**(R6) — 대상 수와 숨긴 권고 건수 둘 다.

    숨긴 건수를 안 내면 게이트를 넣은 뒤 숫자가 반토막 난 것이 "정리됐다" 로 읽힌다. 실제로는
    처음부터 조치 대상이 아니었다는 사실이 화면에서 사라진 것이다.
    """
    recs = [_rich("a", track="excluded", excluded_reason="service_linked"),
            _rich("b", track="excluded", excluded_reason="service_linked"),
            _rich("c", track="excluded", excluded_reason="iac_bootstrap_role")]
    by_reason = {e.reason: e for e in summarize_exclusions(recs, CFG)}
    assert by_reason["service_linked"].targets == 2
    assert by_reason["service_linked"].suppressed_items == 6  # 대상당 3건
    assert by_reason["service_linked"].basis == "aws_owned"
    assert by_reason["iac_bootstrap_role"].basis == "customer_declared"
    assert by_reason["service_linked"].label != "service_linked", "원값이 아니라 사람이 읽는 라벨"
    # 대상 목록까지 낸다 — `customer_declared` 는 "패턴이 잘못 걸렸나" 를 고객만 알아볼 수 있고,
    # 개수만 있으면 잘못 걸린 역할을 찾을 방법이 없다.
    assert by_reason["iac_bootstrap_role"].principals == [_role("c").principal]


# ---- too_new 는 둘로 갈린다: 사용 근거가 없는 것만 '확인 필요' ----


def test_too_new_without_usage_goes_to_needs_confirmation() -> None:
    rec = _role("brand-new", track="excluded", excluded_reason="too_new",
                age_days=5, used_actions=[], used_services=[], unused_tier="new")
    assert cleanup_group(rec, RULES) == "needs_confirmation"
    assert "new_role_unused" in {i.type for i in cleanup_items([rec], CFG)}


def test_too_new_but_actively_used_stays_excluded() -> None:
    """실측 35건 중 25건은 실제로 쓰이는 중이었다 — 확인 목록에 넣으면 판단이 필요한 7건이 묻힌다.

    `role_last_used` 만 있고 `used_actions` 가 빈 3건(Access Advisor 의 action 추적이 그 서비스를
    안 덮는 경우)도 같은 이유로 제외에 남는다: 서비스 단위 근거가 곧 '쓰이는 중' 이라는 사실이다.
    """
    used = _rich("new-but-used", track="excluded", excluded_reason="too_new", age_days=5,
                 unused_tier="new")
    assert cleanup_group(used, RULES) is None
    svc_only = _role("new-svc-evidence", track="excluded", excluded_reason="too_new", age_days=9,
                     unused_tier="new", used_actions=[], used_services=["events"],
                     role_last_used="2026-09-01T00:00:00Z")
    assert cleanup_group(svc_only, RULES) is None


# ---- 아무것도 조용히 사라지지 않는다 ----


def test_no_used_actions_target_still_appears() -> None:
    """action 단위 근거가 없어 제외된 대상도 목록에 남는다 — 유형은 `unverified_usage`.

    라이브에서 이 사유 2건 중 1건은 다른 유형(wildcard)으로도 올라오지만 나머지 1건은 어느 유형에도
    걸리지 않아, '확인 필요' 카드가 약속한 18건이 17건이 됐다. 화면에서 통째로 사라진 것이다(R6).
    """
    rec = _role("no-actions", track="excluded", excluded_reason="no_used_actions",
                used_actions=[], used_services=["s3"], unused_findings=[])
    items = cleanup_items([rec], CFG)
    assert [i.type for i in items] == ["unverified_usage"], [i.type for i in items]
    assert items[0].group == "needs_confirmation"
    assert "삭제" not in items[0].recommendation or "권고 아님" in items[0].recommendation


def test_needs_confirmation_recommendation_says_confirm_first() -> None:
    """'확인 필요' 카드 안의 권고는 조치를 먼저 말하지 않는다 — 카드 제목과 행이 반대를 말하면 안 된다.

    사실(와일드카드 보유)은 지우지 않는다. 그 사실이 바로 확인을 서둘러야 하는 이유다. 다만 F18
    이후 그 사실이 사는 곳은 **권고문이 아니라 detail·evidence** 다 — 권고 칸은 조치 한 줄이다.
    """
    rec = _rich("vendor-role", track="owner_review", trust_scope="unconfirmed",
                unused_days=400, unused_days_basis="role_last_used", unused_tier="cleanup",
                age_days=500)
    wildcard = next(i for i in cleanup_items([rec], CFG) if i.type == "wildcard_grant")
    assert wildcard.group == "needs_confirmation"
    assert wildcard.recommendation.startswith("소유자·용도 확인 후: ")
    # 안전장치 괄호는 남는다(개수를 셀 수 없다는 사실을 조치문 안에 박아둔다).
    assert "제거 개수 산정 불가" in wildcard.recommendation
    # 🔴 F18 은 **길이**도 요구다. 접두문이 문장으로 되돌아가면(라이브에서 83자였다) 이 줄이 잡는다 —
    #    라이브 CSV 전수 검사와 같은 바(60자)를 여기서도 건다.
    assert len(wildcard.recommendation) <= 60, wildcard.recommendation
    # 사실은 사라지지 않았다 — 옮겨졌다. 이 두 줄이 없으면 F18 은 정보 손실이 된다.
    assert "s3:*" in wildcard.detail
    assert "s3:*" in wildcard.evidence["보유 와일드카드"]


def test_delete_review_row_does_not_ask_for_a_policy_rewrite_first() -> None:
    """'삭제 검토' 카드 안의 권한 축소 항목은 **삭제 검토가 먼저**라고 말한다.

    신 미사용 판정(오래된 흔적도 미사용) 이후 한 대상이 `unused_role` 과 `unused_permission`·
    와일드카드를 함께 들고 삭제 검토로 넘어온다(라이브 84개 중 58개). 권고문을 그대로 두면 같은
    대상이 "지워라" 와 "실사용 기준으로 정책을 다시 써라" 를 동시에 말한다 — #6 과 같은 자기모순.
    """
    rec = _rich("stale-service-role", track="delete_review", trust_scope="service",
                unused_days=1103, unused_days_basis="role_last_used", unused_tier="cleanup",
                age_days=1300, used_actions=[UsedAction(action="s3:GetObject",
                                                        last_used="2023-08-29T00:00:00Z")])
    items = cleanup_items([rec], CFG)
    assert {i.group for i in items} == {"delete_review"}
    assert "unused_role" in {i.type for i in items}, "삭제 검토 대상이면 대표 항목이 있어야 한다"
    wildcard = next(i for i in items if i.type == "wildcard_grant")
    assert wildcard.recommendation.startswith("삭제하지 않는다면: ")
    # 사실(와일드카드 보유)은 권고문이 아니라 detail·evidence 에 있다(F18).
    assert "s3:*" in wildcard.detail
    assert "s3:*" in wildcard.evidence["보유 와일드카드"]
    assert "제거 개수 산정 불가" in wildcard.recommendation
    # 대조군: 미사용이 아니면 접두어가 붙지 않는다(붙었다면 접두어가 무조건 붙는 것이다).
    live = _rich("live-role", track="service_role", trust_scope="service", unused_days=3,
                 unused_days_basis="role_last_used", unused_tier="active", age_days=1300)
    live_wc = next(i for i in cleanup_items([live], CFG) if i.type == "wildcard_grant")
    assert live_wc.group == "reduce_scope"
    assert not live_wc.recommendation.startswith("삭제하지 않는다면")


def test_recommendations_are_compact_verb_phrases() -> None:
    """권고 칸은 **조치 한 줄**이다 — 근거를 되풀이하는 괄호·설명절·둘째 문장을 붙이지 않는다(F18).

    🔴 "괄호가 없다" 로 재면 안 된다. 두 종류의 괄호는 문구가 아니라 **안전장치**이고 지워지면
    사람이 잘못된 조치를 한다: `(삭제 권고 아님)`(R5/R6 — 확인이 조치인 유형이 삭제 계열과 한 칸에
    섞여 보인다)·`(제거 개수 산정 불가)`(`*` 는 제거 개수를 셀 수 없다). 그래서 **허용 목록 밖의
    괄호가 없다**로 잰다.

    이 어서션들은 실패할 수 있다 — F18 이전 문구 전부가 여기 걸린다: `(미사용 — PS 카탈로그에
    불필요)`·`(persona 검토 화면에서 … 받아 적용)`·`(장기 키 폐기)`·`(예: aws:PrincipalOrgID)` 는
    괄호 허용 목록에 없고, `신규 역할 — 관측 기간이 짧다.` 는 설명절(`—`)과 둘째 문장(`.`)에,
    `**재작성**` 은 마크다운 검사에 걸린다(화면은 마크다운을 렌더하지 않는다 — 별표가 그대로 보였다).
    """
    # 조치 자체를 특정하는 데 필요한 괄호만 허용한다(안전장치 2종 + API·제품명 표기).
    allowed = ("(삭제 권고 아님)", "(제거 개수 산정 불가)", "(sts:AssumeRole)", "(SSO)", "(SSO+MFA)")
    for ctype, texts in _RECOMMENDATION.items():
        for text in dict.fromkeys(texts):  # IdC/비IdC 문구가 같으면 한 번만 본다
            rest = text
            for token in allowed:
                rest = rest.replace(token, "")
            assert "(" not in rest and ")" not in rest, (ctype, text)
            assert "—" not in text, (ctype, text)
            assert "." not in text, (ctype, text)
            assert "**" not in text, (ctype, text)
            assert len(text) <= 50, (ctype, len(text), text)


def test_stale_role_with_old_traces_lands_in_delete_review() -> None:
    """🔴 3년 전에 마지막으로 쓰인 서비스 역할은 **삭제 검토 카드에 있다**(결함 #9).

    이 대상은 예전에 어느 카드에도 없었다: 미사용 판정이 흔적의 부재를 요구해 '쓰이는 중' 으로
    갈렸고, 그러면서 권한 축소 카드에는 미사용 권한 항목으로만 올라오거나(=지워도 되는 것을
    "정책을 다시 쓰라" 고 권고) 아무 항목도 없어 사라졌다.
    """
    rec = _role("archived-etl", trust_scope="service", unused_days=1103,
                unused_days_basis="role_last_used", unused_tier="cleanup", age_days=1300,
                used_services=["s3"],
                used_actions=[UsedAction(action="s3:GetObject",
                                         last_used="2023-08-29T00:00:00Z")])
    items = cleanup_items([rec], CFG)
    unused = next(i for i in items if i.type == "unused_role")
    assert unused.group == "delete_review"
    # 증거는 흔적을 숨기지 않는다 — 숨기면 고객이 콘솔에서 그 흔적을 보고 목록을 안 믿는다.
    assert unused.evidence["사용 흔적 서비스"] == "s3"
    assert "2023-08-29" in unused.evidence["수집된 사용 흔적"]


def test_two_cards_do_not_disagree_about_the_same_grant() -> None:
    """🔴 와일드카드와 미사용 권한은 **범위가 다르다**는 것을 카드에 적는다(결함 B).

    라이브: 와일드카드 카드는 "미사용 개수 산정: 불가", 미사용 권한 카드는 같은 대상에 "미사용
    N건" 을 센다. `*` 안에 그 N건이 포함돼 있으므로 둘 다 참인데, 범위를 안 적으면 한 대상의 두
    카드가 서로를 반박하는 것으로 읽힌다.
    """
    rec = _rich("wide", track="service_role")
    items = {i.type: i for i in cleanup_items([rec], CFG)}
    assert "예(s3:*)" in items["unused_permission"].evidence["와일드카드 보유"]
    assert "명시 부여분만" in items["unused_permission"].evidence["와일드카드 보유"]
    assert items["wildcard_grant"].evidence["미사용 개수 산정"].startswith("불가")
    # 대조군: 와일드카드가 없으면 그 줄이 아예 없다(무조건 붙는 문구가 아니다).
    plain = _rich("narrow", track="service_role", wildcard_grants=[])
    plain_item = next(i for i in cleanup_items([plain], CFG) if i.type == "unused_permission")
    assert "와일드카드 보유" not in plain_item.evidence


def test_unused_count_states_what_it_excludes() -> None:
    """🔴 `근거 불명` 을 미사용에 합산하지 않는다는 정의를 카드에 싣는다(결함 D).

    라이브에 `실사용 0` 인데 `미사용 5 / 근거 불명 5`(부여 10)인 대상이 있었다. 삭제 검토 카드
    안에서 "미사용 5" 만 읽으면 나머지 절반은 문제가 없는 것처럼 보인다.
    """
    rec = _rich("half-unknown", track="service_role",
                undetermined_findings=["ec2:DescribeTags", "ec2:DescribeVolumes"])
    item = next(i for i in cleanup_items([rec], CFG) if i.type == "unused_permission")
    assert item.evidence["근거 불명 action 수"] == "2"
    assert item.evidence["미사용 셈 기준"] == "근거 불명 2건은 미사용에 합산하지 않음"
    # 대조군: 근거 불명이 0 이면 다른 문장이 나온다 — 같은 문구를 항상 내면 정보가 없다.
    none_left = next(i for i in cleanup_items([_rich("all-known", track="service_role")], CFG)
                     if i.type == "unused_permission")
    assert none_left.evidence["미사용 셈 기준"] == "부여 action 전부에 사용 근거 판정이 있음"


# ---- '확인 필요' 두 갈래가 화면에서 쓸 값 ----


def test_new_role_carries_days_until_judgment() -> None:
    """'기다리면 알 수 있는 것' 은 **남은 일수**로 정렬한다 — 그 값을 엔진이 낸다.

    화면이 detail 문장("생성 후 5일 경과")에서 숫자를 긁으면 문구를 다듬는 순간 정렬이 죽는다.
    임계(`new_principal_days`)도 고객 config 값이라 화면이 알 수 없다.
    """
    rec = _role("brand-new", track="excluded", excluded_reason="too_new",
                age_days=RULES.new_principal_days - 4, used_actions=[], used_services=[],
                unused_tier="new")
    item = next(i for i in cleanup_items([rec], CFG) if i.type == "new_role_unused")
    assert item.evidence["판정까지 남은 일수"] == "4"


def test_unconfirmed_trust_role_carries_trust_accounts() -> None:
    """'확인해야 알 수 있는 것' 은 **신뢰 계정별로 묶는다** — 계정 ID 를 따로 싣는다.

    '신뢰 대상' 줄은 ARN 원문이고 5개로 잘려 있어서, 화면이 그것을 파싱하면 6번째 계정이 조용히
    사라진다. 서비스 principal(계정 없음)은 묶음에 넣지 않는다.
    """
    other = "444455556666"
    rec = _role("vendor", track="owner_review", trust_scope="unconfirmed",
                unused_days=400, unused_days_basis="role_last_used", unused_tier="cleanup",
                age_days=500,
                trust_principals=[f"arn:aws:iam::{other}:root", "events.amazonaws.com",
                                  f"arn:aws:iam::{ACCOUNT}:role/x"])
    item = next(i for i in cleanup_items([rec], CFG) if i.type == "unconfirmed_trust_role")
    assert item.evidence["신뢰 계정"] == f"{ACCOUNT}, {other}"


def test_tooling_trust_row_does_not_say_external() -> None:
    """`tooling` 신뢰(= 이 도구가 사는 계정만 신뢰)에 "외부 연동 의심" 이라고 쓰면 안 된다.

    라이브 17건 중 6건이 그 상태였다 — 한 줄 문장은 "외부 연동 의심", 같은 행의 증거 표는 "정상
    운영 경로" 라고 말해 행이 자기와 모순됐다. 분류(`unconfirmed_trust_role` → 소유자 확인)는
    의도된 것이라 그대로다: 내부라고 **확인**한 것은 아니다.
    """
    rec = _role("stackset-exec", track="owner_review", trust_scope="tooling",
                unused_days=400, unused_days_basis="role_last_used", unused_tier="cleanup",
                age_days=500,
                trust_principals=[f"arn:aws:iam::{ACCOUNT}:role/admin-role"])
    item = next(i for i in cleanup_items([rec], CFG) if i.type == "unconfirmed_trust_role")
    assert "외부" not in item.detail, item.detail
    assert "이 도구가 사는 계정" in item.detail, item.detail
    # 대조군 — 수집 밖 계정을 신뢰하면 그 문구가 **맞다**(위 어서션에 판별력이 있음을 증명).
    vendor = _role("vendor", track="owner_review", trust_scope="unconfirmed",
                   unused_days=400, unused_days_basis="role_last_used", unused_tier="cleanup",
                   age_days=500, trust_principals=["arn:aws:iam::444455556666:root"])
    other = next(i for i in cleanup_items([vendor], CFG) if i.type == "unconfirmed_trust_role")
    assert "외부 연동 의심" in other.detail, other.detail


# ---- 가드 어서션 2개 ----


def _mixed() -> list[PrincipalRecord]:
    """세 그룹이 모두 나오고, 한 대상이 여러 유형에 걸리는 표본."""
    return [
        _idle("idle-a"), _idle("idle-b", granted_actions=[], has_managed_policies=False),
        _rich("active-svc", track="service_role"),
        _rich("active-human", track="persona", principal_kind="human"),
        _rich("vendor", track="owner_review", trust_scope="unconfirmed", unused_days=400,
              unused_days_basis="role_last_used", unused_tier="cleanup", age_days=500),
        _role("new", track="excluded", excluded_reason="too_new", age_days=3, unused_tier="new",
              used_actions=[], used_services=[]),
        _role("svc-linked", track="excluded", excluded_reason="service_linked",
              wildcard_grants=["*"], unused_findings=["s3:Delete*"]),
    ]


def test_card_number_equals_row_count_of_the_list_it_opens() -> None:
    """카드의 큰 숫자는 **그 카드가 여는 목록의 행 수**로 정의된다.

    예전 대시보드 KPI 는 action(41,451)을 세고, 눌러서 열린 목록은 principal(329행)을 셌다. 숫자를
    각자 계산하는 것이 원인이었으므로, 정의를 한 곳에 두고 여기서 못박는다. 목록은 대상 1행이다.
    """
    recs = _mixed()
    items = cleanup_items(recs, CFG)
    for card in summarize_groups(items, recs):
        rows = {(i.account_id, i.principal) for i in items if i.group == card.group}
        assert card.targets == len(rows), f"{card.group}: 카드 {card.targets} vs 목록 {len(rows)}"
        assert card.items == sum(1 for i in items if i.group == card.group)


def test_three_cards_are_disjoint_and_sum_to_the_whole() -> None:
    """한 대상은 정확히 한 카드에만 있다 — 유형으로 묶던 시절의 자기모순을 차단한다.

    `unused_role` 126건 중 121건이 `unused_permission` 도 갖고 있어서, 같은 역할이 '지워라' 와
    '정책을 다시 써라' 두 카드에 동시에 나왔다.
    """
    recs = _mixed()
    items = cleanup_items(recs, CFG)
    sets = [
        {(i.account_id, i.principal) for i in items if i.group == g}
        for g in ("delete_review", "reduce_scope", "needs_confirmation")
    ]
    for a, b in itertools.combinations(sets, 2):
        assert not (a & b), a & b
    assert set().union(*sets) == {(i.account_id, i.principal) for i in items}
    assert all(i.group is not None for i in items), "엔진이 낸 항목에 미분류는 없다"


def test_group_totals_and_exclusions_account_for_every_record() -> None:
    """대상 전체 = 세 카드 + 제외. 어느 대상도 두 곳에 없고, 어느 대상도 빠지지 않는다."""
    recs = _mixed()
    groups = {cleanup_group(r, RULES) for r in recs}
    assert None in groups, "표본에 제외 대상이 있어야 이 테스트가 의미가 있다"
    in_cards = sum(1 for r in recs if cleanup_group(r, RULES) is not None)
    excluded = sum(e.targets for e in summarize_exclusions(recs, CFG))
    assert in_cards + excluded == len(recs)
