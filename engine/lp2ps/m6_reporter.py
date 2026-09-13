"""M6 Reporter — cleanup 백로그 + 리포트 + exec summary.

M3/M4/M5 로 enrich 된 normalized.parquet + catalog 를 읽어:
- `cleanup_backlog.csv` — CleanupItem 목록(유형 정본은 `models.CleanupType`: unused_permission/
  unused_role/new_role_unused/long_lived_key/no_mfa/escalation_path/wildcard_grant/
  trust_policy_wildcard/…). UI 는 카테고리 요약→드릴다운.
- `exec_summary.json` — ExecSummary(accounts/principals/personas/unused_permission_*/generated_at).
- `report.html` — 사람이 읽는 요약(결정론 정적 HTML).

불변식 ②(결정론): 안정 정렬, generated_at 은 run.started_at(유일 허용 wall-clock)에서. 불변식 ③: AI 미사용.
"""

from __future__ import annotations

import csv
import html
import io
import re
from typing import TYPE_CHECKING

from .models import (
    ActionGroupMetrics,
    CatalogEntry,
    CleanupGroup,
    CleanupItem,
    CleanupType,
    ExclusionEntry,
    ExecSummary,
    PrincipalRecord,
)

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config, RiskRules
    from .runctx import RunContext
    from .storage import Storage

BACKLOG_NAME = "cleanup_backlog.csv"

# 권장 조치 문구. IdC 를 쓰는 고객에게만 "Permission Set 로 마이그레이션" 이 실행 가능한 조언이다 —
# IdC 가 없는 고객에게 그렇게 쓰면 조치할 수 없는 항목을 영구히 안고 가게 된다(그 고객은 정책을
# 다듬어 IAM 정책/역할로 적용하는 것이 완결된 조치다). 문구만 다르고 판정 로직은 동일하다.
#
# 🔴 **동사구만 쓴다**(F18). 이 칸은 "무엇을 할 것인가" 한 칸이고, 그 판단의 **근거는 detail 과
# evidence 가 이미 말한다** — 같은 사실을 권고문에 다시 넣으면 한 줄이 두 문장이 되고 조치가 흐려진다.
# 예: "역할 삭제 (미사용 — PS 카탈로그에 불필요)" → "역할 삭제"(미사용 기간·근거는 상세에 있다).
#
# 🔴 다만 **괄호를 일괄로 걷어내면 안 된다.** 남긴 괄호 두 종류는 문구가 아니라 안전장치다:
#   - `(삭제 권고 아님)` — R5/R6. 이 유형들은 "확인" 이 조치인데, 목록에서 삭제 계열과 한 칸에
#     섞여 보이므로 "지우라는 말이 아니다" 를 조치문 안에 박아둔다.
#   - `(제거 개수 산정 불가)` — `*` 부여는 제거할 개수를 셀 수 없다. 개수를 말하는 순간 "그만큼만
#     지우면 최소권한" 이 되고 `*` 는 남는다.
_RECOMMENDATION: dict[str, tuple[str, str]] = {
    # type: (IdC 사용, IdC 미사용)
    "unused_role": (
        "역할 삭제",
        "역할 삭제",
    ),
    # 관측 기간이 짧아 판단 근거가 부족한 신규 역할. **삭제를 권고하지 않는다** —
    # 어제 만든 역할에 사용 기록이 없는 건 당연하고, 그걸 근거로 지우면 배포 중인 것을 깬다.
    # (관측 기간이 짧다는 사실·판정까지 남은 일수는 detail 과 evidence 가 말한다.)
    "new_role_unused": (
        "용도 확인 후 판단 (삭제 권고 아님)",
        "용도 확인 후 판단 (삭제 권고 아님)",
    ),
    "unused_permission": (
        "실사용 기반 최소권한 Permission Set 로 마이그레이션",
        "실사용 기반 최소권한 IAM 정책으로 교체",
    ),
    "long_lived_key": (
        "액세스키 폐기 후 Identity Center(SSO) 임시 자격증명으로 전환",
        "액세스키 폐기 후 IAM Role 임시 자격증명(sts:AssumeRole)으로 전환",
    ),
    "no_mfa": (
        "IAM User 폐기 후 Identity Center(SSO+MFA)로 전환",
        "이 IAM User 에 MFA 설정",
    ),
    "escalation_path": (
        "상승 유발 권한 제거 후 최소권한 Permission Set 로 마이그레이션",
        "상승 유발 권한 제거 후 최소권한 IAM 정책으로 교체",
    ),
    # 🔴 "미사용 N개 제거" 라고 쓰지 않는다. 부여 범위에 상한이 없어 제거할 개수를 셀 수 **없다** —
    # 개수를 말하면 그 수만 지우면 최소권한이 된다는 뜻이 되고, `*` 는 그대로 남는다.
    "wildcard_grant": (
        "실사용 기반 Permission Set 로 재작성 (제거 개수 산정 불가)",
        "실사용 기반 최소권한 정책으로 재작성 (제거 개수 산정 불가)",
    ),
    # 🔴 **삭제를 권고하지 않는다.** 90일 이상 미사용이지만 신뢰 대상이 우리 테넌트로 확인되지 않은
    # 역할이다 — 실측에서 이 부류의 다수가 벤더·외부 도구가 심어놓은(안 쓰이는 게 정상인) 역할이었다.
    # 여기에 삭제 권고를 붙이면 고객이 벤더 연동을 끊고, 그 한 건으로 목록 전체의 신뢰가 깨진다(R5).
    # (신뢰 대상을 확인할 수 없다는 사실은 detail 과 evidence '신뢰 범위 판정' 이 말한다.)
    "unconfirmed_trust_role": (
        "소유자·용도 확인 후 판단 (삭제 권고 아님)",
        "소유자·용도 확인 후 판단 (삭제 권고 아님)",
    ),
    # 미사용 여부와 무관한 **경계 위반 의심**이다. 조치는 삭제도 정책 재작성도 아니고, 이 신뢰가
    # 의도된 것인지 확인하는 것이다. 의도된 연동일 때 할 일(config 그룹 선언 수정)은 조치문에서
    # 빼고 evidence '의도된 연동이라면' 으로 옮겼다 — 한 칸에 두 조치를 적으면 둘 다 안 읽힌다.
    "cross_tenant_trust": (
        "경계 위반인지 확인 (삭제 권고 아님)",
        "경계 위반인지 확인 (삭제 권고 아님)",
    ),
    # 🔴 **삭제도 정책 재작성도 권고하지 않는다.** 실사용 근거가 서비스 단위로는 있는데 action 단위로
    # 없는 대상이다 — 최소권한 정책을 만들면 그 정책은 빈 정책이거나 실제 사용을 빠뜨린다. 예전에는
    # 이 대상이 트랙 배정에서 `no_used_actions` 로 제외되고 백로그에 아무 유형도 없어, 화면에서
    # 통째로 사라졌다(R6 위반 — "왜 우리 역할이 여기 없지?" 에 답할 수 없다).
    "unverified_usage": (
        "용도 확인 후 판단 (삭제 권고 아님)",
        "용도 확인 후 판단 (삭제 권고 아님)",
    ),
    # 권한 범위 문제가 아니라 신뢰 경계 문제다 → 정책 재작성이 아니라 신뢰정책 자체를 좁혀야 한다.
    # 조건 예시(aws:PrincipalOrgID)는 evidence '권장 조건 예' 로 옮겼다.
    "trust_policy_wildcard": (
        "신뢰정책 `Principal` 을 특정 계정·역할로 좁히고 조건 추가",
        "신뢰정책 `Principal` 을 특정 계정·역할로 좁히고 조건 추가",
    ),
}


# 신뢰 범위(R5) 라벨. 증거에 원값(`unconfirmed`)만 적으면 고객이 "확인 안 된 것" 과 "외부로
# 확인된 것" 을 구분할 수 없다 — 이 도구는 후자를 판정하지 않는다(모르면 보수적으로).
_TRUST_SCOPE_LABEL = {
    "internal": "같은 테넌트 그룹(내부로 확인됨)",
    "cross_tenant": "다른 테넌트 그룹(경계 위반 의심)",
    "tooling": "이 도구가 사는 관리 계정(정상 운영 경로 — 내부로 확인한 것은 아님)",
    "service": "AWS 서비스",
    "unconfirmed": "확인되지 않음(외부라고 판정한 것이 아니다)",
}


# '지금 조치하라' 계열 유형. `needs_confirmation` 그룹(우리가 판단할 수 없는 대상)에서는 이 권고를
# 그대로 낼 수 없다 — 소유자를 확인하지 못한 벤더 역할에 "정책을 다시 써라" 고 하는 것은 "지워라" 와
# 같은 종류의 오판이고, 카드 제목("확인 필요")과 행의 권고가 서로 반대를 말하는 자기모순이 된다.
_ACT_NOW_TYPES: frozenset[str] = frozenset({
    "unused_permission", "wildcard_grant", "escalation_path", "trust_policy_wildcard",
})

# 확인이 먼저라는 사실을 권고문 앞에 붙인다. 사실(와일드카드 보유 등)은 지우지 않는다 — 그 사실이
# 바로 확인을 서둘러야 하는 이유다.
# 🔴 접두문을 압축했다(F18 후속, 라이브 실측 2026-09-11). 압축 전 문장은
# *"소유자·용도 확인이 먼저입니다(삭제·정책 변경 권고 아님). 확인된 뒤: "* 였고, 뒤에 붙는 조치문과
# 합쳐 **76~83자** 두 문장이 됐다(백로그 42행이 그랬다) — F18 이 `_DELETE_FIRST_PREFIX` 에서 고친
# 것과 **같은 종류의 결함**이고, 그때 이 접두문은 같이 안 고쳐졌다.
# 안전장치는 사라지지 않는다: `확인 후:` 라는 **조건절 자체**가 "지금 하지 말라" 를 말하고,
# 같은 카드가 이미 *"아직 판단할 수 없는 대상 — 조치 권고가 아닙니다"* 를 말한다(CSV 에도 `group`
# 열이 남는다). `(제거 개수 산정 불가)` 처럼 **셀 수 없다는 사실**을 담은 괄호는 그대로 둔다.
_CONFIRM_FIRST_PREFIX = "소유자·용도 확인 후: "

# 삭제 검토 대상에 붙는 '지금 조치하라' 권고. 미사용 판정이 사용 근거의 부재를 요구하던 동안에는
# 이 조합이 나올 수 없었다. 신 판정식(오래된 사용 흔적도 미사용)에서는 나온다 — 실측 84개 중 58개가
# 미사용 권한·와일드카드·상승 경로 항목을 함께 들고 삭제 검토로 넘어왔다. 그대로 두면 한 대상이
# "지워라" 와 "실사용 기준으로 정책을 다시 써라" 를 동시에 말한다(#6 과 같은 종류의 자기모순).
# 사실은 지우지 않는다 — 삭제하지 않기로 결정했을 때 할 일이 바로 그것이다.
# 접두문도 압축했다(F18): "이 대상은 미사용으로 삭제 검토 대상입니다" 는 이 묶음(삭제 검토 카드)에
# 있다는 사실을 되풀이하는 문장이고, 미사용 기간은 같은 행의 detail 이 말한다. 조건절만 남긴다.
_DELETE_FIRST_PREFIX = "삭제하지 않는다면: "


def _recommendation(ctype: CleanupType, uses_idc: bool, group: "CleanupGroup | None" = None) -> str:
    idc_text, plain_text = _RECOMMENDATION[ctype]
    text = idc_text if uses_idc else plain_text
    if group == "needs_confirmation" and ctype in _ACT_NOW_TYPES:
        return _CONFIRM_FIRST_PREFIX + text
    if group == "delete_review" and ctype in _ACT_NOW_TYPES:
        return _DELETE_FIRST_PREFIX + text
    return text


def cleanup_group(rec: PrincipalRecord, risk_rules: "RiskRules") -> "CleanupGroup | None":
    """이 대상이 화면의 어느 카드에 속하는가 — **3그룹 배정의 단일 소스**. `None` = 목록에 올리지 않음.

    `m5_tracks` 가 배정한 `track` 을 **읽는다**(다시 판정하지 않는다 — 모듈 계약). 그래서 카드가
    보여주는 묶음과 트랙이 어긋날 수 없다. 트랙 → 그룹 대응:

        delete_review            → delete_review       (쓰이지 않는다 → 지울지 검토)
        persona · service_role   → reduce_scope        (쓰이고 있다 → 권한 범위를 좁힌다)
        owner_review             → needs_confirmation  (신뢰 대상을 내부로 확인 못 했다)
        excluded                 → 대개 None. 두 사유만 통과한다(아래).
        None(미배정)              → `m5_tracks._track_of` 와 같은 판정식으로 직접 계산

    🔴 **제외가 그룹보다 먼저 이긴다.** 이 게이트가 없던 동안, 제외된 87개 대상이 164건의 조치 권고를
    달고 목록에 올라와 있었다(라이브 실측): AWS service-linked 역할에 "실사용 기반 정책으로 교체",
    IdC 예약 역할에 "상승 권한 제거", CDK 부트스트랩 역할에 "와일드카드 재작성". 셋 다 고객이 할 수
    없거나 하면 배포가 깨지는 조치다. `is_unused_role` 은 이미 같은 게이트를 갖고 있었지만 나머지
    유형(미사용 권한·와일드카드·상승 경로)은 "미사용 여부·트랙과 무관하게" 올라오도록 되어 있었다 —
    미사용 여부와 무관해야 한다는 판단은 맞았고, **제외와도 무관하다**는 것이 틀렸다.

    제외를 통과하는 두 사유는 근거 등급이 `judgment`(우리 판단) 인 것들이고, 판단이 뒤집힐 수 있으므로
    '확인 필요' 로 보낸다:
      - `too_new` — 단, **양성 사용 근거가 없는 것만**(`is_new_unused_role`). 실측 35건 중 25건은
        실제로 쓰이는 중이었다(사용 action > 0) — 쓰이는 것이 확인된 대상에게 확인을 요구하면
        확인 목록이 노이즈가 되고, 정작 판단이 필요한 7건이 그 안에 묻힌다.
      - `no_used_actions` — 서비스 단위로는 쓰이는데 action 단위 근거가 없다. 최소권한 정책을 만들
        수 없다는 사실 자체가 사람이 확인할 대상이다.
    """
    if rec.track == "delete_review":
        return "delete_review"
    if rec.track in ("persona", "service_role"):
        return "reduce_scope"
    if rec.track == "owner_review":
        return "needs_confirmation"
    if rec.track == "excluded":
        if rec.excluded_reason == "no_used_actions":
            return "needs_confirmation"
        if rec.excluded_reason == "too_new":
            return ("needs_confirmation"
                    if is_new_unused_role(rec, risk_rules.new_principal_days) else None)
        return None
    # 미배정(배정 전 레코드 · 이 필드가 없던 시절의 parquet). 제외로 읽지 않는다 — 배정 버그가
    # '정상적으로 제외됨' 으로 보이면 안 된다. `m5_tracks._track_of` 와 같은 순서로 계산한다.
    if is_idle_beyond(rec, risk_rules.unused_role_days):
        return "delete_review" if is_confirmed_internal(rec) else "needs_confirmation"
    return "reduce_scope"


def is_unused_role(rec: PrincipalRecord, unused_role_days: int) -> bool:
    """이 역할이 '미사용 N일 이상' 인가 — 미사용 판정식의 **단일 소스**(R3 신 정의).

    `snapshot._metrics_for` 가 같은 함수를 쓴다. 예전엔 두 곳이 각자 조건을 갖고 있었고
    (스냅샷은 `granted_actions` 만, m6 은 `granted_actions or has_managed_policies`) 그 결과
    대시보드 "미사용 역할 40" 과 백로그 59건이 어긋났다 — 주석은 "같은 판정식" 이라고 적혀
    있었지만 사실이 아니었다.

    🔴 **정의가 바뀌었다.** 구 정의는 "실사용 증거가 어느 층위에도 없다" 였고, 그래서 3년 전에 마지막
    으로 쓰인 역할이 '쓰인 적 있음' 으로 목록에서 빠졌다 — 정리 대상 중 가장 확실한 것이 빠진 셈이다.
    신 정의는 `unused_days`(① IAM 활동 기록 ② 없으면 생성일, M2 산출)가 임계 일수 이상인 것이다.
    임계치는 config(`risk_rules.unused_role_days`). 이 변경으로 이전 run 과 숫자를 직접 비교할 수
    없다 → `MetricsPoint.definition_version` 이 경계선을 그린다.

    양성 사용 근거 가드는 **일수 근거가 활동 기록이 아닐 때만** 남는다 — 자세한 이유는
    `is_idle_beyond` 의 docstring에 있다. 요지: `used_actions`/`used_services` 는 "쓰였다" 만 말하고
    "언제" 를 말하지 않아서, 3년 전에 마지막으로 쓰인 역할이 '쓰이는 중' 으로 목록에서 빠졌다.

    `unused_days` 가 없을 때는 `age_days` 로 내려간다. 사용 근거가 0 인 경우라면(가드 통과)
    이 부재는 M2 케이스 ③(사용 중이라 일수를 세지 않음)이 아니라, 이 필드가 없던 시절에 만들어진
    `normalized.parquet` 을 새 코드가 다시 읽는 경우다 — 그때도 M2 케이스 ②와 같은 근거(생성일)를
    쓰면 판정이 유지된다. 둘 다 없으면(날짜를 셀 근거가 아예 없음 = 정확히 구 정의의 '사용 근거
    전무') 목록에 **남긴다**. 여기서 빼면 증거가 가장 없는 역할이 오히려 백로그에서 사라진다
    (R6 위반). 일수 대신 `_unused_period` 가 '확인 불가' 로 서술한다.

    🔴 R6 제외(`track == "excluded"`)는 이 판정보다 **먼저** 이긴다. `m5_tracks` 모듈 계약이
    "이후 단계는 다시 판정하지 않고 이 값을 읽는다" 인데 이 함수가 그 값을 안 봐서, 라이브 실측에서
    AWS service-linked 역할 7개가 "역할 삭제" 권고를 달고 백로그에 올라왔다 — AWS 가 소유해 **고객이
    정책을 수정할 수 없는** 역할이고(삭제 자체는 `DeleteServiceLinkedRole` 로 가능하다 — "지울 수
    없다" 고 쓰면 틀린 말이다), 하나라도 그런 것이 섞이면 목록 전체를 안 믿는다. CDK 부트스트랩
    역할(config 패턴 제외)도 같은 경로로 '외부 연동 의심' 에 올라왔다.

    정의 변경이 아니라 **누락된 상위 게이트**이므로 `definition_version` 은 올리지 않는다. 미사용
    판정의 뜻("미사용 N일 이상")은 그대로이고, 애초에 조치 대상이 아닌 것을 세지 않게 된 것뿐이다.
    `track` 이 비어 있으면(배정 전 레코드) 게이트는 걸리지 않는다 — 미배정을 제외로 읽으면 배정
    버그가 '정상적으로 제외됨' 으로 보인다(`m5_tracks` 가 `track=None` 을 기본값으로 둔 이유).

    🔴 **부여 권한 보유를 조건으로 걸지 않는다.** 예전에는 `granted_actions or has_managed_policies`
    를 함께 요구했다. 그러면 권한이 하나도 없는 미사용 역할이 백로그에서 사라진다 — 라이브 실측에서
    199일·1,066일 미사용 역할 2개가 이 조건 때문에 빠졌고, 두 역할은 트랙 배정에서는 `delete_review`
    라 대시보드 집계에만 남아 "삭제 검토 128 vs 목록 126" 의 어긋남을 만들었다. 권한이 없다는 것은
    빼야 할 이유가 아니라 **가장 안전하게 지울 수 있다는 근거**다(영향 범위가 없다).
    """
    return (
        rec.identity_type == "role"
        and rec.track != "excluded"
        and is_idle_beyond(rec, unused_role_days)
    )


# 신뢰 대상이 **우리 테넌트로 확인된** 범위. 여기에 들 때만 삭제 검토(트랙③)를 권고한다.
# `tooling` 을 넣지 않는다 — 관제 계정을 신뢰하는 역할은 정상 운영 경로이고(R5) 벤더가 심은
# 교차계정 역할과 형태가 같다. 오판의 비대칭 때문에 삭제 권고 대신 소유자 확인으로 보낸다.
_CONFIRMED_INTERNAL = {"internal", "service"}


def is_confirmed_internal(rec: PrincipalRecord) -> bool:
    """신뢰 대상이 우리 테넌트로 확인됐나 — 삭제 권고 자격의 **단일 판정식**(R5).

    `m5_tracks` 의 트랙 배정과 이 모듈의 백로그 유형이 같은 함수를 쓴다. 두 곳이 각자 조건을
    갖게 되면 화면이 "소유자 확인" 이라고 배정한 대상의 백로그 문구가 "역할 삭제" 가 된다 —
    같은 함정을 대시보드 40 vs 백로그 59 로 이미 한 번 겪었다.
    """
    return rec.trust_scope in _CONFIRMED_INTERNAL


def is_deletion_reviewable(rec: PrincipalRecord) -> bool:
    """삭제 검토(트랙③)로 권고해도 되는 대상인가.

    배정 결과(`track`)가 있으면 **그것을 읽는다** — `m5_tracks` 가 정본이고, 이후 단계는 다시
    판정하지 않는다는 계약(모듈 docstring)이 있다. 없을 때만(`assign_tracks` 를 지나지 않은
    레코드 · 이 필드가 없던 시절의 `normalized.parquet`) 같은 판정식으로 직접 계산한다.
    """
    if rec.track in ("delete_review", "owner_review"):
        return rec.track == "delete_review"
    if rec.track == "excluded":
        # R6 제외는 "손댈 수 없다" 는 뜻이다 → 삭제 검토 자격이 없다. 이 줄이 없으면 아래 폴백이
        # 신뢰 축만 보고 True 를 내며, service-linked 역할(trust_scope="service")이 삭제 권고를
        # 받는다(라이브 실측 7건). `is_unused_role` 이 이미 같은 게이트를 갖지만, 이 함수를 직접
        # 부르는 경로에도 같은 답이 나와야 판정식이 하나로 유지된다.
        return False
    return is_confirmed_internal(rec)


def is_idle_beyond(rec: PrincipalRecord, unused_role_days: int) -> bool:
    """양성 사용 근거 없이 임계 일수를 넘겼는가 — `is_unused_role` 의 공통부이고 트랙 배정(R5-b)의
    "90일 이상 미사용?" 분기가 쓰는 **같은** 판정식이다.

    분리한 이유: 트랙 배정은 역할뿐 아니라 **IAM 사용자**도 갈라야 한다(수집 대상은 사용자 전부 +
    역할 전부). `is_unused_role` 의 `identity_type == "role"` 과 부여 권한 조건은 백로그 항목
    `unused_role` 의 정의이지 미사용 자체의 정의가 아니다. 두 곳이 각자 조건을 갖게 되면 화면이
    "삭제 검토" 라고 배정한 대상이 백로그에는 없는 어긋남이 생긴다(같은 함정을 대시보드 40 vs
    백로그 59 로 한 번 겪었다).

    🔴 **사용 근거의 '유무' 가 아니라 '언제' 를 본다.** 예전 판정식은 `used_actions`/`used_services`
    가 비어 있기를 요구했다. 두 필드는 "쓰였다" 만 말하고 "언제 쓰였나" 를 말하지 않으므로, IAM 이
    1,103일 미사용이라고 기록한 역할이 3년 전 사용 흔적 때문에 '쓰이는 중' 으로 판정돼 조치 목록에서
    통째로 빠졌다(라이브 실측 26개, 최장 1,206일 — 이 26개는 어느 카드에도 없었다). 두 근거는 서로
    모순되지 않는다: 같은 날짜를 말하고 있었고, 판정식이 그 날짜를 **버렸을** 뿐이다.

    그래서 일수 근거(`unused_days_basis`)에 따라 가드를 다르게 적용한다:

    - `role_last_used` — IAM 이 직접 기록한 **활동 시각**(전 리전, 콘솔 "Last activity")이다. 우리가
      가진 어떤 사용 근거도 이보다 새로울 수 없다(CloudTrail·Advisor 가 관측한 호출은 모두 IAM 이
      말하는 그 활동에 포함된다). 따라서 이 값이 임계를 넘겼다면 사용 근거가 있든 없든 미사용이다.
      실측으로 확인했다: 이 경로로 미사용이 되는 84개 중 action 근거가 임계보다 최근인 것은 **0개**.
    - `create_date` / 근거 없음 — "마지막으로 언제 썼나" 를 아는 값이 없다(IAM 사용자는 애초에
      `RoleLastUsed` 가 없다). 생성일만 오래됐다는 이유로 미사용이라고 하면, 10년 전에 만들어 지금도
      매일 쓰는 IAM 사용자가 삭제 검토에 올라온다 → 이때는 사용 근거의 **존재**가 판정을 막는다.

    이 규칙은 `run.started_at` 같은 기준시각을 받지 않는다 — 날짜 비교는 M2 가 이미 run 시각 기준으로
    계산해 둔 `unused_days` 로 끝난다(불변식 ②: 코어에 wall-clock 을 들이지 않는다).
    """
    days = rec.unused_days if rec.unused_days is not None else rec.age_days
    # 일수를 셀 근거가 아예 없으면(활동 기록도 생성일도 없음) 판정을 유지한다 — 여기서 빼면
    # 증거가 가장 없는 대상이 오히려 조치 목록에서 사라진다(R6).
    if days is not None and days < unused_role_days:
        return False
    if rec.unused_days is not None and rec.unused_days_basis == "role_last_used":
        return True
    return not rec.used_actions and not rec.used_services


def is_too_new_to_judge(rec: PrincipalRecord, min_age_days: int) -> bool:
    """관측 가능 기간이 최소 기준보다 짧은가(= 미사용이라 말할 근거가 부족한가).

    나이를 모르면(구버전 raw 로 create_date 미수집) 판정을 바꾸지 않는다 — 모른다는 이유로
    조치 대상을 늘리거나 줄이지 않고, 증거에 '확인 불가' 로 남긴다.
    """
    return rec.age_days is not None and rec.age_days < min_age_days


def is_new_unused_role(rec: PrincipalRecord, new_principal_days: int) -> bool:
    """생성 직후라 **아직 판단할 수 없는** 역할(사용 근거 0 + 나이 미달).

    `is_unused_role` 과 분리해야 하는 이유: 신 정의(미사용 N일 이상)에서는 30일도 안 된 역할이
    구조적으로 90일 미사용일 수 없어 그 판정식에 걸리지 않는다. 그러면 "배포 중인 신규 역할" 이
    백로그에서 조용히 사라져, 왜 목록에 없는지 답할 수 없게 된다(R6 — 조용히 사라지는 것 금지).
    삭제 권고가 아니라 **판단 보류** 항목이다.

    R6 제외 중 `too_new` 만 통과시킨다 — 그 사유는 이 유형과 같은 사실을 말하므로 빼면 유형 자체가
    비어버린다(라이브 8건이 전부 그 사유였다). 다른 제외 사유(service-linked·CDK 부트스트랩·IdC
    예약)는 "우리가 손댈 대상이 아니다" 라는 뜻이니 판단 보류로도 올리지 않는다.
    """
    if rec.track == "excluded" and rec.excluded_reason != "too_new":
        return False
    return (
        rec.identity_type == "role"
        and not rec.used_actions
        and not rec.used_services
        and rec.role_last_used is None
        and (bool(rec.granted_actions) or rec.has_managed_policies)
        and is_too_new_to_judge(rec, new_principal_days)
    )


# ---- 상승 경로 사람용 문구 ----
#
# `m3_escalation._RULES` 의 (via, to) 는 **규칙 식별자**다. 그대로 화면에 내면
# "iam:PassRole + lambda:CreateFunction → lambda-exec-role (TA0004)" 처럼 읽히는데, 이건
# 규칙을 이미 아는 사람에게만 문장이다. 고객이 알아야 하는 것은 **이 권한 조합으로 무엇을 할 수
# 있는가** 이므로 그것을 한 문장으로 적는다.
#
# 🔴 원문(via/to/MITRE)을 지우지 않고 함께 싣는다 — 고객이 정책에서 실제로 찾아야 하는 문자열이고,
# 우리 규칙표와 대조할 유일한 열쇠다. 설명으로 **대체**하면 추적이 끊긴다.
#
# 키가 없는 규칙(= 규칙을 추가하고 문구를 안 붙인 경우)은 원문으로 폴백한다. 그 폴백이 조용히
# 쌓이지 않도록 `test_escalation_labels_cover_every_rule` 이 _RULES 전건을 대조한다.
_ESCALATION_LABEL: dict[tuple[str, str], tuple[str, str, str]] = {
    # (via, to): (짧은 제목, 무엇이 가능한가, 도달 대상 사람말)
    ("iam:CreateRole + AttachRolePolicy", "new-admin-role"): (
        "역할을 새로 만들어 관리자 권한 획득",
        "역할을 스스로 만들고 그 역할에 관리자급 정책을 붙일 수 있습니다 — 지금 자기 권한 밖의"
        " 역할을 만들어 그 역할로 갈아탈 수 있다는 뜻입니다.",
        "새로 만든 관리자급 역할",
    ),
    ("iam:CreatePolicyVersion (정책 재작성)", "any-policy"): (
        "기존 정책 내용을 덮어써서 권한 확대",
        "이미 붙어 있는 정책의 내용을 새 버전으로 바꿀 수 있습니다 — 새 정책을 붙이지 않고도"
        " 자기 권한을 넓힐 수 있어 변경이 눈에 잘 띄지 않습니다.",
        "이 계정의 고객 관리형 정책 전체",
    ),
    ("iam:AttachRolePolicy (자기 역할에 정책 부착)", "self-role"): (
        "자기 역할에 더 강한 정책 부착",
        "자기 자신이 쓰는 역할에 더 강한 관리형 정책을 붙일 수 있습니다 — 예를 들어"
        " AdministratorAccess 를 자기에게 부여할 수 있습니다.",
        "자기 자신(이 역할)",
    ),
    ("iam:AttachUserPolicy", "self-user"): (
        "자기 사용자에 더 강한 정책 부착",
        "자기 IAM 사용자에게 더 강한 관리형 정책을 붙일 수 있습니다 — 승인 절차 없이 스스로"
        " 권한을 올릴 수 있습니다.",
        "자기 자신(이 IAM 사용자)",
    ),
    ("iam:PutRolePolicy (inline 정책 주입)", "self-role"): (
        "자기 역할에 인라인 정책 직접 주입",
        "자기 역할 안에 정책 문장을 직접 써넣을 수 있습니다 — 관리형 정책을 거치지 않으므로"
        " '어떤 정책이 붙었나' 를 보는 점검에 걸리지 않습니다.",
        "자기 자신(이 역할)",
    ),
    ("iam:PutUserPolicy", "self-user"): (
        "자기 사용자에 인라인 정책 직접 주입",
        "자기 IAM 사용자 안에 정책 문장을 직접 써넣을 수 있습니다 — 관리형 정책 목록만 보는"
        " 점검에는 드러나지 않습니다.",
        "자기 자신(이 IAM 사용자)",
    ),
    ("iam:PassRole + lambda:CreateFunction", "lambda-exec-role"): (
        "Lambda 함수를 만들어 더 강한 역할로 실행",
        "Lambda 함수를 새로 만들면서 자기보다 강한 역할을 그 함수에 붙일 수 있습니다 — 함수를"
        " 실행하면 코드가 그 역할의 권한으로 동작하므로, 결국 그 권한을 손에 넣습니다.",
        "새 Lambda 함수에 붙일 실행 역할",
    ),
    ("iam:PassRole + ec2:RunInstances", "ec2-instance-profile"): (
        "EC2 인스턴스를 띄워 더 강한 역할 탈취",
        "EC2 인스턴스를 띄우면서 자기보다 강한 역할을 붙일 수 있습니다 — 그 인스턴스에 접속해"
        " 역할의 임시 자격증명을 꺼내 쓸 수 있습니다.",
        "새 EC2 인스턴스에 붙일 인스턴스 프로파일 역할",
    ),
    ("iam:CreateAccessKey (다른 사용자 키 발급)", "other-user"): (
        "다른 사용자의 액세스키를 발급해 그 사람으로 행동",
        "다른 IAM 사용자의 액세스키를 새로 만들 수 있습니다 — 그 사용자로 API 를 호출할 수 있고,"
        " 원래 사용자는 자기 키가 하나 더 생긴 것을 알기 어렵습니다.",
        "다른 IAM 사용자",
    ),
    ("iam:UpdateAssumeRolePolicy (신뢰정책 변경)", "assume-any-role"): (
        "역할의 신뢰정책을 고쳐 아무 역할이나 맡기",
        "역할의 신뢰정책(누가 이 역할을 맡을 수 있는지)을 고칠 수 있습니다 — 자기를 신뢰 대상에"
        " 추가하면 그 역할의 권한을 그대로 쓸 수 있습니다.",
        "이 계정의 역할 전체",
    ),
    ("iam:CreateRole + sts:AssumeRole", "new-role-chain"): (
        "역할을 만들고 곧바로 그 역할로 갈아타기",
        "역할을 새로 만들고 그 역할을 즉시 맡을 수 있습니다 — 권한을 갈아타는 사슬을 스스로"
        " 만들 수 있습니다.",
        "새로 만든 역할",
    ),
}

# MITRE 전술 코드는 코드만 두면 검색해 봐야 뜻을 알 수 있다. 뜻을 함께 적고 코드도 남긴다
# (보안팀은 코드로 사내 문서·탐지 규칙과 대조한다).
_MITRE_LABEL = {
    "TA0004": "TA0004 · 권한 상승(Privilege Escalation)",
    "TA0003": "TA0003 · 발판 유지(Persistence)",
}


# 미사용 일수를 무엇부터 셌는지의 사람용 라벨. 값만 보면 같은 "1,076일" 이 AWS 가 기록한 사실인지
# 우리가 생성일부터 센 것인지 구분되지 않는다 — 후자에만 추적 보장 문구가 붙는다.
_BASIS_LABEL = {
    "role_last_used": "IAM 활동 기록(전 리전)",
    "create_date": "생성일(활동 기록 없음)",
}

# 일수를 셀 근거가 없을 때의 문구. "0일" 이나 빈 문자열로 두면 '방금 쓰였다'/'표기 누락' 으로 읽힌다.
_UNKNOWN_PERIOD = "확인 불가(일수를 셀 근거 없음)"


def _tier_label(tier: str | None, boundaries: list[int]) -> str:
    """미사용 등급 → **고객이 읽는 문구**.

    `active`/`watch`/`review`/`cleanup` 은 우리 계약 값(`models.UnusedTier`)이지 화면 문구가
    아니다. 산출물에 원값을 그대로 실으면 고객은 `cleanup` 을 사전 없이 해석해야 하고, 실제로
    "cleanup = 지워도 되는 것" 으로 읽힌다 — 등급은 **며칠 안 썼는가**만 말하며 삭제 권고는
    별도 게이트(`cleanup_group_of`)를 거친다(그 게이트가 CDK 부트스트랩 역할을 빼는 이유다).
    그래서 라벨을 사실 문장으로 쓴다: 라벨이 곧 측정값이면 잘못 해석할 여지가 없다.

    🔴 경계 숫자를 문구에 박지 않는다 — `boundaries` 는 `risk_rules.unused_tier_days` 이고
    고객이 30/60/90 을 바꿀 수 있다(불변식 ④). 박으면 경계를 조정한 고객의 화면이 거짓을 말한다.

    등급 없음(None)은 0 이 아니라 미측정이다 — 문구에서도 그 구분을 잃지 않는다.
    """
    watch, review, cleanup = boundaries
    return {
        "active": f"{watch}일 이내 사용",
        "watch": f"{watch}일 이상 미사용",
        "review": f"{review}일 이상 미사용",
        "cleanup": f"{cleanup}일 이상 미사용",
        "new": "신규 (관측 기간 부족 · 판정 보류)",
    }.get(tier or "", "미측정 (사용 일수 근거 없음)")

# IAM 이 last-accessed/last-used 정보를 유지하는 추적 창(일). **AWS 사양이며 조정 대상이 아니다** —
# config 로 빼지 않는 이유가 이것이다(불변식 ④ 는 고객별 임계치를 config 로 옮기라는 규칙이고,
# 이 값은 우리가 고를 수 있는 값이 아니다). 여기서만 정의해 문구가 서로 어긋나지 않게 한다.
_IAM_TRACKING_DAYS = 400


def _trust_accounts(rec: PrincipalRecord) -> list[str]:
    """신뢰정책 principal 에서 **계정 ID 만** 뽑는다(중복 제거·정렬).

    ARN 은 `arn:aws:iam::<account>:root|role/...` 이라 5번째 필드가 계정이고, 서비스 principal
    (`events.amazonaws.com`)에는 계정이 없다. 못 뽑은 principal 은 **빼고** 남은 것만 낸다 —
    '미확인 계정' 같은 가짜 묶음으로 만들면 화면이 실제보다 정리된 것처럼 보인다.
    """
    accounts = {
        parts[4] for pr in rec.trust_principals
        if len(parts := pr.split(":")) > 4 and parts[4].isdigit()
    }
    return sorted(accounts)


def _window_phrase(rec: PrincipalRecord) -> str:
    """이 principal 의 미사용 판정 근거 창을 **실측값**으로 서술.

    화면·CSV 가 "90일" 이라고 쓰던 자리다. 그 90일은 어디서도 측정되지 않았다: CloudTrail
    LookupEvents 는 페이지 상한에 걸려 라이브에서 2일만 덮었고, Access Advisor 는 AWS 가 문서화한
    추적 창(최대 400일, 서비스·action 별로 상이)을 쓴다. 그래서 CloudTrail 쪽은 실측 일수를 쓰고
    Advisor 쪽은 측정값이 아니라 **AWS 사양**임을 문구로 드러낸다.
    """
    ct = f"CloudTrail {rec.observed_days}일" if rec.observed_days is not None else "CloudTrail 근거 없음"
    return f"{ct} + Access Advisor 추적 창(AWS 사양: 최대 {_IAM_TRACKING_DAYS}일)"


def _usage_evidence_phrase(rec: PrincipalRecord) -> str:
    """사용 근거를 '없음/있음' 이 아니라 **마지막이 언제였나**로 서술.

    미사용 역할에도 오래된 사용 흔적이 남아 있을 수 있다(신 판정식 — `is_idle_beyond`). 그때
    "사용 근거: 없음" 이라고 적으면 증거가 사실과 반대를 말하고, 고객이 그 역할의 흔적을 콘솔에서
    보는 순간 목록 전체를 안 믿는다. 날짜가 없는 흔적(서비스 단위 인증만 확인된 경우)은 날짜를
    지어내지 않고 그렇게 적는다.

    🔴 **층위를 밝힌다**(라이브 결함 A). `used_actions` 만 보고 "없음" 을 내던 판이 있었는데, 같은
    카드에 `사용 흔적 서비스: ec2` 와 `마지막 활동: 2022-12-19` 가 함께 실려 정면으로 부딪쳤다.
    Access Advisor 의 action 단위 추적은 서비스별로 커버리지가 달라, 쓰이는 역할도 서비스 단위
    근거만 남는 경우가 있다(라이브에서 이 조합이 실제로 나왔다). 그때 정확한 말은 "없음" 이 아니라
    **"action 단위 근거는 없고 서비스 단위 흔적은 있다"** 다. 두 층위를 한 낱말로 접으면 어느 쪽이
    없는 것인지 알 수 없고, 그것이 이 결함의 원인이었다.
    """
    win = _window_phrase(rec)
    if rec.used_actions:
        dated = [u.last_used for u in rec.used_actions if u.last_used]
        n = len(rec.used_actions)
        if not dated:
            return f"action {n}개에 흔적 있으나 사용 시각 미수집({win})"
        return f"action {n}개, 가장 최근 사용 {max(dated)}({win})"
    if rec.used_services:
        n = len(rec.used_services)
        return f"action 단위 근거 없음 · 서비스 단위 흔적 {n}개({win})"
    return f"없음({win})"


def _unused_period(rec: PrincipalRecord) -> tuple[str, str]:
    """(마지막 활동, 미사용 기간) 표기. **실측값과 하한을 문구로 구분한다.**

    이 자리에 예전엔 "90일간 미사용" 이 있었다. 그 90일은 어디서도 측정되지 않은 리터럴이었고,
    지운 뒤 실제 값을 채워 넣지 않아 기간 표기가 **아예 사라졌다**(사용자 지적). 실제 값은
    이미 우리가 받아오는 `GetAccountAuthorizationDetails` 응답의 `RoleLastUsed` 에 있었다.

    세 경우를 다르게 말한다(근거 = M2 가 `unused_days_basis` 에 남긴 것):
      - 활동 기록 있음(①) → as_of 기준 정확한 경과일, **상한 없음**(실측에서 1,076일이 그대로
        나왔고 AWS 가 기록한 사실이다). 활동이 있던 **리전**도 함께 보여 준다(그 리전이 CloudTrail
        수집 리전과 다르면, 왜 CloudTrail 에 안 잡혔는지가 그 자리에서 설명된다).
      - 기록 없음 → 생성일부터의 경과 + "사용 기록 없음". 추적 보장 창 문구는 **이 경로에만**
        붙는다(①에 붙이면 AWS 가 기록한 사실을 우리가 못 믿는 것처럼 읽힌다). 이 문구는 기간을
        측정했다고 주장하지 않는다 — 생성 후 경과는 사실이고, 그 안에 기록이 없다는 것도 사실이다.
      - 셀 근거가 없음 → 숫자를 만들지 않는다.

    `age_days` 로 내려가지 않는다(`is_unused_role` 과 의도적으로 다르다). 이 함수는 사용 중인
    역할의 미사용 **권한** 증거에도 쓰이는데, 그 경우 M2 는 일수를 세지 않으므로(케이스 ③)
    나이로 메꾸면 쓰이는 역할에 "생성 후 N일 사용 기록 없음" 을 적게 된다.
    """
    if rec.role_last_used:
        region = f" ({rec.role_last_used_region})" if rec.role_last_used_region else ""
        last = f"{rec.role_last_used}{region}"
        return last, (f"{rec.unused_days}일" if rec.unused_days is not None else _UNKNOWN_PERIOD)
    if rec.unused_days is not None:
        return (
            "IAM 활동 기록 없음",
            f"생성 후 {rec.unused_days}일 · 사용 기록 없음(AWS 추적 보장 {_IAM_TRACKING_DAYS}일)",
        )
    return "IAM 활동 기록 없음", _UNKNOWN_PERIOD


def cleanup_finding_key(ctype: str, account_id: str, principal: str, extra: str = "") -> str:
    """cleanup 항목의 **내용 기반 안정 키**(sha256 hex) — 조치 상태를 붙이는 식별자.

    `CleanupItem.id`(c1, c2…)는 정렬 후 부여하는 순번이라 다음 run 에서 항목이 하나 늘거나 줄면
    뒤가 전부 밀린다. 그걸 상태 키로 쓰면 "조치완료" 표시가 조용히 다른 항목으로 옮겨간다.

    키에 넣는 것은 **같은 문제를 같은 것으로 보게 하는 최소 식별자**뿐이다: 유형 + 계정 + principal
    (+ escalation 처럼 principal 당 여러 건이 나오는 유형만 경로 식별자). `detail` 은 일부러 넣지
    않는다 — "액세스키 age 612일" 이나 "외 34건" 처럼 매일 변하는 수치가 들어 있어서, 넣으면 값이
    1 바뀔 때마다 새 항목으로 보여 조치 상태가 사라진다.

    API(`routers/cleanup.py`)가 상태 저장·조회에 같은 함수를 쓴다(키 산출 단일 소스).
    """
    import hashlib

    joined = "\x1f".join([ctype, account_id, principal, extra])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
EXEC_SUMMARY_NAME = "exec_summary.json"
REPORT_NAME = "report.html"


def build_reports(storage: "Storage", run: "RunContext", cfg: "Config") -> ExecSummary:
    records = storage.read_normalized()
    catalog = _load_catalog(storage)

    items = _cleanup_items(records, cfg)
    _write_backlog(storage, items)

    summary = _exec_summary(records, catalog, items, run)
    storage.write_json(EXEC_SUMMARY_NAME, summary.model_dump())
    # 종합 리포트: manifest(소스 신뢰도)·escalation 요약도 함께 실어 사람이 읽는 보고서 생성.
    manifest = _read_json_safe(storage, MANIFEST_NAME)
    escalation = _read_json_safe(storage, "escalation_status.json")
    # 전체(모든 계정 통합) 리포트.
    storage.write_text(
        REPORT_NAME, _render_html(summary, items, catalog, records, manifest, escalation, run)
    )
    # 계정별 리포트(report-<account>.html) — 리포트 페이지가 특정 계정 선택 시 다운로드/열람.
    acct_ids = sorted({r.account_id for r in records})
    if len(acct_ids) > 1:
        for aid in acct_ids:
            arecs = [r for r in records if r.account_id == aid]
            acat = [e for e in catalog if any(f":{aid}:" in m for m in e.members)]
            aitems = [it for it in items if it.account_id == aid]
            asum = next((b for b in summary.by_account if b.account_id == aid), summary)
            amanifest = _manifest_for_account(manifest, aid)
            aesc = _escalation_for_account(arecs, escalation)
            storage.write_text(
                f"report-{aid}.html",
                _render_html(asum, aitems, acat, arecs, amanifest, aesc, run),
            )
    return summary


def _manifest_for_account(manifest: dict, account_id: str) -> dict:
    """manifest 를 한 계정 것만 남긴 얕은 사본(소스 신뢰도 섹션이 그 계정만 보이게)."""
    if not isinstance(manifest, dict):
        return {}
    accts = [a for a in manifest.get("accounts", []) if a.get("account_id") == account_id]
    return {**manifest, "accounts": accts}


def _escalation_for_account(records: list[PrincipalRecord], escalation: dict) -> dict:
    """계정별 escalation 요약 재계산(escalation_status.json 은 전체 집계라 계정별로 다시 센다)."""
    scanned = len(records)
    with_esc = sum(1 for r in records if r.escalation_paths)
    total = sum(len(r.escalation_paths) for r in records)
    base = dict(escalation) if isinstance(escalation, dict) else {}
    base.update({"principals_scanned": scanned, "principals_with_escalation": with_esc,
                 "total_escalation_paths": total})
    return base


MANIFEST_NAME = "collection_manifest.json"


def _read_json_safe(storage: "Storage", relpath: str) -> dict:
    if not storage.exists(relpath):
        return {}
    data = storage.read_json(relpath)
    return data if isinstance(data, dict) else {}


_GROUP_ORDER: tuple[CleanupGroup, ...] = ("delete_review", "reduce_scope", "needs_confirmation")


def cleanup_items(records: list[PrincipalRecord], cfg: "Config") -> list[CleanupItem]:
    """백로그 항목 전체(공개 진입점). `snapshot` 이 KPI 를 **같은 항목 목록에서** 세게 하기 위한 것.

    예전에는 대시보드 KPI 가 `snapshot` 안에서 레코드를 다시 훑어 자기 기준으로 셌다. 그래서
    KPI 는 action 을 세고(41,451) 그 KPI 를 눌러 열린 목록은 principal 을 세는(329행) 단위 불일치가
    났다. 카드의 숫자는 **자기가 여는 목록의 행 수**로 정의한다 — 그 정의를 코드 한 곳에 둔다.
    """
    return _cleanup_items(records, cfg)


def summarize_groups(
    items: list[CleanupItem], records: list[PrincipalRecord]
) -> list[ActionGroupMetrics]:
    """3그룹 카드에 들어갈 숫자. `targets` 는 **항목 목록에서** 센 principal 수다(레코드에서 세지 않는다).

    레코드에서 세면 항목이 0건인 대상까지 포함돼 "카드 128 vs 목록 126" 같은 어긋남이 다시 난다
    (실측으로 났던 결함이다). 세부 숫자(미사용 action·와일드카드·상승 경로)는 카드 안의 부속 줄로,
    분류를 늘리지 않고 정보를 잃지 않기 위한 것이다.
    """
    by_key = {(r.account_id, r.principal): r for r in records}
    out: list[ActionGroupMetrics] = []
    for g in _GROUP_ORDER:
        gi = [it for it in items if it.group == g]
        keys = {(it.account_id, it.principal) for it in gi}
        recs = [by_key[k] for k in sorted(keys) if k in by_key]
        out.append(ActionGroupMetrics(
            group=g,
            targets=len(keys),
            items=len(gi),
            unused_actions=sum(
                len([f for f in r.unused_findings if ":" in f]) for r in recs
            ),
            wildcard_targets=sum(1 for r in recs if r.wildcard_grants),
            escalation_paths=sum(len(r.escalation_paths) for r in recs),
            long_lived_keys=sum(1 for it in gi if it.type == "long_lived_key"),
        ))
    return out


def summarize_exclusions(
    records: list[PrincipalRecord], cfg: "Config"
) -> list[ExclusionEntry]:
    """제외 내역 — 사유별 대상 수 + **그 게이트가 숨긴 권고 건수**.

    개수를 남기는 것이 R6 의 요구다: 조용히 사라지면 "왜 우리 역할이 여기 없지?" 에 답할 수 없다.
    숨긴 건수를 함께 내는 이유는 신뢰다 — 게이트를 넣은 뒤 미사용 action 이 41,451 → 18,532 로
    줄었다. 그 차이를 화면 어디에도 적지 않으면 "숫자가 반토막 났다" 로 보이고, 그건 정리된 것이
    아니라 처음부터 조치 대상이 아니었다는 사실이 사라진 것이다.

    `judgment` 등급 중 일부(`too_new` 무사용·`no_used_actions`)는 '확인 필요' 로 올라가므로 여기
    남는 것은 실제로 목록에서 빠진 것만이다.
    """
    from .m5_tracks import EXCLUSION_BASIS, EXCLUSION_LABEL

    agg: dict[str, tuple[int, int, list[str]]] = {}
    for rec in records:
        if cleanup_group(rec, cfg.risk_rules) is not None:
            continue
        reason = rec.excluded_reason or "unknown"
        # 게이트가 없었다면 몇 건이 올라왔을까 — 같은 함수로 센다(사본 금지). group 인자는 권고
        # 문구만 바꾸고 건수에는 영향이 없으므로 실제 값이 무엇이든 개수는 같다.
        hidden = len(_items_for(rec, cfg, "reduce_scope"))
        t, s, names = agg.get(reason, (0, 0, []))
        names.append(rec.principal)
        agg[reason] = (t + 1, s + hidden, names)
    return [
        ExclusionEntry(
            reason=reason,
            # 라벨의 정본은 `m5_tracks`. 없는 사유는 원값을 그대로 보여준다 — 조용히 '기타' 로
            # 묶으면 라벨 추가를 잊은 것이 화면에서 보이지 않는다.
            label=EXCLUSION_LABEL.get(reason, reason),
            basis=EXCLUSION_BASIS.get(reason, "judgment"),
            targets=t,
            suppressed_items=s,
            principals=sorted(names),
        )
        for reason, (t, s, names) in sorted(agg.items())
    ]


def _cleanup_items(records: list[PrincipalRecord], cfg: "Config") -> list[CleanupItem]:
    """principal 레코드에서 cleanup 항목 도출(결정론 id·정렬). 유형은 `CleanupType` 이 정본이다."""
    items: list[CleanupItem] = []

    for rec in records:
        # 🔴 그룹 배정이 **모든 유형보다 먼저**다. `None` 이면 이 대상은 조치 목록에 올리지 않는다 —
        # 개수는 `summarize_exclusions` 가 '제외 내역' 으로 화면에 남긴다(조용히 사라지지 않는다).
        # 이 게이트가 없던 동안 제외 대상 87개가 164건의 잘못된 권고를 달고 목록에 있었다.
        group = cleanup_group(rec, cfg.risk_rules)
        if group is None:
            continue
        items.extend(_items_for(rec, cfg, group))

    # 결정론 id: (type, account, principal, detail) 정렬 후 c1.. 부여.
    items.sort(key=lambda x: (x.type, x.account_id, x.principal, x.detail))
    for i, item in enumerate(items, start=1):
        item.id = f"c{i}"
    return items


def _item(ctype: CleanupType, group: "CleanupGroup | None", rec: PrincipalRecord,
          risk, detail: str, rec_text: str,
          evidence: dict[str, str] | None = None, key_extra: str = "") -> CleanupItem:
    return CleanupItem(
        id="",  # 나중에 정렬 후 부여
        # 조치 상태용 안정 키. key_extra 는 principal 당 여러 건이 나오는 유형(escalation_path)에서만
        # 건을 구분하는 데 쓴다 — 나머지 유형은 (유형, 계정, principal) 이 곧 한 건이다.
        finding_key=cleanup_finding_key(ctype, rec.account_id, rec.principal, key_extra),
        type=ctype,
        group=group,
        track=rec.track,
        account_id=rec.account_id,
        principal=rec.principal,
        detail=detail,
        risk_level=risk,
        recommendation=rec_text,
        # M4 점수·근거를 그대로 실어 "왜 이 레벨인지" 설명 가능하게(운영자 위험 인지).
        risk_score=rec.risk_score,
        risk_reasons=rec.risk_reasons,
        evidence=evidence or {},
    )


_CSV_INJECT_RE = re.compile(r"^[=+\-@\t\r\n]")  # 개행(\n)도 포함(줄바꿈 시작 셀 방지)


def _csv_safe(value: object) -> str:
    """CSV formula injection 무력화. 셀 앞글자가 `= + - @ tab CR` 이면 `'` 프리픽스로
    스프레드시트가 수식으로 해석하지 못하게 한다. 프론트 toCsv 의 csvSafe 와 동일 규칙."""
    s = "" if value is None else str(value)
    return "'" + s if _CSV_INJECT_RE.match(s) else s


def _write_backlog(storage: "Storage", items: list[CleanupItem]) -> None:
    import json

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")  # 결정론(플랫폼 무관 개행)
    # risk_score/risk_reasons/evidence 추가 — reasons 는 '|' join, evidence 는 JSON(정렬키·결정론).
    # finding_key 추가 — API 가 조치 상태를 이 키로 병합한다(순번 id 로는 run 간 대응이 깨진다).
    # 조치 상태 자체는 여기 쓰지 않는다(엔진 산출물은 결정론, 사람의 판단은 findings 테이블 소관).
    # group 추가 — 화면의 3카드(삭제 검토/권한 축소/확인 필요)가 이 값으로 묶는다. 유형(type)이
    # '무엇이 잘못됐나' 라면 group 은 '무엇을 해야 하나' 다. 화면이 type 으로 다시 묶으면 같은
    # 역할이 두 카드에 나온다(실측: unused_role 126건 중 121건이 unused_permission 도 갖고 있었다).
    writer.writerow(["id", "finding_key", "type", "group", "track", "account_id", "principal",
                     "risk_level", "detail", "recommendation", "risk_score", "risk_reasons",
                     "evidence"])
    for it in items:
        # 사용자/자원 유래 텍스트 셀을 formula-injection 무력화(수치 컬럼 제외).
        writer.writerow([_csv_safe(it.id), _csv_safe(it.finding_key),
                         _csv_safe(it.type), _csv_safe(it.group or ""),
                         _csv_safe(it.track or ""), _csv_safe(it.account_id),
                         _csv_safe(it.principal), _csv_safe(it.risk_level), _csv_safe(it.detail),
                         _csv_safe(it.recommendation), it.risk_score,
                         _csv_safe("|".join(it.risk_reasons)),
                         _csv_safe(json.dumps(it.evidence, sort_keys=True, ensure_ascii=False))])
    storage.write_text(BACKLOG_NAME, buf.getvalue())


def _exec_summary(
    records: list[PrincipalRecord], catalog: list[CatalogEntry],
    items: list[CleanupItem], run: "RunContext",
) -> ExecSummary:
    total = _exec_summary_for(records, catalog, items, run, account_id="")
    # 계정별 분해(계정 2개 이상일 때만). 리포트 페이지가 특정 계정 선택 시 사용.
    acct_ids = sorted({r.account_id for r in records})
    if len(acct_ids) > 1:
        by: list[ExecSummary] = []
        for aid in acct_ids:
            arecs = [r for r in records if r.account_id == aid]
            acat = [e for e in catalog if any(f":{aid}:" in m for m in e.members)]
            aitems = [it for it in items if it.account_id == aid]
            by.append(_exec_summary_for(arecs, acat, aitems, run, account_id=aid))
        total.by_account = by
    return total


def _exec_summary_for(
    records: list[PrincipalRecord], catalog: list[CatalogEntry],
    items: list[CleanupItem], run: "RunContext", account_id: str,
) -> ExecSummary:
    accounts = len({r.account_id for r in records})
    # 두 단위를 **둘 다** 낸다: 항목(principal) 수와 그 안의 action 총계. 하나만 내면 다른 화면의
    # 같은 이름 지표와 어긋난다(예전: 리포트 74 = principal, 대시보드 2,271 = action).
    with_unused = [it for it in items if it.type == "unused_permission"]
    # action 총계는 `snapshot._metrics_for.unused_permissions` 와 **같은 식**이어야 한다 — 리포트와
    # 대시보드가 같은 이름으로 다른 숫자를 보여주면 어느 쪽이 맞는지 알 수 없다.
    action_total = sum(len([f for f in r.unused_findings if ":" in f]) for r in records)
    return ExecSummary(
        accounts=accounts,
        principals=len(records),
        personas=len(catalog),
        unused_permission_principals=len(with_unused),
        unused_permission_actions=action_total,
        generated_at=run.started_at,  # 유일 허용 wall-clock(불변식 ②)
        account_id=account_id,
    )


_TYPE_LABEL_HTML = {
    "unused_permission": "미사용 권한",
    "unused_role": "미사용 역할",
    "new_role_unused": "신규 역할(관측 기간 부족)",
    "long_lived_key": "장기 액세스키",
    "no_mfa": "MFA 미설정",
    "escalation_path": "권한 상승 경로",
    # 삭제 권고가 아닌 두 유형. 라벨에 그 사실을 넣는다 — HTML 리포트는 카드 설명 없이 라벨만
    # 나열되므로, 라벨이 "미사용 역할" 과 구별되지 않으면 표를 훑는 사람이 같은 것으로 읽는다.
    "unconfirmed_trust_role": "외부 연동 의심(소유자 확인 — 삭제 권고 아님)",
    "cross_tenant_trust": "테넌트 경계 위반 의심",
    "wildcard_grant": "와일드카드 권한",
    "trust_policy_wildcard": "신뢰정책 와일드카드",
}
_SOURCE_LABEL_HTML = {
    "access_advisor": "Access Advisor",
    "cloudtrail": "CloudTrail",
    "analyzer_unused": "Access Analyzer",
    "credential_report": "Credential Report",
    "idc_permission_sets": "Identity Center",
}
_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_RISK_COLOR = {"critical": "#d13212", "high": "#e07b00", "medium": "#b8a300", "low": "#1d8102"}


def _render_html(
    summary: ExecSummary, items: list[CleanupItem], catalog: list[CatalogEntry],
    records: list[PrincipalRecord], manifest: dict, escalation: dict, run: "RunContext",
) -> str:
    """사람이 읽는 종합 보고서(결정론 정적 HTML, 외부 자원·스크립트 없음)."""
    esc = html.escape

    # 위험 등급 분포 — **수집된 전 principal** 기준(활성/비활성 구분은 하지 않는다. 예전 주석은
    # "활성 principal 기준" 이라고 적혀 있었지만 아래 루프에 그런 필터가 없다).
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in records:
        dist[r.risk_level] = dist.get(r.risk_level, 0) + 1

    # 유형별 건수.
    by_type: dict[str, int] = {}
    for it in items:
        by_type[it.type] = by_type.get(it.type, 0) + 1

    # 데이터 소스 신뢰도(manifest). status 를 사람이 읽는 라벨로 구분한다:
    #  - ok       : 정상 수집(초록)
    #  - degraded : 수집은 됐으나 부분/저품질 — 실제 주의 필요(주황)
    #  - skipped  : 선택적 소스가 없어 대체됨 — 정상, 조치 불필요(회색·'선택적')
    _STATUS_LABEL = {
        "ok": ("정상", "#1d8102"),
        "degraded": ("부분 수집", "#e07b00"),
        "skipped": ("선택적 소스 없음 (정상)", "#879596"),
    }
    src_rows = ""
    accounts_m = manifest.get("accounts", []) if isinstance(manifest, dict) else []
    # 소스별로 **가장 나쁜 상태**를 대표로 쓴다. 예전엔 `setdefault` 로 첫 계정 것만 남겼는데,
    # 그러면 계정 A 가 ok 이고 계정 B 가 degraded 일 때 표가 "정상" 만 보여주고 B 의 note 는
    # 사라진다 — 경고 배너는 뜨는데 표에는 근거가 없어 어느 소스가 문제인지 알 수 없다.
    _RANK = {"ok": 0, "skipped": 1, "degraded": 2}
    worst: dict[str, dict] = {}
    degraded_accounts: dict[str, list[str]] = {}
    for acct in accounts_m:
        aid = str(acct.get("account_id", ""))
        for s in acct.get("sources", []):
            src = s.get("source", "")
            cur = worst.get(src)
            if cur is None or _RANK.get(s.get("status", ""), 0) > _RANK.get(cur.get("status", ""), 0):
                worst[src] = s
            if s.get("status") == "degraded":
                degraded_accounts.setdefault(src, []).append(aid)
    any_degraded = bool(degraded_accounts)
    for src, s in sorted(worst.items()):
        status = s.get("status", "")
        label, color = _STATUS_LABEL.get(status, (status, "#879596"))
        note = s.get("note", "")
        hit = degraded_accounts.get(src, [])
        # 계정이 여러 개면 몇 개 계정에서 그랬는지 함께 — 대표 1건의 note 만으로는 범위를 알 수 없다.
        if len(accounts_m) > 1 and hit:
            note = f"[계정 {len(hit)}/{len(accounts_m)}개] {note}"
        src_rows += (
            f"<tr><td>{esc(_SOURCE_LABEL_HTML.get(src, src))}</td>"
            f"<td style='color:{color};font-weight:600'>{esc(label)}</td>"
            f"<td>{esc(note) or '—'}</td></tr>"
        )
    # 경고 배너는 **실제 부분 수집(degraded)**이 있을 때만. skipped(선택적 소스 없음)는 정상이라 경고 안 함.
    degraded_note = ""
    if any_degraded:
        degraded_note = (
            "<div class='banner warn'>⚠ 일부 소스가 <b>부분 수집(degraded)</b> 상태입니다 — 사용 실태가 "
            "과소 집계됐을 수 있습니다. 아래 '데이터 소스 신뢰도'를 확인하세요.</div>"
        )
    else:
        degraded_note = (
            "<div class='banner ok'>✓ 핵심 소스는 정상 수집됐습니다. "
            "'선택적 소스 없음'은 정상이며(대체 소스로 커버), 조치가 필요하지 않습니다.</div>"
        )

    # 위험도별 Top — **principal 단위 집계**(경로 건별 중복 나열 방지). 한 principal 의 여러 항목을
    # 묶어 최고 위험도·최고 점수·항목 유형 요약·대표 권장조치로. critical·high 만, 점수순 최대 20명.
    by_principal: dict[str, list[CleanupItem]] = {}
    for it in items:
        by_principal.setdefault(it.principal, []).append(it)
    principal_rows_data = []
    for principal, its in by_principal.items():
        worst = min(its, key=lambda x: (_RISK_ORDER.get(x.risk_level, 9), -x.risk_score))
        if worst.risk_level not in ("critical", "high"):
            continue
        type_counts: dict[str, int] = {}
        for x in its:
            type_counts[x.type] = type_counts.get(x.type, 0) + 1
        issues = ", ".join(
            f"{_TYPE_LABEL_HTML.get(t, t)} {n}건" for t, n in sorted(type_counts.items(), key=lambda kv: -kv[1])
        )
        principal_rows_data.append((worst.risk_level, worst.risk_score, principal, issues, worst.recommendation))
    principal_rows_data.sort(key=lambda r: (_RISK_ORDER.get(r[0], 9), -r[1]))
    top_rows = "".join(
        f"<tr><td><span style='color:{_RISK_COLOR.get(lv)};font-weight:600'>{esc(lv)}</span></td>"
        f"<td>{sc}</td><td class='mono'>{esc(pr)}</td><td>{esc(iss)}</td>"
        f"<td>{esc(rec)}</td></tr>"
        for lv, sc, pr, iss, rec in principal_rows_data[:20]
    ) or "<tr><td colspan='5'>critical/high 항목 없음</td></tr>"
    top_principal_count = len(principal_rows_data)

    # 유형별 건수 행.
    type_rows = "".join(
        f"<tr><td>{esc(_TYPE_LABEL_HTML.get(t, t))}</td><td>{n}</td></tr>"
        for t, n in sorted(by_type.items(), key=lambda kv: -kv[1])
    )

    # persona 카탈로그(멤버·action·기여 소스·승인).
    persona_rows = "".join(
        f"<tr><td>{esc(e.persona)}</td><td>{e.member_count}</td><td>{len(e.actions)}</td>"
        f"<td>{esc(', '.join(_SOURCE_LABEL_HTML.get(s, s) for s in (e.contributing_sources or [])) or '—')}</td>"
        f"<td>{esc(e.approval_status)}</td></tr>"
        for e in catalog
    )

    # 위험 등급 분포 막대(인라인).
    total_p = summary.principals or 1
    dist_bars = "".join(
        f"<div class='distrow'><span class='distlabel' style='color:{_RISK_COLOR[k]}'>{k}</span>"
        f"<span class='distbar' style='width:{max(1, round(300 * dist[k] / total_p))}px;background:{_RISK_COLOR[k]}'></span>"
        f"<span class='distn'>{dist[k]}</span></div>"
        for k in ("critical", "high", "medium", "low")
    )

    e = escalation if isinstance(escalation, dict) else {}
    esc_scanned = e.get("principals_scanned", 0)
    esc_with = e.get("principals_with_escalation", 0)
    esc_total = e.get("total_escalation_paths", 0)
    esc_pct = round(100 * esc_with / esc_scanned) if isinstance(esc_scanned, int) and esc_scanned else 0

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>LP2PS 분석 리포트 — {esc(run.run_id)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, "Noto Sans KR", sans-serif; color:#16191f;
         max-width: 1080px; margin: 0 auto; padding: 32px 24px; line-height: 1.5; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; }}
  h2 {{ font-size: 19px; margin: 34px 0 12px; padding-bottom: 6px; border-bottom: 2px solid #e9ebed; }}
  .meta {{ color:#5f6b7a; font-size: 13px; margin-bottom: 20px; }}
  .kpis {{ display:flex; gap:16px; flex-wrap:wrap; }}
  .kpi {{ flex:1; min-width:150px; border:1px solid #e9ebed; border-radius:8px; padding:14px 16px; }}
  .kpi .n {{ font-size:30px; font-weight:700; }}
  .kpi .l {{ color:#5f6b7a; font-size:13px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; margin-top:8px; }}
  th, td {{ border:1px solid #e9ebed; padding:7px 10px; text-align:left; vertical-align:top; }}
  th {{ background:#f2f3f3; font-weight:600; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; font-size:12px; word-break:break-all; }}
  .banner {{ padding:12px 16px; border-radius:8px; margin:16px 0; font-size:14px; }}
  .banner.warn {{ background:#fef6f0; border:1px solid #e07b00; color:#8a4b00; }}
  .banner.ok {{ background:#f0faf2; border:1px solid #1d8102; color:#0f5c01; }}
  .distrow {{ display:flex; align-items:center; gap:10px; margin:4px 0; }}
  .distlabel {{ width:70px; font-weight:600; font-size:13px; }}
  .distbar {{ height:16px; border-radius:3px; }}
  .distn {{ font-size:13px; color:#5f6b7a; }}
  footer {{ margin-top:40px; color:#879596; font-size:12px; border-top:1px solid #e9ebed; padding-top:12px; }}
</style></head>
<body>
<h1>LP2PS 최소권한 분석 리포트</h1>
<div class="meta">실행 ID {esc(run.run_id)} · 생성 {esc(summary.generated_at)} · 고객 {esc(run.customer)}</div>

{degraded_note}

<h2>1. 요약 (Executive Summary)</h2>
<div class="kpis">
  <div class="kpi"><div class="n">{summary.accounts}</div><div class="l">분석 계정</div></div>
  <div class="kpi"><div class="n">{summary.principals:,}</div><div class="l">Principal</div></div>
  <div class="kpi"><div class="n">{summary.personas}</div><div class="l">Persona</div></div>
  <div class="kpi"><div class="n">{summary.unused_permission_actions:,}</div><div class="l">미사용 action ({summary.unused_permission_principals:,}개 principal)</div></div>
  <div class="kpi"><div class="n">{esc_with}</div><div class="l">상승 경로 보유 principal</div></div>
</div>

<h2>2. 위험 등급 분포</h2>
{dist_bars}

<h2>3. 권한 상승 경로 요약</h2>
<p style="color:#5f6b7a;font-size:13px;margin:0 0 10px">
낮은 권한으로 시작해 <b>스스로 더 큰 권한(관리자급)을 부여</b>할 수 있는 principal 을 규칙 기반으로 탐지합니다.
이런 principal 이 탈취되면 계정 전체가 위험합니다.</p>
<div class="kpis">
  <div class="kpi"><div class="n">{esc_with} <span style="font-size:16px;color:#5f6b7a">/ {esc_scanned}</span></div><div class="l">상승 경로 보유 principal ({esc_pct}%)</div></div>
  <div class="kpi"><div class="n">{esc_total}</div><div class="l">탐지된 상승 경로 (한 principal 이 여러 개 보유 가능)</div></div>
</div>

<h2>4. 위험 Top principal (critical · high) — {top_principal_count}명</h2>
<p style="color:#5f6b7a;font-size:13px;margin:0 0 10px">principal 단위로 묶어 표시합니다(같은 주체의 여러 경로·항목은 한 행으로 합산).</p>
<table><tr><th>위험도</th><th>점수</th><th>Principal</th><th>발견 항목</th><th>권장 조치</th></tr>{top_rows}</table>

<h2>5. 조치 필요 항목 (유형별)</h2>
<table><tr><th>유형</th><th>건수</th></tr>{type_rows}</table>

<h2>6. Persona 카탈로그</h2>
<table><tr><th>Persona</th><th>멤버 수</th><th>Action 수</th><th>기여 소스</th><th>승인 상태</th></tr>{persona_rows}</table>

<h2>7. 데이터 소스 신뢰도</h2>
<p style="color:#5f6b7a;font-size:13px;margin:0 0 10px">
<b>정상</b>=완전 수집 · <b>부분 수집</b>=일부만(주의) · <b>선택적 소스 없음</b>=해당 소스가 없어 대체
소스로 커버(정상, 조치 불필요). LP2PS 는 무료 소스만 사용합니다(CloudTrail Lake·유료 분석기 미사용).</p>
<table><tr><th>소스</th><th>상태</th><th>비고</th></tr>{src_rows or "<tr><td colspan=3>—</td></tr>"}</table>

<footer>LP2PS — IAM 최소권한 분석. 이 리포트는 읽기 전용 수집 데이터 기반으로 결정론적으로 생성됩니다.
실제 권한 변경(Permission Set 적용·역할 삭제 등)은 사람이 검토 후 수행합니다.</footer>
</body></html>
"""


def _load_catalog(storage: "Storage") -> list[CatalogEntry]:
    if not storage.exists("catalog.json"):
        return []
    raw = storage.read_json("catalog.json")
    return [CatalogEntry.model_validate(e) for e in raw]  # type: ignore[union-attr]



def _items_for(rec: PrincipalRecord, cfg: "Config",
               group: "CleanupGroup | None") -> list[CleanupItem]:
    """한 대상에서 나오는 항목 전부(id 미부여). `group` 은 이미 배정된 값을 받는다.

    `_cleanup_items` 의 루프 본문을 그대로 떼어낸 것이다. 함수로 뺀 이유는 재사용이 아니라
    **정확성**이다 — `summarize_exclusions` 가 "제외 게이트가 없었다면 몇 건이 올라왔을까"
    (= 숨긴 권고 수)를 세야 하는데, 그 계산을 사본으로 두면 유형이 하나 늘 때마다 화면의
    '제외 내역' 숫자가 조용히 틀린다. 같은 함수를 부르면 어긋날 수 없다.
    """
    items: list[CleanupItem] = []
    uses_idc = cfg.provisioning.uses_identity_center

    # unverified_usage — action 단위 근거가 없어 트랙 배정에서 제외된 대상.
    # 🔴 이 유형이 없으면 대상이 **화면에서 통째로 사라진다**(R6 위반). 실측: `no_used_actions`
    # 2건 중 1건은 다른 유형(wildcard)으로도 올라오지만, 나머지 1건은 어느 유형에도 걸리지
    # 않아 '확인 필요' 카드가 약속한 18건이 17건이 됐다. 없는 것을 세지 않으려면 있는 것을
    # 빠뜨리지도 않아야 한다.
    if rec.track == "excluded" and rec.excluded_reason == "no_used_actions":
        items.append(_item("unverified_usage", group, rec, rec.risk_level,
                           "실사용 권한이 action 단위로 확인되지 않음 — 최소권한 정책을 만들 수 없다",
                           _recommendation("unverified_usage", uses_idc, group),
                           evidence={
                               "식별 유형": rec.identity_type,
                               "부여된 action 수": str(len(rec.granted_actions)),
                               "실사용 action 수": "0",
                               # 서비스 단위 근거가 있으면 이 대상은 **쓰이는 중**이다 —
                               # 그 사실이 "지우면 안 된다" 의 근거이므로 반드시 싣는다.
                               "사용 흔적 서비스": ", ".join(rec.used_services[:5]) or "없음",
                               "관측 창": _window_phrase(rec),
                               "제외 사유": "실사용 권한이 action 단위로 확인되지 않음",
                               "수집 소스": ", ".join(rec.source) or "-",
                           }))

    # unused_role: **미사용 N일 이상**(R3 신 정의 — 근거가 IAM 활동 기록이든 생성일이든 무관).
    # 권한 보유는 inline(granted_actions) 또는 attached managed 정책 중 하나면 성립
    # (managed-only 역할도 미사용 대상으로 잡는다).
    #
    # `used_services` 를 함께 보는 이유: Access Advisor 의 action-level 추적 범위는 서비스별로
    # 달라, 실제로 쓰이는 역할도 action 세부가 안 나와 `used_actions` 가 빌 수 있다. 그때 서비스
    # 단위 last_authenticated 만 있으면 그 역할은 **쓰이는 중**이다 — "미사용, 삭제 검토"
    # 라고 권하면 운영 중인 역할을 지우게 된다(S3 복제 역할 등이 실제로 이 오탐에 걸렸다).
    #
    # 신규 역할은 별 유형으로 가른다: 30일도 안 된 역할은 사용 기록이 없는 게 당연하다(라이브
    # 575: 미사용 판정 59건 중 3건은 당일 생성). 신 정의에서는 구조적으로 `unused_role` 조건에
    # 걸릴 수 없으므로 `is_new_unused_role` 이 따로 잡아 **판단 보류**로 남긴다.
    too_new = is_new_unused_role(rec, cfg.risk_rules.new_principal_days)
    if is_unused_role(rec, cfg.risk_rules.unused_role_days) or too_new:
        # 🔴 미사용이라는 사실만으로 삭제를 권고하지 않는다(R5·트랙③-b). 신뢰 대상이 우리
        # 테넌트로 **확인된** 것만 `unused_role`(삭제 검토)이고, 확인되지 않은 것은
        # `unconfirmed_trust_role` 로 갈라 소유자 확인으로 보낸다. 이 분기가 없으면 벤더가
        # 심어놓은 역할이 "역할 삭제" 권고를 달고 목록에 섞여 목록 전체의 신뢰를 깬다.
        if too_new:
            ctype: CleanupType = "new_role_unused"
        elif is_deletion_reviewable(rec):
            ctype = "unused_role"
        else:
            ctype = "unconfirmed_trust_role"
        last_activity, unused_period = _unused_period(rec)
        if too_new:
            # 관측 기간 자체가 부족한 역할에 하한을 적으면 안 된다. 라이브 575 에서 당일 생성
            # 역할이 "미사용 최소 0일 이상" 으로 나왔다 — 참이지만 아무 정보가 없고, 숫자가
            # 판단처럼 읽힌다. 이 유형에서 정확한 말은 "아직 판단할 수 없다" 다.
            unused_period = f"판단 보류(생성 후 {rec.age_days}일 — 관측 기간 부족)"
            detail = f"생성 후 미사용(생성 {rec.age_days}일 경과 — 관측 기간 부족)"
        elif ctype == "unconfirmed_trust_role":
            # 유형 자체가 "미사용" 이 아니라 **미사용 + 신뢰 미확인** 이므로 두 사실을 함께 적는다.
            # 미사용만 적으면 화면에서 `unused_role` 과 구별되지 않고, 그러면 카드를 갈라 놓은
            # 의미(삭제 권고 여부가 다르다)가 detail 문장에서 사라진다.
            # 🔴 문장은 `trust_scope` 별로 갈라야 한다. `tooling`(신뢰 대상이 이 도구가 사는 계정뿐)
            # 에 "외부 연동 의심" 을 적으면 **거짓**이다 — 같은 행의 증거 표는 `_TRUST_SCOPE_LABEL`
            # 로 "정상 운영 경로" 라고 말하므로 한 행이 자기와 모순된다(라이브 17건 중 6건이 그
            # 상태였다: 같은 계정 역할을 신뢰하는 StackSet 실행 역할들). 분류·권고는 그대로 둔다 —
            # 내부로 **확인**한 것은 아니므로 소유자 확인이 맞고, 문장만 사실에 맞춘다.
            if rec.trust_scope == "tooling":
                detail = (f"미사용 {unused_period}이나 신뢰 대상이 이 도구가 사는 계정뿐 — "
                          f"내부로 확인은 못 함({last_activity})")
            else:
                detail = f"미사용 {unused_period}이나 신뢰 대상 미확인 — 외부 연동 의심({last_activity})"
        else:
            detail = f"미사용 역할(미사용 {unused_period} — {last_activity})"
        trust_evidence = {
            # 신뢰 축 근거는 이 유형에만 싣는다(unused_role 은 '확인된 내부' 라는 사실이 유형
            # 자체에 이미 들어 있다). 소유자에게 물어볼 사람에게 필요한 것이 이 줄들이다.
            "신뢰 범위 판정": _TRUST_SCOPE_LABEL.get(rec.trust_scope, rec.trust_scope),
            "신뢰 대상": ", ".join(rec.trust_principals[:5]) or "미수집",
            "소속 테넌트 그룹": rec.tenant_group or "기본 그룹",
            "판정 기준": "config `accounts[].group` 으로 확인된 계정·AWS 서비스만 내부로 본다",
            # 계정 ID 만 따로 싣는다 — '확인 필요' 화면이 **신뢰 계정별로 묶어** 보여준다. 소유자
            # 확인은 역할 하나씩 하는 일이 아니라 "저 계정 누구 것이냐" 한 번으로 여러 건이 같이
            # 풀리는 일이다. 화면이 위 '신뢰 대상' ARN 문자열을 다시 파싱하면 형식이 조금만 달라도
            # 조용히 '미확인' 묶음으로 떨어진다(게다가 위 줄은 5개로 잘려 있다).
            "신뢰 계정": ", ".join(_trust_accounts(rec)) or "미수집",
        } if ctype == "unconfirmed_trust_role" else {}
        # 신규 역할에는 **언제 판정할 수 있게 되는지**를 싣는다. "관측 기간 부족" 만 적으면 고객이
        # 할 수 있는 일이 없어 보이지만, 실제로 할 일은 그날까지 기다리는 것이다. 화면은 이 값으로
        # 오름차순 정렬해 "곧 판정되는 것" 을 위에 올린다 — detail 문장에서 숫자를 긁으면 안 된다.
        days_left = {
            "판정까지 남은 일수": (
                str(max(0, cfg.risk_rules.new_principal_days - rec.age_days))
                if rec.age_days is not None else "확인 불가"
            ),
        } if too_new else {}
        items.append(_item(ctype, group, rec, rec.risk_level, detail,
                           _recommendation(ctype, uses_idc, group),
                           evidence={
                               "식별 유형": "role",
                               **trust_evidence,
                               **days_left,
                               "부여된 action 수": str(len(rec.granted_actions)),
                               # 기간과 흔적을 나눠 싣는다: '미사용 기간' 은 IAM 이 추적한 역할
                               # 활동 기준, '수집된 사용 흔적' 은 우리가 CloudTrail·Advisor 에서
                               # 실제로 받은 것이다.
                               "마지막 활동": last_activity,
                               "미사용 기간": unused_period,
                               # 🔴 예전에는 이 두 줄이 "없음" 리터럴이었다. 미사용 판정이 사용
                               # 근거의 **부재**를 요구했으니 참이었지만, 신 판정식에서는 오래된
                               # 사용 흔적이 있어도 미사용이 된다(84개) — 리터럴을 남겨 두면 증거가
                               # 거짓을 말한다. 흔적을 지우지 않고 **언제였는지**를 적는다.
                               #
                               # 🔴 라벨이 `사용 근거` 였다가 바뀌었다(결함 C). 와일드카드 카드의
                               # 같은 이름 줄은 **관측 창 설명**이어서, 한 라벨이 카드마다 다른
                               # 것을 가리켰다 — 세 카드를 나란히 놓고 비교할 수 없었다.
                               "수집된 사용 흔적": _usage_evidence_phrase(rec),
                               "사용 흔적 서비스": ", ".join(rec.used_services[:8]) or "없음",
                               "역할 생성일": rec.create_date or "미수집",
                               "생성 후 경과": f"{rec.age_days}일" if rec.age_days is not None else "확인 불가",
                               # 등급과 임계치를 함께 싣는다 — 같은 90일이 어떤 경계로 이
                               # 유형이 됐는지 보이지 않으면 config 를 바꾼 고객이 화면 숫자를
                               # 자기 기준으로 재해석할 수 없다.
                               "미사용 등급": _tier_label(
                                   rec.unused_tier, cfg.risk_rules.unused_tier_days),
                               "일수 근거": _BASIS_LABEL.get(rec.unused_days_basis or "", "없음"),
                               # 라벨이 유형에 따라 달라야 한다: `unconfirmed_trust_role` 에
                               # "삭제 검토 임계" 라고 적으면 권고 문구가 "삭제 아님" 인데
                               # 증거는 삭제 임계를 말하는 자기모순이 된다.
                               ("미사용 판정 임계" if ctype == "unconfirmed_trust_role"
                                else "삭제 검토 임계"):
                                   f"미사용 {cfg.risk_rules.unused_role_days}일 이상",
                               "판단 보류 기준": f"생성 후 {cfg.risk_rules.new_principal_days}일 미만",
                               "관리형 정책 연결": "예" if rec.has_managed_policies else "아니오",
                               "수집 소스": ", ".join(rec.source) or "-",
                           }))

    # unused_permission: granted-vs-used 갭 중 **미사용이 확정된 것만**(m2 가 이미 가름).
    # 판정 불가분은 건수만 증거로 실어 보낸다 — 조치 대상이 아니지만, 이 백로그가 부여 권한
    # 전체를 설명한다고 오해하지 않게 하려면 얼마가 미판정인지 보여야 한다.
    action_gaps = [f for f in rec.unused_findings if ":" in f]
    undetermined = [f for f in rec.undetermined_findings if ":" in f]
    if action_gaps:
        detail = f"granted 이나 미사용: {action_gaps[0]} 외 {max(0, len(action_gaps) - 1)}건"
        evidence = {
            "부여된 action 수": str(len(rec.granted_actions)),
            "실사용 action 수": str(len(rec.used_actions)),
            "미사용 action 수": str(len(action_gaps)),
            "근거 불명 action 수": str(len(undetermined)),
            # 🔴 셈의 정의를 카드에 적는다(결함 D). 라이브에 `실사용 0` 인데 `미사용 5 / 근거
            # 불명 5`(부여 10)인 대상이 있었다 — 역할 전체가 미사용인데 "미사용 5" 만 읽으면
            # 절반은 문제가 없는 것처럼 보인다. 근거 불명을 미사용에 합산하지 않는 것은 의도이며
            # (근거가 없다는 것은 안 썼다는 증거가 아니다), 그 의도를 화면에 남긴다.
            "미사용 셈 기준": (
                f"근거 불명 {len(undetermined)}건은 미사용에 합산하지 않음"
                if undetermined else "부여 action 전부에 사용 근거 판정이 있음"
            ),
            "대표 미사용": ", ".join(action_gaps[:5]),
            # 권고문에서 떼어낸 '어디서 하나'(F18). 조치문은 "무엇을" 한 줄이면 되고, 그 작업을
            # 하는 화면은 근거 칸에서 알려준다.
            "적용 경로": "persona 검토 화면에서 정책·역할 Terraform 을 받아 적용",
            "수집 소스": ", ".join(rec.source) or "-",
        }
        if rec.wildcard_grants:
            # 🔴 같은 부여를 두 카드가 다르게 말하던 자리다(결함 B). 와일드카드 카드는 "산정
            # 불가", 이 카드는 "미사용 N건" 이라 세는데, `*` 안에 그 N건이 포함돼 있다. 어느
            # 쪽도 틀린 말이 아니라 **범위가 다르다** — 그 범위를 명시한다.
            evidence["와일드카드 보유"] = (
                f"예({', '.join(rec.wildcard_grants[:3])}) — 위 개수는 명시 부여분만"
            )
        if rec.identity_type == "role":
            # 역할이면 IAM 이 추적한 마지막 활동 시각을 함께 싣는다(전 리전). user 에는 넣지
            # 않는다 — user 에는 RoleLastUsed 가 애초에 없어서 '기록 없음' 이 '안 쓰였다' 로
            # 잘못 읽힌다. 기간(하한)은 여기서 말하지 않는다: 실사용 action 이 있는 항목에
            # "최소 N일 미사용" 을 붙이면 같은 화면이 서로 반대를 주장한다.
            evidence["마지막 활동"] = _unused_period(rec)[0]
        items.append(_item("unused_permission", group, rec, rec.risk_level, detail,
                           _recommendation("unused_permission", uses_idc, group), evidence=evidence))

    # wildcard_grant (R4) — **미사용 여부·트랙과 무관하게** 올린다.
    #
    # 이 유형이 없던 동안 전 권한 보유자는 findings 0 으로 목록에서 가장 깨끗해 보였다:
    # `*` 는 부여 범위에 상한이 없어 갭 계산에서 빠지고(그건 맞다 — "미사용 3개" 처럼 셀 수가
    # 없다), 빠진 뒤 아무 데도 안 남았기 때문이다. 세는 것을 포기하는 것과 **보고하지 않는
    # 것**은 다르다.
    if rec.wildcard_grants:
        head = rec.wildcard_grants[0]
        more = len(rec.wildcard_grants) - 1
        detail = (f"와일드카드 권한 보유: {head}" + (f" 외 {more}건" if more else ""))
        items.append(_item("wildcard_grant", group, rec, rec.risk_level, detail,
                           _recommendation("wildcard_grant", uses_idc, group),
                           evidence={
                               "식별 유형": rec.identity_type,
                               "보유 와일드카드": ", ".join(rec.wildcard_grants[:5]),
                               "와일드카드 수": str(len(rec.wildcard_grants)),
                               "부여된 action 수": str(len(rec.granted_actions)),
                               "실사용 action 수": str(len(rec.used_actions)),
                               # 이 줄이 핵심이다 — 다른 유형과 달리 "미사용 N개" 를 낼 수
                               # 없는 이유를 화면에 남긴다. 없으면 0 이 '깨끗함' 으로 읽힌다.
                               "미사용 개수 산정": "불가(부여 범위에 상한이 없음)",
                               # 라벨을 `사용 근거` 에서 바꿨다(결함 C) — 이 값은 사용 흔적이
                               # 아니라 **무엇을 얼마나 관측했는지**다.
                               "관측 창": _window_phrase(rec),
                               "수집 소스": ", ".join(rec.source) or "-",
                           }))

    # trust_policy_wildcard (R4) — 권한 범위가 아니라 **신뢰 경계** 결함이다.
    if rec.trust_wildcard:
        items.append(_item("trust_policy_wildcard", group, rec, rec.risk_level,
                           "신뢰정책 와일드카드(조건 없이 누구든 assume 가능)",
                           _recommendation("trust_policy_wildcard", uses_idc, group),
                           evidence={
                               "식별 유형": rec.identity_type,
                               "신뢰 대상": ", ".join(rec.trust_principals[:5]) or "미수집",
                               # 조건이 붙은 와일드카드는 이 유형에 오지 않는다(M2 판정).
                               # 그 기준을 증거에 적어 둬야 "왜 저 역할은 안 나왔나" 에 답할 수 있다.
                               "판정 기준": "Condition 없는 `Principal:\"*\"`(조건부는 제외)",
                               # 권고문에서 떼어낸 예시(F18) — 조치는 "조건 추가" 이고, 어떤 조건이
                               # 쓸 만한지는 근거 칸에서 보여준다.
                               "권장 조건 예": "aws:PrincipalOrgID(조직 내부로 제한)",
                               "부여된 action 수": str(len(rec.granted_actions)),
                               "수집 소스": ", ".join(rec.source) or "-",
                           }))

    # cross_tenant_trust (R5) — **미사용 여부·트랙과 무관하게** 올린다. 현역이든 미사용이든
    # 다른 고객 계정을 신뢰한다는 사실 자체가 조사 사유다. 이 도구가 스스로 찾기 가장 어려운
    # 종류의 문제이고(조직도가 아니라 config 그룹 선언만이 답을 준다), 미사용 조건을 걸면
    # 활발히 쓰이는 경계 위반이 조용히 빠진다.
    if rec.trust_scope == "cross_tenant":
        head = rec.trust_principals[0] if rec.trust_principals else "미수집"
        more = max(0, len(rec.trust_principals) - 1)
        detail = ("다른 테넌트 그룹 계정을 신뢰: " + head + (f" 외 {more}건" if more else ""))
        items.append(_item("cross_tenant_trust", group, rec, rec.risk_level, detail,
                           _recommendation("cross_tenant_trust", uses_idc, group),
                           evidence={
                               "식별 유형": rec.identity_type,
                               "소속 테넌트 그룹": rec.tenant_group or "기본 그룹",
                               "신뢰 대상": ", ".join(rec.trust_principals[:5]) or "미수집",
                               "신뢰 범위 판정": _TRUST_SCOPE_LABEL["cross_tenant"],
                               # 미사용이 아니어도 올라온다는 사실을 증거에 남긴다 — 없으면
                               # "안 쓰이니 지우면 되겠네" 로 읽힌다.
                               "미사용 등급": _tier_label(
                                   rec.unused_tier, cfg.risk_rules.unused_tier_days),
                               "판정 기준": "config `accounts[].group` 이 이 계정과 다른 계정을 신뢰",
                               # 권고문에서 떼어낸 두 번째 조치(F18) — 의도된 연동이면 고칠 곳은
                               # 신뢰정책이 아니라 우리 config 다. 조치 칸에 함께 적으면 둘 다
                               # 안 읽히므로 여기 남긴다.
                               "의도된 연동이라면": "config `accounts[].group` 선언을 고칠 것",
                               "부여된 action 수": str(len(rec.granted_actions)),
                               "수집 소스": ", ".join(rec.source) or "-",
                           }))

    # long_lived_key
    if rec.access_key_age_days is not None and rec.access_key_age_days >= cfg.risk_rules.long_lived_key_days:
        items.append(_item("long_lived_key", group, rec, rec.risk_level,
                           f"액세스키 age {rec.access_key_age_days}일",
                           _recommendation("long_lived_key", uses_idc, group),
                           evidence={
                               "액세스키 나이": f"{rec.access_key_age_days}일",
                               "임계 기준": f"{cfg.risk_rules.long_lived_key_days}일 이상",
                               "MFA": "설정" if rec.mfa else "미설정",
                               "콘솔 로그인": "가능" if rec.console_login else "불가",
                           }))

    # no_mfa (콘솔 로그인 가능한 user 한정 — 서비스 계정 오탐 방지)
    if rec.identity_type == "user" and rec.console_login and not rec.mfa:
        items.append(_item("no_mfa", group, rec, rec.risk_level,
                           "MFA 미설정 콘솔 사용자", _recommendation("no_mfa", uses_idc, group),
                           evidence={
                               "식별 유형": "user",
                               "콘솔 로그인": "가능",
                               "MFA": "미설정",
                               "액세스키 나이": f"{rec.access_key_age_days}일" if rec.access_key_age_days is not None else "해당 없음",
                           }))

    # escalation_path (건별)
    for path in rec.escalation_paths:
        # 규칙 식별자(via/to)는 그대로 두고, 사람이 읽는 문장을 앞에 세운다. 문구가 없는 규칙은
        # 원문으로 폴백한다(설명이 없다고 항목을 빠뜨리면 그게 더 나쁘다).
        title, what, to_label = _ESCALATION_LABEL.get(
            (path.via, path.to),
            (f"{path.via} → {path.to}", "이 권한 조합은 스스로 권한을 넓히는 데 쓸 수 있습니다.", path.to),
        )
        items.append(_item("escalation_path", group, rec, rec.risk_level,
                           title,
                           _recommendation("escalation_path", uses_idc, group),
                           evidence={
                               # 결론(무엇이 가능한가)을 맨 위에 둔다 — 아래 두 줄은 그것을 확인하러
                               # 정책을 열 때 쓰는 열쇠다.
                               "무엇이 가능한가": what,
                               "필요한 권한(정책에서 찾을 문자열)": path.via,
                               "도달 대상": f"{to_label} ({path.to})",
                               "MITRE ATT&CK": _MITRE_LABEL.get(path.mitre, path.mitre),
                               "부여된 action 수": str(len(rec.granted_actions)),
                           },
                           # 한 principal 에 상승 경로가 여러 건 나오므로 경로 자체로 건을 구분한다.
                           key_extra=f"{path.via}\x1f{path.to}\x1f{path.mitre}"))

    return items