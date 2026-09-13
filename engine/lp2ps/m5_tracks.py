"""M5 Tracks — 트랙 배정(R5-b) + 제외 사유(R6).

수집 대상은 계정의 **IAM 사용자 전부 + 역할 전부**다. 아무도 처음부터 버리지 않고, 대신 넷 중
하나로 배정한다. 배정은 `normalized.parquet` 의 `track` · `excluded_reason` 에 기록되며 이후
단계(M5 카탈로그·트랙② 산출물·M6 백로그)는 **다시 판정하지 않고 이 값을 읽는다.**

```
90일 이상 미사용?
   ├─ 예 → 신뢰 대상이 우리 테넌트로 확인됐나?(trust_scope)
   │        ├─ 예   → delete_review  (트랙③, 정책 초안 없음)
   │        └─ 아니오 → owner_review  (트랙③-b, 삭제 권고 안 함)
   └─ 아니오 → 누가 쓰나?
            ├─ 사람·판별 불가 → persona      (트랙①, 여러 대상을 묶어 공통 정책 1개)
            └─ 기계          → service_role (트랙②, 역할별 개별 정책 — 절대 묶지 않는다)
```

**우선순위가 이 모듈의 전부다.** 지울 대상의 정책을 다듬는 것은 낭비이므로 90일 이상 미사용이면
트랙③ 이 트랙①②를 이긴다. 그보다 먼저 제외(R6)가 이긴다 — 손댈 수 없는 대상(AWS 소유)이나
고치면 배포가 깨지는 대상을 조치 목록에 올리면 목록 전체의 신뢰가 깨진다.

제외는 **개수를 화면에 남긴다**(`excluded_reason`). 조용히 사라지면 "왜 우리 역할이 여기 없지?" 에
답할 수 없다. `track=None`(미배정)을 기본값으로 둔 이유도 같다 — `excluded` 를 기본값으로 두면
배정 버그가 '정상적으로 제외됨' 으로 보인다.

불변식 ②(결정론): 입력 레코드의 값만 보고 판정하며 wall-clock·random 없음.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .m5_catalog import _matches_pattern
from .m6_reporter import is_confirmed_internal, is_idle_beyond

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config
    from .models import PrincipalRecord
    from .runctx import RunContext
    from .storage import Storage

# 제외 사유(R6) — 닫힌 집합. **라벨의 정본은 여기다**(화면이 사본을 갖지 않는다). 예전에는 이 dict 에
# 4개만 있고 `rec.exception_type` 이 넣는 3개(service_linked·idc_reserved·sso_ps_synthetic)가 빠져
# 있었다 — 실측 제외 102건 중 53건이 라벨 없는 사유였고, 그러면 화면에 원값이 그대로 뜬다.
EXCLUSION_LABEL = {
    "service_linked": "AWS service-linked 역할(AWS 소유 — 정책 수정 불가)",
    "idc_reserved": "Identity Center 예약 역할(AWS 소유)",
    "sso_ps_synthetic": "Identity Center Permission Set(역할이 아니라 PS 정의)",
    "exception": "AWS 예약 경로의 역할",
    "tool_readonly_role": "이 도구 자신의 읽기 전용 역할",
    "iac_bootstrap_role": "배포 도구 부트스트랩 역할(고객이 config 에 선언한 이름 패턴)",
    "too_new": "생성 후 관측 기간 미달 — 미사용도 현역도 주장할 수 없다",
    "no_used_actions": "실사용 권한이 action 단위로 확인되지 않음(묶을 대상이 없다)",
}

# 🔴 **이 제외를 얼마나 믿을 수 있나.** 세 등급이 섞여 있고, 등급이 다르면 고객이 해야 할 일도 다르다:
#
#   aws_owned         — 사실. ARN 이 AWS 예약 경로(`/aws-service-role/`·`/aws-reserved/…`)에 있다.
#                       고객이 정책을 수정할 수 없으므로 "정책을 다시 쓰라" 는 권고가 성립하지 않는다.
#                       (삭제는 `DeleteServiceLinkedRole` 로 가능하다 — "지울 수 없다" 고 말하면 틀린다.)
#   customer_declared — 고객이 config 에 적은 이름 패턴에 걸렸다. 패턴이 틀리면 조치 대상이 조용히
#                       빠지므로, 화면에서 **패턴별로 무엇이 걸렸는지 볼 수 있어야** 한다.
#   judgment          — 우리 판단이다(관측 기간·근거 부족). 판단이 뒤집힐 수 있으므로 확인 대상으로
#                       올릴 몫이 있다 → `m6_reporter.cleanup_group` 이 일부를 '확인 필요' 로 보낸다.
EXCLUSION_BASIS = {
    "service_linked": "aws_owned",
    "idc_reserved": "aws_owned",
    "sso_ps_synthetic": "aws_owned",
    "exception": "aws_owned",
    "tool_readonly_role": "customer_declared",
    "iac_bootstrap_role": "customer_declared",
    "too_new": "judgment",
    "no_used_actions": "judgment",
}

# 하위호환 별칭(옛 이름). 지우지 않는 이유는 외부 참조가 아니라, 이 dict 가 "제외 사유는 닫힌
# 집합이다" 라는 계약을 문서화하는 자리였기 때문이다.
EXCLUDED_REASONS = EXCLUSION_LABEL

# 신뢰 범위 판정식(`is_confirmed_internal`)은 `m6_reporter` 에 둔다 — 백로그 유형(삭제 권고를
# 하는지)과 트랙 배정이 **같은 함수**를 봐야 한다. 여기 사본을 두면 화면이 "소유자 확인" 이라고
# 배정한 대상의 백로그 문구가 "역할 삭제" 가 되는 어긋남이 생긴다.


def assign_tracks(storage: "Storage", run: "RunContext", cfg: "Config") -> dict[str, int]:
    """normalized 를 읽어 `track`·`excluded_reason` 을 채우고 되쓴다. 반환 = 트랙별 개수.

    `run` 은 쓰지 않지만(결정론 코어는 wall-clock 을 안 본다) 다른 stage 와 시그니처를 맞춰
    파이프라인에서 순서를 바꿔 끼울 수 있게 둔다.
    """
    records = storage.read_normalized()
    counts: dict[str, int] = {}
    for rec in records:
        track, reason = _track_of(rec, cfg)
        rec.track = track  # type: ignore[assignment]
        rec.excluded_reason = reason
        counts[track] = counts.get(track, 0) + 1
    storage.write_normalized(records)
    return dict(sorted(counts.items()))


def _track_of(rec: "PrincipalRecord", cfg: "Config") -> tuple[str, str | None]:
    """(트랙, 제외 사유). 제외가 아니면 사유는 None."""
    excluded = _exclusion_reason(rec, cfg)
    if excluded:
        return "excluded", excluded

    # 90일 이상 미사용이 트랙①② 를 이긴다. 신뢰 대상이 우리 테넌트로 **확인됐을 때만** 삭제 검토다 —
    # 실측에서 미사용 역할의 다수가 벤더·다른 도구가 심어놓은(안 쓰이는 게 정상인) 역할이었고,
    # 삭제 권고 목록에 하나라도 위험한 것이 섞이면 고객이 목록 전체를 안 믿는다.
    if is_idle_beyond(rec, cfg.risk_rules.unused_role_days):
        if is_confirmed_internal(rec):
            return "delete_review", None
        return "owner_review", None

    if _is_machine(rec) and cfg.catalog.exclude_service_roles:
        # 트랙②. `exclude_service_roles` 의 의미가 바뀌었다: "버린다" → "persona 묶음에서 빼고
        # 트랙② 로 보낸다"(키 이름은 기존 고객 config 호환을 위해 유지).
        return "service_role", None

    # 트랙①. 실사용 권한이 없으면 묶을 것이 없다 — 빈 정책이 나오는데 빈 정책은 위험하다.
    if not rec.used_actions:
        return "excluded", "no_used_actions"
    return "persona", None


def _exclusion_reason(rec: "PrincipalRecord", cfg: "Config") -> str | None:
    """R6 제외. 순서는 **더 구체적인 사유가 먼저**다(화면에 뜨는 문장이 달라진다)."""
    if rec.is_exception:
        # AWS 관리 service-linked 역할 · IdC Permission Set 등. M2 가 이미 판정해 둔 사유를 쓴다.
        return rec.exception_type or "exception"
    name = rec.principal.rsplit("/", 1)[-1]
    if cfg.readonly_role_name and name == cfg.readonly_role_name:
        # 모든 대상 계정에 존재하고 관제 계정을 신뢰한다 → 빼지 않으면 계정 수만큼 노이즈가 늘고,
        # 실측에서 실제로 persona 목록에 '판별 불가' 로 올라와 있었다.
        return "tool_readonly_role"
    if cfg.catalog.exclude_principal_patterns and _matches_pattern(
        rec.principal, cfg.catalog.exclude_principal_patterns
    ):
        return "iac_bootstrap_role"
    if rec.unused_tier == "new":
        # 관측 기간 자체가 짧다. 미사용도 현역도 주장할 수 없다.
        return "too_new"
    return None


def _is_machine(rec: "PrincipalRecord") -> bool:
    """기계가 쓰는 대상인가 — **두 축의 논리합**이다(`models.py` 계약).

    `usage_subject`(실제로 누가 집었나, CloudTrail 유래)가 있으면 그것이 이긴다. 없을 때만
    `principal_kind`(누가 집을 수 **있나**, 신뢰정책 유래)로 내려간다. 반대로 두면 신뢰정책이
    `Principal.AWS` 뿐인 자동화 역할(실측 다수)이 계속 persona 로 올라온다.

    `unknown` 은 기계로 보지 않는다 — 추측으로 트랙② 에 보내면 사람이 쓰는 역할이 persona 묶음에서
    빠져 화면에서 사라진다. 남겨서 사람이 보게 하는 쪽이 되돌리기 쉽다.
    """
    if rec.usage_subject == "machine":
        return True
    if rec.usage_subject == "human":
        return False
    return rec.principal_kind == "service"
