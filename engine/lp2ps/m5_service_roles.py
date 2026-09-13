"""M5 Service Roles — 트랙② 산출물(`service_roles.json`). 화면은 P6 에서 판단한다.

**권한을 세지 말고 결정을 센다**(R7). 부여 권한을 하나씩 뿌리면 한 역할에서 3,000줄이 나오고,
그건 안 뿌리는 것과 같다 — 아무도 읽지 않는다. 권한 이름이 `서비스:동작` 구조라서 앞부분으로
접으면 실측 미사용 14,732개가 서비스 단위 2,669행이 되고, 여기서 "인증 이력이 전혀 없는 서비스" 를
한 덩어리로 묶으면 사람이 내릴 **결정이 수백 건**으로 떨어진다.

접기는 **엔진에서** 한다(결정론 코어, 안정 정렬). UI 가 수천 개를 파싱하지 않는다.

트랙② 는 **묶지 않는다**. Lambda 실행 역할 둘을 한 정책으로 묶으면 서로의 권한을 얻는다 —
최소권한의 반대다. `group_key`(부여 권한이 같은 역할을 묶는 해시)는 **표시만** 접기 위한 것이고
정책은 역할별로 낸다.

미사용 판정은 M2 의 3분류(`unused_findings` 확정 / `undetermined_findings` 판정 불가 / used)를
그대로 쓴다. 여기서 Advisor 커버리지를 다시 해석하면 같은 권한이 두 화면에서 다르게 읽힌다.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from .m2_normalizer import _days_since, _unused_tier
from .models import ServiceRollup, ServiceRoleEntry
from .timeutil import max_ts

if TYPE_CHECKING:  # pragma: no cover
    from datetime import datetime

    from .config import Config
    from .models import PrincipalRecord
    from .runctx import RunContext
    from .storage import Storage

SERVICE_ROLES_NAME = "service_roles.json"


def build_service_roles(
    storage: "Storage", run: "RunContext", cfg: "Config"
) -> list[ServiceRoleEntry]:
    """`track == "service_role"` 레코드 → `service_roles.json`. 반환 = ServiceRoleEntry[]."""
    records = storage.read_normalized()
    targets = [r for r in records if r.track == "service_role"]
    # 기준 시각은 `run.started_at` 뿐이다(불변식 ② — 코어에 wall-clock 금지). M2 가 일수를 셀 때
    # 쓴 것과 같은 값이어야 역할 등급과 서비스 등급이 같은 기준선을 갖는다.
    entries = [_entry_for(rec, cfg, run.started_dt) for rec in targets]
    # (계정, ARN) 정렬 — 결정론. 계정을 먼저 두는 이유는 화면이 계정 축으로 필터하기 때문이다.
    entries.sort(key=lambda e: (e.account_id, e.principal))
    storage.write_json(SERVICE_ROLES_NAME, [e.model_dump() for e in entries])
    return entries


def _namespace(action: str) -> str:
    """`s3:GetObject` → `s3`. 네임스페이스가 없는 형태(와일드카드 `*` 등)는 빈 문자열."""
    return action.split(":", 1)[0] if ":" in action else ""


def _entry_for(rec: "PrincipalRecord", cfg: "Config", as_of: "datetime") -> ServiceRoleEntry:
    rollups = _rollups(rec, cfg, as_of)
    # 판단 필요 서비스 = **`keep` 서비스 수**. 화면 라벨이 "판단 필요 서비스" 이므로 값도 서비스
    # 개수여야 한다(사용자 지시 2026-09-11, F15-2).
    #
    # 예전에는 여기에 "인증 이력 없는 서비스 일괄 제거" 묶음 **1건**을 더했다. 그 `+1` 은 서비스가
    # 아니라 작업 1건이어서, 서비스 개수를 세는 컬럼에 단위가 다른 값이 섞였다(실측 79역할:
    # keep 574 + remove 보유 역할 34 = 608). remove 쪽은 `remove_services`(=`줄일 서비스`) 컬럼이
    # 이미 개수로 말하고 있어 정보가 사라지지도 않는다.
    # `undetermined` 는 세지 않는다 — 결론이 '손대지 않는다' 인 항목은 사람이 내릴 결정이 없다.
    # (세면 근거 없는 항목이 값을 부풀려 "정리 권고 N건" 헤드라인이 과장된다.)
    decisions = sum(1 for r in rollups if r.verdict == "keep")
    return ServiceRoleEntry(
        account_id=rec.account_id,
        tenant_group=rec.tenant_group,
        principal=rec.principal,
        group_key=_group_key(rec.granted_actions),
        unused_tier=rec.unused_tier,
        unused_days=rec.unused_days,
        unused_days_basis=rec.unused_days_basis,
        # 관측 구간을 그대로 내려보낸다(측정값). 화면은 "90일" 처럼 측정하지 않은 숫자를 쓰지 않고,
        # 아래 기준값 미만이면 **일수를 아예 표기하지 않는다**.
        observed_days=rec.observed_days,
        # 관측 구간을 숫자로 말해도 되는 최소 일수(기준값, config `catalog.count_min_observed_days`).
        # 예전에는 UI 에 `OBSERVED_MIN_DAYS = 30` 리터럴이 있었고(불변식 ④ 위반), 그 값은
        # `cloudtrail_max_pages` 와 양립하지 않아 **도달 불가능**했다 — 워크로드가 있는 계정은
        # 전부 경고 `error` 로 떠서 판별력이 0 이었다(실측 79/79 가 `observed_days = 0`).
        count_min_observed_days=cfg.catalog.count_min_observed_days,
        granted_count=len(rec.granted_actions),
        unused_count=len(rec.unused_findings),
        wildcard_grants=list(rec.wildcard_grants),
        service_rollups=rollups,
        decision_count=decisions,
    )


def _group_key(granted: list[str]) -> str:
    """부여 권한 **집합**의 안정 해시(앞 12자). 같은 집합을 가진 역할을 한 행으로 접기 위한 키다.

    실측 84 역할 → 49 그룹. 순서·중복에 흔들리지 않게 정렬 후 중복 제거한다(같은 정책을 순서만
    다르게 쓴 두 역할이 다른 그룹으로 갈리면 접기가 무의미해진다). 빈 집합은 빈 키 — 부여 권한이
    없는 역할끼리 '동일 집합' 으로 묶어 보여줄 이유가 없다.
    """
    if not granted:
        return ""
    payload = "\n".join(sorted(set(granted)))
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def _rollups(rec: "PrincipalRecord", cfg: "Config", as_of: "datetime") -> list[ServiceRollup]:
    """부여 권한을 서비스 네임스페이스 단위로 접는다.

    verdict:
      - `keep`         : 이 서비스를 **썼다** → 정책에 남긴다. 근거는 두 층위 중 하나면 된다:
                         action 단위 사용(`used_actions`) 또는 Advisor 의 서비스 단위 인증
                         (`used_services`). 후자만 있으면 어느 action 인지는 모르지만 **서비스를
                         쓴다는 것은 안다** — 그걸 '판정 불가' 라고 하면 아는 것을 모른다고 말한다.
      - `remove`       : 부여된 권한 전부가 **미사용 확정**이다(Advisor 가 이 서비스 인증 기록 없음을
                         확인했다) → 그 안의 어떤 권한도 쓰였을 수 없다.
      - `undetermined` : 안 썼다는 증거가 없다(Advisor 커버리지 없음·소스 degraded, 또는 이 서비스에
                         **와일드카드만** 부여돼 셀 수 있는 권한이 없다) → 손대지 않는다.

    판정은 **셀 수 있는** 부여 권한으로만 한다. 서비스 단위 와일드카드(`acm:Get*`)는 M2 의 갭 계산에서
    빠져 있어 미사용 확정에 들어올 수 없다 — 그것을 개수에 세면 열거 가능한 권한이 전부 미사용 확정인
    서비스까지 '판정 불가' 가 된다. 대신 `wildcard_grants` 로 행에 남겨, 정리를 실행할 때 이 와일드카드
    문 자체를 고쳐야 한다는 사실이 화면에서 사라지지 않게 한다.

    등급(`tier`)은 R2 의 **권한 단위** 규칙이다: 미사용 action 에는 마지막 사용일이 정의상 없으므로
    그 서비스를 마지막으로 쓴 날을 **하한선**으로 쓴다(서비스를 200일 안 썼으면 그 안의 어떤 권한도
    200일 안 쓰였다). 서비스 사용 기록이 아예 없으면 최상위 등급이고, 판정 불가면 등급도 없다 —
    등급이 0 이 아니라 **미측정**임을 None 으로 표현한다.
    """
    used_last: dict[str, str | None] = {}
    used_count: dict[str, int] = {}
    for u in rec.used_actions:
        ns = _namespace(u.action)
        if not ns:
            continue
        used_count[ns] = used_count.get(ns, 0) + 1
        used_last[ns] = max_ts(used_last.get(ns), u.last_used)

    unused = set(rec.unused_findings)
    # 와일드카드 판정은 M2 가 이미 한 것을 그대로 쓴다(여기서 다시 해석하면 같은 권한이 두 화면에서
    # 다르게 읽힌다). `*` 는 네임스페이스가 없어 어느 행에도 안 붙고, `acm:Get*` 는 acm 행에 붙는다.
    wildcards = set(rec.wildcard_grants)
    granted_by_ns: dict[str, list[str]] = {}
    wildcard_by_ns: dict[str, list[str]] = {}
    for action in rec.granted_actions:
        ns = _namespace(action)
        if not ns:
            # 전역 와일드카드(`*`)는 어느 서비스에도 접히지 않는다 — 부여 범위에 상한이 없어 개수를
            # 셀 수 없다(R4). 보유 사실은 항목 단위 `wildcard_grants` 로 이미 남아 있다.
            continue
        if action in wildcards:
            # 서비스 단위 와일드카드는 **세지 않지만 이 서비스 행에 남긴다**. 예전에는 그냥 갯수에
            # 넣었고, 그 결과 미사용 확정 근거가 없는 이 권한 때문에 서비스 전체가 '판정 불가' 로
            # 떨어졌다 — 실측 판정 불가 1,365행 중 대부분(ReadOnlyAccess 형태 정책)이 이것이었다.
            wildcard_by_ns.setdefault(ns, []).append(action)
            continue
        granted_by_ns.setdefault(ns, []).append(action)

    # Advisor 가 **인증을 확인한** 서비스. action 단위 근거가 없어도 "이 서비스는 쓰인다" 는 사실이다.
    # 이것을 빼면 M2 케이스 ③(서비스는 썼는데 이 action 의 근거가 없음)의 서비스가 통째로
    # '판정 불가' 로 표시된다 — 실측에서 접기 행의 절반 이상이 그렇게 나왔고, 화면이 아는 것을
    # 모른다고 말하는 셈이었다.
    authed = set(rec.used_services)

    boundaries = cfg.risk_rules.unused_tier_days
    new_days = cfg.risk_rules.new_principal_days
    rollups: list[ServiceRollup] = []
    for ns in sorted(set(granted_by_ns) | set(wildcard_by_ns) | set(used_count) | authed):
        granted = granted_by_ns.get(ns, [])
        used_n = used_count.get(ns, 0)
        last_used = used_last.get(ns)
        if used_n or ns in authed:
            verdict = "keep"
        elif granted and all(a in unused for a in granted):
            verdict = "remove"
        else:
            verdict = "undetermined"
        if verdict == "keep":
            # 하한선이 짧으면(어제 썼다) 아무 말도 못 한다 — `_unused_tier` 가 active 를 준다.
            tier = _unused_tier(_days_since(last_used, as_of), None, boundaries, new_days)
        elif verdict == "remove":
            # 인증 기록이 아예 없다 → 최상위 등급. 나이 미달(new)은 트랙 배정에서 이미 제외됐다.
            tier = "cleanup"
        else:
            tier = None
        rollups.append(
            ServiceRollup(
                namespace=ns,
                granted_count=len(granted),
                wildcard_grants=sorted(wildcard_by_ns.get(ns, [])),
                used_count=used_n,
                last_used=last_used,
                tier=tier,  # type: ignore[arg-type]
                verdict=verdict,  # type: ignore[arg-type]
            )
        )
    return rollups
