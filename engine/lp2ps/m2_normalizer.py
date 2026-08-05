"""M2 Normalizer — raw/** → normalized.parquet (`PrincipalRecord[]`).

M1 수집 raw JSON 을 계정 단위로 읽어 principal 단위 `PrincipalRecord` 로 정규화한다:
- granted_actions ← credential_report 의 inline 정책 문서(Allow Action)
- used_actions   ← access_advisor(action-level) ∪ cloudtrail(event → action 근사)
- unused_findings ← analyzer_unused findings + (granted − used) 계산 갭
- mfa / access_key_age_days ← credential report CSV
- source          ← 이 principal 에 기여한 수집 소스 목록

불변식 ②(결정론): as_of(run.started_at) 기준으로만 시간 계산, 안정 정렬, wall-clock 미사용.
risk_score/risk_level/persona 등은 후속 모듈(m4/m5)이 채운다 — 여기선 계약 기본값.

한계(M1): attached **managed** 정책의 action 확장은 하지 않는다(문서 미수집). granted_actions 는
inline 정책 기준이며, managed 확장은 후속에서 GetPolicyVersion 으로 보강한다(읽기전용 유지).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .collectors.access_advisor import SOURCE as ADVISOR
from .collectors.analyzer_unused import SOURCE as ANALYZER
from .collectors.cloudtrail import SOURCE as CLOUDTRAIL
from .collectors.credential_report import SOURCE as CRED_REPORT
from .collectors.idc_permission_sets import SOURCE as IDC
from .models import PrincipalRecord, UsedAction
from .timeutil import max_ts

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

_NO_DATE_SENTINELS = frozenset({"", "N/A", "no_information", "not_supported"})


def normalize(storage: "Storage", run: "RunContext") -> list[PrincipalRecord]:
    """raw/** → PrincipalRecord[] (정렬됨) 를 만들고 normalized.parquet 로 기록."""
    as_of = run.started_dt
    records: list[PrincipalRecord] = []

    for account_id in storage.list_accounts():
        raw = _load_account_raw(storage, account_id)
        records.extend(_normalize_account(account_id, raw, run.run_id, as_of))

    records.sort(key=lambda r: (r.account_id, r.principal))
    storage.write_normalized(records)
    return records


def _load_account_raw(storage: "Storage", account_id: str) -> dict[str, dict]:
    """계정의 존재하는 소스 raw JSON 을 {source: data} 로 로드(없으면 생략)."""
    out: dict[str, dict] = {}
    for source in storage.list_sources(account_id):
        out[source] = storage.read_raw(account_id, source)  # type: ignore[assignment]
    return out


def _normalize_account(
    account_id: str, raw: dict[str, dict], run_id: str, as_of: datetime
) -> list[PrincipalRecord]:
    cred = raw.get(CRED_REPORT, {})
    inventory = {p["principal"]: p for p in (cred.get("principals", []) or [])}
    cred_by_arn = _index_credential_report(cred.get("credential_report", []) or [])

    used_by_arn, used_sources_by_arn = _used_actions_by_principal(raw)
    analyzer_by_arn = _analyzer_findings_by_principal(raw.get(ANALYZER, {}))

    # principal 집합 = 인벤토리 ∪ used ∪ analyzer. credential_report 가 degraded 여도 다른 소스가
    # 본 principal 은 최소 레코드로 살린다(그렇지 않으면 이 소스 하나 실패로 전체가 비어버림).
    all_arns = set(inventory) | set(used_by_arn) | set(analyzer_by_arn)

    records: list[PrincipalRecord] = []
    for arn in all_arns:
        p = inventory.get(arn)
        in_inventory = p is not None
        granted = _granted_actions(p) if in_inventory else []
        used = used_by_arn.get(arn, [])
        used_action_names = {u.action for u in used}

        # (granted − used) 갭 + analyzer findings 를 unused_findings 로 합친다.
        gap = sorted(a for a in granted if a not in used_action_names and not _is_wildcard(a))
        analyzer_findings = analyzer_by_arn.get(arn, [])
        unused_findings = sorted(set(gap) | set(analyzer_findings))

        cred_row = cred_by_arn.get(arn, {})
        # 이 principal 에 **실제로 기여한** 소스만 기록(거짓 양성 방지):
        #   credential_report=인벤토리 출처일 때만, advisor/cloudtrail=used 기여분,
        #   analyzer_unused=이 principal 에 finding 이 있을 때만.
        contributing: set[str] = set()
        if in_inventory:
            contributing.add(CRED_REPORT)
        contributing |= used_sources_by_arn.get(arn, set())
        if analyzer_findings:
            contributing.add(ANALYZER)

        identity_type = p.get("identity_type", "role") if in_inventory else _identity_from_arn(arn)
        has_managed = bool(p.get("attached_policies")) if in_inventory else False

        records.append(
            PrincipalRecord(
                account_id=account_id,
                principal=arn,
                identity_type=identity_type,
                granted_actions=sorted(set(granted)),
                used_actions=used,
                unused_findings=unused_findings,
                mfa=_mfa(cred_row),
                console_login=_console_login(cred_row),
                has_managed_policies=has_managed,
                access_key_age_days=_access_key_age_days(cred_row, as_of),
                source=sorted(contributing),
                run_id=run_id,
            )
        )

    # IdC Permission Set 할당 → sso_ps principal 레코드(PS 기반 사람 접근).
    # 마이그레이션 스냅샷 비율(사람 접근 중 PS 기반 비율) 산출에 쓰인다.
    records.extend(_sso_ps_records(account_id, raw.get(IDC, {}), run_id))
    return records


def _sso_ps_records(account_id: str, idc_raw: dict, run_id: str) -> list[PrincipalRecord]:
    """IdC account assignment → identity_type='sso_ps' 레코드(할당 principal 당 1건, 중복 제거)."""
    seen: set[str] = set()
    out: list[PrincipalRecord] = []
    for a in idc_raw.get("permission_set_assignments", []) or []:
        # principal(사람/그룹) + PS 조합을 고유 식별자로. 사람 접근 1건 = sso_ps 1개.
        pid = a.get("principal_id", "")
        ps = a.get("permission_set_name", "")
        if not pid:
            continue
        key = f"sso_ps::{account_id}::{ps}::{pid}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            PrincipalRecord(
                account_id=account_id,
                principal=key,
                identity_type="sso_ps",
                source=[IDC],
                run_id=run_id,
            )
        )
    out.sort(key=lambda r: r.principal)
    return out


def _identity_from_arn(arn: str) -> str:
    """인벤토리에 없는 principal(예: credential_report degraded 시 CloudTrail/analyzer 발) 의
    identity_type 을 ARN 모양으로 추정. 모르면 'role'(대다수) 로 둔다."""
    if ":user/" in arn:
        return "user"
    if ":role/" in arn:
        return "role"
    return "role"


# ---- granted actions (inline 정책) ----
def _granted_actions(principal: dict) -> list[str]:
    actions: set[str] = set()
    for pol in principal.get("inline_policies", []) or []:
        actions.update(_actions_from_document(pol.get("document", {})))
    return sorted(actions)


def _actions_from_document(document: dict) -> set[str]:
    """IAM 정책 문서에서 Allow Action 을 추출(Deny·NotAction 제외)."""
    out: set[str] = set()
    if not isinstance(document, dict):
        return out
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action")
        if isinstance(action, str):
            out.add(action)
        elif isinstance(action, list):
            out.update(a for a in action if isinstance(a, str))
    return out


def _is_wildcard(action: str) -> bool:
    return "*" in action


# ---- used actions (access advisor ∪ cloudtrail) ----
def _used_actions_by_principal(
    raw: dict[str, dict],
) -> tuple[dict[str, list[UsedAction]], dict[str, set[str]]]:
    """principal ARN → (병합된 UsedAction 목록, 실제 기여한 used 소스 집합).

    두 번째 반환값으로 각 principal 에 어느 소스(advisor/cloudtrail)가 실제 used action 을
    기여했는지 추적한다 → source 필드 거짓 양성 방지.
    """
    merged: dict[str, dict[str, UsedAction]] = {}
    sources: dict[str, set[str]] = {}

    # Access Advisor: action-level, 서비스 네임스페이스 + action 이름.
    # 중요: TrackedActionsLastAccessed 는 principal 이 "추적되는" 모든 action 을 나열하며,
    # 그중 실제 사용된 것만 last_accessed 가 채워진다. last_accessed=None 은 **미사용**이므로
    # used 에 넣지 않는다(넣으면 granted-vs-used 갭이 무너져 도구 목적이 사라진다).
    for entry in raw.get(ADVISOR, {}).get("last_accessed", []) or []:
        arn = entry.get("principal", "")
        for svc in entry.get("services", []) or []:
            namespace = svc.get("service", "")
            for a in svc.get("actions", []) or []:
                name = a.get("action", "")
                last = a.get("last_accessed")
                if not name or last is None:
                    continue
                full = name if ":" in name else f"{namespace}:{name}"
                _merge_used(merged, arn, full, last, 0)
                sources.setdefault(arn, set()).add(ADVISOR)

    # CloudTrail: eventSource(예: s3.amazonaws.com) + eventName → action 근사.
    for row in raw.get(CLOUDTRAIL, {}).get("usage", []) or []:
        arn = row.get("principal", "") or ""
        if not arn:
            continue
        action = _event_to_action(row.get("event_source", ""), row.get("event_name", ""))
        if not action:
            continue
        _merge_used(merged, arn, action, row.get("last_used"), int(row.get("count", 0) or 0))
        sources.setdefault(arn, set()).add(CLOUDTRAIL)

    out: dict[str, list[UsedAction]] = {}
    for arn, by_action in merged.items():
        out[arn] = sorted(by_action.values(), key=lambda u: u.action)
    return out, sources


def _merge_used(
    merged: dict[str, dict[str, UsedAction]],
    arn: str,
    action: str,
    last_used: str | None,
    count: int,
) -> None:
    by_action = merged.setdefault(arn, {})
    existing = by_action.get(action)
    if existing is None:
        by_action[action] = UsedAction(action=action, last_used=last_used, count_90d=count)
        return
    # 병합: 더 최근 last_used, count 합산.
    newest = max_ts(existing.last_used, last_used)
    by_action[action] = UsedAction(
        action=action, last_used=newest, count_90d=existing.count_90d + count
    )


def _event_to_action(event_source: str, event_name: str) -> str:
    """CloudTrail eventSource + eventName → 'service:Action' 근사.

    예: ('s3.amazonaws.com', 'GetObject') → 's3:GetObject'.
    """
    if not event_name:
        return ""
    service = event_source.split(".", 1)[0] if event_source else ""
    return f"{service}:{event_name}" if service else event_name


# ---- analyzer findings ----
def _analyzer_findings_by_principal(analyzer_raw: dict) -> dict[str, list[str]]:
    """analyzer findings 의 resource(ARN) → finding_type 목록."""
    out: dict[str, list[str]] = {}
    for f in analyzer_raw.get("findings", []) or []:
        resource = f.get("resource", "")
        if not resource:
            continue
        out.setdefault(resource, []).append(f.get("finding_type", "unused"))
    return {k: sorted(set(v)) for k, v in out.items()}


# ---- credential report 파생 ----
def _index_credential_report(rows: list[dict]) -> dict[str, dict]:
    return {row.get("arn", ""): row for row in rows if row.get("arn")}


def _mfa(cred_row: dict) -> bool:
    return str(cred_row.get("mfa_active", "")).lower() == "true"


def _console_login(cred_row: dict) -> bool:
    """콘솔 로그인 가능 여부. credential report 의 password_enabled=true 면 콘솔 계정.

    서비스/자동화 계정(액세스키만, password 없음)은 false → MFA 무관(no_mfa 오탐 방지)."""
    return str(cred_row.get("password_enabled", "")).lower() == "true"


def _access_key_age_days(cred_row: dict, as_of: datetime) -> int | None:
    """**활성** 액세스키 중 가장 오래된 것의 나이(일). 활성 키 없으면 None.

    비활성(access_key_N_active=false) 키는 장기키 위험이 아니므로 나이를 계산하지 않는다
    (그렇지 않으면 이미 비활성화된 키가 cleanup 백로그에 잘못 오른다)."""
    ages: list[int] = []
    for n in (1, 2):
        if str(cred_row.get(f"access_key_{n}_active", "")).lower() != "true":
            continue
        dt = _parse_iso(cred_row.get(f"access_key_{n}_last_rotated", ""))
        if dt is not None:
            ages.append(max(0, (as_of - dt).days))
    return max(ages) if ages else None


# ---- 시간 유틸 ----
def _parse_iso(value: str | None) -> datetime | None:
    if not value or str(value).strip() in _NO_DATE_SENTINELS:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# 타임스탬프 최댓값(포맷 혼합 안전)은 timeutil.max_ts 사용 — _merge_used 에서 호출.
