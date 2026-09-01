"""M2 Normalizer — raw/** → normalized.parquet (`PrincipalRecord[]`).

M1 수집 raw JSON 을 계정 단위로 읽어 principal 단위 `PrincipalRecord` 로 정규화한다:
- granted_actions ← credential_report 의 inline ∪ 연결된 관리형 정책 ∪ (user)그룹 정책(Allow Action)
- used_actions   ← access_advisor(action-level) ∪ cloudtrail(event → action 근사)
- used_services  ← access_advisor 서비스 단위 last_authenticated(action 세부 없어도 "썼다"는 증거)
- unused_findings ← analyzer_unused findings + (granted − used) 갭 중 **미사용이 확정되는 것**
- undetermined_findings ← 같은 갭 중 **판정 불가**(아래 3단 근거)
- mfa / access_key_age_days ← credential report CSV
- principal_kind / trust_principals ← role 신뢰정책(AssumeRolePolicyDocument)
- tags            ← role/user 태그
- source          ← 이 principal 에 기여한 수집 소스 목록

**미사용 vs 판정 불가**(granted action A, 서비스 ns, 실사용 증거 없음일 때):
  1. A 가 Access Advisor 의 추적 목록에 있고 last_accessed 가 비어 있다 → **미사용 확정**
     (AWS 가 그 action 을 추적하고 있는데 기록이 없다 = 안 썼다)
  2. ns 를 이 principal 이 인증한 적이 없다(서비스 단위 last_authenticated 부재) → **미사용 확정**
     (서비스 자체를 안 썼으니 그 안의 어떤 action 도 안 썼다)
  3. ns 는 인증했는데 A 가 추적 목록에 없다 → **판정 불가**. Access Advisor 의 action-level 추적은
     서비스·action 별로 지원 범위가 다르고, CloudTrail 은 관리 이벤트·단일 리전만 본다. 여기서
     "미사용" 이라고 부르면 실제로 쓰이는 권한을 지우라고 권하게 된다.
  0. (위 3단보다 먼저) 이 principal 의 Access Advisor 근거가 **아예 없다** → **판정 불가**.
     2번은 "advisor 가 이 principal 을 조회했고 그 서비스 인증 기록이 없었다" 일 때만 성립한다.
     조회가 실패했거나 소스가 degraded 여서 데이터가 없는 것을 "서비스를 안 썼다" 로 읽으면,
     근거 0인 상태에서 전 권한을 삭제 권고하게 된다(라이브 실행에서 실제로 1개 principal 이
     이 경로로 '미사용 확정' 판정을 받았다). 근거 부재는 증거가 아니다.

불변식 ②(결정론): as_of(run.started_at) 기준으로만 시간 계산, 안정 정렬, wall-clock 미사용.
risk_score/risk_level/persona 등은 후속 모듈(m4/m5)이 채운다 — 여기선 계약 기본값.

granted_actions 범위: inline 정책 ∪ 연결된 관리형 정책(기본 버전 문서) ∪ user 의 그룹 정책.
문서는 M1 이 같은 `GetAccountAuthorizationDetails` 응답에서 함께 받아 온다(추가 호출·권한 없음).
관리형 정책 문서가 빠지면 관리형만 붙은 principal 이 "부여 권한 0" 으로 보이고, AdministratorAccess
보유자가 risk=low 로 표시된다 — 라이브 계정에서 실제로 그랬다. 문서를 못 받으면 M1 이 degraded 로
말하므로 여기서 조용히 0으로 넘어가지 않는다.

한계: `Resource`/`Condition` 은 보지 않는다 — action 단위 최소권한만 다룬다. NotAction 도 확장하지
않는다(부정 집합을 전체 action 목록 없이 펼칠 수 없다).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from .collectors.access_advisor import SOURCE as ADVISOR
from .collectors.analyzer_unused import SOURCE as ANALYZER
from .collectors.cloudtrail import SOURCE as CLOUDTRAIL
from .collectors.credential_report import SOURCE as CRED_REPORT
from .collectors.idc_permission_sets import SOURCE as IDC
from .models import PrincipalKind, PrincipalRecord, UsedAction
from .timeutil import max_ts

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

_NO_DATE_SENTINELS = frozenset({"", "N/A", "no_information", "not_supported"})

# AWS 가 소유·관리하는 역할 경로. 이 경로의 역할은 사람이 쓰는 신원이 아니라 서비스 실행 주체이므로
# persona 군집 대상에서 제외한다(`is_exception=True`) — 섞이면 (a) 서비스 전용 action 이 사람용 정책에
# 합성되고, (b) 서비스 역할 수가 min_members_for_persona 를 채워 실재하지 않는 persona 가 생긴다.
# 제외는 M5 카탈로그에만 적용된다(M6 cleanup·스냅샷 지표는 `is_exception` 을 보지 않으므로 미사용
# 서비스 역할도 계속 조치 대상으로 남는다).
_SERVICE_LINKED_PATH = "/aws-service-role/"
# IdC 가 PS 할당 시 자동 생성하는 역할. 사람의 실제 접근 기록이지만 직접 수정하면 IdC 동기화가
# 덮어쓴다 → persona 대상이 아니다. (사용 실적을 PS 레코드로 귀속시키는 것은 후속 과제.)
_IDC_RESERVED_PATH = "/aws-reserved/sso.amazonaws.com/"

EXC_SERVICE_LINKED = "service_linked"
EXC_IDC_RESERVED = "idc_reserved"
# sso_ps 는 IAM principal 이 아니라 "PS 할당 1건"을 나타내는 합성 레코드다(principal 필드가 ARN 이 아닌
# `sso_ps::<account>::<PS>::<id>` 키). persona 정책을 여기에 붙일 수는 없고, 같은 사람의 접근은 이미
# AWSReservedSSO_* 역할로도 잡혀 있다 → persona 군집 대상에서 제외한다. PS 마이그레이션 비율
# (`snapshot._metrics_for`)은 `is_exception` 을 보지 않으므로 분자로 계속 집계된다.
EXC_SSO_PS = "sso_ps_synthetic"


def _exception_type(arn: str) -> str | None:
    """persona 대상에서 제외할 principal 이면 그 사유, 아니면 None.

    ARN 경로로 판정한다 — credential_report 가 degraded 여도(인벤토리 밖 principal) 동일하게 판정되어야
    하므로 수집된 `path` 대신 ARN 을 본다.
    """
    if _SERVICE_LINKED_PATH in arn:
        return EXC_SERVICE_LINKED
    if _IDC_RESERVED_PATH in arn:
        return EXC_IDC_RESERVED
    return None


# ---- 신뢰정책 → 사용 주체 구분 ----
# 실측 근거(188 계정 role 398개): Service 353 / AWS 만 38 / AWS+Service 5 / Federated 2.
# 혼합(AWS+Service)은 1.3% 이고 전부 "서비스 + 배포 계정 root" 패턴이었다 → Service 가 있으면
# 서비스 실행 역할로 본다. 서비스 principal 이 `*.amazonaws.com` 이 아닌 경우도 있으므로
# (`*.aws.internal` 실측 2건) 도메인 접미가 아니라 **Principal 의 키**로 판정한다.
_TRUST_SERVICE = "Service"
_TRUST_FEDERATED = "Federated"
_TRUST_AWS = "AWS"


def _trust_principals(trust_policy: dict) -> tuple[set[str], list[str]]:
    """신뢰정책 → (Principal 키 집합, principal 원문 목록 정렬).

    Allow statement 만 본다(Deny 는 신뢰를 부여하지 않는다). `Principal: "*"` 처럼 문자열인
    경우도 있어 dict/str 양쪽을 처리한다.
    """
    keys: set[str] = set()
    values: set[str] = set()
    statements = trust_policy.get("Statement", []) if isinstance(trust_policy, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if isinstance(principal, str):
            keys.add(_TRUST_AWS)
            values.add(principal)
            continue
        if not isinstance(principal, dict):
            continue
        for key, val in principal.items():
            keys.add(key)
            values.update(v for v in ([val] if isinstance(val, str) else val or []) if isinstance(v, str))
    return keys, sorted(values)


def _principal_kind(identity_type: str, trust_keys: set[str]) -> PrincipalKind:
    """사용 주체 구분. IAM 사용자는 신뢰정책이 없으므로 identity_type 으로 즉시 판정."""
    if identity_type == "user":
        return "human"
    if identity_type == "sso_ps":
        return "human"  # PS 할당 = 사람 접근 1건(합성 레코드).
    if _TRUST_FEDERATED in trust_keys:
        return "human"  # SAML/OIDC → 사람이 IdP 로 로그인해 assume.
    if _TRUST_SERVICE in trust_keys:
        return "service"
    # Principal.AWS 만 있거나 신뢰정책 미수집 → 신뢰정책만으로는 갈릴 수 없다.
    return "unknown"


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
    # 관리형 정책 문서(ARN→문서) · 그룹(이름→그룹). 구버전 raw(두 키가 없는 run)에서도 동작해야
    # 하므로 없으면 빈 맵 — 그때 granted_actions 는 예전처럼 inline 만 담는다.
    policy_docs = {p["arn"]: p.get("document") or {} for p in (cred.get("managed_policies") or [])}
    groups_by_name = {g["name"]: g for g in (cred.get("groups") or [])}

    used_by_arn, used_sources_by_arn = _used_actions_by_principal(raw)
    observed_days, observed_from = _observed_window(raw.get(CLOUDTRAIL, {}), as_of)
    analyzer_by_arn = _analyzer_findings_by_principal(raw.get(ANALYZER, {}))
    authed_svcs_by_arn, tracked_by_arn_svc, advisor_covered = _advisor_evidence(raw.get(ADVISOR, {}))

    # principal 집합 = 인벤토리 ∪ used ∪ analyzer. credential_report 가 degraded 여도 다른 소스가
    # 본 principal 은 최소 레코드로 살린다(그렇지 않으면 이 소스 하나 실패로 전체가 비어버림).
    all_arns = set(inventory) | set(used_by_arn) | set(analyzer_by_arn)

    records: list[PrincipalRecord] = []
    for arn in all_arns:
        p = inventory.get(arn)
        in_inventory = p is not None
        granted = _granted_actions(p, policy_docs, groups_by_name) if in_inventory else []
        used = used_by_arn.get(arn, [])
        used_action_names = {u.action for u in used}

        # (granted − used) 갭을 "미사용 확정" 과 "판정 불가" 로 가른다(모듈 독스트링의 3단 근거).
        gap = sorted(a for a in granted if a not in used_action_names and not _is_wildcard(a))
        authed_svcs = authed_svcs_by_arn.get(arn, frozenset())
        confirmed_unused: list[str] = []
        undetermined: list[str] = []
        # advisor 근거가 없는 principal 은 ②(서비스 미인증)를 주장할 수 없다 — 근거 부재와
        # "안 썼다는 근거" 는 다르다. 이 principal 은 전부 판정 불가로 간다.
        has_advisor = arn in advisor_covered
        for action in gap:
            ns, _, name = action.partition(":")
            if name in tracked_by_arn_svc.get((arn, ns), frozenset()):
                confirmed_unused.append(action)   # ① AWS 가 추적 중인데 기록 없음
            elif not has_advisor:
                undetermined.append(action)       # ⓞ advisor 근거 자체가 없음(조회 실패·소스 degraded)
            elif ns not in authed_svcs:
                confirmed_unused.append(action)   # ② 서비스 자체를 인증한 적 없음
            else:
                undetermined.append(action)       # ③ 서비스는 썼는데 이 action 은 근거 없음

        # analyzer_unused finding 은 action 이 아니라 finding_type 라벨("UnusedIAMRole" 등)이라
        # 위 3단 판정과 겹치지 않는다 — 그래서 판정 불가에서 빼는 처리가 필요 없다.
        # (collector 가 언젠가 action 단위 finding 을 싣게 되면 그때 우선순위를 정해야 한다.)
        analyzer_findings = analyzer_by_arn.get(arn, [])
        unused_findings = sorted(set(confirmed_unused) | set(analyzer_findings))
        undetermined_findings = sorted(undetermined)

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
        exc_type = _exception_type(arn)

        # 신뢰정책 → 사용 주체. 인벤토리 밖 principal(credential_report degraded 등)은 신뢰정책이
        # 없어 'unknown' 이 된다 — 추측하지 않고 모른다고 남긴다.
        trust_keys, trust_values = _trust_principals(p.get("trust_policy") or {} if in_inventory else {})
        kind = _principal_kind(identity_type, trust_keys)

        records.append(
            PrincipalRecord(
                account_id=account_id,
                principal=arn,
                identity_type=identity_type,
                principal_kind=kind,
                trust_principals=trust_values,
                tags=dict(p.get("tags") or {}) if in_inventory else {},
                granted_actions=sorted(set(granted)),
                used_actions=used,
                used_services=sorted(authed_svcs),
                unused_findings=unused_findings,
                undetermined_findings=undetermined_findings,
                mfa=_mfa(cred_row),
                console_login=_console_login(cred_row),
                has_managed_policies=has_managed,
                access_key_age_days=_access_key_age_days(cred_row, as_of),
                create_date=(p.get("create_date") if in_inventory else None),
                age_days=_days_since(p.get("create_date") if in_inventory else None, as_of),
                role_last_used=(p.get("role_last_used") if in_inventory else None),
                role_last_used_region=(p.get("role_last_used_region") if in_inventory else None),
                unused_days=_days_since(p.get("role_last_used") if in_inventory else None, as_of),
                observed_days=observed_days,
                observed_from=observed_from,
                is_exception=exc_type is not None,
                exception_type=exc_type,
                source=sorted(contributing),
                run_id=run_id,
            )
        )

    # IdC Permission Set 할당 → sso_ps principal 레코드(PS 기반 사람 접근).
    # 마이그레이션 스냅샷 비율(사람 접근 중 PS 기반 비율) 산출에 쓰인다.
    # 같은 사람의 접근은 (a) 이 sso_ps 레코드와 (b) IdC 가 대상 계정에 만든 AWSReservedSSO_* 역할
    # 두 곳에 나뉘어 있고, 실사용 action 은 (b) 에만 기록된다 → PS 별로 (b) 의 실사용을 귀속시킨다.
    # 그래야 "이 PS 가 과다권한인가"를 granted−used 로 판정할 수 있다.
    records.extend(_sso_ps_records(account_id, raw.get(IDC, {}), run_id, records))
    return records


def _reserved_sso_usage(records: list[PrincipalRecord]) -> dict[str, list[UsedAction]]:
    """AWSReservedSSO_<PS이름>_<suffix> 역할의 실사용을 PS 이름별로 합친다.

    역할명은 IdC 가 `AWSReservedSSO_{PermissionSetName}_{16자리hex}` 로 만든다. PS 이름 자체에 `_` 가
    있을 수 있으므로 **마지막** `_` 를 기준으로 suffix 만 떼어낸다.
    """
    by_ps: dict[str, dict[str, UsedAction]] = {}
    for r in records:
        if _IDC_RESERVED_PATH not in r.principal or not r.used_actions:
            continue
        role_name = r.principal.rsplit("/", 1)[-1]
        if not role_name.startswith("AWSReservedSSO_"):
            continue
        stem = role_name[len("AWSReservedSSO_") :]
        ps_name = stem.rsplit("_", 1)[0] if "_" in stem else stem
        if not ps_name:
            continue
        bucket = by_ps.setdefault(ps_name, {})
        for u in r.used_actions:
            prev = bucket.get(u.action)
            if prev is None:
                bucket[u.action] = u.model_copy()
            else:
                # 같은 action 이 여러 예약 역할에 있으면 호출수 합·최근 시각 채택(결정론).
                prev.count_observed += u.count_observed
                prev.last_used = max_ts(prev.last_used, u.last_used)
    return {ps: sorted(b.values(), key=lambda u: u.action) for ps, b in by_ps.items()}


def _sso_ps_records(
    account_id: str, idc_raw: dict, run_id: str, iam_records: list[PrincipalRecord]
) -> list[PrincipalRecord]:
    """IdC account assignment → identity_type='sso_ps' 레코드(할당 principal 당 1건, 중복 제거)."""
    usage_by_ps = _reserved_sso_usage(iam_records)
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
                principal_kind="human",  # PS 할당은 사람 접근이다.
                # 이 PS 로 실제 호출된 action(대상 계정의 AWSReservedSSO_* 역할에서 귀속).
                # granted 는 PS 정책 문서를 수집하지 않아 아직 비어 있다(후속) → 지금은 미사용 갭 계산
                # 대상이 아니고, "이 PS 가 실제로 쓰이는지"까지만 판정한다.
                used_actions=usage_by_ps.get(ps, []),
                # used_actions 가 채워지면서 M5 의 active 필터(used_actions 존재)를 통과하게 됐다 →
                # 합성 레코드가 persona 멤버로 군집되어 UI 가 PS 이름을 계정으로 오인한다. 명시적 제외.
                is_exception=True,
                exception_type=EXC_SSO_PS,
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


# ---- granted actions (inline ∪ 관리형 ∪ 그룹) ----
def _granted_actions(
    principal: dict, policy_docs: dict[str, dict], groups_by_name: dict[str, dict]
) -> list[str]:
    """이 principal 에게 실제로 부여된 Allow action 전체.

    세 경로를 합친다: inline 정책, 연결된 관리형 정책(기본 버전 문서), 그리고 user 의 소속 그룹이
    가진 inline/관리형 정책. 관리형 문서가 `policy_docs` 에 없으면 그 정책분은 빠진다 —
    그 상황은 M1(credential_report collector)이 degraded + note 로 이미 말한다.
    """
    actions: set[str] = set()
    _add_holder_actions(actions, principal, policy_docs)
    for group_name in principal.get("groups") or []:
        group = groups_by_name.get(group_name)
        if group:
            _add_holder_actions(actions, group, policy_docs)
    return sorted(actions)


def _add_holder_actions(out: set[str], holder: dict, policy_docs: dict[str, dict]) -> None:
    """정책 보유자(principal 또는 group)의 inline + 연결 관리형 정책 action 을 out 에 더한다."""
    for pol in holder.get("inline_policies") or []:
        out.update(_actions_from_document(pol.get("document", {})))
    for att in holder.get("attached_policies") or []:
        doc = policy_docs.get(att.get("arn", ""))
        if doc:
            out.update(_actions_from_document(doc))


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


# ---- 관측 가능 기간 ----
def _days_since(iso_ts: str | None, as_of: datetime) -> int | None:
    """ISO8601 시각 → as_of 기준 경과일. 값이 없으면 None(추정하지 않는다).

    생성일(age_days)과 마지막 활동(unused_days) 둘 다 이 계산이다."""
    dt = _parse_dt(iso_ts)
    if dt is None:
        return None
    return max((as_of - dt).days, 0)


def _observed_window(ct_raw: dict, as_of: datetime) -> tuple[int | None, str | None]:
    """CloudTrail raw → (실제로 훑은 구간의 일수, 그 구간 시작 시각). 근거 없으면 (None, None).

    두 경우를 가른다:
      - 페이지 상한에 걸림(`truncated`) → 실측값은 관측한 **가장 오래된 이벤트** 시각이다.
        요청한 90일이 아니라 실제로 며칠뿐일 수 있다(라이브 575: 2일).
      - 끝까지 훑음 → 요청한 창(`window_days`) 전체를 봤다. 이벤트가 하나도 없어도 그 구간은
        "봤고 없었다" 는 근거다.

    이 값을 표시하지 않으면 화면이 "90일" 을 주장하는데 그 90일은 어디서도 측정되지 않는다.
    """
    if not ct_raw or ct_raw.get("mode") != "lookup_events":
        return None, None
    window_days = ct_raw.get("window_days")
    if ct_raw.get("truncated"):
        start = _parse_dt(ct_raw.get("coverage_start"))
        if start is None:
            return None, None
        return max((as_of - start).days, 0), ct_raw.get("coverage_start")
    if not isinstance(window_days, int) or window_days < 0:
        # 구버전 raw(window_days 없음) — 요청 창을 모르므로 주장하지 않는다.
        return None, None
    return window_days, (as_of - timedelta(days=window_days)).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---- advisor 근거 인덱스(미사용 확정 vs 판정 불가 판별용) ----
def _advisor_evidence(
    advisor_raw: dict,
) -> tuple[dict[str, frozenset[str]], dict[tuple[str, str], frozenset[str]], frozenset[str]]:
    """Access Advisor raw → (principal→인증한 서비스 집합, (principal,서비스)→추적 action 이름 집합,
    advisor 근거가 실제로 있는 principal 집합).

    두 값의 역할이 다르다:
      - 인증한 서비스(`last_authenticated` 존재): "이 서비스를 썼다" 는 증거. action 세부를 못 줘도
        남는다 → 미사용 판정을 막는 근거.
      - 근거 있는 principal(covered): advisor 응답에 **서비스 행이 하나라도** 있는 principal.
        AWS 는 정상 응답이면 계정이 접근 가능한 서비스 목록 전체를 돌려주므로, 서비스 행이 0개인
        entry 는 "안 썼다" 가 아니라 "못 받았다"(조회 실패·잡 미완료)다. 이걸 구분하지 않으면
        근거 0인 principal 의 전 권한이 '미사용 확정' 이 된다.
      - 추적 action 이름: `TrackedActionsLastAccessed` 에 **올라온 이름 전체**(last_accessed 가 비어
        있는 것도 포함). AWS 가 추적하는 action 인지 여부를 알려주므로, 기록 없음을 "안 썼다" 로
        확정할 수 있는지 가른다. 목록에 아예 없는 action 은 추적 대상이 아니라 근거가 없는 것이다.
    """
    authed: dict[str, frozenset[str]] = {}
    tracked: dict[tuple[str, str], frozenset[str]] = {}
    covered: set[str] = set()
    for entry in advisor_raw.get("last_accessed", []) or []:
        arn = entry.get("principal", "")
        if not arn:
            continue
        rows = entry.get("services", []) or []
        if rows:
            covered.add(arn)
        svcs: set[str] = set()
        for svc in rows:
            ns = svc.get("service", "")
            if not ns:
                continue
            if svc.get("last_authenticated"):
                svcs.add(ns)
            names = {a.get("action", "") for a in (svc.get("actions") or [])}
            names.discard("")
            if names:
                tracked[(arn, ns)] = frozenset(names)
        authed[arn] = frozenset(svcs)
    return authed, tracked, frozenset(covered)


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
        by_action[action] = UsedAction(action=action, last_used=last_used, count_observed=count)
        return
    # 병합: 더 최근 last_used, count 합산.
    newest = max_ts(existing.last_used, last_used)
    by_action[action] = UsedAction(
        action=action, last_used=newest, count_observed=existing.count_observed + count
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
