"""M6 Reporter — cleanup 백로그 + 리포트 + exec summary.

M3/M4/M5 로 enrich 된 normalized.parquet + catalog 를 읽어:
- `cleanup_backlog.csv` — 6유형(unused_permission/unused_role/new_role_unused/long_lived_key/
  no_mfa/escalation_path) CleanupItem 목록(계약 model). UI 는 카테고리 요약→드릴다운.
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

from .models import CatalogEntry, CleanupItem, CleanupType, ExecSummary, PrincipalRecord

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config
    from .runctx import RunContext
    from .storage import Storage

BACKLOG_NAME = "cleanup_backlog.csv"

# 권장 조치 문구. IdC 를 쓰는 고객에게만 "Permission Set 로 마이그레이션" 이 실행 가능한 조언이다 —
# IdC 가 없는 고객에게 그렇게 쓰면 조치할 수 없는 항목을 영구히 안고 가게 된다(그 고객은 정책을
# 다듬어 IAM 정책/역할로 적용하는 것이 완결된 조치다). 문구만 다르고 판정 로직은 동일하다.
_RECOMMENDATION: dict[str, tuple[str, str]] = {
    # type: (IdC 사용, IdC 미사용)
    "unused_role": (
        "역할 삭제 (미사용 — PS 카탈로그에 불필요)",
        "역할 삭제 (미사용 — 최소권한 정책 대상이 아님)",
    ),
    # 관측 기간이 짧아 판단 근거가 부족한 신규 역할. **삭제를 권고하지 않는다** —
    # 어제 만든 역할에 사용 기록이 없는 건 당연하고, 그걸 근거로 지우면 배포 중인 것을 깬다.
    "new_role_unused": (
        "신규 역할 — 관측 기간이 짧다. 용도 확인 후 판단(삭제 권고 아님)",
        "신규 역할 — 관측 기간이 짧다. 용도 확인 후 판단(삭제 권고 아님)",
    ),
    "unused_permission": (
        "실사용 기반 최소권한 Permission Set 로 마이그레이션",
        "실사용 기반 최소권한 IAM 정책으로 교체 (persona 검토 화면에서 정책·역할 Terraform 을 받아 적용)",
    ),
    "long_lived_key": (
        "Identity Center(SSO) + Permission Set 임시 자격증명으로 전환 (장기 키 폐기)",
        "액세스키를 교체·폐기하고 IAM Role 임시 자격증명(sts:AssumeRole)으로 전환",
    ),
    "no_mfa": (
        "Identity Center(SSO+MFA) + Permission Set 로 전환 (IAM User 폐기)",
        "이 IAM User 에 MFA 를 설정 (장기적으로는 Identity Center 도입 검토)",
    ),
    "escalation_path": (
        "상승 유발 권한을 제거한 최소권한 Permission Set 로 마이그레이션",
        "상승 유발 권한을 제거한 최소권한 IAM 정책으로 교체",
    ),
}


def _recommendation(ctype: CleanupType, uses_idc: bool) -> str:
    idc_text, plain_text = _RECOMMENDATION[ctype]
    return idc_text if uses_idc else plain_text


def is_unused_role(rec: PrincipalRecord) -> bool:
    """이 역할이 '실사용 증거가 어느 층위에도 없다' 인가 — 미사용 판정식의 **단일 소스**.

    `snapshot._metrics_for` 가 같은 함수를 쓴다. 예전엔 두 곳이 각자 조건을 갖고 있었고
    (스냅샷은 `granted_actions` 만, m6 은 `granted_actions or has_managed_policies`) 그 결과
    대시보드 "미사용 역할 40" 과 백로그 59건이 어긋났다 — 주석은 "같은 판정식" 이라고 적혀
    있었지만 사실이 아니었다.

    `role_last_used` 를 함께 보는 이유: IAM 자신이 이 역할의 활동을 추적하며(콘솔 "Last activity")
    그 기록은 **전 리전**을 아우른다. Access Advisor 가 action·서비스를 안 주고 CloudTrail 이
    다른 리전이라 못 본 역할이라도, 이 값이 있으면 그 역할은 **쓰인 적이 있다**. 그걸 무시하고
    "사용 기록 없음" 이라고 부르면 IAM 이 반대로 말하는 것을 화면이 주장하게 된다.
    (기록이 오래된 역할까지 살려 두는 것은 `used_services` 와 같은 처리다 — 이 판정식은 "얼마나
    오래 안 썼나" 가 아니라 "쓴 증거가 어느 층위에도 없나" 를 묻는다.)
    """
    return (
        rec.identity_type == "role"
        and not rec.used_actions
        and not rec.used_services
        and rec.role_last_used is None
        and (bool(rec.granted_actions) or rec.has_managed_policies)
    )


def is_too_new_to_judge(rec: PrincipalRecord, min_age_days: int) -> bool:
    """관측 가능 기간이 최소 기준보다 짧은가(= 미사용이라 말할 근거가 부족한가).

    나이를 모르면(구버전 raw 로 create_date 미수집) 판정을 바꾸지 않는다 — 모른다는 이유로
    조치 대상을 늘리거나 줄이지 않고, 증거에 '확인 불가' 로 남긴다.
    """
    return rec.age_days is not None and rec.age_days < min_age_days


# IAM 이 last-accessed/last-used 정보를 유지하는 추적 창(일). **AWS 사양이며 조정 대상이 아니다** —
# config 로 빼지 않는 이유가 이것이다(불변식 ④ 는 고객별 임계치를 config 로 옮기라는 규칙이고,
# 이 값은 우리가 고를 수 있는 값이 아니다). 여기서만 정의해 문구가 서로 어긋나지 않게 한다.
_IAM_TRACKING_DAYS = 400


def _window_phrase(rec: PrincipalRecord) -> str:
    """이 principal 의 미사용 판정 근거 창을 **실측값**으로 서술.

    화면·CSV 가 "90일" 이라고 쓰던 자리다. 그 90일은 어디서도 측정되지 않았다: CloudTrail
    LookupEvents 는 페이지 상한에 걸려 라이브에서 2일만 덮었고, Access Advisor 는 AWS 가 문서화한
    추적 창(최대 400일, 서비스·action 별로 상이)을 쓴다. 그래서 CloudTrail 쪽은 실측 일수를 쓰고
    Advisor 쪽은 측정값이 아니라 **AWS 사양**임을 문구로 드러낸다.
    """
    ct = f"CloudTrail {rec.observed_days}일" if rec.observed_days is not None else "CloudTrail 근거 없음"
    return f"{ct} + Access Advisor 추적 창(AWS 사양: 최대 {_IAM_TRACKING_DAYS}일)"


def _unused_period(rec: PrincipalRecord) -> tuple[str, str]:
    """(마지막 활동, 미사용 기간) 표기. **실측값과 하한을 문구로 구분한다.**

    이 자리에 예전엔 "90일간 미사용" 이 있었다. 그 90일은 어디서도 측정되지 않은 리터럴이었고,
    지운 뒤 실제 값을 채워 넣지 않아 기간 표기가 **아예 사라졌다**(사용자 지적). 실제 값은
    이미 우리가 받아오는 `GetAccountAuthorizationDetails` 응답의 `RoleLastUsed` 에 있었다.

    두 경우를 다르게 말한다:
      - 기록 있음 → as_of 기준 정확한 경과일. 활동이 있던 **리전**도 함께 보여 준다(그 리전이
        CloudTrail 수집 리전과 다르면, 왜 CloudTrail 에 안 잡혔는지가 그 자리에서 설명된다).
      - 기록 없음 → 정확한 기간은 **알 수 없다**. 다만 IAM 이 추적 창 내내 기록하지 않았으므로
        "최소 N일 이상" 이라는 하한은 말할 수 있다. N = min(생성 후 경과, 추적 창) — 생성 후
        200일 된 역할에 "최소 400일" 이라고 하면 존재하지도 않던 기간을 주장하는 것이 된다.
        나이를 모르면 하한도 말하지 않는다(숫자를 만들지 않는다).
    """
    if rec.role_last_used:
        region = f" ({rec.role_last_used_region})" if rec.role_last_used_region else ""
        days = f"{rec.unused_days}일" if rec.unused_days is not None else "확인 불가"
        return f"{rec.role_last_used}{region}", days
    if rec.age_days is None:
        return "IAM 활동 기록 없음", f"확인 불가(IAM 추적 창 {_IAM_TRACKING_DAYS}일 내 활동 없음)"
    return "IAM 활동 기록 없음", f"최소 {min(rec.age_days, _IAM_TRACKING_DAYS)}일 이상"


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


def _cleanup_items(records: list[PrincipalRecord], cfg: "Config") -> list[CleanupItem]:
    """principal 레코드에서 5유형 cleanup 항목 도출(결정론 id·정렬)."""
    items: list[CleanupItem] = []
    uses_idc = cfg.provisioning.uses_identity_center

    for rec in records:
        # unused_role: role 인데 실사용 증거가 **어느 층위에도** 없음.
        # 권한 보유는 inline(granted_actions) 또는 attached managed 정책 중 하나면 성립
        # (managed-only 역할도 미사용 대상으로 잡는다).
        #
        # `used_services` 를 함께 보는 이유: Access Advisor 의 action-level 추적 범위는 서비스별로
        # 달라, 실제로 쓰이는 역할도 action 세부가 안 나와 `used_actions` 가 빌 수 있다. 그때 서비스
        # 단위 last_authenticated 만 있으면 그 역할은 **쓰이는 중**이다 — "미사용, 삭제 검토"
        # 라고 권하면 운영 중인 역할을 지우게 된다(S3 복제 역할 등이 실제로 이 오탐에 걸렸다).
        #
        # 나이로 한 번 더 가른다: 생성 후 `unused_action_days` 도 안 지난 역할은 사용 기록이 없는
        # 게 당연하다(라이브 575: 미사용 판정 59건 중 16건이 90일 미만, 3건은 당일 생성). 그걸
        # "미사용 역할, 삭제 후보" 로 내면 배포 중인 것을 지우라고 권하는 셈이다 → new_role_unused.
        if is_unused_role(rec):
            min_age = cfg.risk_rules.unused_action_days
            too_new = is_too_new_to_judge(rec, min_age)
            ctype: CleanupType = "new_role_unused" if too_new else "unused_role"
            last_activity, unused_period = _unused_period(rec)
            if too_new:
                # 관측 기간 자체가 부족한 역할에 하한을 적으면 안 된다. 라이브 575 에서 당일 생성
                # 역할이 "미사용 최소 0일 이상" 으로 나왔다 — 참이지만 아무 정보가 없고, 숫자가
                # 판단처럼 읽힌다. 이 유형에서 정확한 말은 "아직 판단할 수 없다" 다.
                unused_period = f"판단 보류(생성 후 {rec.age_days}일 — 관측 기간 부족)"
            detail = (f"생성 후 미사용(생성 {rec.age_days}일 경과 — 관측 기간 부족)"
                      if too_new else f"미사용 역할(미사용 {unused_period} — {last_activity})")
            items.append(_item(ctype, rec, rec.risk_level, detail,
                               _recommendation(ctype, uses_idc),
                               evidence={
                                   "식별 유형": "role",
                                   "부여된 action 수": str(len(rec.granted_actions)),
                                   # 기간과 근거를 나눠 싣는다: '미사용 기간' 은 IAM 이 추적한
                                   # 역할 활동 기준, '사용 근거' 는 action 단위 판정에 쓴 창이다.
                                   "마지막 활동": last_activity,
                                   "미사용 기간": unused_period,
                                   "사용 근거": f"없음({_window_phrase(rec)})",
                                   "사용 흔적 서비스": "없음",
                                   "역할 생성일": rec.create_date or "미수집",
                                   "생성 후 경과": f"{rec.age_days}일" if rec.age_days is not None else "확인 불가",
                                   "삭제 판단 최소 경과": f"{min_age}일",
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
                "대표 미사용": ", ".join(action_gaps[:5]),
                "수집 소스": ", ".join(rec.source) or "-",
            }
            if rec.identity_type == "role":
                # 역할이면 IAM 이 추적한 마지막 활동 시각을 함께 싣는다(전 리전). user 에는 넣지
                # 않는다 — user 에는 RoleLastUsed 가 애초에 없어서 '기록 없음' 이 '안 쓰였다' 로
                # 잘못 읽힌다. 기간(하한)은 여기서 말하지 않는다: 실사용 action 이 있는 항목에
                # "최소 N일 미사용" 을 붙이면 같은 화면이 서로 반대를 주장한다.
                evidence["마지막 활동"] = _unused_period(rec)[0]
            items.append(_item("unused_permission", rec, rec.risk_level, detail,
                               _recommendation("unused_permission", uses_idc), evidence=evidence))

        # long_lived_key
        if rec.access_key_age_days is not None and rec.access_key_age_days >= cfg.risk_rules.long_lived_key_days:
            items.append(_item("long_lived_key", rec, rec.risk_level,
                               f"액세스키 age {rec.access_key_age_days}일",
                               _recommendation("long_lived_key", uses_idc),
                               evidence={
                                   "액세스키 나이": f"{rec.access_key_age_days}일",
                                   "임계 기준": f"{cfg.risk_rules.long_lived_key_days}일 이상",
                                   "MFA": "설정" if rec.mfa else "미설정",
                                   "콘솔 로그인": "가능" if rec.console_login else "불가",
                               }))

        # no_mfa (콘솔 로그인 가능한 user 한정 — 서비스 계정 오탐 방지)
        if rec.identity_type == "user" and rec.console_login and not rec.mfa:
            items.append(_item("no_mfa", rec, rec.risk_level,
                               "MFA 미설정 콘솔 사용자", _recommendation("no_mfa", uses_idc),
                               evidence={
                                   "식별 유형": "user",
                                   "콘솔 로그인": "가능",
                                   "MFA": "미설정",
                                   "액세스키 나이": f"{rec.access_key_age_days}일" if rec.access_key_age_days is not None else "해당 없음",
                               }))

        # escalation_path (건별)
        for path in rec.escalation_paths:
            items.append(_item("escalation_path", rec, rec.risk_level,
                               f"{path.via} → {path.to} ({path.mitre})",
                               _recommendation("escalation_path", uses_idc),
                               evidence={
                                   "경유(via)": path.via,
                                   "도달 대상(to)": path.to,
                                   "MITRE ATT&CK": path.mitre,
                                   "부여된 action 수": str(len(rec.granted_actions)),
                               },
                               # 한 principal 에 상승 경로가 여러 건 나오므로 경로 자체로 건을 구분한다.
                               key_extra=f"{path.via}\x1f{path.to}\x1f{path.mitre}"))

    # 결정론 id: (type, account, principal, detail) 정렬 후 c1.. 부여.
    items.sort(key=lambda x: (x.type, x.account_id, x.principal, x.detail))
    for i, item in enumerate(items, start=1):
        item.id = f"c{i}"
    return items


def _item(ctype: CleanupType, rec: PrincipalRecord, risk, detail: str, rec_text: str,
          evidence: dict[str, str] | None = None, key_extra: str = "") -> CleanupItem:
    return CleanupItem(
        id="",  # 나중에 정렬 후 부여
        # 조치 상태용 안정 키. key_extra 는 principal 당 여러 건이 나오는 유형(escalation_path)에서만
        # 건을 구분하는 데 쓴다 — 나머지 유형은 (유형, 계정, principal) 이 곧 한 건이다.
        finding_key=cleanup_finding_key(ctype, rec.account_id, rec.principal, key_extra),
        type=ctype,
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
    writer.writerow(["id", "finding_key", "type", "account_id", "principal", "risk_level", "detail",
                     "recommendation", "risk_score", "risk_reasons", "evidence"])
    for it in items:
        # 사용자/자원 유래 텍스트 셀을 formula-injection 무력화(수치 컬럼 제외).
        writer.writerow([_csv_safe(it.id), _csv_safe(it.finding_key),
                         _csv_safe(it.type), _csv_safe(it.account_id),
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
