"""M3 Escalation — 권한 상승 경로 탐지.

normalized.parquet 의 각 principal 이 **granted** 권한으로 자기 권한을 상승시킬 수 있는 경로를
규칙 기반으로 탐지해 `escalation_paths[]` 를 채우고, `escalation_status.json` 에 요약을 남긴다.

PMapper(그래프 기반, 계정 전역 상승경로)는 self-mode 로컬에서 라이브러리/그래프 없이는 못 돌리므로
**규칙 기반(principal 자체 granted 권한)** 으로 degrade 한다(단일 계정 self-mode). PMapper 가 있으면
M3 를 그 결과로 업그레이드(추후). 각 규칙은 MITRE ATT&CK 전술 태그를 단다.

불변식 ②(결정론): granted action 집합만 보고 판정, 안정 정렬, wall-clock 없음.
불변식 ①: 읽기 전용 — 이 모듈은 AWS 를 호출하지 않고 이미 수집된 normalized 데이터만 쓴다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import EscalationPath, PrincipalRecord

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

# 규칙: (필요 action 집합, via 설명, 도달 대상, MITRE 전술).
# action 은 정확 일치 또는 서비스 와일드카드('iam:*') 매칭. 모두 만족해야 hit.
# MITRE: TA0004=Privilege Escalation, TA0003=Persistence.
_RULES: tuple[tuple[frozenset[str], str, str, str], ...] = (
    (frozenset({"iam:CreateRole", "iam:AttachRolePolicy"}), "iam:CreateRole + AttachRolePolicy", "new-admin-role", "TA0004"),
    (frozenset({"iam:CreatePolicyVersion"}), "iam:CreatePolicyVersion (정책 재작성)", "any-policy", "TA0004"),
    (frozenset({"iam:AttachRolePolicy"}), "iam:AttachRolePolicy (자기 역할에 정책 부착)", "self-role", "TA0004"),
    (frozenset({"iam:AttachUserPolicy"}), "iam:AttachUserPolicy", "self-user", "TA0004"),
    (frozenset({"iam:PutRolePolicy"}), "iam:PutRolePolicy (inline 정책 주입)", "self-role", "TA0004"),
    (frozenset({"iam:PutUserPolicy"}), "iam:PutUserPolicy", "self-user", "TA0004"),
    (frozenset({"iam:PassRole", "lambda:CreateFunction"}), "iam:PassRole + lambda:CreateFunction", "lambda-exec-role", "TA0004"),
    (frozenset({"iam:PassRole", "ec2:RunInstances"}), "iam:PassRole + ec2:RunInstances", "ec2-instance-profile", "TA0004"),
    (frozenset({"iam:CreateAccessKey"}), "iam:CreateAccessKey (다른 사용자 키 발급)", "other-user", "TA0003"),
    (frozenset({"iam:UpdateAssumeRolePolicy"}), "iam:UpdateAssumeRolePolicy (신뢰정책 변경)", "assume-any-role", "TA0004"),
    (frozenset({"sts:AssumeRole", "iam:CreateRole"}), "iam:CreateRole + sts:AssumeRole", "new-role-chain", "TA0004"),
)


def detect_escalations(storage: "Storage", run: "RunContext") -> list[PrincipalRecord]:
    """normalized.parquet 을 읽어 escalation_paths 를 채우고 다시 기록.

    granted 권한 기반 **규칙 탐지**(iam:PassRole·CreateRole+AttachRolePolicy 등 → MITRE 태그).
    escalation_status.json 에 요약을 남긴다. 결정론(권한 집합만 보고 판정, 안정 정렬).
    """
    records = storage.read_normalized()

    total_paths = 0
    principals_with_paths = 0
    for rec in records:
        paths = _paths_for(rec)
        rec.escalation_paths = paths
        if paths:
            principals_with_paths += 1
            total_paths += len(paths)

    records.sort(key=lambda r: (r.account_id, r.principal))
    storage.write_normalized(records)

    status = {
        "run_id": run.run_id,
        "mode": "rule_based",
        "note": "granted 권한 기반 규칙 탐지(계정 전역 그래프 분석은 범위 밖).",
        "principals_scanned": len(records),
        "principals_with_escalation": principals_with_paths,
        "total_escalation_paths": total_paths,
    }
    storage.write_json("escalation_status.json", status)
    return records


def _paths_for(rec: PrincipalRecord) -> list[EscalationPath]:
    """principal 의 granted action 집합으로 매칭되는 상승경로 규칙을 찾는다(안정 정렬)."""
    granted = set(rec.granted_actions)
    # 와일드카드 확장: 'iam:*' 또는 '*' 는 모든 필요 action 을 만족시킨다.
    has_full_wildcard = "*" in granted
    service_wildcards = {a.split(":", 1)[0] for a in granted if a.endswith(":*")}

    def _satisfied(action: str) -> bool:
        if has_full_wildcard or action in granted:
            return True
        service = action.split(":", 1)[0]
        return service in service_wildcards

    paths: list[EscalationPath] = []
    for needed, via, to, mitre in _RULES:
        if all(_satisfied(a) for a in needed):
            paths.append(EscalationPath(via=via, to=to, mitre=mitre))
    paths.sort(key=lambda p: (p.via, p.to))
    return paths
