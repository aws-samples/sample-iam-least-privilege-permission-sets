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

import re
from functools import lru_cache
from typing import TYPE_CHECKING

from .models import EscalationPath, PrincipalRecord

if TYPE_CHECKING:  # pragma: no cover
    from .runctx import RunContext
    from .storage import Storage

# 규칙: (필요 action 집합, via 설명, 도달 대상, MITRE 전술).
# action 은 정확 일치 또는 IAM 와일드카드 패턴('iam:*', 'iam:Create*', '*') 매칭. 모두 만족해야 hit.
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


@lru_cache(maxsize=4096)
def _glob(pattern: str) -> re.Pattern[str]:
    """IAM action 와일드카드 패턴 → 컴파일된 정규식(소문자 비교용).

    IAM 은 action 매칭에서 대소문자를 구분하지 않고 `*`(0자 이상)·`?`(1자)만 와일드카드로 본다.
    `fnmatch` 는 `[seq]` 문자클래스도 해석해 IAM 문법과 어긋나므로 직접 변환한다.
    """
    parts = ".*".join(
        ".".join(re.escape(chunk) for chunk in segment.split("?"))
        for segment in pattern.lower().split("*")
    )
    return re.compile(f"^{parts}$")


def _paths_for(rec: PrincipalRecord) -> list[EscalationPath]:
    """principal 의 granted action 집합으로 매칭되는 상승경로 규칙을 찾는다(안정 정렬)."""
    granted_exact = {a.lower() for a in rec.granted_actions if "*" not in a and "?" not in a}
    # 와일드카드 패턴은 IAM 정책 문법(`*`=0자 이상, `?`=1자)으로 매칭한다.
    # 관리형 정책 문서를 수집하기 시작하면서 'iam:Create*' 같은 **접두 와일드카드**가 실제로
    # 들어온다 — 서비스 와일드카드('iam:*')만 확장하면 그런 정책을 놓친다.
    patterns = [_glob(a) for a in rec.granted_actions if "*" in a or "?" in a]

    def _satisfied(action: str) -> bool:
        lowered = action.lower()
        if lowered in granted_exact:
            return True
        return any(p.match(lowered) for p in patterns)

    paths: list[EscalationPath] = []
    for needed, via, to, mitre in _RULES:
        if all(_satisfied(a) for a in needed):
            paths.append(EscalationPath(via=via, to=to, mitre=mitre))
    paths.sort(key=lambda p: (p.via, p.to))
    return paths
