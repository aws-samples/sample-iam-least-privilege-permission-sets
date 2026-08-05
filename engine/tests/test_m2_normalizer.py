"""M2 Normalizer (raw → PrincipalRecord[]) — 정규화 정확성 + 결정론."""

from __future__ import annotations

from lp2ps.m2_normalizer import normalize
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage

RUN = RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")

ACCOUNT = "111122223333"
ARN = f"arn:aws:iam::{ACCOUNT}:role/data-eng"


def _seed_raw(storage: LocalFSStorage) -> None:
    # credential_report: 1 role(inline s3 3종) + credential CSV row.
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {
            "account_id": ACCOUNT,
            "principals": [
                {
                    "principal": ARN,
                    "name": "data-eng",
                    "identity_type": "role",
                    "inline_policies": [
                        {
                            "name": "inline",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "attached_policies": [],
                    "path": "/",
                }
            ],
            "credential_report": [
                {
                    "arn": ARN,
                    "mfa_active": "false",
                    "access_key_1_active": "true",
                    "access_key_1_last_rotated": "2026-01-01T00:00:00+00:00",
                    "access_key_2_active": "false",
                    "access_key_2_last_rotated": "N/A",
                }
            ],
        },
    )
    # access_advisor: s3:GetObject 만 실사용.
    storage.write_raw(
        ACCOUNT,
        "access_advisor",
        {
            "account_id": ACCOUNT,
            "last_accessed": [
                {
                    "principal": ARN,
                    "services": [
                        {
                            "service": "s3",
                            "last_authenticated": "2026-07-10T00:00:00Z",
                            "actions": [
                                {"action": "GetObject", "last_accessed": "2026-07-10T00:00:00Z"}
                            ],
                        }
                    ],
                }
            ],
        },
    )
    # cloudtrail: s3:PutObject 이벤트 → 실사용에 추가.
    storage.write_raw(
        ACCOUNT,
        "cloudtrail",
        {
            "account_id": ACCOUNT,
            "mode": "lookup_events",
            "usage": [
                {
                    "principal": ARN,
                    "event_source": "s3.amazonaws.com",
                    "event_name": "PutObject",
                    "count": 12,
                    "last_used": "2026-07-11T00:00:00Z",
                }
            ],
        },
    )
    # analyzer_unused: skipped(빈 findings).
    storage.write_raw(
        ACCOUNT,
        "analyzer_unused",
        {"account_id": ACCOUNT, "analyzer_arn": None, "findings": []},
    )


def test_normalize_derives_gap(tmp_path) -> None:
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_raw(storage)

    records = normalize(storage, RUN)
    assert len(records) == 1
    r = records[0]

    assert r.granted_actions == ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"]
    used = {u.action for u in r.used_actions}
    assert used == {"s3:GetObject", "s3:PutObject"}  # advisor ∪ cloudtrail
    # cloudtrail count 반영.
    put = next(u for u in r.used_actions if u.action == "s3:PutObject")
    assert put.count_90d == 12
    # granted − used = DeleteObject 가 미사용 갭.
    assert r.unused_findings == ["s3:DeleteObject"]
    # credential report 파생.
    assert r.mfa is False
    assert r.access_key_age_days == (RUN.started_dt.date() - __import__("datetime").date(2026, 1, 1)).days
    # 기여 소스.
    assert set(r.source) == {"credential_report", "access_advisor", "cloudtrail"}


def test_max_ts_handles_mixed_source_formats() -> None:
    """소스별 포맷이 달라도(공백 vs 'T') 실제 시각 기준으로 더 최근을 고른다(timeutil)."""
    from lp2ps.timeutil import max_ts

    advisor_earlier = "2026-07-01T00:00:00Z"       # Access Advisor 포맷('T' 구분)
    spaced_later = "2026-07-20 00:00:00.000"        # 공백 구분 포맷(구분자 다름)
    # lexical max 라면 'T'(0x54) > ' '(0x20) 라 advisor 를 잘못 고른다. 시각 비교는 더 최근을 골라야.
    assert max_ts(advisor_earlier, spaced_later) == spaced_later
    assert max_ts(spaced_later, advisor_earlier) == spaced_later
    # 역방향: advisor 가 실제로 더 최근이면 advisor.
    assert max_ts("2026-07-25T00:00:00Z", "2026-07-20 00:00:00.000") == "2026-07-25T00:00:00Z"


def test_normalize_is_deterministic(tmp_path) -> None:
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_raw(storage)

    normalize(storage, RUN)
    first = storage.read_bytes("normalized.parquet")
    normalize(storage, RUN)
    second = storage.read_bytes("normalized.parquet")
    assert first == second, "같은 raw 입력 → normalized.parquet 바이트 동일(불변식 ②)"


def test_normalize_bare_account_no_used(tmp_path) -> None:
    """used 소스가 전부 없어도(granted 만) 완주 — granted 전부가 미사용 갭."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {
            "account_id": ACCOUNT,
            "principals": [
                {
                    "principal": ARN,
                    "name": "data-eng",
                    "identity_type": "role",
                    "inline_policies": [
                        {
                            "name": "inline",
                            "document": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                                ]
                            },
                        }
                    ],
                    "attached_policies": [],
                }
            ],
            "credential_report": [],
        },
    )
    records = normalize(storage, RUN)
    r = records[0]
    assert r.used_actions == []
    assert r.unused_findings == ["s3:GetObject"]
    assert r.source == ["credential_report"]
    assert r.access_key_age_days is None


def test_inactive_access_key_not_counted(tmp_path) -> None:
    """비활성 액세스키는 나이 계산에서 제외(장기키 오탐 방지)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {
            "account_id": ACCOUNT,
            "principals": [{"principal": ARN, "name": "x", "identity_type": "user",
                            "inline_policies": [], "attached_policies": []}],
            "credential_report": [
                {"arn": ARN, "mfa_active": "true",
                 "access_key_1_active": "false",  # 비활성 → 무시
                 "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00"}
            ],
        },
    )
    r = normalize(storage, RUN)[0]
    assert r.access_key_age_days is None
    assert r.mfa is True


def test_principal_survives_credential_report_degraded(tmp_path) -> None:
    """credential_report 가 비어도(degraded) analyzer/used 가 본 principal 은 레코드로 살아남는다."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    # credential_report: principal 인벤토리 없음(degraded 시나리오).
    storage.write_raw(ACCOUNT, "credential_report",
                      {"account_id": ACCOUNT, "principals": [], "credential_report": []})
    # analyzer 가 한 principal 을 봄.
    storage.write_raw(ACCOUNT, "analyzer_unused",
                      {"account_id": ACCOUNT, "analyzer_arn": "arn:x",
                       "findings": [{"id": "f1", "finding_type": "UnusedIAMRole",
                                     "resource": ARN, "resource_type": "AWS::IAM::Role",
                                     "status": "ACTIVE"}]})
    records = normalize(storage, RUN)
    assert len(records) == 1, "credential_report 비어도 analyzer 발 principal 이 드롭되면 안 됨"
    r = records[0]
    assert r.principal == ARN
    assert "UnusedIAMRole" in r.unused_findings
    assert r.source == ["analyzer_unused"]  # credential_report 는 기여 안 함(인벤토리 없음)
    assert r.identity_type == "role"  # ARN 모양에서 추정
