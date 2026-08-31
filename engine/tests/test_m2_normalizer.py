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
                            # DeleteObject 는 **추적 목록에 있으나 기록 없음** → 미사용 확정.
                            # (추적 목록에 없으면 근거 부재라 미사용이 아니라 판정 불가다 —
                            #  test_gap_without_advisor_tracking_is_undetermined 가 그 쪽을 본다.)
                            "actions": [
                                {"action": "DeleteObject", "last_accessed": None},
                                {"action": "GetObject", "last_accessed": "2026-07-10T00:00:00Z"},
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
    # granted − used = DeleteObject 가 미사용 갭(추적 목록에 있고 기록 없음 → 확정).
    assert r.unused_findings == ["s3:DeleteObject"]
    assert r.undetermined_findings == []
    assert r.used_services == ["s3"]
    # credential report 파생.
    assert r.mfa is False
    assert r.access_key_age_days == (RUN.started_dt.date() - __import__("datetime").date(2026, 1, 1)).days
    # 기여 소스.
    assert set(r.source) == {"credential_report", "access_advisor", "cloudtrail"}


# ---- 미사용 확정 vs 판정 불가 ----
#
# Access Advisor 의 action-level 추적 범위는 서비스·action 별로 다르고 CloudTrail 은 단일 리전·관리
# 이벤트만 본다. "실사용 기록이 없다" 를 곧 "안 쓴다" 로 읽으면 실제로 쓰이는 권한을 지우라고 권한다.
# 실제 계정 데이터에서 이 오독이 미사용 권한 판정의 27.7%, 미사용 역할 판정의 19.6% 였다.


def _seed_one_role(storage: LocalFSStorage, granted: list[str], advisor_services: list[dict],
                   analyzer_findings: list[dict] | None = None) -> None:
    """inline 정책 1개 + advisor 응답만 있는 최소 계정. CloudTrail 은 비운다(근거 없음 상태 재현)."""
    storage.write_raw(ACCOUNT, "credential_report", {
        "account_id": ACCOUNT,
        "principals": [{
            "principal": ARN, "name": "data-eng", "identity_type": "role",
            "inline_policies": [{"name": "inline", "document": {
                "Statement": [{"Effect": "Allow", "Action": granted, "Resource": "*"}]}}],
            "attached_policies": [], "path": "/",
        }],
        "credential_report": [],
    })
    storage.write_raw(ACCOUNT, "access_advisor", {
        "account_id": ACCOUNT,
        "last_accessed": [{"principal": ARN, "services": advisor_services}],
    })
    storage.write_raw(ACCOUNT, "analyzer_unused", {
        "account_id": ACCOUNT, "analyzer_arn": None, "findings": analyzer_findings or [],
    })


def test_gap_without_advisor_tracking_is_undetermined(tmp_path) -> None:
    """서비스는 인증됐고 그 action 은 추적 목록에 없다 → 미사용이 아니라 판정 불가."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["s3:GetObject", "s3:DeleteObject"], [{
        "service": "s3",
        "last_authenticated": "2026-07-10T00:00:00Z",
        # GetObject 만 추적 대상. DeleteObject 는 목록에 아예 없다 → 증거 없음.
        "actions": [{"action": "GetObject", "last_accessed": "2026-07-10T00:00:00Z"}],
    }])
    r = normalize(storage, RUN)[0]
    assert r.undetermined_findings == ["s3:DeleteObject"]
    assert r.unused_findings == [], "근거 없는 action 을 '미사용' 이라 부르면 안 된다"


def test_gap_with_advisor_tracking_is_confirmed_unused(tmp_path) -> None:
    """대조: 같은 action 이 추적 목록에 있고 기록만 비면 미사용 확정이다.

    이 대조가 없으면 위 테스트는 '전부 판정 불가로 밀어버려도' 통과한다 — 판별력 확인용.
    """
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["s3:GetObject", "s3:DeleteObject"], [{
        "service": "s3",
        "last_authenticated": "2026-07-10T00:00:00Z",
        "actions": [
            {"action": "DeleteObject", "last_accessed": None},   # 추적됨 + 기록 없음
            {"action": "GetObject", "last_accessed": "2026-07-10T00:00:00Z"},
        ],
    }])
    r = normalize(storage, RUN)[0]
    assert r.unused_findings == ["s3:DeleteObject"]
    assert r.undetermined_findings == []


def test_gap_in_never_authenticated_service_is_unused(tmp_path) -> None:
    """서비스 자체를 인증한 적이 없으면 그 안의 action 은 추적 여부와 무관하게 미사용 확정."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["dynamodb:DeleteTable"], [{
        "service": "dynamodb", "last_authenticated": None, "actions": [],
    }])
    r = normalize(storage, RUN)[0]
    assert r.unused_findings == ["dynamodb:DeleteTable"]
    assert r.undetermined_findings == []
    assert r.used_services == []


def test_no_advisor_coverage_is_undetermined_not_unused(tmp_path) -> None:
    """advisor 응답의 서비스 행이 0개면(조회 실패·잡 미완료) 그 principal 은 전부 판정 불가.

    라이브 실행에서 실제로 새어나간 경로다: 142개 중 1개 principal 의 Access Advisor 조회가 실패했고,
    데이터가 없으니 "서비스를 인증한 적 없다"(②)로 읽혀 granted 전부가 '미사용 확정' 이 됐다.
    소스 전체가 실패하면 전 계정의 전 권한에 삭제 권고가 붙는다 — 근거 부재는 증거가 아니다.
    """
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["s3:GetObject", "dynamodb:DeleteTable"], [])  # 조회 실패 재현
    r = normalize(storage, RUN)[0]
    assert r.unused_findings == []
    assert r.undetermined_findings == ["dynamodb:DeleteTable", "s3:GetObject"]


def test_advisor_coverage_with_no_authentication_stays_unused(tmp_path) -> None:
    """대조: 같은 principal 에 advisor 서비스 행이 **있고** 인증 기록만 없으면 미사용 확정이다.

    이 대조가 없으면 위 테스트는 '전부 판정 불가로 밀어버려도' 통과한다. 근거 있는 미사용 판정을
    죽이면 도구의 본래 산출물(미사용 권한 정리)이 통째로 사라진다.
    """
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["s3:GetObject", "dynamodb:DeleteTable"], [
        {"service": "s3", "last_authenticated": None, "actions": []},
        {"service": "dynamodb", "last_authenticated": None, "actions": []},
    ])
    r = normalize(storage, RUN)[0]
    assert r.unused_findings == ["dynamodb:DeleteTable", "s3:GetObject"]
    assert r.undetermined_findings == []


def test_analyzer_findings_are_labels_not_actions(tmp_path) -> None:
    """analyzer finding 은 finding_type 라벨이라 3단 판정과 겹치지 않는다.

    이 전제가 깨지면(collector 가 action 단위 finding 을 싣게 되면) '미사용 확정 vs 판정 불가'
    우선순위를 새로 정해야 한다 — 그때 이 테스트가 먼저 깨져서 알려준다.
    """
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(
        storage, ["s3:DeleteObject"],
        [{"service": "s3", "last_authenticated": "2026-07-10T00:00:00Z", "actions": []}],
        analyzer_findings=[{"id": "f1", "finding_type": "UnusedPermission",
                            "resource": ARN, "resource_type": "AWS::IAM::Role",
                            "status": "ACTIVE"}],
    )
    r = normalize(storage, RUN)[0]
    assert r.unused_findings == ["UnusedPermission"], "라벨은 그대로 남는다"
    assert not any(":" in f for f in r.unused_findings), "analyzer 발 항목에 action 형태는 없다"
    # 서비스는 인증됐고 DeleteObject 는 추적 목록에 없으므로 판정 불가로 간다.
    assert r.undetermined_findings == ["s3:DeleteObject"]


def test_used_services_records_authenticated_only(tmp_path) -> None:
    """used_services 는 인증 기록이 있는 서비스만 담는다(권한만 있는 서비스는 제외)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_one_role(storage, ["s3:GetObject", "kms:Decrypt"], [
        {"service": "s3", "last_authenticated": "2026-07-10T00:00:00Z", "actions": []},
        {"service": "kms", "last_authenticated": None, "actions": []},
    ])
    r = normalize(storage, RUN)[0]
    assert r.used_services == ["s3"], "권한만 있고 인증 기록 없는 kms 가 섞이면 미사용 판정이 죽는다"


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
    """used 소스가 전부 없어도(granted 만) 완주 — granted 전부가 갭.

    단 그 갭은 **미사용 확정이 아니라 판정 불가**다: Access Advisor raw 가 아예 없으면
    "이 서비스를 인증한 적 없다" 는 주장의 근거가 없다. 예전엔 이걸 미사용 확정으로 냈고,
    그래서 advisor 조회가 실패한 principal 의 전 권한에 삭제 권고가 붙었다.
    """
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
    assert r.unused_findings == []
    assert r.undetermined_findings == ["s3:GetObject"]
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


# ---- 서비스 소유 역할은 persona 대상에서 제외(is_exception) ----

_SLR = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
_SSO = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc123"


def _seed_principal(storage: LocalFSStorage, arn: str, path: str) -> None:
    """arn 1건만 있는 최소 credential_report + 실사용 1건(persona 대상 조건 충족)."""
    storage.write_raw(
        ACCOUNT,
        "credential_report",
        {
            "account_id": ACCOUNT,
            "principals": [
                {
                    "principal": arn,
                    "name": arn.rsplit("/", 1)[-1],
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
                    "path": path,
                }
            ],
            "credential_report": [],
        },
    )


def test_service_linked_role_marked_exception(tmp_path) -> None:
    """서비스 연결 역할 → is_exception=True(m5 카탈로그가 제외). 사람이 쓰는 신원이 아니다."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_principal(storage, _SLR, "/aws-service-role/config.amazonaws.com/")
    r = normalize(storage, RUN)[0]
    assert r.is_exception is True
    assert r.exception_type == "service_linked"


def test_idc_reserved_role_marked_exception(tmp_path) -> None:
    """IdC 가 자동 생성한 AWSReservedSSO_* 역할 → is_exception=True(직접 수정 시 동기화가 덮어씀)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_principal(storage, _SSO, "/aws-reserved/sso.amazonaws.com/")
    r = normalize(storage, RUN)[0]
    assert r.is_exception is True
    assert r.exception_type == "idc_reserved"


def test_ordinary_role_not_exception(tmp_path) -> None:
    """대조군 — 일반 역할은 제외되지 않는다(위 두 테스트가 무조건 통과하는 게 아님을 보장)."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_principal(storage, ARN, "/")
    r = normalize(storage, RUN)[0]
    assert r.is_exception is False
    assert r.exception_type is None


def test_exception_detected_without_inventory(tmp_path) -> None:
    """credential_report degraded(인벤토리 없음)여도 ARN 경로로 판정된다 — path 필드에 의존하지 않는다."""
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    storage.write_raw(ACCOUNT, "credential_report",
                      {"account_id": ACCOUNT, "principals": [], "credential_report": []})
    storage.write_raw(ACCOUNT, "analyzer_unused",
                      {"account_id": ACCOUNT, "analyzer_arn": "arn:x",
                       "findings": [{"id": "f1", "finding_type": "UnusedIAMRole",
                                     "resource": _SLR, "resource_type": "AWS::IAM::Role",
                                     "status": "ACTIVE"}]})
    r = normalize(storage, RUN)[0]
    assert r.is_exception is True
    assert r.exception_type == "service_linked"


def test_excluded_from_catalog_but_kept_in_cleanup(tmp_path) -> None:
    """제외는 M5 카탈로그에만 적용 — 미사용 서비스 역할은 M6 조치 항목에 그대로 남아야 한다."""
    from lp2ps.config import CatalogConfig
    from lp2ps.m5_catalog import build_catalog
    from lp2ps.m6_reporter import _cleanup_items
    from lp2ps.models import UsedAction

    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    _seed_principal(storage, _SLR, "/aws-service-role/config.amazonaws.com/")
    records = normalize(storage, RUN)
    # 실사용을 붙여 persona 후보 조건(used_actions 존재)을 만족시킨다.
    records[0].used_actions = [UsedAction(action="s3:GetObject", last_used="2026-07-10T00:00:00Z")]
    storage.write_normalized(records)

    catalog = build_catalog(storage, RUN, CatalogConfig(min_members_for_persona=1))
    members = [m for e in catalog for m in e.members]
    assert _SLR not in members, "서비스 연결 역할이 persona 멤버로 남으면 안 됨"

    # M6 은 is_exception 을 보지 않으므로 미사용 역할 조치 항목은 유지된다.
    records[0].used_actions = []
    items = _cleanup_items(records, _cfg_for_cleanup())
    assert any(i.type == "unused_role" and i.principal == _SLR for i in items), \
        "제외가 조치 항목까지 지우면 안 됨(미사용 서비스 역할도 정리 대상)"


def _cfg_for_cleanup():
    from lp2ps.config import Config
    return Config.model_validate(
        {"customer": "test", "region": "us-west-2", "cross_account": False, "accounts": ["self"]}
    )
