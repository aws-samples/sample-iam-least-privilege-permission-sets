"""self-mode 수집 통합 (M1) — moto.

검증:
- self-mode 는 sts:AssumeRole 을 호출하지 않는다(ambient 자격증명 사용).
- 미프로비저닝 소스(Access Advisor/Analyzer)는 crash 없이 degraded/skipped 로 완주.
- run status 는 정직하게: degraded 소스가 있을 때만 degraded, skipped 만이면 succeeded.
- manifest 에 소스별 상태 기록, raw/** 산출.
- 수집 경로에서 ReadOnlyViolation 이 발생하지 않는다(allowlist 준수).
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from lp2ps.config import Config
from lp2ps.m1_collector import collect
from lp2ps.runctx import RunContext
from lp2ps.storage import LocalFSStorage


def _self_config() -> Config:
    # 고객 무관: 테스트는 mock 계정/단일계정(ambient)만 쓴다(하드코딩된 고객 값 없음).
    return Config.model_validate(
        {
            "customer": "test",
            "region": "us-west-2",
            "cross_account": False,
            "accounts": ["self"],
        }
    )


def _run() -> RunContext:
    # started_at 고정 → 결정론.
    return RunContext(run_id="run-fixed", customer="test", started_at="2026-07-15T00:00:00Z")


def _seed_iam() -> None:
    iam = boto3.client("iam", region_name="us-west-2")
    iam.create_role(
        RoleName="data-eng",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    iam.put_role_policy(
        RoleName="data-eng",
        PolicyName="inline",
        PolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"*"}]}'
        ),
    )
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")


@mock_aws
def test_selfmode_collect_completes_with_degraded(tmp_path) -> None:
    _seed_iam()
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")

    manifest = collect(_self_config(), storage, _run())

    assert manifest["account_scope"] == 1
    account = manifest["accounts"][0]
    statuses = {s["source"]: s["status"] for s in account["sources"]}

    # credential_report 는 moto 에서 동작 → ok.
    assert statuses["credential_report"] == "ok"
    # Access Advisor·Analyzer·CloudTrail 은 moto 미구현 → degraded/skipped 로 완주(crash 아님).
    assert statuses["access_advisor"] in {"degraded", "skipped"}
    assert statuses["analyzer_unused"] in {"degraded", "skipped"}
    assert statuses["cloudtrail"] in {"degraded", "skipped"}
    # run status(정직 판정): degraded 소스가 하나라도 있으면 degraded, 없고 skipped 만이면 succeeded.
    # (skipped=선택적 소스 미존재는 정상이므로 run 을 낮추지 않는다.)
    any_degraded = any(v == "degraded" for v in statuses.values())
    assert manifest["status"] == ("degraded" if any_degraded else "succeeded")
    # status_summary 근거가 실제 소스 상태와 일치해야 한다(UI 실행 이력 상세용).
    summary = manifest["status_summary"]
    assert set(summary["degraded_sources"]) == {k for k, v in statuses.items() if v == "degraded"}
    assert set(summary["skipped_sources"]) == {k for k, v in statuses.items() if v == "skipped"}

    # raw/** 산출 확인.
    caller = boto3.client("sts", region_name="us-west-2").get_caller_identity()["Account"]
    assert storage.exists(f"raw/{caller}/credential_report.json")
    raw = storage.read_raw(caller, "credential_report")
    principals = {p["name"] for p in raw["principals"]}
    assert "data-eng" in principals
    assert "alice" in principals


@mock_aws
def test_selfmode_does_not_assume_role(tmp_path, monkeypatch) -> None:
    _seed_iam()
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")

    # 어떤 코드도 AssumeRole 을 부르면 즉시 실패.
    import botocore.client

    orig = botocore.client.BaseClient._make_api_call

    def _guard(self, operation_name, kwargs):
        assert operation_name != "AssumeRole", "self-mode 는 AssumeRole 을 부르면 안 된다"
        return orig(self, operation_name, kwargs)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _guard)
    collect(_self_config(), storage, _run())


@mock_aws
def test_collect_raises_nothing_readonly(tmp_path) -> None:
    """수집 전 과정에서 ReadOnlyViolation 이 새어나오지 않는다(가드 준수)."""
    from lp2ps.awsguard import ReadOnlyViolation

    _seed_iam()
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")
    try:
        collect(_self_config(), storage, _run())
    except ReadOnlyViolation as e:  # pragma: no cover
        pytest.fail(f"수집이 쓰기 API 를 시도했다: {e}")


@mock_aws
def test_skipped_only_is_succeeded(tmp_path, monkeypatch) -> None:
    """모든 소스가 ok/skipped(선택적 소스 미존재)면 run 은 succeeded 여야 한다.

    과거엔 skipped 도 run 을 degraded 로 낮춰 정상 환경조차 '부분 성공'으로 보였다(버그).
    선택적 소스 미존재는 정상이므로 degraded 소스가 실제로 있을 때만 degraded 여야 한다.
    """
    from lp2ps.collectors import CollectorResult

    _seed_iam()
    storage = LocalFSStorage(tmp_path, "test", "run-fixed")

    # 모든 collector 를 ok/skipped 조합만 반환하도록 대체(degraded 없음).
    def _fake_collect(self, account, context):
        status = "skipped" if self.source in {"analyzer_unused", "idc_permission_sets"} else "ok"
        return CollectorResult(source=self.source, status=status,
                               data={"account_id": account.account_id}, note="")

    import lp2ps.m1_collector as m1

    for c in m1.all_collectors():
        monkeypatch.setattr(type(c), "collect", _fake_collect, raising=True)

    manifest = collect(_self_config(), storage, _run())
    assert manifest["status"] == "succeeded"
    assert manifest["status_summary"]["degraded_sources"] == []
    assert set(manifest["status_summary"]["skipped_sources"]) == {"analyzer_unused", "idc_permission_sets"}
    assert manifest["status_summary"]["has_skipped"] is True


@mock_aws
def test_collection_budget_reaches_collectors(tmp_path, monkeypatch) -> None:
    """config.collection 의 예산이 collector context 로 실제로 전달된다.

    collector 는 context 에 값이 없으면 모듈 기본값으로 조용히 폴백하므로, 배선이 끊겨도
    수집은 성공한다 — 즉 이 어설션 없이는 배선 손상이 어떤 테스트에도 안 잡힌다.
    """
    _seed_iam()
    cfg = Config.model_validate({"customer": "test", "region": "us-west-2",
                                 "cross_account": False, "accounts": ["self"],
                                 "collection": {"cloudtrail_max_pages": 7}})
    seen: list[dict] = []

    def _spy(self, account, context):  # noqa: ANN001
        seen.append(dict(context))
        from lp2ps.collectors import CollectorResult
        return CollectorResult(source=self.source, status="ok",
                               data={"account_id": account.account_id}, note="")

    import lp2ps.m1_collector as m1
    for c in m1.all_collectors():
        monkeypatch.setattr(type(c), "collect", _spy, raising=True)

    collect(cfg, LocalFSStorage(tmp_path, "test", "run-fixed"), _run())
    assert seen, "collector 가 한 번도 호출되지 않았다(대조 전제)"
    assert all(ctx["cloudtrail_max_pages"] == 7 for ctx in seen)


def test_sec012_014_exception_note_no_leak() -> None:
    """collector 예외 시 manifest note 에 예외 메시지·traceback 을 넣지 않는다
    (예외 타입명만). 민감정보(계정ID·ARN 등)가 섞인 예외 텍스트의 고객 노출 방지."""

    class _Boom:
        source = "boomsrc"

        def collect(self, account, context):
            raise RuntimeError("arn:aws:iam::999988887777:role/secret 접근 실패 — 민감 상세")

    from types import SimpleNamespace

    from lp2ps.m1_collector import _run_one

    account = SimpleNamespace(account_id="111122223333")
    result = _run_one(_Boom(), account, {})
    assert result.status == "degraded"
    # 예외 타입명만 — 메시지 본문·ARN·traceback 은 없어야 한다.
    assert result.note == "수집 중 예외: RuntimeError"
    assert "arn:aws:iam" not in result.note
    assert "민감 상세" not in result.note
    assert "Traceback" not in result.note and "role/secret" not in result.note
