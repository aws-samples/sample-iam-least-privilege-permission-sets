"""models.py 계약 테스트 — frontend types.ts 와 일치하는 필드가 라운드트립 되는지."""

from __future__ import annotations

from lp2ps.models import (
    AssistantAnswer,
    CatalogEntry,
    MetricsPoint,
    PrincipalRecord,
    ProvisionResult,
    Run,
)


def test_principal_record_roundtrip() -> None:
    rec = PrincipalRecord(
        account_id="111122223333",
        principal="arn:aws:iam::111122223333:role/data-eng",
        identity_type="role",
        run_id="run-005",
    )
    dumped = rec.model_dump()
    assert dumped["ai_suggested"] is False
    assert PrincipalRecord.model_validate(dumped) == rec


def test_metrics_point_risk_dist_default() -> None:
    mp = MetricsPoint(run_id="run-005", ts="2026-07-14T02:00:00Z")
    assert mp.risk_dist.critical == 0


def test_run_status_literal() -> None:
    run = Run(run_id="r", customer="self", started_at="2026-07-14T02:00:00Z", account_scope=1, status="succeeded")
    assert run.status == "succeeded"


def test_catalog_entry_defaults() -> None:
    e = CatalogEntry(persona="DataEngineer", description="d", policy_ref="policies/x.json")
    assert e.approval_status == "draft"
    assert e.synthesis_source == "access_analyzer"


def test_assistant_answer_ai_suggested_always_true() -> None:
    a = AssistantAnswer(answer="...", grounded=True)
    assert a.ai_suggested is True


def test_provision_result_assignment_skipped() -> None:
    r = ProvisionResult(
        persona="DataEngineer",
        permission_set_arn="arn:aws:sso:::permissionSet/x",
        created=True,
        provisioned_at="2026-07-14T02:00:00Z",
    )
    # account assignment 은 절대 안 함 — 계약으로 강제.
    assert r.assignment_skipped is True
