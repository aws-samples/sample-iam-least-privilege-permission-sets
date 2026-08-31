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
    assert e.synthesis_source == "last_accessed_evidence"


def test_count_observed_accepts_legacy_count_90d() -> None:
    """이전 run 의 산출물·DynamoDB 에 저장된 편집 오버라이드는 `count_90d` 키를 갖고 있다.

    이름을 바꾼 이유는 90일을 **어디서도 측정하지 않았다**는 것이다(실제 구간은
    `PrincipalRecord.observed_days`). alias 가 깨지면 옛 키로 저장된 값이 조용히 0 이 된다.
    """
    from lp2ps.models import PolicyAction, UsedAction

    assert UsedAction.model_validate({"action": "s3:GetObject", "count_90d": 7}).count_observed == 7
    # 새 이름도 그대로 받는다(대조군 — 위 assert 가 alias 때문이 아니라 우연히 통과하는 것 배제).
    assert UsedAction.model_validate({"action": "s3:GetObject", "count_observed": 7}).count_observed == 7
    # dump 는 새 이름으로만 나간다 — 옛 키를 다시 흘리면 프론트 계약(types.ts)과 어긋난다.
    assert "count_90d" not in UsedAction(action="s3:GetObject").model_dump()

    legacy = {"action": "s3:PutObject", "used": True, "included": True,
              "last_used": None, "count_90d": 3}
    assert PolicyAction.model_validate(legacy).count_observed == 3


def test_synthesis_source_accepts_legacy_access_analyzer() -> None:
    """옛 라벨 'access_analyzer' 로 기록된 catalog.json 도 읽을 수 있어야 한다.

    라벨 자체가 오표기였다(근거가 Access **Advisor** 인 경우까지 IAM Access Analyzer 라고 적었다).
    이 값은 고객이 받아 간 Terraform 태그·정책 JSON 에도 박혀 있으므로 옛 값을 계속 읽어야 한다.
    """
    e = CatalogEntry.model_validate(
        {"persona": "P", "description": "d", "policy_ref": "policies/P.json",
         "synthesis_source": "access_analyzer"}
    )
    assert e.synthesis_source == "last_accessed_evidence"
    # 대조: 폴백 등급은 매핑 대상이 아니라 그대로 남는다.
    assert CatalogEntry.model_validate(
        {"persona": "P", "description": "d", "policy_ref": "policies/P.json",
         "synthesis_source": "fallback_used_actions"}
    ).synthesis_source == "fallback_used_actions"


def test_principal_record_has_no_phantom_persona_fields() -> None:
    """`persona`/`persona_confidence` 는 어느 모듈도 채우지 않던 유령 필드였다 — 계약에서 제거.

    남겨 두면 UI·고객이 항상 null/0.0 인 값을 실측값(신뢰도 0)으로 읽는다. 되살릴 때는 채우는
    코드와 함께 되살려야 하므로, 되돌아오면 이 테스트가 먼저 깨진다.
    """
    assert "persona" not in PrincipalRecord.model_fields
    assert "persona_confidence" not in PrincipalRecord.model_fields


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
