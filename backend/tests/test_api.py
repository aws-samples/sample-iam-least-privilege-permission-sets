"""API 라우터 통합 테스트 — moto(S3+DynamoDB) + FastAPI TestClient.

계약 일치(프론트 Api 인터페이스) + 인증(401) + 쓰기 경계(도구 소유만)를 검증한다.
"""

from __future__ import annotations

import importlib
import json

import boto3
import pytest
from moto import mock_aws

CUSTOMER = "self"
BUCKET = "lp2ps-test-data"
RUNS_TABLE = "runs"
METRICS_TABLE = "metrics"


def _seed_env(monkeypatch):
    monkeypatch.setenv("LP2PS_CUSTOMER", CUSTOMER)
    monkeypatch.setenv("LP2PS_DATA_BUCKET", BUCKET)
    monkeypatch.setenv("LP2PS_RUNS_TABLE", RUNS_TABLE)
    monkeypatch.setenv("LP2PS_METRICS_TABLE", METRICS_TABLE)
    monkeypatch.setenv("LP2PS_CATALOG_TABLE", "catalog")
    monkeypatch.setenv("LP2PS_STATE_MACHINE_ARN",
                       "arn:aws:states:us-west-2:111122223333:stateMachine:Pipeline")
    # 버킷 소유 계정 + S3 KMS 키(hosted 배포에서 CDK 가 주입하는 값). moto 에선 키를
    # _seed_aws 가 만들어 LP2PS_DATA_KEY_ARN 으로 설정한다(아래).
    monkeypatch.setenv("LP2PS_EXPECTED_BUCKET_OWNER", "111122223333")


def _seed_aws(monkeypatch=None):
    s3 = boto3.client("s3", region_name="us-west-2")
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "us-west-2"})
    # S3 put 에 필요한 CMK. moto KMS 로 생성해 env 에 주입.
    key_arn = boto3.client("kms", region_name="us-west-2").create_key()["KeyMetadata"]["Arn"]
    import os
    if monkeypatch is not None:
        monkeypatch.setenv("LP2PS_DATA_KEY_ARN", key_arn)
    else:
        os.environ["LP2PS_DATA_KEY_ARN"] = key_arn
    ddb = boto3.resource("dynamodb", region_name="us-west-2")
    runs = ddb.create_table(
        TableName=RUNS_TABLE, KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    metrics = ddb.create_table(
        TableName=METRICS_TABLE,
        KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"}, {"AttributeName": "ts", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"}, {"AttributeName": "ts", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    ddb.create_table(
        TableName="catalog", KeySchema=[{"AttributeName": "persona", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "persona", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    runs.put_item(Item={"run_id": "run-001", "customer": CUSTOMER, "started_at": "2026-07-16T00:00:00Z",
                        "account_scope": 1, "status": "succeeded"})
    metrics.put_item(Item={"run_id": "run-001", "ts": "2026-07-16T00:00:00Z", "personas": 3, "no_mfa": 0})
    # S3 산출물(catalog/cleanup/exec_summary/iac).
    from lp2ps.storage import S3Storage
    st = S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001")
    st.write_json("catalog.json", [{"persona": "DataPersona", "description": "d",
                                    "members": ["arn:aws:iam::444455556666:role/data"], "member_count": 1,
                                    "policy_ref": "policies/DataPersona.json"}])
    st.write_json("policies/DataPersona.json", {"Version": "2012-10-17",
                  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]})
    st.write_text("cleanup_backlog.csv",
                  "id,type,account_id,principal,risk_level,detail,recommendation,risk_score,risk_reasons,evidence\n"
                  'c1,no_mfa,111122223333,arn:u,medium,MFA 없음,MFA 강제,35,MFA 미설정 콘솔 사용자|미사용 권한/발견 10건,"{""MFA"": ""미설정"", ""콘솔 로그인"": ""가능""}"\n')
    # 구 키(`unused_permissions_removed`)를 일부러 그대로 둔다 — 이전 run 의 exec_summary.json 이
    # 이 이름으로 S3 에 남아 있고, alias 가 깨지면 /reports 가 500 을 낸다(test_reports 가 잡는다).
    st.write_json("exec_summary.json", {"accounts": 1, "principals": 10, "personas": 3,
                  "unused_permissions_removed": 5, "generated_at": "2026-07-16T00:00:00Z"})
    st.write_text("report.html", "<html>ok</html>")
    st.write_text("iac/permission_sets.tf", "# tf")


def _client(monkeypatch, *, auth=True):
    monkeypatch.setenv("LP2PS_AUTH_DISABLED", "true" if auth else "false")
    # 캐시된 settings/repos 리셋(env 반영).
    from lp2ps_api import deps, routers
    deps.get_settings.cache_clear()
    routers.get_repos.cache_clear()
    from lp2ps_api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


@mock_aws
def test_get_runs(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    r = c.get("/runs")
    assert r.status_code == 200
    assert r.json()[0]["run_id"] == "run-001"


@mock_aws
def test_post_runs_triggers_sfn(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    # moto 에 상태머신 등록 후 그 ARN 을 env 에.
    sfn = boto3.client("stepfunctions", region_name="us-west-2")
    role = "arn:aws:iam::111122223333:role/sfn"
    sm = sfn.create_state_machine(name="Pipeline", definition=json.dumps(
        {"StartAt": "x", "States": {"x": {"Type": "Pass", "End": True}}}), roleArn=role)
    monkeypatch.setenv("LP2PS_STATE_MACHINE_ARN", sm["stateMachineArn"])
    c = _client(monkeypatch)
    r = c.post("/runs")
    assert r.status_code == 200
    body = r.json()
    # run_id·started_at 을 API 가 생성(4 stage 공유). status=running.
    assert body["run_id"].startswith("run-")
    assert body["status"] == "running"
    # 실제로 실행이 시작됐는지(입력에 run_id 포함).
    execs = sfn.list_executions(stateMachineArn=sm["stateMachineArn"])["executions"]
    assert len(execs) == 1


@mock_aws
def test_post_runs_account_scope_from_config(monkeypatch):
    """account_scope 는 config.accounts 길이 반영(멀티계정 하드코딩 1 아님)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    sfn = boto3.client("stepfunctions", region_name="us-west-2")
    sm = sfn.create_state_machine(name="P2", definition=json.dumps(
        {"StartAt": "x", "States": {"x": {"Type": "Pass", "End": True}}}),
        roleArn="arn:aws:iam::111122223333:role/sfn")
    monkeypatch.setenv("LP2PS_STATE_MACHINE_ARN", sm["stateMachineArn"])
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps(
        {"accounts": ["111122223333", "444455556666", "777788889999"]}))
    c = _client(monkeypatch)
    assert c.post("/runs").json()["account_scope"] == 3


@mock_aws
def test_post_runs_records_running_row(monkeypatch):
    """POST /runs 는 시작된 run 을 runs 테이블에 status="running" 으로 즉시 기록한다.

    이 레코드가 없으면 시작된 run 은 파이프라인이 끝날 때까지 GET /runs 에 나타나지 않아
    대시보드가 완료를 감지할 수 없다(실행 이력도 빈 상태).
    """
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    sfn = boto3.client("stepfunctions", region_name="us-west-2")
    sm = sfn.create_state_machine(name="P3", definition=json.dumps(
        {"StartAt": "x", "States": {"x": {"Type": "Pass", "End": True}}}),
        roleArn="arn:aws:iam::111122223333:role/sfn")
    monkeypatch.setenv("LP2PS_STATE_MACHINE_ARN", sm["stateMachineArn"])
    c = _client(monkeypatch)
    run_id = c.post("/runs").json()["run_id"]

    # DynamoDB 에 직접 들어갔는지.
    item = boto3.resource("dynamodb", region_name="us-west-2").Table(RUNS_TABLE).get_item(
        Key={"run_id": run_id})["Item"]
    assert item["status"] == "running"
    # API 계약으로도 관측 가능한지(대시보드 폴링 경로).
    listed = {r["run_id"]: r for r in c.get("/runs").json()}
    assert listed[run_id]["status"] == "running"


@mock_aws
def test_post_runs_survives_runs_table_write_failure(monkeypatch):
    """이력 기록 실패는 트리거를 실패시키지 않는다 — SFN 실행은 이미 시작됐고 파일이 SoT."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    sfn = boto3.client("stepfunctions", region_name="us-west-2")
    sm = sfn.create_state_machine(name="P4", definition=json.dumps(
        {"StartAt": "x", "States": {"x": {"Type": "Pass", "End": True}}}),
        roleArn="arn:aws:iam::111122223333:role/sfn")
    monkeypatch.setenv("LP2PS_STATE_MACHINE_ARN", sm["stateMachineArn"])
    monkeypatch.setenv("LP2PS_RUNS_TABLE", "does-not-exist")
    c = _client(monkeypatch)
    r = c.post("/runs")
    assert r.status_code == 200
    assert r.json()["status"] == "running"
    assert len(sfn.list_executions(stateMachineArn=sm["stateMachineArn"])["executions"]) == 1


@mock_aws
def test_get_metrics(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    r = c.get("/metrics")
    assert r.status_code == 200
    assert r.json()[0]["personas"] == 3


@mock_aws
def test_approve_persists_and_get_reflects(monkeypatch):
    """approve → DynamoDB catalog override → GET /catalog 이 approved 반영(persist 확인)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # 초기 상태(draft).
    assert c.get("/catalog").json()[0]["approval_status"] in ("draft", "review")
    c.post("/catalog/DataPersona/approve", json={"policy_doc": ""})
    # 재조회 시 approved 로 유지(override 병합).
    entry = next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")
    assert entry["approval_status"] == "approved"


@mock_aws
def test_patch_persona_saves_actions(monkeypatch):
    """PATCH /catalog/{persona} 가 action override 를 저장하고 GET 에 반영."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # `count_90d` 는 구 키다. 이미 DynamoDB 에 저장된 override 가 이 키로 들어 있어서 alias 로
    # 받아야 한다 — 못 받으면 조용히 0 이 되고 UI 는 "관측 0회" 라는 거짓을 보여준다.
    new_actions = [{"action": "s3:GetObject", "used": True, "included": True,
                    "last_used": None, "count_90d": 5}]
    r = c.patch("/catalog/DataPersona", json={"actions": new_actions})
    assert r.status_code == 200
    entry = next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")
    assert [a["action"] for a in entry["actions"]] == ["s3:GetObject"]
    assert entry["actions"][0]["count_observed"] == 5
    assert "count_90d" not in entry["actions"][0]  # 응답은 새 이름으로만 나간다.

    # 새 이름도 그대로 받는다(대조군 — 위 assert 가 alias 때문이 아니라 우연히 통과하는 것 배제).
    r2 = c.patch("/catalog/DataPersona", json={"actions": [
        {"action": "s3:PutObject", "used": True, "included": True,
         "last_used": None, "count_observed": 7}]})
    assert r2.status_code == 200
    entry2 = next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")
    assert [(a["action"], a["count_observed"]) for a in entry2["actions"]] == [("s3:PutObject", 7)]


@mock_aws
def test_get_catalog_and_terraform(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.get("/catalog").json()[0]["persona"] == "DataPersona"
    tf = c.get("/catalog/DataPersona/terraform").json()
    assert "aws_ssoadmin_permission_set" in tf["hcl"]
    assert "s3:GetObject" in tf["hcl"]


@mock_aws
def test_approve_returns_terraform(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    r = c.post("/catalog/DataPersona/approve", json={"policy_doc": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["entry"]["approval_status"] == "approved"
    assert body["terraform"]["persona"] == "DataPersona"
    # 승인 응답만으로 반영까지 갈 수 있어야 한다(별도 GET 없이).
    assert [a["target"] for a in body["artifacts"]] == [
        "iam_policy_tf", "policy_json", "iam_role_tf", "permission_set_tf"
    ]


@mock_aws
def test_artifacts_endpoint(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    arts = c.get("/catalog/DataPersona/artifacts").json()
    by_target = {a["target"]: a for a in arts}
    assert 'resource "aws_iam_policy"' in by_target["iam_policy_tf"]["content"]
    assert "s3:GetObject" in by_target["iam_policy_tf"]["content"]
    # 다운로드만 하는 사람에게도 Resource "*" 제약이 보여야 한다.
    assert any('Resource 는 "*"' in n for n in by_target["policy_json"]["notes"])


@mock_aws
def test_artifacts_omit_permission_set_without_identity_center(monkeypatch):
    """IdC 미사용 고객: PS 산출물을 주면 apply 할 IdC 가 없다. 대신 IAM 산출물은 그대로 있어야 한다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"provisioning": {"uses_identity_center": False}}))
    c = _client(monkeypatch)
    targets = {a["target"] for a in c.get("/catalog/DataPersona/artifacts").json()}
    assert targets == {"iam_policy_tf", "policy_json", "iam_role_tf"}


@mock_aws
def test_artifacts_unknown_persona_404(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.get("/catalog/NoSuchPersona/artifacts").status_code == 404


@mock_aws
def test_terraform_uses_configured_session_duration(monkeypatch):
    """세션 유지시간은 config 를 따른다 — 예전엔 백엔드가 PT8H 를 하드코딩해 M7 산출물과 달랐다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"permission_sets": {"session_duration": "PT2H"}}))
    c = _client(monkeypatch)
    assert 'session_duration = "PT2H"' in c.get("/catalog/DataPersona/terraform").json()["hcl"]


@mock_aws
def test_iac_download_falls_back_to_iam_policies(monkeypatch):
    """IdC 미사용 run 에는 permission_sets.tf 가 없다 — 그때 iam_policies.tf 를 내려준다(404 금지)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    import boto3
    boto3.client("s3", region_name="us-west-2").delete_object(
        Bucket=BUCKET, Key=f"{CUSTOMER}/run-001/iac/permission_sets.tf"
    )
    from lp2ps.storage import S3Storage
    S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001").write_text("iac/iam_policies.tf", "# iam")
    c = _client(monkeypatch)
    r = c.get("/iac/run-001/download")
    assert r.status_code == 200
    assert "iam_policies.tf" in r.json()["url"]


@mock_aws
def test_iac_download_404_when_no_artifact(monkeypatch):
    """대조군: 두 후보 모두 없으면 404. (폴백이 무조건 200 을 주는 게 아니라는 증거)"""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    import boto3
    boto3.client("s3", region_name="us-west-2").delete_object(
        Bucket=BUCKET, Key=f"{CUSTOMER}/run-001/iac/permission_sets.tf"
    )
    c = _client(monkeypatch)
    assert c.get("/iac/run-001/download").status_code == 404


@mock_aws
def test_provision_ps_requires_approval(monkeypatch):
    """승인 전 provision → 409(approved 아님). opt-in config 없이도 게이트는 approved 상태."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.post("/catalog/DataPersona/provision-ps").status_code == 409


@mock_aws
def test_provision_ps_creates_ps_after_approval(monkeypatch):
    """승인 후 provision → tooling IdC 에 PS 정의 생성. IdC 인스턴스는 런타임 자동 조회.

    opt-in config 불필요(무조건 기능). account assignment 은 안 함(불변식①)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    # IdC 리전 조회를 위해 idc_region 만 config 로(인스턴스 ARN 은 자동 조회 — moto 가 기본 인스턴스 제공).
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"provisioning": {"idc_region": "us-west-2"}}))
    c = _client(monkeypatch)
    c.post("/catalog/DataPersona/approve", json={"policy_doc": ""})
    r = c.post("/catalog/DataPersona/provision-ps")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] is True
    assert body["assignment_skipped"] is True  # 불변식①: 멤버계정 권한 부여 안 함
    assert body["permission_set_arn"].startswith("arn:aws:sso:::")


@mock_aws
def test_cleanup_and_reports(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    item = c.get("/cleanup-backlog").json()[0]
    assert item["type"] == "no_mfa"
    # 위험도 설명(점수·근거)이 항목에 실려 옴.
    assert item["risk_score"] == 35
    assert "MFA 미설정 콘솔 사용자" in item["risk_reasons"]
    # 유형별 상세 근거(evidence) JSON → dict 복원.
    assert item["evidence"]["MFA"] == "미설정"
    assert item["evidence"]["콘솔 로그인"] == "가능"
    rep = c.get("/reports/run-001").json()
    assert rep["exec_summary"]["personas"] == 3
    assert rep["report_html_url"].startswith("https://")
    # 최신 리포트(run_id 없이) — 백엔드가 최신 run 을 고른다.
    latest = c.get("/reports").json()
    assert latest["run_id"] == "run-001"
    assert latest["exec_summary"]["personas"] == 3


# ---- 배포 성격(GET /settings/deployment) ----

@mock_aws
def test_deployment_settings_defaults_to_identity_center(monkeypatch):
    """config 에 값이 없으면 True — 기존 배포의 화면을 바꾸지 않는다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.delenv("LP2PS_CONFIG_INLINE", raising=False)
    c = _client(monkeypatch)
    assert c.get("/settings/deployment").json() == {"uses_identity_center": True}


@mock_aws
def test_deployment_settings_reflects_config_false(monkeypatch):
    """uses_identity_center=false 를 그대로 내린다(대시보드가 PS 지표를 '해당 없음' 으로 표시)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE",
                       json.dumps({"provisioning": {"uses_identity_center": False}}))
    c = _client(monkeypatch)
    assert c.get("/settings/deployment").json() == {"uses_identity_center": False}


# ---- 조치 상태(미조치/조치완료/보류) ----

KEY_A = "a" * 64
KEY_B = "b" * 64


def _seed_findings_table(monkeypatch):
    """findings 테이블 생성 + env 배선(CDK api-stack 이 하는 일과 동일)."""
    boto3.resource("dynamodb", region_name="us-west-2").create_table(
        TableName="findings", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    monkeypatch.setenv("LP2PS_FINDINGS_TABLE", "findings")


def _write_backlog(run_id: str, rows: list[str]) -> None:
    """finding_key 컬럼이 있는 백로그 CSV 를 그 run 에 쓴다."""
    from lp2ps.storage import S3Storage

    header = ("id,finding_key,type,account_id,principal,risk_level,detail,"
              "recommendation,risk_score,risk_reasons,evidence\n")
    S3Storage(f"s3://{BUCKET}", CUSTOMER, run_id).write_text(
        "cleanup_backlog.csv", header + "".join(r + "\n" for r in rows))


@mock_aws
def test_cleanup_status_put_then_get_merges(monkeypatch):
    """조치완료 표시 → GET /cleanup-backlog 에 status·메모·작성자가 병합돼 보인다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    _write_backlog("run-001", [f"c1,{KEY_A},no_mfa,111122223333,arn:u,medium,MFA 없음,fix,35,,{{}}"])
    c = _client(monkeypatch)
    # 표시 전에는 미조치.
    assert c.get("/cleanup-backlog").json()[0]["status"] == "open"
    r = c.put(f"/cleanup-backlog/{KEY_A}/status",
              json={"status": "done", "note": "IdC 없이 IAM 정책만 다듬어 적용함"})
    assert r.status_code == 200, r.text
    assert r.json()["finding_key"] == KEY_A
    item = c.get("/cleanup-backlog").json()[0]
    assert item["status"] == "done"
    assert item["status_note"] == "IdC 없이 IAM 정책만 다듬어 적용함"
    assert item["status_updated_at"].endswith("Z")
    # 보류로 변경 — 마지막 쓰기가 이긴다.
    c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "deferred", "note": "차기 분기"})
    assert c.get("/cleanup-backlog").json()[0]["status"] == "deferred"


@mock_aws
def test_cleanup_status_survives_new_run_with_shifted_id(monkeypatch):
    """이 기능의 핵심 — 새 run 에서 순번 id 가 밀려도 finding_key 가 같으면 상태가 유지된다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    _write_backlog("run-001", [f"c1,{KEY_A},no_mfa,111122223333,arn:u,medium,MFA 없음,fix,35,,{{}}"])
    c = _client(monkeypatch)
    c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "done", "note": "처리"})

    # 새 run: 항목이 하나 늘어 기존 항목의 id 가 c1 → c2 로 밀렸다(detail 수치도 변했다).
    boto3.resource("dynamodb", region_name="us-west-2").Table(RUNS_TABLE).put_item(
        Item={"run_id": "run-002", "customer": CUSTOMER, "started_at": "2026-07-17T00:00:00Z",
              "account_scope": 1, "status": "succeeded"})
    _write_backlog("run-002", [
        f"c1,{KEY_B},long_lived_key,111122223333,arn:v,high,액세스키 age 613일,fix,50,,{{}}",
        f"c2,{KEY_A},no_mfa,111122223333,arn:u,medium,MFA 없음(외 2건),fix,35,,{{}}",
    ])
    items = {i["finding_key"]: i for i in c.get("/cleanup-backlog").json()}
    assert items[KEY_A]["id"] == "c2", "순번이 실제로 밀려야 함(대조 전제)"
    assert items[KEY_A]["status"] == "done", "id 가 밀렸는데 상태가 유실되면 안 된다"
    assert items[KEY_B]["status"] == "open", "표시하지 않은 새 항목은 미조치"


@mock_aws
def test_cleanup_status_rejects_bad_finding_key(monkeypatch):
    """경로 파라미터가 sha256 hex 가 아니면 400 — 임의 문자열이 DynamoDB 키가 되지 않게."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    c = _client(monkeypatch)
    assert c.put("/cleanup-backlog/not-a-key/status", json={"status": "done"}).status_code == 400
    # 대조군: 형식이 맞으면 통과한다(위 400 이 경로 자체 문제가 아님을 보장).
    assert c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "done"}).status_code == 200


@mock_aws
def test_cleanup_status_503_when_table_unwired(monkeypatch):
    """findings 테이블 env 가 없으면 조용히 성공하지 않고 503(표시했다고 착각 방지)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.delenv("LP2PS_FINDINGS_TABLE", raising=False)
    c = _client(monkeypatch)
    r = c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "done"})
    assert r.status_code == 503, r.text
    # 조회는 계속 동작(전부 미조치로 보인다).
    assert c.get("/cleanup-backlog").status_code == 200


@mock_aws
def test_cleanup_status_requires_auth(monkeypatch):
    """쓰기 경로는 인증 필수(auth 미비활성 → 401)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    c = _client(monkeypatch, auth=False)
    assert c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "done"}).status_code == 401


@mock_aws
def test_cleanup_status_rejects_unknown_status_and_long_note(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    c = _client(monkeypatch)
    assert c.put(f"/cleanup-backlog/{KEY_A}/status", json={"status": "resolved"}).status_code == 422
    assert c.put(f"/cleanup-backlog/{KEY_A}/status",
                 json={"status": "done", "note": "x" * 501}).status_code == 422


@mock_aws
def test_cleanup_legacy_csv_without_finding_key_has_no_status(monkeypatch):
    """구 산출물(finding_key 컬럼 없음)은 빈 키 → 상태 병합 안 함(엉뚱한 항목에 붙는 것보다 낫다)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch); _seed_findings_table(monkeypatch)
    c = _client(monkeypatch)
    # _seed_aws 의 CSV 는 finding_key 컬럼이 없다.
    item = c.get("/cleanup-backlog").json()[0]
    assert item["finding_key"] == ""
    assert item["status"] == "open"


def _seed_aws_no_runs(monkeypatch):
    """갓 배포한 상태 — 테이블/버킷은 있고 run 은 0건(_seed_aws 의 run-001 산출물이 없다)."""
    s3 = boto3.client("s3", region_name="us-west-2")
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "us-west-2"})
    key_arn = boto3.client("kms", region_name="us-west-2").create_key()["KeyMetadata"]["Arn"]
    monkeypatch.setenv("LP2PS_DATA_KEY_ARN", key_arn)
    ddb = boto3.resource("dynamodb", region_name="us-west-2")
    ddb.create_table(
        TableName=RUNS_TABLE, KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    ddb.create_table(
        TableName=METRICS_TABLE,
        KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"}, {"AttributeName": "ts", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"}, {"AttributeName": "ts", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")
    ddb.create_table(
        TableName="catalog", KeySchema=[{"AttributeName": "persona", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "persona", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")


@mock_aws
def test_latest_report_is_null_not_404_on_fresh_deploy(monkeypatch):
    """리포트가 아직 없는 것은 갓 배포한 고객의 정상 상태 — 200 + null 이어야 한다.

    404 면 프론트가 이것을 오류로 취급해 "리포트를 불러오지 못했습니다 / 404 Not Found" 를 붉은
    경고로 띄운다. 형제 endpoint 들과 동일하게 '비어 있음'으로 응답하는지 함께 고정한다.
    """
    _seed_env(monkeypatch); _seed_aws_no_runs(monkeypatch)
    c = _client(monkeypatch)
    r = c.get("/reports")
    assert r.status_code == 200
    assert r.json() is None
    # 같은 상태에서 형제 endpoint 들은 200 + 빈 목록(일관성).
    for path in ("/runs", "/metrics", "/accounts", "/catalog", "/cleanup-backlog"):
        rr = c.get(path)
        assert rr.status_code == 200, path
        assert rr.json() == [], path


@mock_aws
def test_report_by_run_id_still_404s(monkeypatch):
    """특정 run 을 지목한 조회는 여전히 404 — 그건 진짜 not-found 다(빈 상태와 구분)."""
    _seed_env(monkeypatch); _seed_aws_no_runs(monkeypatch)
    c = _client(monkeypatch)
    assert c.get("/reports/run-20260101T000000Z-abcdef12").status_code == 404


@mock_aws
def test_latest_artifacts_ignore_in_progress_run(monkeypatch):
    """진행 중 run 이 최신이어도 산출물 조회는 **직전 완료 run** 을 본다.

    POST /runs 가 status="running" 레코드를 즉시 넣으므로(진행 상태 관측용), '최신 run'을 단순히
    started_at 최댓값으로 잡으면 조회가 도는 수 분 동안 catalog·cleanup·accounts 가 비고
    /reports 가 사라진다 — 이전 완료 결과가 멀쩡히 있는데도.
    """
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    # run-001(succeeded) 보다 더 최신인 진행 중 run 을 삽입.
    boto3.resource("dynamodb", region_name="us-west-2").Table(RUNS_TABLE).put_item(
        Item={"run_id": "run-20261231T000000Z-99999999", "customer": CUSTOMER,
              "started_at": "2026-12-31T00:00:00Z", "account_scope": 1, "status": "running"})
    c = _client(monkeypatch)
    latest = c.get("/reports").json()
    assert latest is not None
    assert latest["run_id"] == "run-001"  # 진행 중 run 이 아니라 직전 완료 run
    assert len(c.get("/catalog").json()) == 1
    assert len(c.get("/cleanup-backlog").json()) == 1
    # 실행 이력에는 진행 중 run 이 그대로 보인다(관측 가능성은 유지).
    assert c.get("/runs").json()[0]["status"] == "running"


@mock_aws
def test_presigned_url_does_not_sign_expected_bucket_owner(monkeypatch):
    """리그레션: presigned URL 의 SignedHeaders 에 x-amz-expected-bucket-owner 가 들어가면 안 된다.

    들어가면 브라우저가 URL 을 열 때 그 헤더를 보낼 수 없어 S3 가 SignatureDoesNotMatch(403, XML)
    를 반환한다("This XML file..."). 리포트/IaC 다운로드가 전부 깨졌던 버그. EBO 를 서명 헤더로
    쓰지 않음을 URL 쿼리스트링으로 검증한다(LP2PS_EXPECTED_BUCKET_OWNER 가 설정돼 있어도).
    """
    from urllib.parse import parse_qs, urlparse

    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    # EBO 가 설정된 상태여야 회귀 의미가 있다(_seed_env 가 111122223333 설정).
    import os
    assert os.environ.get("LP2PS_EXPECTED_BUCKET_OWNER") == "111122223333"
    c = _client(monkeypatch)
    url = c.get("/reports/run-001").json()["report_html_url"]
    signed = parse_qs(urlparse(url).query).get("X-Amz-SignedHeaders", [""])[0]
    assert "x-amz-expected-bucket-owner" not in signed.lower(), (
        f"presigned URL 이 EBO 를 서명함(브라우저 접근 불가): SignedHeaders={signed!r}"
    )
    # IaC 다운로드 URL 도 동일하게 EBO 미서명.
    iac_url = c.get("/iac/run-001/download").json()["url"]
    iac_signed = parse_qs(urlparse(iac_url).query).get("X-Amz-SignedHeaders", [""])[0]
    assert "x-amz-expected-bucket-owner" not in iac_signed.lower()


@mock_aws
def test_report_per_account(monkeypatch):
    """account 지정 시 계정별 exec_summary + report-<account>.html 반환. 없으면 전체 폴백."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    from lp2ps.storage import S3Storage
    st = S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001")
    # 계정별 분해가 담긴 exec_summary + 계정별 리포트 html.
    st.write_json("exec_summary.json", {
        "accounts": 2, "principals": 10, "personas": 3, "unused_permission_principals": 5, "unused_permission_actions": 41,
        "generated_at": "2026-07-16T00:00:00Z",
        "by_account": [
            {"accounts": 1, "principals": 7, "personas": 2, "unused_permission_principals": 3, "unused_permission_actions": 25,
             "generated_at": "2026-07-16T00:00:00Z", "account_id": "111122223333"},
            {"accounts": 1, "principals": 3, "personas": 1, "unused_permission_principals": 2, "unused_permission_actions": 16,
             "generated_at": "2026-07-16T00:00:00Z", "account_id": "444455556666"},
        ],
    })
    st.write_text("report-111122223333.html", "<html>188</html>")
    c = _client(monkeypatch)
    r = c.get("/reports?account=111122223333").json()
    assert r["exec_summary"]["account_id"] == "111122223333"
    assert r["exec_summary"]["principals"] == 7
    assert "report-111122223333.html" in r["report_html_url"]
    # 계정별 html 없는 계정(575) → 전체 리포트로 폴백(report.html), 하지만 exec_summary 는 전체.
    r2 = c.get("/reports?account=444455556666").json()
    assert "report.html" in r2["report_html_url"]  # 575 html 없음 → 폴백
    # 잘못된 account 형식 → 400.
    assert c.get("/reports?account=bad").status_code == 400


@mock_aws
def test_cleanup_backward_compat_no_extra_columns(monkeypatch):
    """구버전 CSV(risk_score/risk_reasons 컬럼 없음)도 안전하게 로드(기본값 0/[])."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    from lp2ps.storage import S3Storage
    st = S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001")
    st.write_text("cleanup_backlog.csv",
                  "id,type,account_id,principal,risk_level,detail,recommendation\n"
                  "c1,no_mfa,111122223333,arn:u,medium,MFA 없음,MFA 강제\n")
    c = _client(monkeypatch)
    item = c.get("/cleanup-backlog").json()[0]
    assert item["risk_score"] == 0
    assert item["risk_reasons"] == []


@mock_aws
def test_risk_criteria(monkeypatch):
    """위험도 산정 기준 노출 — 레벨 경계 + 규칙별 가중치(config 유래)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps(
        {"risk_rules": {"level_critical": 75, "level_high": 50, "weight_escalation_path": 30}}))
    c = _client(monkeypatch)
    r = c.get("/cleanup-backlog/risk-criteria")
    assert r.status_code == 200
    body = r.json()
    assert body["level_critical"] == 75
    assert body["level_high"] == 50
    esc = next(x for x in body["rules"] if x["key"] == "escalation_path")
    assert esc["weight"] == 30


@mock_aws
def test_bad_run_id_rejected(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # path traversal 시도 → 400.
    assert c.get("/reports/..%2f..%2fetc").status_code in (400, 404)
    assert c.get("/reports/run-x'or'1").status_code == 400


@mock_aws
def test_assistant_ai_off(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    r = c.post("/assistant/ask", json={"question": "무엇이 위험한가?"})
    assert r.status_code == 200
    assert r.json()["grounded"] is False  # ai off


@mock_aws
def test_assistant_ai_on_grounded(monkeypatch):
    """ai.enabled=true 면 하네스 경유. bedrock invoke 를 모킹해 grounded 답변 반환 확인."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps(
        {"ai": {"enabled": True, "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"}}))
    # bedrock 호출을 grounded draft 로 스텁(라이브 Bedrock 없이 배선 검증).
    from lp2ps.ai import bedrock_client
    from lp2ps.ai.schemas import AssistantAnswerDraft
    monkeypatch.setattr(bedrock_client, "invoke_structured",
        lambda **kw: AssistantAnswerDraft(answer="DataPersona는 s3:GetObject를 사용합니다.",
                                          grounded=True, cited_actions=["s3:GetObject"]))
    c = _client(monkeypatch)
    r = c.post("/assistant/ask", json={"question": "DataPersona가 뭘 하나?"})
    assert r.status_code == 200
    body = r.json()
    assert body["grounded"] is True
    assert body["ai_suggested"] is True
    assert any(cit.get("action") == "s3:GetObject" for cit in body["citations"])


@mock_aws
def test_assistant_context_includes_cleanup_and_accounts(monkeypatch):
    """어시스턴트 grounding 컨텍스트에 조치항목·계정 집계가 들어가 계정별 질문에 답 가능."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps(
        {"ai": {"enabled": True, "model": "m"}}))
    # 계정 목록 노출을 위해 manifest 시드.
    from lp2ps.storage import S3Storage
    st = S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001")
    st.write_json("collection_manifest.json", {"accounts": [
        {"account_id": "444455556666", "sources": [{"source": "access_advisor", "status": "ok"}]}]})
    from lp2ps.ai import bedrock_client
    from lp2ps.ai.schemas import AssistantAnswerDraft
    captured = {}
    def _fake(**kw):
        captured["prompt"] = kw.get("prompt", "")
        return AssistantAnswerDraft(answer="575 계정에 조치 항목 1건", grounded=True,
                                    cited_principals=["444455556666"])
    monkeypatch.setattr(bedrock_client, "invoke_structured", _fake)
    c = _client(monkeypatch)
    r = c.post("/assistant/ask", json={"question": "575 계정 조치 항목 몇 개?"})
    assert r.status_code == 200
    # 프롬프트 컨텍스트에 계정별 조치항목 집계 + persona 계정 소속이 실렸는지.
    assert "444455556666" in captured["prompt"]
    assert "Action items" in captured["prompt"] or "조치" in captured["prompt"]
    assert "Persona count per account" in captured["prompt"]  # persona 계정별 수 집계
    # 계정 ID 인용이 grounding 통과(거부 안 됨).
    assert r.json()["grounded"] is True


def _seed_schedule_rule():
    """engine-stack 이 만드는 규칙을 moto 에 생성(disabled + 기본 cron)."""
    events = boto3.client("events", region_name="us-west-2")
    events.put_rule(Name="lp2ps-self-scan-schedule",
                    ScheduleExpression="cron(0 2 * * ? *)", State="DISABLED")
    return events


@mock_aws
def test_get_schedule_default_disabled(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_SCHEDULE_RULE_NAME", "lp2ps-self-scan-schedule")
    _seed_schedule_rule()
    c = _client(monkeypatch)
    r = c.get("/schedule")
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["cron"] == "0 2 * * ? *"


@mock_aws
def test_put_schedule_weekly_sets_cron_and_enables(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_SCHEDULE_RULE_NAME", "lp2ps-self-scan-schedule")
    events = _seed_schedule_rule()
    c = _client(monkeypatch)
    r = c.put("/schedule", json={"enabled": True, "frequency": "weekly", "hour_utc": 5, "day_of_week": 2})
    assert r.status_code == 200, r.text
    assert r.json()["cron"] == "0 5 ? * 2 *"
    # 실제 EventBridge 규칙에 반영됐는지.
    rule = events.describe_rule(Name="lp2ps-self-scan-schedule")
    assert rule["State"] == "ENABLED"
    assert rule["ScheduleExpression"] == "cron(0 5 ? * 2 *)"


@mock_aws
def test_put_schedule_custom_cron_validated(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_SCHEDULE_RULE_NAME", "lp2ps-self-scan-schedule")
    _seed_schedule_rule()
    c = _client(monkeypatch)
    # 잘못된 cron(필드 수 부족) → 422.
    bad = c.put("/schedule", json={"enabled": True, "frequency": "custom", "cron": "0 2 * *"})
    assert bad.status_code == 422
    # 올바른 6필드 → 200.
    ok = c.put("/schedule", json={"enabled": True, "frequency": "custom", "cron": "30 3 1 * ? *"})
    assert ok.status_code == 200
    assert ok.json()["cron"] == "30 3 1 * ? *"


@mock_aws
def test_put_schedule_no_rule_deployed(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_SCHEDULE_RULE_NAME", "")  # 규칙 미배포
    c = _client(monkeypatch)
    assert c.put("/schedule", json={"enabled": True, "frequency": "daily"}).status_code == 409


@mock_aws
def test_list_accounts_from_manifest(monkeypatch):
    """collection_manifest 에서 계정 목록·상태 노출, 관제 계정 표기."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_TOOLING_ACCOUNT", "111122223333")
    from lp2ps.storage import S3Storage
    st = S3Storage(f"s3://{BUCKET}", CUSTOMER, "run-001")
    st.write_json("collection_manifest.json", {
        "accounts": [
            {"account_id": "111122223333", "sources": [{"source": "access_advisor", "status": "ok"}]},
            {"account_id": "444455556666", "sources": [
                {"source": "access_advisor", "status": "ok"},
                {"source": "cloudtrail", "status": "degraded"}]},
        ],
    })
    c = _client(monkeypatch)
    r = c.get("/accounts")
    assert r.status_code == 200
    accts = {a["account_id"]: a for a in r.json()}
    assert accts["111122223333"]["is_tooling"] is True
    assert accts["111122223333"]["status"] == "ok"
    assert accts["444455556666"]["status"] == "degraded"  # 소스 중 하나라도 degraded


@mock_aws
def test_ai_settings_default_from_config(monkeypatch):
    """SSM 파라미터 없으면 config ai.enabled 로 폴백."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"ai": {"enabled": True}}))
    c = _client(monkeypatch)
    r = c.get("/settings/ai")
    assert r.status_code == 200
    assert r.json()["enabled"] is True  # SSM 없음 → config 폴백


@mock_aws
def test_ai_settings_put_then_get(monkeypatch):
    """PUT 으로 SSM 저장 → GET 이 SSM 값 반영(config 폴백보다 우선)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"ai": {"enabled": False}}))
    c = _client(monkeypatch)
    assert c.put("/settings/ai", json={"enabled": True}).json()["enabled"] is True
    # SSM 이 config(false) 를 덮어씀.
    assert c.get("/settings/ai").json()["enabled"] is True
    # 실제 SSM 파라미터에 기록됐는지.
    ssm = boto3.client("ssm", region_name="us-west-2")
    assert ssm.get_parameter(Name="/lp2ps/self/ai_enabled")["Parameter"]["Value"] == "true"


@mock_aws
def test_assistant_respects_ai_toggle_off(monkeypatch):
    """config 로 ai.enabled=true 여도 SSM 토글이 false 면 어시스턴트 비활성."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"ai": {"enabled": True}}))
    ssm = boto3.client("ssm", region_name="us-west-2")
    ssm.put_parameter(Name="/lp2ps/self/ai_enabled", Value="false", Type="String")
    c = _client(monkeypatch)
    body = c.post("/assistant/ask", json={"question": "무엇이 위험한가?"}).json()
    assert body["grounded"] is False
    assert "비활성" in body["answer"]


@mock_aws
def test_unauthenticated_401(monkeypatch):
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch, auth=False)  # LP2PS_AUTH_DISABLED=false
    # Authorization 헤더 없음 → 401.
    assert c.get("/runs").status_code == 401
    # 헬스체크는 인증 불필요.
    assert c.get("/health").status_code == 200


# ---- 보안 회귀 테스트 (보안 검토 지적사항 수정 검증) ----

@mock_aws
def test_sec015_lambda_env_denies_without_claims(monkeypatch):
    """/ADV-002: Lambda(프로덕션) 환경에서 authorizer 검증 claims 가 없으면 Bearer 헤더가
    있어도 401. (과거엔 Bearer 존재만으로 통과하는 fail-open 이 있었음.)"""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "lp2ps-api-fn")  # 프로덕션 환경 시뮬레이션
    c = _client(monkeypatch, auth=False)
    # Bearer 헤더가 있어도(서명 미검증) authorizer claims 가 없으므로 401 이어야 한다.
    r = c.get("/runs", headers={"Authorization": "Bearer forged.jwt.token"})
    assert r.status_code == 401


@mock_aws
def test_sec015_local_env_allows_bearer(monkeypatch):
    """대조군: 로컬(authorizer 없음) 환경에선 Bearer 헤더 존재로 통과(개발 편의) — Lambda 아님."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    c = _client(monkeypatch, auth=False)
    assert c.get("/runs", headers={"Authorization": "Bearer devtoken"}).status_code == 200


@mock_aws
def test_sec013_invalid_patch_body_422_and_no_save(monkeypatch):
    """잘못된 PATCH body → 422(500 아님) + DynamoDB override 미저장(검증 후 저장)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # actions 항목이 PolicyAction 스키마에 안 맞음(action 필드 없음) → 422.
    r = c.patch("/catalog/DataPersona", json={"actions": [{"bogus": "x"}]})
    assert r.status_code == 422
    # 알 수 없는 최상위 필드도 거부(extra=forbid).
    assert c.patch("/catalog/DataPersona", json={"unknown_field": 1}).status_code == 422
    # 검증 실패했으므로 catalog override 테이블에 아무것도 저장되지 않아야 한다.
    ddb = boto3.resource("dynamodb", region_name="us-west-2")
    items = ddb.Table("catalog").scan().get("Items", [])
    assert items == [], "검증 실패 입력이 부분 저장되면 안 된다"


@mock_aws
def test_sec002_edited_policy_saved_and_provision_reads_it(monkeypatch):
    """승인 시 편집된 policy_doc 가 저장되고, provision-ps 가 그 편집본을 읽어 생성한다."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    monkeypatch.setenv("LP2PS_CONFIG_INLINE", json.dumps({"provisioning": {"idc_region": "us-west-2"}}))
    c = _client(monkeypatch)
    # S3 합성 정책은 s3:GetObject. 승인 시 편집본(ec2:DescribeInstances)을 넘긴다.
    edited = json.dumps({"Version": "2012-10-17",
                         "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"}]})
    c.post("/catalog/DataPersona/approve", json={"policy_doc": edited})
    # get_policy_doc 은 편집본(override)을 우선 반환해야 한다(승인=집행 일치의 핵심).
    from lp2ps_api.routers import get_repos
    doc = get_repos().get_policy_doc("DataPersona")
    assert doc["Statement"][0]["Action"] == ["ec2:DescribeInstances"], "승인된 편집본이 저장돼야 함"
    # provision-ps 가 그 편집본을 읽어 PS 를 생성한다(성공 = 편집본 경로가 살아있음).
    r = c.post("/catalog/DataPersona/provision-ps")
    assert r.status_code == 200, r.text
    ps_arn = r.json()["permission_set_arn"]
    # moto IdC 에 주입된 inline policy 가 편집본(ec2:DescribeInstances)인지 직접 확인.
    sso = boto3.client("sso-admin", region_name="us-west-2")
    instance_arn = sorted(i["InstanceArn"] for i in sso.list_instances()["Instances"])[0]
    inline = sso.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=ps_arn)["InlinePolicy"]
    assert "ec2:DescribeInstances" in inline, "provision 이 승인된 편집본을 집행해야 함"


@mock_aws
def test_sec024_concurrent_patch_conflict_409(monkeypatch):
    """낙관적 락 — 같은 기대버전으로 두 번째 쓰기는 409(동시 수정 충돌)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    _client(monkeypatch)  # settings/repos 캐시 초기화
    from lp2ps_api.repositories import CatalogConflict, Repositories
    from lp2ps_api.deps import get_settings
    repos = Repositories(get_settings())
    # 첫 쓰기: version 0 → 1.
    v1 = repos.put_catalog_override("DataPersona", {"approval_status": "approved"}, expected_version=0)
    assert v1 == 1
    # 동시성 시뮬: 두 요청 모두 version 0 을 기대 → 두 번째는 충돌.
    with pytest.raises(CatalogConflict):
        repos.put_catalog_override("DataPersona", {"approval_status": "review"}, expected_version=0)


@mock_aws
def test_sec023_member_change_invalidates_approval(monkeypatch):
    """승인 후 persona 멤버셋이 바뀌면 승인 상속이 무효화되어 draft 로 강등."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    c.post("/catalog/DataPersona/approve", json={"policy_doc": ""})
    assert next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")["approval_status"] == "approved"
    # 새 run 의 catalog 에서 멤버셋이 달라진 상황을 시뮬(멤버 추가) → 승인 상속 무효.
    from lp2ps_api.routers import get_repos
    st = get_repos()._storage("run-001")
    st.write_json("catalog.json", [{"persona": "DataPersona", "description": "d",
                  "members": ["arn:aws:iam::444455556666:role/data", "arn:aws:iam::444455556666:role/NEW"],
                  "member_count": 2, "policy_ref": "policies/DataPersona.json"}])
    entry = next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")
    assert entry["approval_status"] == "draft", "멤버셋 변경 시 승인은 상속되면 안 된다"


@mock_aws
def test_sec001_cache_control_no_store(monkeypatch):
    """민감 응답에 Cache-Control: no-store."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.get("/catalog").headers.get("cache-control") == "no-store"
    assert c.get("/reports/run-001").headers.get("cache-control") == "no-store"


# ---- 2차 재스캔 회귀 테스트 (Round 2) ----

@mock_aws
def test_r2_sec001_malformed_policy_doc_422(monkeypatch):
    """R2-비어있지 않은 malformed policy_doc → 422(조용히 버리지 않음). 빈 문자열은 허용."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # 잘못된 JSON → 422.
    assert c.post("/catalog/DataPersona/approve", json={"policy_doc": "{not json"}).status_code == 422
    # 유효 JSON이지만 객체(dict)가 아님 → 422.
    assert c.post("/catalog/DataPersona/approve", json={"policy_doc": "[1,2,3]"}).status_code == 422
    # 빈 문자열(편집 안 함)은 정상 승인.
    assert c.post("/catalog/DataPersona/approve", json={"policy_doc": ""}).status_code == 200


@mock_aws
def test_r2_sec008_missing_member_hash_fail_closed(monkeypatch):
    """R2-member_hash 없는 레거시 approved override → 상속 안 하고 draft(fail-closed)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    # member_hash 없이 approved override 를 직접 심는다(레거시 상태 시뮬).
    from lp2ps_api.routers import get_repos
    get_repos().put_catalog_override("DataPersona", {"approval_status": "approved"})  # hash 없음
    entry = next(e for e in c.get("/catalog").json() if e["persona"] == "DataPersona")
    assert entry["approval_status"] == "draft", "member_hash 없으면 approved 상속 금지(fail-closed)"


@mock_aws
def test_r2_sec013_scan_caps_items(monkeypatch):
    """R2-_scan 은 항목 상한(_SCAN_MAX_ITEMS)까지만 반환(무제한 방지)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    _client(monkeypatch)
    from lp2ps_api.repositories import Repositories
    from lp2ps_api.deps import get_settings
    repos = Repositories(get_settings())
    # 상한을 작게 낮춰(테스트 속도) cap 동작만 검증.
    monkeypatch.setattr(Repositories, "_SCAN_MAX_ITEMS", 3, raising=False)
    monkeypatch.setattr(Repositories, "_SCAN_MAX_PAGES", 2, raising=False)
    import boto3
    t = boto3.resource("dynamodb", region_name="us-west-2").Table(RUNS_TABLE)
    for i in range(10):
        t.put_item(Item={"run_id": f"run-cap-{i:03d}", "customer": CUSTOMER,
                         "started_at": "2026-07-16T00:00:00Z", "account_scope": 1, "status": "succeeded"})
    got = repos._scan(RUNS_TABLE)
    assert len(got) <= 3, "scan 은 _SCAN_MAX_ITEMS 상한을 넘지 않아야 한다"


def test_r2_sec005_member_hash_full_digest():
    """R2-_member_hash 는 truncate 없이 전체 SHA-256(64 hex)."""
    from lp2ps_api.repositories import _member_hash
    import hashlib
    members = ["arn:aws:iam::111122223333:role/a", "arn:aws:iam::111122223333:role/b"]
    h = _member_hash(members)
    assert len(h) == 64  # 전체 digest(과거 16 truncate 아님)
    # 순서 무관(정렬 후 해시).
    assert _member_hash(list(reversed(members))) == h
    assert h == hashlib.sha256("\n".join(sorted(members)).encode()).hexdigest()


@mock_aws
def test_r2_sec012_sources_bad_run_id_400(monkeypatch):
    """R2-/runs/{run_id}/sources 에 잘못된 run_id → 400(형제 endpoint 일관)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.get("/runs/..%2F..%2Fetc/sources").status_code in (400, 404)
    assert c.get("/runs/not-a-valid-runid!/sources").status_code == 400
    # 정상 형식은 통과(manifest 없어도 200 빈 구조).
    assert c.get("/runs/run-20260101T000000Z-abcd1234/sources").status_code == 200


@mock_aws
def test_r2_sec006_question_length_422(monkeypatch):
    """R2-assistant question 길이 초과(>4000) 또는 빈 값 → 422."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    assert c.post("/assistant/ask", json={"question": "x" * 4001}).status_code == 422
    assert c.post("/assistant/ask", json={"question": ""}).status_code == 422


@mock_aws
def test_r2_sec007_schedule_bad_frequency_422(monkeypatch):
    """R2-schedule frequency 는 Literal — 잘못된 값 422(원값 에코 없음)."""
    _seed_env(monkeypatch); _seed_aws(monkeypatch)
    c = _client(monkeypatch)
    r = c.put("/schedule", json={"enabled": True, "frequency": "hourly"})  # 허용 목록 밖
    assert r.status_code == 422
    # 응답 본문에 원값("hourly")이 에코되지 않아야 한다(정보 노출 방지).
    assert "hourly" not in r.text


def test_audit_logger_level_allows_info_in_lambda_text_format():
    """`lp2ps.audit` 이 INFO 를 통과시켜야 한다 — 프로덕션 감사 가시성 회귀 가드.

    Lambda(Python) 는 로그 포맷이 Text 일 때 root 로거 레벨을 WARNING 으로 둔다 → 레벨을
    올리지 않으면 audit_event 의 INFO 라인이 CloudWatch 에 아예 나가지 않는다. 실측에서 배포된
    ApiFn 로그그룹 3개월치에 감사 라인이 **0건**이었다(인증 성공 요청이 있었는데도) — 감사 설비가
    코드상으로만 존재하고 프로덕션에선 비작동이었다. app.py 엔트리의 setLevel 이 제거되는 회귀를
    CI 에서 잡는다. 엔진 쪽 동일 가드는 engine/tests/test_session_audit.py 에 있다.
    """
    import logging

    import lp2ps_api.app  # noqa: F401 — import 시 엔트리포인트가 레벨을 설정한다

    assert logging.getLogger("lp2ps.audit").isEnabledFor(logging.INFO)
    assert logging.getLogger("lp2ps.api").isEnabledFor(logging.INFO)
