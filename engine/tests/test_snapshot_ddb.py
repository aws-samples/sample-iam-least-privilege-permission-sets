"""snapshot._write_dynamodb 의 runs 테이블 쓰기 조건 — moto.

핵심 계약: API(POST /runs)가 시작 시점에 넣어둔 status="running" 레코드를 파이프라인 종료 상태로
갱신할 수 있어야 한다. 동시에 이미 종료된 run_id 를 다시 덮어쓰는 것은 계속 거부해야 한다
(멱등 위반 감지).
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from lp2ps.models import MetricsPoint, Run
from lp2ps.snapshot import _write_dynamodb

RUNS_TABLE = "runs"
METRICS_TABLE = "metrics"


def _create_tables():
    ddb = boto3.resource("dynamodb", region_name="us-west-2")
    ddb.create_table(
        TableName=RUNS_TABLE,
        KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=METRICS_TABLE,
        KeySchema=[
            {"AttributeName": "run_id", "KeyType": "HASH"},
            {"AttributeName": "ts", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "run_id", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return ddb


def _row(status: str) -> Run:
    return Run(
        run_id="run-1",
        customer="test",
        started_at="2026-07-15T00:00:00Z",
        account_scope=1,
        status=status,  # type: ignore[arg-type]
    )


def _point() -> MetricsPoint:
    return MetricsPoint(run_id="run-1", ts="2026-07-15T00:00:00Z")


def _env(monkeypatch, *, metrics: bool = True):
    monkeypatch.setenv("LP2PS_RUNS_TABLE", RUNS_TABLE)
    if metrics:
        monkeypatch.setenv("LP2PS_METRICS_TABLE", METRICS_TABLE)
    else:
        monkeypatch.delenv("LP2PS_METRICS_TABLE", raising=False)


@mock_aws
def test_writes_when_no_row_exists(monkeypatch):
    """CLI/로컬 트리거 — API 를 거치지 않아 레코드가 없는 경우."""
    ddb = _create_tables()
    _env(monkeypatch)
    _write_dynamodb(_row("succeeded"), _point())
    item = ddb.Table(RUNS_TABLE).get_item(Key={"run_id": "run-1"})["Item"]
    assert item["status"] == "succeeded"


@mock_aws
def test_updates_running_row_to_terminal(monkeypatch):
    """정상 API 흐름 — POST /runs 가 넣은 running 레코드를 종료 상태로 갱신."""
    ddb = _create_tables()
    ddb.Table(RUNS_TABLE).put_item(Item={"run_id": "run-1", "customer": "test",
                                         "started_at": "2026-07-15T00:00:00Z",
                                         "account_scope": 1, "status": "running"})
    _env(monkeypatch, metrics=False)
    _write_dynamodb(_row("degraded"), _point())
    item = ddb.Table(RUNS_TABLE).get_item(Key={"run_id": "run-1"})["Item"]
    assert item["status"] == "degraded"


@mock_aws
def test_does_not_overwrite_terminal_row(monkeypatch):
    """이미 종료된 run_id 재기록은 거부(덮어쓰지 않음) — 예외는 올리지 않고 완주."""
    ddb = _create_tables()
    ddb.Table(RUNS_TABLE).put_item(Item={"run_id": "run-1", "customer": "test",
                                         "started_at": "2026-07-15T00:00:00Z",
                                         "account_scope": 1, "status": "succeeded"})
    _env(monkeypatch, metrics=False)
    _write_dynamodb(_row("failed"), _point())  # 예외 없이 반환
    item = ddb.Table(RUNS_TABLE).get_item(Key={"run_id": "run-1"})["Item"]
    assert item["status"] == "succeeded"  # 원래 값 유지
