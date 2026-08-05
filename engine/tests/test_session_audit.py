"""Assume-role audit logging regression (security audit requirement).

Verifies that:
- Both the success and denial paths emit a structured audit event (`lp2ps.audit`, type=audit).
- The run_id correlation (correlation_id) and caller/target account context are included.
- On denial an operator can triage the cause (error_code + external_id_used + request_id).
- **No credentials appear in the logs** (AccessKeyId / SecretAccessKey / SessionToken).
- The denial exception is **re-raised unchanged** after the audit emit (behavior preserved).
- The `lp2ps.audit` logger level is set to INFO in code — this catches, in CI, the failure mode
  where the Lambda plain-text log format leaves root at WARNING and INFO never reaches
  CloudWatch.
"""

from __future__ import annotations

import json
import logging

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from moto import mock_aws

from lp2ps.config import Config
from lp2ps.session import resolve_sessions

# moto's default caller account (playing the tooling account). The target account must differ
# from it for the assume path to be exercised.
_CALLER = "123456789012"
_TARGET = "444455556666"


def _cross_config(external_id: str | None = None) -> Config:
    # Customer-agnostic (invariant 4): mock accounts only.
    raw = {
        "customer": "test",
        "region": "us-west-2",
        "cross_account": True,
        "accounts": [_TARGET],
        "readonly_role_name": "lp2ps-readonly",
    }
    if external_id:
        raw["external_id"] = external_id
    return Config.model_validate(raw)


def _audit_records(caplog: pytest.LogCaptureFixture) -> list[dict]:
    """Parse and return only the lp2ps.audit JSON lines from caplog."""
    out = []
    for rec in caplog.records:
        if rec.name != "lp2ps.audit":
            continue
        out.append(json.loads(rec.getMessage()))
    return out


# ---- success path ----
@mock_aws
def test_assume_role_success_emits_audit(caplog) -> None:
    """On success: exactly one audit event, with run_id and account context.

    `caplog.set_level` is deliberately not used. If the test forced the level up, it could no
    longer catch a missing production level setting (which means invisibility in CloudWatch).
    The assertions below only pass if `lp2ps.audit` carries INFO as its own level.
    """
    sessions = resolve_sessions(_cross_config(), run_id="run-fixed-1")

    assert [s.account_id for s in sessions] == [_TARGET]

    events = _audit_records(caplog)
    assert len(events) == 1, f"expected exactly one audit event: {events}"
    e = events[0]
    assert e["type"] == "audit"
    assert e["action"] == "assume_role"
    assert e["result"] == "success"
    assert e["resource"] == f"arn:aws:iam::{_TARGET}:role/lp2ps-readonly"
    assert e["correlation_id"] == "run-fixed-1"
    assert e["caller_account"] == _CALLER
    assert e["target_account"] == _TARGET
    assert e["external_id_used"] is False
    # Shape isomorphic with the backend audit (shared log aggregation filter).
    assert e["caller"] == {"sub": None, "email": None}
    assert e["principal_type"] == "role"


@mock_aws
def test_audit_never_logs_credentials(caplog) -> None:
    """No credentials in the audit line, or anywhere in captured output — a hard constraint."""
    resolve_sessions(_cross_config(), run_id="run-fixed-2")

    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    for forbidden in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Credentials"):
        assert forbidden not in blob, f"credential-related key leaked into the logs: {forbidden}"


@mock_aws
def test_external_id_flag_recorded_without_value(caplog) -> None:
    """For ExternalId record **whether it was used** only — never the value."""
    secret_external_id = "ext-id-must-not-appear"
    resolve_sessions(_cross_config(external_id=secret_external_id), run_id="run-fixed-3")

    events = _audit_records(caplog)
    assert events[0]["external_id_used"] is True
    blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert secret_external_id not in blob, "the ExternalId value leaked into the logs"


# ---- denial path ----
def _deny_sts(monkeypatch, code: str = "AccessDenied", request_id: str = "req-1234") -> None:
    """Make only AssumeRole fail with a ClientError; other STS calls pass through."""
    import botocore.client

    orig = botocore.client.BaseClient._make_api_call

    def _fake(self, operation_name, kwargs):  # noqa: ANN001
        if operation_name == "AssumeRole":
            raise ClientError(
                {
                    "Error": {"Code": code, "Message": "fake denial message (must not be logged)"},
                    "ResponseMetadata": {"RequestId": request_id},
                },
                operation_name,
            )
        return orig(self, operation_name, kwargs)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _fake)


@mock_aws
def test_assume_role_denied_emits_audit_and_reraises(caplog, monkeypatch) -> None:
    """On denial: emit the audit event, then re-raise unchanged (behavior preserved)."""
    _deny_sts(monkeypatch)

    with pytest.raises(ClientError):
        resolve_sessions(_cross_config(), run_id="run-fixed-4")

    events = _audit_records(caplog)
    assert len(events) == 1, f"expected exactly one audit event: {events}"
    e = events[0]
    assert e["result"] == "deny"
    assert e["action"] == "assume_role"
    # Record the error code: type(e).__name__ would collapse every AWS denial to "ClientError".
    assert e["error_code"] == "AccessDenied"
    assert e["error_code"] != "ClientError"
    # Correlation key for pivoting to the target account's CloudTrail.
    assert e["request_id"] == "req-1234"
    assert e["correlation_id"] == "run-fixed-4"
    assert e["caller_account"] == _CALLER
    assert e["target_account"] == _TARGET


@mock_aws
def test_denied_audit_omits_exception_message(caplog, monkeypatch) -> None:
    """Keep the exception **message** out of the audit line (account IDs / policy ARNs leak)."""
    _deny_sts(monkeypatch)

    with pytest.raises(ClientError):
        resolve_sessions(_cross_config(), run_id="run-fixed-5")

    audit_lines = "\n".join(
        rec.getMessage() for rec in caplog.records if rec.name == "lp2ps.audit"
    )
    assert "fake denial message" not in audit_lines


@mock_aws
def test_non_clienterror_failure_is_also_audited(caplog, monkeypatch) -> None:
    """Non-ClientError failures (network and similar) must not propagate unrecorded either.

    Catching only ClientError would let ParamValidationError / EndpointConnectionError /
    NoCredentialsError kill the run with no audit trail. We read the audit requirement's "proper error handling
    for STS AssumeRole failures" broadly and record every failure.
    """
    import botocore.client

    orig = botocore.client.BaseClient._make_api_call

    def _fake(self, operation_name, kwargs):  # noqa: ANN001
        if operation_name == "AssumeRole":
            raise EndpointConnectionError(endpoint_url="https://sts.us-west-2.amazonaws.com/")
        return orig(self, operation_name, kwargs)

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", _fake)

    with pytest.raises(EndpointConnectionError):
        resolve_sessions(_cross_config(), run_id="run-fixed-6")

    events = _audit_records(caplog)
    assert len(events) == 1
    # Not a ClientError, so the exception type name substitutes for an error code.
    assert events[0]["error_code"] == "EndpointConnectionError"
    assert events[0]["result"] == "deny"
    assert events[0]["request_id"] == ""


# ---- production visibility regression (log level) ----
def test_audit_logger_level_allows_info_in_lambda_text_format() -> None:
    """`lp2ps.audit` must carry INFO (or lower) as its own level.

    The Lambda Python runtime leaves the root logger at WARNING when the log format is plain
    text, so without this setting audit lines **never reach CloudWatch at all** (measured: in the
    deployed API log group the platform lines START/REPORT were present while application lines
    numbered zero, and authenticated requests over the same window matched the REPORT count 1:1).
    This assertion catches a regression that removes the setLevel call from the code. It checks
    the logger's **own** level so that it cannot pass by accidentally inheriting from root.
    """
    logger = logging.getLogger("lp2ps.audit")
    assert logger.level != logging.NOTSET, (
        "lp2ps.audit carries no level of its own — relying on root (WARNING by default under "
        "Lambda) means INFO audit lines are lost in production."
    )
    assert logger.level <= logging.INFO
    assert logger.isEnabledFor(logging.INFO)


def test_audit_event_is_best_effort(caplog) -> None:
    """An unserializable value must not raise out of the helper (protects the collection run)."""
    from lp2ps.audit import audit_event

    class Unserializable:
        def __repr__(self) -> str:  # pragma: no cover - defensive
            raise RuntimeError("repr failed")

    # Passing means no exception escaped (absorbed internally via logger.exception).
    audit_event(action="assume_role", resource="x", result="deny", weird=Unserializable())
