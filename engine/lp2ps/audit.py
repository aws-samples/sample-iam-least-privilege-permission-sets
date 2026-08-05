"""Audit logging helper (engine side) — security audit requirement.

Emits security-relevant engine events, such as cross-account role assumption, as a single
structured JSON line on the `lp2ps.audit` logger. These flow to CloudWatch (the EngineFn log
group) and serve as audit and detection evidence.

This module deliberately mirrors `backend/lp2ps_api/audit.py`: **same logger name, same JSON
keys**, so a single log aggregation filter (Logs Insights or a metric filter) covers both the
API and the engine. The reason it is a separate module rather than a shared import is the
deployment split: the engine Lambda asset (`infra/assets/engine-code`) contains only `lp2ps`,
while `lp2ps_api` ships only in the API asset (`infra/scripts/build-engine-assets.sh`), so
importing the backend module would fail at engine runtime. Keep the two shapes in sync when
editing either file.

Principles:
- **Never log secrets.** Credentials (AccessKeyId / SecretAccessKey / SessionToken) must not
  appear in any form. What is recorded: caller account, target account, role ARN, result,
  error code, and the AWS request id.
- **Best effort.** A failure to emit an audit line must never break a collection run, so no
  exception escapes this module.
- **Irrelevant to invariant 2 (determinism).** Logs are not artifacts; nothing here affects
  output bytes.
- **Invariant 3 (AI boundary).** Only stdlib imports (json, logging).
"""

from __future__ import annotations

import json
import logging
from typing import Any

_logger = logging.getLogger("lp2ps.audit")

# The Lambda Python runtime sets the **root logger level to WARNING when the log format is
# plain text**, so without raising a level explicitly, INFO audit lines never reach CloudWatch
# at all. This was measured, not assumed: in the deployed API log group the platform lines
# (START / REPORT) were present while application lines numbered zero, and over the same window
# the count of authenticated requests matched the REPORT count exactly 1:1 — the calls happened
# and only the logs were lost.
#   - AWS docs: "When your function's log format is set to plain text, the default log-level
#     setting for Python runtimes is WARN ... use the Python logging setLevel() method"
#     https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html
#   - Controlling the level via Advanced Logging Controls presupposes switching to JSON log
#     format, so it is not an option for the current structure.
#
# **Set on this namespace, not on root.** The runtime interface client
# (`awslambdaric/bootstrap.py::_setup_logging`) attaches a handler to root but never sets a
# level on that **handler** (handler level = NOTSET = 0). So once a child logger admits an INFO
# record, the root handler emits it — the root logger's own level does not participate
# (`logger.isEnabledFor` decides via the child's effective level, and a propagated record is
# re-checked only against handler levels). Raising root would additionally pull in third-party
# INFO noise from botocore and friends, so we do not.
# A regression that removes this setting is caught in CI by `engine/tests/test_session_audit.py`.
#
# Scope note: this raises `lp2ps.audit` **only** (the backend raises the whole `lp2ps`
# namespace from its entrypoint). The engine's `lp2ps.engine` logger currently uses only
# `.exception()` (ERROR), which is visible under the default root WARNING, but adding INFO
# logging to the engine would make those lines **silently disappear** — at that point widen
# this to `logging.getLogger("lp2ps")` (that stays free of botocore noise, being lp2ps-only).
_logger.setLevel(logging.INFO)


def audit_event(
    *,
    action: str,
    resource: str = "",
    result: str = "success",
    correlation_id: str | None = None,
    **extra: Any,
) -> None:
    """Emit one audit event. Never raises (best effort).

    Same JSON shape as the backend `audit_event`:
        {"type": "audit", "action", "resource", "result", "caller", ["correlation_id"], ...extra}

    action         -- e.g. "assume_role"
    resource       -- target identifier (role ARN or similar; nothing sensitive)
    result         -- "success" | "deny" | "failure"
    correlation_id -- run_id (the correlation key on the engine path)
    extra          -- additional context (never sensitive). Must be JSON-serializable.

    On `caller`: in the engine the acting principal is a role, not a person, so there are no
    claims. To keep the shape isomorphic with the backend we leave sub/email as None and express
    the real principal via `principal_type="role"` plus `caller_account` in extra, so that Logs
    Insights queries do not have to diverge between the two sources.
    """
    try:
        record: dict[str, Any] = {
            "type": "audit",
            "action": action,
            "resource": resource,
            "result": result,
            "caller": {"sub": None, "email": None},
            "principal_type": "role",
        }
        if correlation_id:
            record["correlation_id"] = correlation_id
        if extra:
            record.update(extra)
        _logger.info(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str))
    except Exception:  # noqa: BLE001 — an audit logging failure must not break a collection run
        _logger.exception("failed to emit audit_event (action=%s)", action)
