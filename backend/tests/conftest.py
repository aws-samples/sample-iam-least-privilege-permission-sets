"""백엔드 테스트 공통 — 더미 AWS 자격증명 + moto 격리(엔진 conftest 와 동일 원칙)."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _fake_aws_credentials():
    managed = (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION",
        "AWS_CREDENTIAL_EXPIRATION",
    )
    saved = {k: os.environ.get(k) for k in managed}
    for k in managed:
        os.environ.pop(k, None)
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # pragma: allowlist secret
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-west-2"
    os.environ["AWS_REGION"] = "us-west-2"
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
