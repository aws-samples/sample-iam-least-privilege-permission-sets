"""테스트 공통 설정.

moto 로 AWS 를 모킹할 때, 실제 ambient(SSO) 자격증명이 새어 들어오지 않도록 더미 자격증명을
강제한다. 이렇게 하지 않으면 allowlist 통과 오퍼레이션(예: ListRoles)이 실제 호출 단계에서
로컬 SSO 자격증명을 갱신하려다 실패할 수 있다.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _fake_aws_credentials():
    managed = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        # 이 변수가 있으면 botocore 가 정적 키를 "갱신 가능·만료됨"으로 보고 갱신을 시도한다.
        "AWS_CREDENTIAL_EXPIRATION",
    )
    saved = {k: os.environ.get(k) for k in managed}
    for k in managed:
        os.environ.pop(k, None)  # 로컬 SSO 자격증명·만료정보가 새어들지 않도록 전부 제거
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # pragma: allowlist secret
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-west-2"
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
