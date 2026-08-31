"""API 설정·의존성 — 환경변수에서 리소스 이름 로드.

CDK api 스택이 아래 env 를 Lambda 에 주입한다. 도구 소유 리소스만 참조(멤버계정 무관).
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

from pydantic import BaseModel

# run_id 검증(path traversal 방지). SFN/CLI 가 만드는 형식만 허용.
RUN_ID_RE = re.compile(r"^run-[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# persona 도 경로/키에 쓰이므로 영숫자만.
PERSONA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


class Settings(BaseModel):
    customer: str
    data_bucket: str
    runs_table: str
    metrics_table: str
    catalog_table: str
    # cleanup 항목의 조치 상태(미조치/조치완료/보류)를 보관. 비어 있으면 상태 기능이 읽기 전용으로
    # 퇴화한다(전부 미조치로 보임) — 배포에서 env 를 안 주면 조용히 그렇게 되므로 api-stack 이 항상 준다.
    findings_table: str
    state_machine_arn: str
    schedule_rule_name: str
    region: str
    # 버킷 소유 계정(버킷명과 다른 소스에서 주입). presign 등에 ExpectedBucketOwner 로 사용.
    expected_bucket_owner: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings(
        customer=os.environ.get("LP2PS_CUSTOMER", "self"),
        data_bucket=os.environ.get("LP2PS_DATA_BUCKET", ""),
        runs_table=os.environ.get("LP2PS_RUNS_TABLE", ""),
        metrics_table=os.environ.get("LP2PS_METRICS_TABLE", ""),
        catalog_table=os.environ.get("LP2PS_CATALOG_TABLE", ""),
        findings_table=os.environ.get("LP2PS_FINDINGS_TABLE", ""),
        state_machine_arn=os.environ.get("LP2PS_STATE_MACHINE_ARN", ""),
        schedule_rule_name=os.environ.get("LP2PS_SCHEDULE_RULE_NAME", ""),
        region=os.environ.get("AWS_REGION", "us-west-2"),
        expected_bucket_owner=os.environ.get("LP2PS_EXPECTED_BUCKET_OWNER", ""),
    )


def valid_run_id(run_id: str) -> bool:
    return bool(RUN_ID_RE.match(run_id))


def valid_persona(persona: str) -> bool:
    return bool(PERSONA_RE.match(persona))
