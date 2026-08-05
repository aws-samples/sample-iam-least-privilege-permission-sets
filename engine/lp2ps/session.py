"""세션 진입점 — 자격증명 획득(ambient) + 교차계정 assume-role fan-out.

- cross_account=false: `sts:AssumeRole` 없이 ambient(SSO/role) 자격증명. 대상 = 현재 호출자 계정.
- cross_account=true: 각 멤버 계정의 `readonly_role_name` 을 assume 해 세션 생성.
분석 로직·산출물은 두 경우 동일 — 자격증명 획득 방식만 다르다.

두 경우 모두 반환하는 대상 계정 클라이언트에는 **읽기 전용 가드가 반드시 붙는다**(`guarded_client`).
tooling 계정 IdC 쓰기(provisioning)는 이 모듈이 아니라 별도 경로에서 unguarded 로 처리한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

import boto3

from .audit import audit_event
from .awsguard import guarded_client

if TYPE_CHECKING:  # pragma: no cover
    from boto3.session import Session
    from botocore.client import BaseClient

    from .config import Config

# assume-role 세션에 첨부하는 inline 최소권한 정책(수집에 필요한 read-only 액션만).
# 세션 정책은 role 권한과의 **교집합**으로 동작하므로, 멤버 role 이 넓어도 이 세션에선 조회만 가능하다.
# awsguard 의 allowlist(before-call 훅)와 이중 방어: 훅은 클라이언트단, 이 정책은 IAM 단.
_READONLY_SESSION_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Lp2psReadOnlyCollect",
                "Effect": "Allow",
                "Action": [
                    "iam:Get*", "iam:List*", "iam:GenerateServiceLastAccessedDetails",
                    "iam:GenerateCredentialReport", "iam:SimulatePrincipalPolicy",
                    "access-analyzer:Get*", "access-analyzer:List*",
                    "cloudtrail:LookupEvents",
                    "sso:List*", "sso:Describe*",
                    "sts:GetCallerIdentity",
                ],
                "Resource": "*",
            }
        ],
    },
    separators=(",", ":"),
)


@dataclass
class AccountSession:
    """대상 계정 하나에 대한 세션 래퍼. 클라이언트는 항상 가드가 붙어 나온다."""

    account_id: str
    region: str
    session: "Session"

    def client(self, service_name: str, region: str | None = None, **kwargs) -> "BaseClient":
        # region 미지정 시 계정 세션 기본 리전. IdC 등 다른 리전 서비스는 region 로 오버라이드.
        return guarded_client(self.session, service_name, region_name=region or self.region, **kwargs)


def _caller_account_id(session: "Session", region: str) -> str:
    # sts:GetCallerIdentity 는 조회이므로 가드 통과. 단순화를 위해 여기선 raw 클라이언트.
    return session.client("sts", region_name=region).get_caller_identity()["Account"]


def _error_code(exc: Exception) -> str:
    """botocore ClientError 면 AWS error code, 아니면 예외 타입명.

    `type(exc).__name__` 만 쓰면 AWS 거부가 사실상 전부 "ClientError" 한 값이 되어
    AccessDenied/ExpiredToken 등을 운영자가 구분할 수 없다(finding 의 핵심 요구).
    error code 자체는 AWS 고정 문자열 집합이라 민감정보가 아니다.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
        if code:
            return str(code)
    return type(exc).__name__


def _request_id(exc: Exception) -> str:
    """AWS request id(있으면). 대상 계정 CloudTrail 로 피벗하기 위한 상관관계 키."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        rid = (response.get("ResponseMetadata") or {}).get("RequestId")
        if rid:
            return str(rid)
    return ""


def resolve_sessions(
    config: "Config",
    base_session: "Session | None" = None,
    *,
    run_id: str | None = None,
) -> list[AccountSession]:
    """config 에 따라 대상 계정 세션 목록을 만든다.

    cross_account=false → ambient 자격증명으로 단일 세션(현재 계정 자신).
    cross_account=true  → 각 계정에 readonly_role 을 assume.

    run_id 는 감사 이벤트의 correlation_id 로만 쓰인다(감사 요건). 프로덕션 경로
    (`m1_collector.collect`)는 반드시 채워 넘기고, 테스트/직접 호출은 생략할 수 있다.
    **keyword-only** 인 이유: 2번째 위치 인자는 이미 `base_session` 이므로 위치 인자로
    받으면 오사용(config 를 session 자리에 넣는 등)이 조용히 통과한다.
    """
    session = base_session or boto3.Session()

    if not config.cross_account:
        account_id = _caller_account_id(session, config.region)
        return [AccountSession(account_id=account_id, region=config.region, session=session)]

    # 관제 계정(호출자 자신)이 accounts 에 포함될 수 있다 — 자기 계정은 assume 하지 않고 ambient
    # 자격증명을 그대로 쓴다(자기 계정 role 을 자기 엔진 role 로 assume 하는 건 불필요·불가). 멤버
    # 계정만 readonly_role 을 assume. 이렇게 관제 계정도 '전체' 범위에 포함된다.
    caller_account = _caller_account_id(session, config.region)
    sessions: list[AccountSession] = []
    sts = session.client("sts", region_name=config.region)
    for account_id in config.accounts:
        if account_id == caller_account:
            # 관제 계정 자신 — ambient 세션(assume 없음).
            sessions.append(AccountSession(account_id=account_id, region=config.region, session=session))
            continue
        if not config.readonly_role_name:
            raise ValueError("cross_account 모드에는 readonly_role_name 이 필요합니다(멤버 계정 assume).")
        role_arn = f"arn:aws:iam::{account_id}:role/{config.readonly_role_name}"
        # assume 세션에 **inline read-only 세션 정책**을 붙여 권한을 수집 액션으로 좁힌다
        # (역할 자체가 넓어도 이 세션에서는 조회만 가능 — 방어 심화). ExternalId 설정 시 함께 전달해
        # confused-deputy 를 방어한다(멤버 role trust 의 sts:ExternalId 조건과 일치해야 assume 성공).
        assume_kwargs: dict = {
            "RoleArn": role_arn,
            "RoleSessionName": "lp2ps-collect",
            "Policy": _READONLY_SESSION_POLICY,
        }
        if config.external_id:
            assume_kwargs["ExternalId"] = config.external_id
        # 감사 요건: role assumption 은 명시적 보안 이벤트다 → 성공·실패 양쪽을 구조화 감사
        # 이벤트로 남긴다(run_id 상관관계 + 호출자/대상 컨텍스트). 실패는 **로깅 후 그대로
        # 전파**한다 — 감사는 부수효과이고, 예외 거동은 기존과 동일하게 유지해야 한다
        # (m1_collector 는 이 예외를 `_run_one` 포획 밖에서 받아 run 을 실패시킨다).
        #
        # ClientError 만 잡으면 ParamValidationError·EndpointConnectionError·
        # NoCredentialsError 등이 무기록으로 전파되므로 광범위 포획한다.
        try:
            creds = sts.assume_role(**assume_kwargs)["Credentials"]
        except Exception as e:  # noqa: BLE001 — 모든 assume 실패를 기록 후 재전파
            audit_event(
                action="assume_role",
                resource=role_arn,
                result="deny",
                correlation_id=run_id,
                caller_account=caller_account,
                target_account=account_id,
                # error code(AWS 고정 문자열)만 남긴다 — 예외 메시지·traceback 은 계정ID·정책
                # ARN 등이 섞일 수 있어 감사 라인에 넣지 않는다. ClientError 가 아니면(파라미터·
                # 네트워크·자격증명 오류) 타입명으로 대체한다.
                error_code=_error_code(e),
                # ExternalId **값은 절대 남기지 않고** 사용 여부만 남긴다. AccessDenied 1차 분류에
                # 필요하다(조건 누락 vs 값 불일치). 정확한 원인은 아래 request_id 로 대상 계정
                # CloudTrail 에서 확인한다.
                external_id_used=bool(config.external_id),
                # STS request id — 대상 계정 CloudTrail 이벤트로 정확히 피벗하는 포인터.
                # CloudTrail 이 authoritative source 이므로 in-app 로그는 그쪽 링크 역할을 한다.
                request_id=_request_id(e),
            )
            raise
        audit_event(
            action="assume_role",
            resource=role_arn,
            result="success",
            correlation_id=run_id,
            caller_account=caller_account,
            target_account=account_id,
            external_id_used=bool(config.external_id),
        )
        assumed = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        sessions.append(AccountSession(account_id=account_id, region=config.region, session=assumed))
    return sessions
