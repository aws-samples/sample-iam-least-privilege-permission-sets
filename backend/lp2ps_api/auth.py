"""인증 — Cognito JWT 검증 (defense in depth).

API GW Cognito authorizer 가 1차 게이트다. 여기선 in-process 로 토큰을 **재검증**한다(방어 심층화:
auth.py in-process 재검증). 로컬/테스트에선 LP2PS_AUTH_DISABLED=true 로 우회 가능.

의존성 최소화를 위해 Cognito JWKS 로 서명 검증하는 대신, API GW authorizer 통과를 신뢰하고
requestContext 의 claims 를 사용한다. authorizer 가 없는(로컬) 경우엔 Authorization 헤더 존재만 확인.
운영 강화(JWKS 서명 검증)는 필요 시 추가 — threat model 은 SECURITY.md "웹/API 보안" 참조.
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException, Request


def _auth_disabled() -> bool:
    """LP2PS_AUTH_DISABLED=true 는 로컬/테스트 전용 우회다.

    보안 가드: **Lambda(프로덕션) 환경에서는 이 우회를 무시한다.** AWS Lambda 는 항상
    `AWS_LAMBDA_FUNCTION_NAME` 을 주입하므로, 그 환경에서 auth-disabled 가 켜져 있으면
    (배포 실수로 env 가 새어들어도) 무시하고 정상 인증을 강제한다 — fail-closed.
    CDK/배포 코드는 이 변수를 절대 set 하지 않는다(테스트 코드에서만 사용).
    """
    if os.environ.get("LP2PS_AUTH_DISABLED", "").lower() != "true":
        return False
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        import logging

        logging.getLogger("lp2ps.api").warning(
            "LP2PS_AUTH_DISABLED=true 가 Lambda 환경에서 감지됨 — 무시하고 인증을 강제합니다."
        )
        return False
    return True


def _in_lambda() -> bool:
    """AWS Lambda(프로덕션) 실행 환경인지. Lambda 는 항상 이 env 를 주입한다."""
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


async def require_auth(request: Request, authorization: str | None = Header(default=None)) -> dict:
    """인증 통과 시 claims dict 반환, 아니면 401.

    - API GW + Cognito authorizer 뒤: requestContext.authorizer.claims 에 검증된 클레임.
    - LP2PS_AUTH_DISABLED=true: 완전 우회(로컬/테스트 전용 — Lambda 에선 무시).

    / ADV-002 (fail-open 제거): **Lambda(프로덕션) 환경에서는 authorizer 가 넣어준 검증
    클레임이 없으면 무조건 401** 이다. 과거엔 클레임이 없어도 Authorization 헤더에 'Bearer ' 가 있기만
    하면 통과시키는 fallback 이 있었는데(서명·만료 미검증), 이는 위조 토큰을 통과시키는 fail-open 이라
    제거했다. 헤더-only 통과는 authorizer 가 없는 **로컬 개발** 환경에서만 허용한다.
    """
    from .audit import audit_event

    if _auth_disabled():
        return {"sub": "test", "email": "test@local"}

    # API GW authorizer 가 넣어준 검증된 클레임(Mangum 이 scope 에 매핑).
    claims = _claims_from_request(request)
    if claims:
        audit_event(action="auth", resource=request.url.path, result="allow", claims=claims)
        return claims

    # 여기부터는 authorizer 검증 클레임이 없는 경우.
    # 프로덕션(Lambda): authorizer 가 반드시 클레임을 넣어야 하므로, 없으면 인증 실패(fail-closed).
    if _in_lambda():
        audit_event(action="auth", resource=request.url.path, result="deny")
        raise HTTPException(status_code=401, detail="인증 필요")

    # 로컬(authorizer 없음): 개발 편의로 Bearer 토큰 존재만 확인.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="인증 필요")
    return {"sub": "bearer", "has_bearer": True}


def _claims_from_request(request: Request) -> dict | None:
    """Mangum 이 전달한 API GW requestContext 에서 authorizer claims 추출."""
    aws_event = request.scope.get("aws.event") or {}
    rc = aws_event.get("requestContext") or {}
    authorizer = rc.get("authorizer") or {}
    claims = authorizer.get("claims") or authorizer.get("jwt", {}).get("claims")
    return claims or None
