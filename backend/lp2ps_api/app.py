"""FastAPI 앱 진입 — Mangum 으로 Lambda 핸들러화.

리소스별 router 를 마운트한다. 모든 라우트는 require_auth 의존성으로 Cognito 인증을 강제한다
(2단 인증: API GW authorizer + in-process 재검증). 쓰기는 도구 소유 리소스(DynamoDB/S3/SFN)만.
"""

from __future__ import annotations

import logging
import os

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mangum import Mangum
from pydantic import ValidationError

from .auth import require_auth
from .routers import accounts, assistant, catalog, cleanup, iac, metrics, reports, runs, schedule, settings

# 감사·앱 로거 레벨을 엔트리포인트에서 명시한다.
#
# 왜 필요한가: Lambda(Python) 런타임은 로그 포맷이 Text 일 때 **root 로거 레벨을 WARNING** 으로
# 두므로, 레벨을 올리지 않으면 `audit_event` 의 INFO 라인이 CloudWatch 에 아예 나가지 않는다.
# 즉 감사 설비가 코드상으로만 존재하고 프로덕션에선 비작동이었다. 실측(배포된 ApiFn 로그그룹
# 전체 기간, 363 이벤트): 플랫폼 라인은 START 145 / REPORT 109 / INIT_START 36 으로 존재하는데
# 애플리케이션 라인은 audit·lp2ps·INFO·ERROR 전부 **0건**. 같은 기간 액세스 로그의 인증 성공
# non-OPTIONS 2xx 가 **109 건**으로 REPORT 수와 1:1 일치한다 → 핸들러는 매번 실행됐고
# `require_auth` 의 audit_event 도 매번 호출됐지만 로그로 나가지 않았다는 뜻이다.
#   - "When your function's log format is set to plain text, the default log-level setting for
#     Python runtimes is WARN ... use the Python logging setLevel() method"
#     https://docs.aws.amazon.com/lambda/latest/dg/python-logging.html
#   - Advanced Logging Controls 로 레벨을 제어하려면 JSON 로그 포맷 전환이 전제라 현 구조에선 선택지가 아니다.
#
# 왜 audit.py 모듈이 아니라 여기인가: 로깅 레벨 설정은 라이브러리 모듈이 아니라 **엔트리포인트**의
# 책임이다(import 부수효과로 전역 상태를 바꾸지 않는다). 엔진 쪽(`lp2ps/audit.py`)은 CLI·Lambda·
# 테스트 등 진입점이 여러 개라 모듈에 두었다 — 그 차이는 각 파일 주석에 적어 두었다.
#
# 왜 root 가 아닌가: RIC 은 root 에 핸들러를 붙이지만 **핸들러 자체에는 레벨을 설정하지 않는다**
# (handler level=NOTSET). 따라서 이 네임스페이스만 INFO 로 올려도 root 핸들러가 그대로 emit 한다.
# root 를 올리면 botocore 등 서드파티 INFO 노이즈가 함께 붙는다.
logging.getLogger("lp2ps").setLevel(logging.INFO)

app = FastAPI(title="LP2PS API", version="0.1.0")


# 검증 실패는 일반화된 422 로 응답한다(내부 스키마·경로·예외 텍스트 미노출).
# FastAPI 기본 RequestValidationError 응답은 입력값·필드경로를 그대로 담으므로 대체한다.
@app.exception_handler(RequestValidationError)
async def _on_request_validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "요청 형식이 올바르지 않습니다."})


@app.exception_handler(ValidationError)
async def _on_validation_error(_: Request, __: ValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "요청 형식이 올바르지 않습니다."})

# CORS: API GW Lambda proxy 통합은 응답 헤더를 그대로 통과시키므로, 실제 응답(GET 등)의
# Access-Control-Allow-Origin 을 여기서 붙여야 브라우저가 응답을 읽는다(preflight 는 API GW
# defaultCorsPreflightOptions 가 처리).
#
# 보안: 허용 origin 은 반드시 env(LP2PS_WEB_ORIGIN)로 실제 CloudFront 도메인만 지정한다.
# **fail-safe 기본값 = 아무 origin 도 허용 안 함(빈 목록)**. 과거처럼 미설정 시 `*` 로 열지 않는다
# (와일드카드 CORS 는 공개 리뷰 지적 대상). 배포 스크립트(build/deploy)가 SiteUrl 을 주입한다.
_origins = [o.strip() for o in os.environ.get("LP2PS_WEB_ORIGIN", "").split(",") if o.strip()]
if not _origins:
    # 미설정이면 로그로 경고하고 CORS 를 닫는다(브라우저 교차 origin 차단). API 자체는 동작하되
    # 다른 origin 의 웹에서 응답을 못 읽는다 → 운영자가 LP2PS_WEB_ORIGIN 을 반드시 설정하도록 유도.
    import logging

    logging.getLogger("lp2ps.api").warning(
        "LP2PS_WEB_ORIGIN 미설정 — CORS 를 닫습니다(교차 origin 차단). "
        "배포 시 실제 CloudFront 도메인으로 설정하세요."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,  # 빈 목록 = 교차 origin 불허(와일드카드 금지)
    # PUT 포함 — /settings/ai·/schedule 이 PUT 이다(누락 시 브라우저 preflight 차단으로 저장 실패).
    allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# 모든 API 응답은 민감·동적 데이터(IAM 메타데이터, presigned URL, 카탈로그 등)이므로
# 브라우저·중간 캐시에 저장하지 않는다. no-store 로 캐시 재사용/디스크 잔류를 막는다.
@app.middleware("http")
async def _no_store(request: Request, call_next):  # noqa: ANN001
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response

# 모든 라우터에 인증 의존성 적용.
_auth = [Depends(require_auth)]
app.include_router(runs.router, dependencies=_auth)
app.include_router(schedule.router, dependencies=_auth)
app.include_router(settings.router, dependencies=_auth)
app.include_router(accounts.router, dependencies=_auth)
app.include_router(metrics.router, dependencies=_auth)
app.include_router(catalog.router, dependencies=_auth)
app.include_router(cleanup.router, dependencies=_auth)
app.include_router(reports.router, dependencies=_auth)
app.include_router(assistant.router, dependencies=_auth)
app.include_router(iac.router, dependencies=_auth)


@app.get("/health")
def health() -> dict:
    """헬스체크. 주의: API GW Cognito authorizer 가 proxy 전역이라 배포 환경에선 이 경로도 인증
    필요(미인증 401). 무인증 헬스체크가 필요하면 api-stack 에서 /health 를 authorizer 예외로
    분리해야 한다(현재는 의도적으로 전역 인증 — 무인증 표면 최소화)."""
    return {"status": "ok"}


# Lambda 핸들러(API GW proxy).
handler = Mangum(app)
