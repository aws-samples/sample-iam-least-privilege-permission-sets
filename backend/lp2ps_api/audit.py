"""감사 로그 헬퍼 ( / /).

보안 관련 이벤트(인증, IdC write, 승인 상태전이, catalog 변경, 민감 데이터 접근, assistant 질의)를
구조화 JSON 한 줄로 `lp2ps.audit` 로거에 emit 한다. CloudWatch 로 흘러가 감사·탐지 근거가 된다.

원칙:
- **민감정보 미기록**: caller 는 claims 의 sub/email 만. 프롬프트 본문·정책 문서·자격증명은 남기지 않는다.
- 앱 로직에 영향 없음(로깅 실패해도 요청은 정상 처리 — best-effort).
- correlation_id 로 한 요청의 여러 이벤트를 묶을 수 있게 한다(호출자가 넘기면 사용).
"""

from __future__ import annotations

import json
import logging
from typing import Any

_logger = logging.getLogger("lp2ps.audit")


def _caller(claims: dict | None) -> dict:
    """claims 에서 감사에 남길 최소 식별자만 추출(sub/email). 없으면 anonymous."""
    if not claims:
        return {"sub": None, "email": None}
    return {"sub": claims.get("sub"), "email": claims.get("email")}


def audit_event(
    *,
    action: str,
    resource: str = "",
    result: str = "success",
    claims: dict | None = None,
    correlation_id: str | None = None,
    **extra: Any,
) -> None:
    """감사 이벤트 한 줄 emit. 실패해도 예외를 던지지 않는다(best-effort).

    action  — 예: "auth", "provision_ps", "approve_persona", "catalog_override", "presign",
              "assistant_ask", "assistant_blocked"(가드레일 차단), "assistant_incomplete"(응답 미완)
    resource— 대상 식별자(경로·persona·run_id 등, 민감정보 아님)
    result  — "success" | "allow" | "deny" | "failure" 등
    extra   — 추가 컨텍스트(민감정보 금지). 값은 JSON 직렬화 가능해야 한다.
    """
    try:
        record = {
            "type": "audit",
            "action": action,
            "resource": resource,
            "result": result,
            "caller": _caller(claims),
        }
        if correlation_id:
            record["correlation_id"] = correlation_id
        if extra:
            record.update(extra)
        _logger.info(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str))
    except Exception:  # noqa: BLE001 — 감사 로깅 실패가 요청을 깨뜨리면 안 됨
        _logger.exception("audit_event emit 실패 (action=%s)", action)
