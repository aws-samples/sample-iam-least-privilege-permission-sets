"""고객 config(`LP2PS_CONFIG_INLINE`) 조회 — 여러 라우터가 공유하는 단일 진입점.

CDK 가 `JSON.stringify(config/<customer>.yaml)` 를 Lambda env 로 넣어준다(불변식 ④: 고객별 값은
코드가 아니라 config 에만). 라우터마다 파싱 헬퍼를 두면 기본값이 조용히 어긋나므로 여기 모은다.
"""

from __future__ import annotations

import json
import os


def config_inline() -> dict:
    """CDK 가 Lambda 에 넣어주는 고객 config(JSON). 없거나 깨졌으면 빈 dict.

    캐시하지 않는다 — 테스트가 env 를 바꿔가며 검증한다. 파싱 실패 시 예외를 올리지 않는다:
    config 한 줄 때문에 조회 전체가 500 이 되면 안 되고, 각 호출자가 기본값을 갖는다.
    """
    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if not inline:
        return {}
    try:
        parsed = json.loads(inline)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def uses_identity_center() -> bool:
    """이 고객이 IAM Identity Center 를 쓰는가(config `provisioning.uses_identity_center`).

    기본 True — 기존 배포의 동작을 바꾸지 않는다. false 면:
      - 산출물에서 Permission Set 을 뺀다(IdC 인스턴스가 없어 apply 불가) — routers/catalog.py
      - 대시보드의 PS 마이그레이션 지표를 '해당 없음' 으로 표시한다 — GET /settings/deployment

    데이터로 추론하지 않는 이유는 engine/lp2ps/config.py 에 있다(IdC 도입 직후 고객 오판).
    """
    v = config_inline().get("provisioning", {}).get("uses_identity_center")
    return True if v is None else bool(v)
