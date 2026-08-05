"""AI 하네스 (`lp2ps.ai`) — 순수 가산 계층 (불변식 ③).

**결정론 코어(m1~m7·snapshot)는 이 패키지를 절대 import 하지 않는다.** AI 출력은 모두
`ai_suggested=true` 네임스페이스로 분리되며, `ai.enabled=false` 면 도구는 이 패키지 없이 완전 동작한다.

M2 는 계약·게이트 골격만 둔다(실제 Bedrock 호출은 M6). 골격이라도 하네스 원칙을 강제한다:
- structured output(pydantic 스키마 검증)
- grounding gate(호출 전 컨텍스트 assert + 호출 후 anti-hallucination verify)
- human-in-the-loop(ai_suggested 라벨, 사람 승인 없이 approved 전이 불가)
- hard separation(결정 경로는 Bedrock 미호출)
"""

from __future__ import annotations

__all__ = ["is_enabled"]


def is_enabled(cfg) -> bool:  # noqa: ANN001
    """config.ai.enabled 게이트. False 면 코어는 AI 하네스를 전혀 타지 않는다."""
    return bool(getattr(getattr(cfg, "ai", None), "enabled", False))
