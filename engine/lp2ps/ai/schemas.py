"""AI 하네스 structured output 스키마 (pydantic).

Bedrock 호출은 자유 텍스트가 아니라 이 스키마로 검증된 JSON만 반환한다. 결정에 쓰는 자유 텍스트 없음.
모든 필드는 `ai_suggested` 네임스페이스(순수 가산, 불변식 ③).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PersonaNaming(BaseModel):
    """persona 명명/설명 제안(AI). 결정론 persona 를 대체하지 않고 라벨만 제안."""

    persona_key: str  # 대상 결정론 persona (fingerprint 기반 키)
    suggested_name: str
    suggested_description: str
    ai_suggested: bool = True


class ReportNarrative(BaseModel):
    """exec summary 서술(AI). 수치는 결정론 데이터에서 오고, 서술만 생성."""

    headline: str
    narrative: str
    ai_suggested: bool = True


class AssistantAnswerDraft(BaseModel):
    """리뷰어 Q&A 초안(AI). grounding 통과 여부와 인용 포함."""

    answer: str
    grounded: bool
    cited_principals: list[str] = Field(default_factory=list)
    cited_actions: list[str] = Field(default_factory=list)
    ai_suggested: bool = True
