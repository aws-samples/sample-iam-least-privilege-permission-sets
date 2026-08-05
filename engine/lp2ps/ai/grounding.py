"""Grounding gate (anti-hallucination) — 하네스 보안 핵심.

호출 전: 프롬프트가 참조하는 principal/action 이 grounding 셋(수집·정규화 데이터)에 존재하는지 assert.
호출 후: AI 출력이 grounding 셋에 없는 IAM action/principal/사실을 지어냈으면 거부(verifier).

결정론 코어가 재사용할 수 있도록 순수 함수로 둔다(Bedrock 미호출). M2 는 검증 로직만; 실제 호출은 M6.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GroundingSet:
    """AI 가 참조해도 되는 사실의 화이트리스트(수집 데이터에서 구성)."""

    principals: set[str] = field(default_factory=set)
    actions: set[str] = field(default_factory=set)

    @classmethod
    def from_records(cls, records: list) -> "GroundingSet":  # noqa: ANN001
        principals: set[str] = set()
        actions: set[str] = set()
        for r in records:
            principals.add(r.principal)
            actions.update(r.granted_actions)
            actions.update(u.action for u in r.used_actions)
        return cls(principals=principals, actions=actions)


class HallucinationError(ValueError):
    """AI 출력이 grounding 셋 밖의 principal/action 을 만들어냈을 때."""


def assert_grounded_principals(refs: list[str], grounding: GroundingSet) -> None:
    """호출 전: 참조 principal 이 전부 grounding 셋에 있는지."""
    unknown = [p for p in refs if p not in grounding.principals]
    if unknown:
        raise HallucinationError(f"grounding 밖 principal 참조: {sorted(unknown)}")


def verify_output_actions(cited_actions: list[str], grounding: GroundingSet) -> list[str]:
    """호출 후: grounding 밖 action 을 골라낸다(빈 리스트면 통과). 호출부가 drop/flag 결정."""
    return sorted(a for a in cited_actions if a not in grounding.actions)


def is_output_grounded(cited_principals: list[str], cited_actions: list[str], grounding: GroundingSet) -> bool:
    """출력 전체가 grounding 셋 안에 있는지(참조 없음도 통과)."""
    if any(p not in grounding.principals for p in cited_principals):
        return False
    if any(a not in grounding.actions for a in cited_actions):
        return False
    return True
