"""타임스탬프 비교 유틸 (결정론 코어 공용).

소스마다 포맷이 다르다(예: Access Advisor 'YYYY-MM-DDTHH:MM:SSZ', 공백 구분 'YYYY-MM-DD HH:MM:SS.mmm').
문자열 lexical 비교는 구분자(' ' 0x20 vs 'T' 0x54) 때문에 틀리므로 datetime 으로 파싱해 비교하고,
반환은 원본 문자열(표현 보존·결정론)로 한다.
"""

from __future__ import annotations

from datetime import datetime, timezone


def parse_ts(value: str | None) -> datetime | None:
    """다양한 소스 포맷의 타임스탬프 문자열 → aware datetime(실패 시 None)."""
    if not value:
        return None
    v = str(value).strip().replace("Z", "+00:00")
    # 공백 구분 포맷 → ISO 의 'T' 로 정규화(첫 공백만).
    if " " in v and "T" not in v:
        v = v.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def max_ts(a: str | None, b: str | None) -> str | None:
    """두 타임스탬프 중 더 최근 것(원본 문자열 반환). 파싱 불가하면 lexical 폴백."""
    candidates = [x for x in (a, b) if x]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    def _key(s: str):
        dt = parse_ts(s)
        # 파싱 성공분 우선(True>False), 그 안에서 시각 비교, 실패분은 lexical.
        return (dt is not None, dt if dt is not None else datetime.min.replace(tzinfo=timezone.utc), s)

    return max(candidates, key=_key)
