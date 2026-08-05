"""API 라우터 — 리소스별. 각 라우터는 repositories(read) + 도구 소유 write 만 사용."""

from __future__ import annotations

from functools import lru_cache

from ..deps import get_settings
from ..repositories import Repositories


@lru_cache
def get_repos() -> Repositories:
    """Repositories 싱글턴(Lambda 컨테이너 재사용)."""
    return Repositories(get_settings())
