"""AI 입력 위생 —(숨은 유니코드 제거) 회귀.

_mask_pii/_strip_hidden_unicode 는 결정론 코어가 아니라 ai 패키지지만, 프롬프트 인젝션 방어라
회귀 테스트로 고정한다. Bedrock 호출 없이 순수 문자열 함수만 검증.
"""

from __future__ import annotations

from lp2ps.ai.bedrock_client import _mask_pii, _strip_hidden_unicode


def test_strip_hidden_unicode_removes_zero_width_bidi_tag():
    # zero-width space(200B), RLO(202E), tag char(E0041) 포함.
    s = "hello​world‮EVIL\U000e0041"
    assert _strip_hidden_unicode(s) == "helloworldEVIL"


def test_strip_hidden_unicode_preserves_normal_text():
    for s in ("list s3 buckets", "arn:aws:iam::111122223333:role/x", "한국어 질문", ""):
        assert _strip_hidden_unicode(s) == s


# 가짜 액세스키를 런타임에 조립한다(소스에 AKIA+16자 리터럴을 두지 않음 — 시크릿 스캐너 오탐 회피).
_FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
_ZWSP = "​"  # zero-width space


def test_mask_pii_defeats_zero_width_key_bypass():
    # 액세스키 사이에 제로폭 문자를 끼워 마스킹을 우회하려는 시도 → strip 후 마스킹됨.
    bypass = "AKIA" + _ZWSP + "ABCDEFGHIJKLMNOP"
    assert _mask_pii(bypass) == "[REDACTED_KEY]"


def test_mask_pii_still_masks_plain_key_and_keeps_arn():
    assert _mask_pii(f"key {_FAKE_KEY} here") == "key [REDACTED_KEY] here"
    # ARN 은 분석 대상이라 보존.
    assert _mask_pii("arn:aws:iam::111122223333:role/admin") == "arn:aws:iam::111122223333:role/admin"
