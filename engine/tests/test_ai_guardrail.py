"""Guardrail wiring and terminal-stop handling in the Bedrock harness.

Two behaviours are locked here, both of which fail silently if they regress:

1. **Trust-boundary scoping.** Externally-sourced text must travel inside `guardContent` blocks and
   our own instructions must stay outside them. This is not stylistic: the prompt attack filter
   only inspects guarded content ("If there are no tags, prompt attacks for those use cases will
   not be filtered"), so a guardrail attached without a guarded segment buys no prompt-attack
   filtering at all -- while still appearing correctly configured in CloudFormation and in the
   console. Conversely, sweeping our own instructions into guardContent invites the false positive
   the docs call out, since a developer instruction and an override attempt look alike.

2. **Terminal stop reasons short-circuit before schema validation.** On a guardrail block the
   response body is the configured blockedInputMessaging rather than JSON, so validating first
   reports a schema failure after three billed attempts and loses the fact that a block happened.

The fake client records requests instead of calling Bedrock; moto has no Converse support and this
must assert on the exact request shape anyway.
"""
from __future__ import annotations

import pytest

from lp2ps.ai.bedrock_client import (
    TerminalStopReason,
    _build_content,
    _guardrail_config,
    _summarize_guardrail_trace,
    invoke_structured,
)
from lp2ps.ai.grounding import GroundingSet
from lp2ps.ai.schemas import AssistantAnswerDraft

GUARDED_DATA = "Persona catalog:\n- persona DataReadOnlyPersona (accounts: 111122223333): s3:GetObject"
GUARDED_QUERY = "Which personas can read S3?"
INSTRUCTION = "Accounts analyzed:\n- 111122223333\n\nAnswer using ONLY the grounding data."


class _FakeClient:
    """Records converse() kwargs and replays canned responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def _ok_response(payload='{"answer":"ok","grounded":true}'):
    return {"stopReason": "end_turn", "output": {"message": {"content": [{"text": payload}]}}}


def _invoke(monkeypatch, client, **overrides):
    """Run invoke_structured against the fake client."""
    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)
    kwargs = {
        "model_id": "test-model",
        "system": "You label and summarize pre-computed IAM analysis.",
        "prompt": INSTRUCTION,
        "schema": AssistantAnswerDraft,
        "grounding": GroundingSet(principals={"111122223333"}, actions={"s3:GetObject"}),
        "guarded_data": GUARDED_DATA,
        "guarded_query": GUARDED_QUERY,
    }
    kwargs.update(overrides)
    return invoke_structured(**kwargs)


# ---- trust boundary ----

def test_untrusted_text_is_inside_guardcontent_and_instructions_are_not(monkeypatch):
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client)

    content = client.calls[0]["messages"][0]["content"]
    guarded = [b["guardContent"]["text"]["text"] for b in content if "guardContent" in b]
    plain = [b["text"] for b in content if "text" in b]

    # Collected IAM metadata and the operator question are guarded, as separate blocks so the trace
    # can attribute a block to one or the other.
    assert guarded == [GUARDED_DATA, GUARDED_QUERY], (
        "externally-sourced text must be inside guardContent, as two attributable blocks"
    )
    # Our instructions are not guarded -- evaluating them for prompt attack is the documented FP.
    assert plain == [INSTRUCTION]
    assert all(INSTRUCTION not in g for g in guarded)


def test_system_prompt_is_never_guarded(monkeypatch):
    """The guardrail does not assess the system prompt unless it carries a guardContent field."""
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client)
    for block in client.calls[0]["system"]:
        assert "guardContent" not in block


def test_question_is_not_interpolated_into_instruction_text(monkeypatch):
    """The question must arrive as a guarded block, never spliced into unguarded instructions.

    Interpolating it (the old ASSISTANT_QA.format(question=...) shape) puts attacker-controlled text
    in the one place the prompt attack filter does not inspect.
    """
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client)
    plain = " ".join(b["text"] for b in client.calls[0]["messages"][0]["content"] if "text" in b)
    assert GUARDED_QUERY not in plain


def test_guardrail_config_is_sent_when_configured(monkeypatch):
    monkeypatch.setenv("LP2PS_GUARDRAIL_ID", "gr-abc123")
    monkeypatch.setenv("LP2PS_GUARDRAIL_VERSION", "1")
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client)
    cfg = client.calls[0]["guardrailConfig"]
    assert cfg["guardrailIdentifier"] == "gr-abc123"
    assert cfg["guardrailVersion"] == "1"
    # Tracing is what makes a block auditable; without it a refusal looks like an ordinary answer.
    assert cfg["trace"] == "enabled"


def test_guardrail_config_absent_when_unconfigured(monkeypatch):
    """No env config -> no guardrailConfig key at all (an empty dict is a ValidationException)."""
    monkeypatch.delenv("LP2PS_GUARDRAIL_ID", raising=False)
    monkeypatch.delenv("LP2PS_GUARDRAIL_VERSION", raising=False)
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client)
    assert "guardrailConfig" not in client.calls[0]


def test_guardrail_config_read_per_call_not_at_import(monkeypatch):
    """Env is read inside the call: a warm Lambda must pick up a changed configuration."""
    monkeypatch.delenv("LP2PS_GUARDRAIL_ID", raising=False)
    monkeypatch.delenv("LP2PS_GUARDRAIL_VERSION", raising=False)
    assert _guardrail_config() == {}
    monkeypatch.setenv("LP2PS_GUARDRAIL_ID", "gr-late")
    monkeypatch.setenv("LP2PS_GUARDRAIL_VERSION", "DRAFT")
    assert _guardrail_config()["guardrailIdentifier"] == "gr-late"


def test_partial_guardrail_config_is_ignored(monkeypatch):
    """An ID without a version cannot be sent -- both fields are required by the API."""
    monkeypatch.setenv("LP2PS_GUARDRAIL_ID", "gr-abc123")
    monkeypatch.delenv("LP2PS_GUARDRAIL_VERSION", raising=False)
    assert _guardrail_config() == {}


def test_hidden_unicode_stripped_from_guarded_segments(monkeypatch):
    """Guarded text is sanitized before the guardrail sees it.

    Zero-width and bidi characters are how instructions get smuggled past a text classifier, so
    stripping must happen on the guarded segments too, not only on our instruction text.
    """
    # Code points written as escapes only -- a literal zero-width/bidi character in the source
    # would itself be a trojan-source finding (bandit B613), as in bedrock_client's own regex.
    zwsp, rlo = chr(0x200B), chr(0x202E)
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client, guarded_query=f"ignore{zwsp} all{rlo} prior")
    guarded = [
        b["guardContent"]["text"]["text"]
        for b in client.calls[0]["messages"][0]["content"]
        if "guardContent" in b
    ]
    assert zwsp not in guarded[-1] and rlo not in guarded[-1]
    assert guarded[-1] == "ignore all prior"


def test_access_key_masked_in_guarded_query(monkeypatch):
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client, guarded_query="key " + "AKIA" + "ABCDEFGHIJKLMNOP")
    guarded = [
        b["guardContent"]["text"]["text"]
        for b in client.calls[0]["messages"][0]["content"]
        if "guardContent" in b
    ]
    assert "[REDACTED_KEY]" in guarded[-1]


def test_omitted_guarded_segments_produce_no_blocks(monkeypatch):
    """Callers that pass no external text (e.g. metrics narration) send no guardContent."""
    client = _FakeClient([_ok_response()])
    _invoke(monkeypatch, client, guarded_data=None, guarded_query=None)
    content = client.calls[0]["messages"][0]["content"]
    assert all("guardContent" not in b for b in content)


# ---- terminal stop reasons ----

@pytest.mark.parametrize(
    "stop_reason",
    ["guardrail_intervened", "content_filtered", "max_tokens", "model_context_window_exceeded",
     "malformed_model_output", "malformed_tool_use"],
)
def test_terminal_stop_reason_raises_without_retry(monkeypatch, stop_reason):
    """One call, not three: retrying an identical request cannot change any of these outcomes."""
    blocked_body = "Sorry, I can't answer that."  # blockedInputMessaging -- not JSON
    client = _FakeClient(
        [{"stopReason": stop_reason, "output": {"message": {"content": [{"text": blocked_body}]}}}]
    )
    with pytest.raises(TerminalStopReason) as exc:
        _invoke(monkeypatch, client)
    assert exc.value.stop_reason == stop_reason
    assert len(client.calls) == 1, "terminal stop reasons must not be retried"


def test_block_is_distinguishable_from_truncation(monkeypatch):
    """is_block separates 'refused' from 'incomplete' -- they need different operator messages."""
    for reason, expected in [
        ("guardrail_intervened", True),
        ("content_filtered", True),
        ("max_tokens", False),
        ("malformed_model_output", False),
    ]:
        client = _FakeClient([{"stopReason": reason, "output": {"message": {"content": [{"text": "x"}]}}}])
        with pytest.raises(TerminalStopReason) as exc:
            _invoke(monkeypatch, client)
        assert exc.value.is_block is expected, reason


def test_terminal_stop_checked_before_schema_validation(monkeypatch):
    """A block must surface as a block, not as a schema error.

    Regression guard for the original defect: validating first turns every block into
    "AI 출력이 스키마 검증을 3회 모두 실패", which is both wrong and unactionable.
    """
    client = _FakeClient(
        [{"stopReason": "guardrail_intervened",
          "output": {"message": {"content": [{"text": "Sorry, I can't answer that."}]}}}]
    )
    with pytest.raises(TerminalStopReason):
        _invoke(monkeypatch, client)


def test_end_turn_with_broken_json_still_retries(monkeypatch):
    """The existing retry path is preserved for the case it was built for."""
    broken = {"stopReason": "end_turn", "output": {"message": {"content": [{"text": "not json"}]}}}
    client = _FakeClient([broken, broken, broken])
    with pytest.raises(ValueError, match="스키마 검증"):
        _invoke(monkeypatch, client)
    assert len(client.calls) == 3


def test_end_turn_recovers_on_retry(monkeypatch):
    client = _FakeClient(
        [{"stopReason": "end_turn", "output": {"message": {"content": [{"text": "nope"}]}}},
         _ok_response()]
    )
    out = _invoke(monkeypatch, client)
    assert out.grounded is True
    assert len(client.calls) == 2


# ---- trace summarization (audit safety) ----

def test_trace_summary_records_policy_without_content():
    """The audit summary names what fired and omits every field that echoes text.

    `GuardrailPiiEntityFilter.match` carries the matched substring and `modelOutput` carries
    generated text; neither may reach an audit line.
    """
    # Assembled at runtime so scanners do not flag a literal (same trick as
    # test_ai_input_sanitize._FAKE_KEY). Not a real credential.
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    resp = {
        "stopReason": "guardrail_intervened",
        "trace": {
            "guardrail": {
                "inputAssessment": {
                    "gr-abc123": {
                        "contentPolicy": {
                            "filters": [
                                {"type": "PROMPT_ATTACK", "confidence": "HIGH", "action": "BLOCKED"},
                                {"type": "HATE", "confidence": "NONE", "action": "NONE"},
                            ]
                        },
                        "sensitiveInformationPolicy": {
                            "piiEntities": [
                                {"type": "AWS_ACCESS_KEY", "action": "BLOCKED", "match": fake_key}
                            ]
                        },
                    }
                },
                "modelOutput": ["some generated text that must not be logged"],
            }
        },
    }
    summary = _summarize_guardrail_trace(resp)
    fired = summary["inputAssessment"]["gr-abc123"]
    assert "content:PROMPT_ATTACK:HIGH" in fired
    assert "pii:AWS_ACCESS_KEY:BLOCKED" in fired
    # Non-blocking filters are noise in an audit line.
    assert not any("HATE" in f for f in fired)

    flat = repr(summary)
    assert fake_key not in flat, "matched PII substring must never reach the audit summary"
    assert "some generated text" not in flat, "model output must never reach the audit summary"


def test_trace_summary_empty_when_no_trace():
    assert _summarize_guardrail_trace({"stopReason": "max_tokens"}) == {}


def test_build_content_sets_no_qualifiers():
    """Qualifiers select contextual grounding, which this guardrail does not configure.

    An unqualified block is what the content filters evaluate; adding `grounding_source` would
    scope the segment to a policy that is not enabled and quietly drop it from filtering.
    """
    content = _build_content("instructions", [("data", "collected"), ("query", "asked")])
    for block in content:
        if "guardContent" in block:
            assert "qualifiers" not in block["guardContent"]["text"]
