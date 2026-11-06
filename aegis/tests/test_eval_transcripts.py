"""Eval integrity: a gate must grade a model, not the mock that was tuned to the corpus."""
from __future__ import annotations

import json

import pytest

from aegis.agents.shared.llm_client import LLMClient, LLMResponse, MockClient
from aegis.eval.run import exit_code
from aegis.eval.transcripts import (
    RecordingClient,
    TranscriptClient,
    is_mock,
    open_eval_client,
    prompt_key,
)


class _Canned(LLMClient):
    name = "canned"
    model = "canned-1"

    def __init__(self, text: str = '{"verdict":"benign","confidence":0.9}'):
        self.text = text
        self.calls = 0

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        self.calls += 1
        return LLMResponse(text=self.text, model=self.model, input_tokens=10, output_tokens=5)


def _record(tmp_path, *, system="sys", user="user", max_tokens=100, text='{"verdict":"benign"}'):
    path = tmp_path / "t.jsonl"
    inner = _Canned(text)
    rec = RecordingClient(inner, path)
    rec.complete(system, user, max_tokens=max_tokens)
    return path, rec


def test_prompt_key_is_stable_and_sensitive():
    a = prompt_key("s", "u", 2048)
    assert a == prompt_key("s", "u", 2048)          # no timestamps / process state
    assert a != prompt_key("s", "u", 1024)          # a different budget is a different call
    assert a != prompt_key("s", "u!", 2048)         # one character matters
    assert a != prompt_key("s!", "u", 2048)


def test_record_then_replay_roundtrip(tmp_path):
    path, _ = _record(tmp_path, text='{"verdict":"malicious","confidence":0.8}')
    replay = TranscriptClient(path)
    resp = replay.complete("sys", "user", max_tokens=100)
    assert resp.text == '{"verdict":"malicious","confidence":0.8}'
    assert resp.model == "canned-1"
    assert replay.hits == 1 and replay.misses == []


def test_replay_miss_is_counted_and_never_benign(tmp_path):
    path, _ = _record(tmp_path)
    replay = TranscriptClient(path)
    resp = replay.complete("sys", "a prompt the transcript never saw", max_tokens=100)
    assert len(replay.misses) == 1
    assert resp.model == "transcript-miss"
    obj = json.loads(resp.text)
    assert obj["verdict"] == "uncertain"
    assert obj["actions"] == []


def test_first_record_wins(tmp_path):
    path, _ = _record(tmp_path, text='{"verdict":"benign"}')
    with path.open("a", encoding="utf-8") as fh:      # a re-record appended to the same file
        fh.write(json.dumps({
            "type": "response",
            "key": prompt_key("sys", "user", 100),
            "max_tokens": 100,
            "text": '{"verdict":"malicious"}',
            "model": "canned-1",
        }) + "\n")
    assert json.loads(TranscriptClient(path).complete("sys", "user", 100).text)["verdict"] == "benign"


def test_transcript_stats_rejects_duplicates(tmp_path, capsys):
    from aegis.eval.transcripts import main as transcripts_main
    path, _ = _record(tmp_path)
    assert transcripts_main(["stats", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["responses"] == 1


def test_is_mock_sees_through_wrappers():
    from aegis.agents.shared.pii_tokenizing_client import TokenizingLLMClient
    assert is_mock(MockClient())
    assert is_mock(TokenizingLLMClient(MockClient()))
    assert not is_mock(_Canned())
    assert not is_mock(TokenizingLLMClient(_Canned()))


def test_open_eval_client_reports_a_mock_as_not_credible(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_EVAL_TRANSCRIPT", raising=False)
    monkeypatch.delenv("AEGIS_EVAL_RECORD", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    _client, meta = open_eval_client()
    assert meta["credible"] is False


def test_open_eval_client_prefers_transcript_over_the_mock(monkeypatch, tmp_path):
    path, _ = _record(tmp_path)
    monkeypatch.setenv("AEGIS_EVAL_TRANSCRIPT", str(path))
    monkeypatch.setenv("LLM_BACKEND", "mock")
    client, meta = open_eval_client()
    assert meta["credible"] is True and meta["replay"] is True
    assert isinstance(client, TranscriptClient)


def test_a_transcript_recorded_from_the_mock_is_not_credible(tmp_path):
    from aegis.eval.transcripts import RecordingClient as Rec
    path = tmp_path / "mock.jsonl"
    rec = Rec(MockClient(), path)                 # header says mock / mock-rules-1
    rec.complete("sys", "user", max_tokens=100)
    client = TranscriptClient(path)
    assert client.credible is False


def test_open_eval_client_refuses_to_record_a_mock(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_EVAL_TRANSCRIPT", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("AEGIS_EVAL_RECORD", str(tmp_path / "never.jsonl"))
    with pytest.raises(RuntimeError, match="refusing to record"):
        open_eval_client()


@pytest.mark.parametrize("gate,credible,correct,n,leaks,expected", [
    (True, False, 37, 37, [], 2),     # the whole point: 37/37 on a mock is not a pass
    (True, True, 32, 37, [], 1),      # a real model that misses is a normal gate failure
    (True, True, 37, 37, [], 0),
    (True, True, 37, 37, ["leak"], 1),
    (False, False, 37, 37, [], 0),    # interactive run against the mock: allowed, and printed
])
def test_exit_code(gate, credible, correct, n, leaks, expected):
    assert exit_code(credible=credible, correct=correct, n=n, leaks=leaks, gate=gate) == expected
