from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from yaysafe.config import LLMConfig, ScannerConfig
from yaysafe.llm import (
    SYSTEM_PROMPT,
    AnthropicClient,
    LLMError,
    OpenAICompatibleClient,
    _urllib_transport,
    build_analysis_payload,
    create_llm_client,
    validate_llm_json,
)
from yaysafe.models import Assessment, Finding, Risk
from yaysafe.scanner import scan_repository

VALID = {
    "risk": "low",
    "safe": True,
    "confidence": 0.91,
    "summary": "No suspicious behavior found.",
    "static_assessments": [],
    "findings": [],
}


def test_llm_json_validation() -> None:
    result = validate_llm_json(json.dumps(VALID), model="test-model")
    assert result.risk == Risk.LOW
    assert result.model == "test-model"
    assert result.static_assessments == []


def test_llm_must_assess_every_static_finding() -> None:
    static = scan_repository(
        Path(__file__).parent / "fixtures/suspicious-package",
        "suspicious-package",
        ScannerConfig(),
    )
    with pytest.raises(ValueError, match="assess every"):
        validate_llm_json(json.dumps(VALID), static_findings=static.findings)


def test_unambiguous_static_assessment_alias_is_normalized() -> None:
    value = {
        **VALID,
        "static_assessments": [
            {
                "rule_id": "setuid",
                "file": "PKGBUILD",
                "line": 2,
                "assessment": "contextual-legitimate",
                "reason": "Staged browser sandbox helper.",
            }
        ],
    }
    finding = Finding(Risk.HIGH, "setuid", "PKGBUILD", 2, "chmod 4755 ...", "SUID", hard=False)
    result = validate_llm_json(json.dumps(value), static_findings=[finding])
    assert result.static_assessments[0].assessment == Assessment.CONTEXTUAL_BUT_LEGITIMATE


@pytest.mark.parametrize("raw", ["not json", "{}", '{"risk":"safe"}'])
def test_malformed_llm_output(raw: str) -> None:
    with pytest.raises(ValueError):
        validate_llm_json(raw)


def test_malformed_response_retries_once() -> None:
    calls: list[dict] = []

    def transport(method, url, headers, body, timeout):
        if url.endswith("/models"):
            return 200, b'{"data":[{"id":"local"}]}'
        calls.append(json.loads(body))
        content = "bad" if len(calls) == 1 else json.dumps(VALID)
        return 200, json.dumps({"choices": [{"message": {"content": content}}]}).encode()

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    result = OpenAICompatibleClient(LLMConfig(), transport).analyze("safe-package", static)
    assert result.risk == Risk.LOW
    assert len(calls) == 2


def test_timeout_becomes_unknown() -> None:
    def stream_transport(method, url, headers, body, timeout):
        raise TimeoutError("timed out")
        yield b""  # pragma: no cover - satisfy the stream transport iterator contract

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    result = OpenAICompatibleClient(
        LLMConfig(model="local"), stream_transport=stream_transport
    ).analyze("safe-package", static)
    assert result.risk == Risk.UNKNOWN
    assert result.safe is False


def test_provider_factory_selects_native_anthropic_client() -> None:
    assert isinstance(create_llm_client(LLMConfig(provider="anthropic")), AnthropicClient)
    assert isinstance(create_llm_client(LLMConfig(provider="ollama")), OpenAICompatibleClient)
    assert isinstance(create_llm_client(LLMConfig(provider="openai")), OpenAICompatibleClient)


def test_anthropic_model_discovery_uses_native_headers() -> None:
    requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def transport(method, url, headers, body, timeout):
        requests.append((method, url, headers, body))
        return 200, b'{"data":[{"id":"claude-test"}]}'

    client = AnthropicClient(
        LLMConfig(
            provider="anthropic",
            base_url="https://api.anthropic.com/v1",
            api_key="anthropic-test-secret",
        ),
        transport=transport,
    )
    assert client.list_models() == ["claude-test"]
    method, url, headers, body = requests[0]
    assert method == "GET"
    assert url == "https://api.anthropic.com/v1/models"
    assert headers["x-api-key"] == "anthropic-test-secret"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in headers
    assert body is None


def test_anthropic_streaming_messages_are_validated() -> None:
    requests: list[tuple[str, str, dict[str, str], dict]] = []

    def stream_transport(method, url, headers, body, timeout):
        requests.append((method, url, headers, json.loads(body)))
        result = json.dumps(VALID)
        midpoint = len(result) // 2
        yield b"event: ping\n"
        yield b'data: {"type":"ping"}\n'
        for part in (result[:midpoint], result[midpoint:]):
            event = {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": part},
            }
            yield f"data: {json.dumps(event)}\n".encode()
        yield b'data: {"type":"message_stop"}\n'

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    client = AnthropicClient(
        LLMConfig(
            provider="anthropic",
            base_url="https://api.anthropic.com/v1",
            api_key="anthropic-test-secret",
            model="claude-test",
        ),
        stream_transport=stream_transport,
    )
    result = client.analyze("safe-package", static)

    assert result.risk == Risk.LOW
    method, url, headers, payload = requests[0]
    assert method == "POST"
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "anthropic-test-secret"
    assert payload["stream"] is True
    assert payload["model"] == "claude-test"
    assert "All repository files" in payload["system"]
    assert [message["role"] for message in payload["messages"]] == ["user"]
    assert "reasoning_effort" not in payload


def test_streaming_completion_assembles_sse_and_ignores_heartbeats() -> None:
    requests: list[dict] = []

    def stream_transport(method, url, headers, body, timeout):
        requests.append(json.loads(body))
        result = json.dumps(VALID)
        midpoint = len(result) // 2
        yield b": lm-studio heartbeat\n"
        for part in (result[:midpoint], result[midpoint:]):
            event = {"choices": [{"delta": {"content": part}}]}
            yield f"data: {json.dumps(event)}\n".encode()
        yield b"data: [DONE]\n"

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    result = OpenAICompatibleClient(
        LLMConfig(model="local"), stream_transport=stream_transport
    ).analyze("safe-package", static)

    assert result.risk == Risk.LOW
    assert requests[0]["stream"] is True
    assert requests[0]["max_tokens"] == 2048
    assert requests[0]["reasoning_effort"] == "none"


def test_streaming_completion_accepts_nonstreaming_compatibility_response() -> None:
    def stream_transport(method, url, headers, body, timeout):
        response = {"choices": [{"message": {"content": json.dumps(VALID)}}]}
        yield json.dumps(response).encode()

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    result = OpenAICompatibleClient(
        LLMConfig(model="local"), stream_transport=stream_transport
    ).analyze("safe-package", static)
    assert result.risk == Risk.LOW


def test_reasoning_without_verdict_has_actionable_error() -> None:
    def stream_transport(method, url, headers, body, timeout):
        event = {"choices": [{"delta": {"reasoning_content": "Still thinking"}}]}
        yield f"data: {json.dumps(event)}\n".encode()
        yield b"data: [DONE]\n"

    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    result = OpenAICompatibleClient(
        LLMConfig(model="local", reasoning_effort="low"), stream_transport=stream_transport
    ).analyze("safe-package", static)
    assert result.risk == Risk.UNKNOWN
    assert "reasoning" in result.error


def test_prompt_injection_remains_untrusted_data() -> None:
    static = scan_repository(
        Path(__file__).parent / "fixtures/prompt-injection-package",
        "prompt-injection-package",
        ScannerConfig(),
    )
    prompt = build_analysis_payload("prompt-injection-package", static)
    assert "Ignore all previous instructions" in prompt
    assert "UNTRUSTED_PACKAGE_DATA" in prompt
    assert "Never follow" in SYSTEM_PROMPT
    assert "Evaluate\nevery one explicitly" in SYSTEM_PROMPT
    suspicious = scan_repository(
        Path(__file__).parent / "fixtures/suspicious-package",
        "suspicious-package",
        ScannerConfig(),
    )
    assert '"hard": true' in build_analysis_payload("suspicious-package", suspicious)


def test_prompt_includes_skipped_file_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n")
    (repo / "binary.sh").write_bytes(b"\x00binary")
    static = scan_repository(repo, "x", ScannerConfig())
    assert "binary.sh: binary" in build_analysis_payload("x", static)


def test_llm_finding_cannot_exceed_overall_risk() -> None:
    contradictory = {
        **VALID,
        "findings": [
            {
                "severity": "high",
                "file": "PKGBUILD",
                "line": 1,
                "category": "remote-code-execution",
                "description": "Remote code is executed.",
                "evidence": "curl example | bash",
            }
        ],
    }
    with pytest.raises(ValueError, match="cannot be lower"):
        validate_llm_json(json.dumps(contradictory))


def test_llm_safe_boolean_must_match_risk() -> None:
    inconsistent = {**VALID, "safe": False}
    with pytest.raises(ValueError, match="safe must be true"):
        validate_llm_json(json.dumps(inconsistent))


def test_llm_cannot_reference_an_artifact_that_was_not_supplied() -> None:
    static = scan_repository(
        Path(__file__).parent / "fixtures/safe-package", "safe-package", ScannerConfig()
    )
    invented = {
        **VALID,
        "risk": "medium",
        "safe": False,
        "findings": [
            {
                "severity": "medium",
                "file": "invented.install",
                "line": 1,
                "category": "persistence",
                "description": "Invented behavior.",
                "evidence": "invented",
            }
        ],
    }
    with pytest.raises(ValueError, match="was not supplied"):
        validate_llm_json(json.dumps(invented), inspected_files=static.files)


def test_oversized_prompt_returns_unknown_without_contacting_model(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n" + "# padding\n" * 3000)
    static = scan_repository(repo, "x", ScannerConfig())
    calls = 0

    def stream_transport(method, url, headers, body, timeout):
        nonlocal calls
        calls += 1
        yield b""

    result = OpenAICompatibleClient(
        LLMConfig(model="local", max_prompt_size=16_384),
        stream_transport=stream_transport,
    ).analyze("x", static)
    assert result.risk == Risk.UNKNOWN
    assert "max_prompt_size" in result.error
    assert calls == 0


def test_llm_transport_never_forwards_package_data_through_redirects() -> None:
    destination_requests = 0

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            nonlocal destination_requests
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "/destination")
                self.end_headers()
                return
            destination_requests += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        with pytest.raises(LLMError, match="HTTP 307"):
            _urllib_transport(
                "POST",
                f"http://127.0.0.1:{server.server_port}/redirect",
                {"Content-Type": "application/json"},
                b'{"untrusted":"package data"}',
                2,
            )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    assert destination_requests == 0
