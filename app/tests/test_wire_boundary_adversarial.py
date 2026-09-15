from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest

from app.privacy.approvals import ApprovalContext, ScopedApproval
from app.privacy.detection import DetectorEnsemble
from app.privacy.models import PrivacyDirection
from app.privacy.wire import FinalWirePrivacyGuard, WirePrivacyViolation
from app.proxy.llm_client import LLMClient

CORPUS_PATH = Path(__file__).parents[2] / "evaluation" / "adversarial" / "media_cases.json"
WIRE_CASES = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))["wire_cases"]


@pytest.mark.parametrize("stream", [False, True], ids=["nonstream", "stream"])
@pytest.mark.parametrize("case", WIRE_CASES, ids=lambda case: case["id"])
def test_adversarial_value_never_reaches_openai_compatible_transport(
    case: dict[str, object],
    stream: bool,
) -> None:
    transport_calls: list[bytes] = []

    def provider(request: httpx.Request) -> httpx.Response:
        transport_calls.append(request.content)
        raise AssertionError("the final wire guard must reject before network transport")

    upstream = LLMClient(
        "https://provider.invalid/v1",
        "synthetic-provider-key",
        transport=httpx.MockTransport(provider),
    )
    payload = {
        "model": "synthetic-test-model",
        "messages": [{"role": "user", "content": "Process this synthetic fixture"}],
        "metadata": {"adversarial_probe": case["value"]},
        "stream": stream,
    }

    async def invoke_transport_path() -> None:
        if stream:
            async for _ in upstream.complete_stream(payload):
                pass
        else:
            await upstream.complete(payload)

    with pytest.raises(WirePrivacyViolation):
        asyncio.run(invoke_transport_path())

    assert case["expected_error"] == "wire_privacy_violation"
    assert transport_calls == []


def test_corpus_contains_every_required_wire_evasion_class() -> None:
    classes = {str(case["class"]) for case in WIRE_CASES}

    assert classes == {
        "base64",
        "hex",
        "nested_json",
        "numeric_pii",
        "percent_escape",
        "unicode_escape",
        "user_injected_token",
    }


@pytest.mark.parametrize(
    ("payload", "guard"),
    [
        ({"outer": {"inner": {"value": "safe"}}}, FinalWirePrivacyGuard(
            DetectorEnsemble(), max_structure_depth=1
        )),
        ({"one": "safe", "two": "safe"}, FinalWirePrivacyGuard(
            DetectorEnsemble(), max_nodes=3
        )),
    ],
    ids=["depth", "field-count"],
)
def test_wire_guard_enforces_aggregate_structural_work(payload, guard) -> None:
    with pytest.raises(WirePrivacyViolation, match="structural inspection limits"):
        guard.check(provider="openai-compatible-chat", payload=payload)


def _approval_context(**overrides: object) -> ApprovalContext:
    values: dict[str, object] = {
        "principal_id": "tenant-a:maskgate:subject-a",
        "application_id": "maskgate",
        "route": "/v1/chat/completions",
        "provider": "openai-chat-completions",
        "direction": PrivacyDirection.INPUT,
        "purpose": "general-assistance",
        "policy_revision": "2",
        "now_epoch": time.time(),
    }
    values.update(overrides)
    return ApprovalContext(**values)  # type: ignore[arg-type]


def _scoped_email_approval(**overrides: object) -> ScopedApproval:
    values: dict[str, object] = {
        "value": "press@example.org",
        "entity_type": "EMAIL",
        "principal_id": "tenant-a:maskgate:subject-a",
        "application_id": "maskgate",
        "route": "/v1/chat/completions",
        "provider": "openai-chat-completions",
        "direction": PrivacyDirection.INPUT,
        "purpose": "general-assistance",
        "source_path": ("messages", 0, "content"),
        "wire_path": ("messages", 0, "content"),
        "policy_revision": "2",
        "expires_at_epoch": time.time() + 60,
        "decision_id": "assertion:press-address",
    }
    values.update(overrides)
    return ScopedApproval.issue(**values)  # type: ignore[arg-type]


def test_scoped_approval_allows_only_its_exact_wire_occurrence() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble())
    approval = _scoped_email_approval()
    context = _approval_context()

    checked = guard.check(
        provider=context.provider,
        payload={
            "model": "synthetic-model",
            "messages": [{"role": "user", "content": "Contact press@example.org"}],
        },
        scoped_approvals=(approval,),
        approval_context=context,
    )

    assert b"press@example.org" in checked.body


@pytest.mark.parametrize(
    ("approval", "context"),
    [
        (
            _scoped_email_approval(wire_path=("tools", 0, "function", "description")),
            _approval_context(),
        ),
        (_scoped_email_approval(), _approval_context(principal_id="tenant-b:maskgate:user")),
        (_scoped_email_approval(), _approval_context(provider="gemini-generate-content")),
        (_scoped_email_approval(), _approval_context(policy_revision="3")),
        (
            _scoped_email_approval(expires_at_epoch=time.time() - 1),
            _approval_context(),
        ),
    ],
    ids=["relocated", "wrong-owner", "wrong-provider", "wrong-policy", "expired"],
)
def test_scoped_approval_rejects_wrong_or_expired_scope(
    approval: ScopedApproval,
    context: ApprovalContext,
) -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble())

    with pytest.raises(WirePrivacyViolation):
        guard.check(
            provider=context.provider,
            payload={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "Contact press@example.org"}],
            },
            scoped_approvals=(approval,),
            approval_context=context,
        )


def test_approved_value_copied_to_disallowed_field_is_still_rejected() -> None:
    guard = FinalWirePrivacyGuard(DetectorEnsemble())
    context = _approval_context()

    with pytest.raises(WirePrivacyViolation):
        guard.check(
            provider=context.provider,
            payload={
                "model": "synthetic-model",
                "messages": [{"role": "user", "content": "Contact press@example.org"}],
                "metadata": {"copied": "press@example.org"},
            },
            scoped_approvals=(_scoped_email_approval(),),
            approval_context=context,
        )
