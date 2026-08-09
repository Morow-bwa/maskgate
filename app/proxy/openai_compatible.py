from __future__ import annotations

from typing import Any, Iterable

from app.masking.anonymizer import MappingItem
from app.schemas import ChatCompletionRequest


def request_to_payload(request: ChatCompletionRequest) -> dict[str, Any]:
    """Serialize the validated request while preserving OpenAI-compatible extras."""
    return request.model_dump(mode="json", exclude_none=False)


def add_masking_instruction(payload: dict[str, Any], mappings: Iterable[MappingItem]) -> None:
    """Tell the upstream model how to handle request-scoped masked values.

    The model never receives the original values. This short system message
    helps it copy placeholders/surrogates faithfully so the response can be
    rehydrated after the upstream call.
    """
    replacements = list(
        dict.fromkeys(item.replacement for item in mappings if item.restore and item.replacement)
    )
    if not replacements:
        return

    instruction = (
        "MaskGate privacy instruction: the following tokens represent masked "
        "values from the user's request: "
        f"{', '.join(replacements)}. "
        "Preserve these tokens exactly when referring to the same values. "
        "Do not decode, reconstruct, or invent the original values, and do "
        "not change token spelling, case, digits, or punctuation."
    )
    messages = payload.setdefault("messages", [])
    system_index = 0
    while system_index < len(messages) and messages[system_index].get("role") == "system":
        system_index += 1
    messages.insert(system_index, {"role": "system", "content": instruction})
