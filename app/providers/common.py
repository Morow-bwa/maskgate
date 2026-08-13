from __future__ import annotations

from typing import Any

from app.privacy.ir import (
    CanonicalRole,
    GenerationSettings,
    TextClassification,
    TextContent,
    ToolChoice,
    ToolChoiceMode,
)

from .base import ProviderAdapterError, expect_list, expect_string


def classification_for_role(role: CanonicalRole) -> TextClassification:
    if role in {CanonicalRole.SYSTEM, CanonicalRole.DEVELOPER}:
        return TextClassification.INSTRUCTION
    if role is CanonicalRole.ASSISTANT:
        return TextClassification.ASSISTANT_TEXT
    if role is CanonicalRole.TOOL:
        return TextClassification.TOOL_RESULT
    return TextClassification.USER_TEXT


def text_content(value: Any, role: CanonicalRole, provider: str, path: str) -> TextContent:
    return TextContent(expect_string(value, provider, path), classification_for_role(role))


def parse_stop(value: Any, provider: str, path: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(
        expect_string(item, provider, f"{path}[{index}]")
        for index, item in enumerate(expect_list(value, provider, path))
    )


def generation_settings(
    *,
    provider: str,
    max_output_tokens: Any = None,
    temperature: Any = None,
    top_p: Any = None,
    stop: Any = None,
) -> GenerationSettings:
    if max_output_tokens is not None and (
        not isinstance(max_output_tokens, int) or isinstance(max_output_tokens, bool)
    ):
        raise ProviderAdapterError(provider, "$.max_output_tokens", "expected an integer")
    for name, value in (("temperature", temperature), ("top_p", top_p)):
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            raise ProviderAdapterError(provider, f"$.{name}", "expected a number")
    return GenerationSettings(
        max_output_tokens=max_output_tokens,
        temperature=float(temperature) if temperature is not None else None,
        top_p=float(top_p) if top_p is not None else None,
        stop_sequences=parse_stop(stop, provider, "$.stop"),
    )


def parse_simple_tool_choice(value: Any, provider: str, path: str) -> ToolChoice | None:
    if value is None:
        return None
    mode = expect_string(value, provider, path)
    mapping = {
        "auto": ToolChoiceMode.AUTO,
        "none": ToolChoiceMode.NONE,
        "required": ToolChoiceMode.REQUIRED,
        "any": ToolChoiceMode.REQUIRED,
    }
    if mode not in mapping:
        raise ProviderAdapterError(provider, path, "unsupported tool choice")
    return ToolChoice(mapping[mode])
