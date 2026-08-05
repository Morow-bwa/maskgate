from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    content: Any = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(default_factory=list)
    stream: bool = False
    # Local Playground override; it is stripped before the upstream request.
    masking_mode: str | None = None
    # Optional opaque id for RAM-only multi-turn conversations.
    conversation_id: str | None = None


class DebugTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str


class DebugMaskRequest(DebugTextRequest):
    mode: str | None = None
