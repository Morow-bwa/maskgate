from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class StreamEventKind(StrEnum):
    TEXT_DELTA = "text_delta"
    TOOL_ARGUMENTS_DELTA = "tool_arguments_delta"
    STRUCTURED_DATA_DELTA = "structured_data_delta"
    FINISH = "finish"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class TextDelta:
    path: tuple[str | int, ...]
    text: str
    kind: StreamEventKind = field(default=StreamEventKind.TEXT_DELTA, init=False)


@dataclass(frozen=True, slots=True)
class ToolArgumentsDelta:
    call_id: str
    path: tuple[str | int, ...]
    fragment: str
    kind: StreamEventKind = field(default=StreamEventKind.TOOL_ARGUMENTS_DELTA, init=False)


@dataclass(frozen=True, slots=True)
class StructuredDataDelta:
    path: tuple[str | int, ...]
    fragment: str
    kind: StreamEventKind = field(default=StreamEventKind.STRUCTURED_DATA_DELTA, init=False)


@dataclass(frozen=True, slots=True)
class FinishEvent:
    reason: str
    path: tuple[str | int, ...] = ()
    kind: StreamEventKind = field(default=StreamEventKind.FINISH, init=False)


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    code: str
    message: str
    kind: StreamEventKind = field(default=StreamEventKind.ERROR, init=False)


CanonicalStreamEvent = (
    TextDelta | ToolArgumentsDelta | StructuredDataDelta | FinishEvent | ErrorEvent
)
