from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.privacy.ir import (
    CanonicalRequest,
    CanonicalStreamEvent,
    OpaqueExtension,
    RemoteToolDefinition,
    validated_json,
)


class ProviderAdapterError(ValueError):
    def __init__(self, provider: str, path: str, message: str) -> None:
        self.provider = provider
        self.path = path
        super().__init__(f"{provider} {path}: {message}")


@dataclass(frozen=True, slots=True)
class AdapterPolicy:
    allow_remote_tools: bool = False
    allow_provider_storage: bool = False
    safe_extension_fields: frozenset[str] = field(default_factory=frozenset)


class ProviderAdapter(Protocol):
    name: str
    version: str

    def from_wire(self, payload: dict[str, Any]) -> CanonicalRequest: ...

    def to_wire(self, request: CanonicalRequest) -> dict[str, Any]: ...

    def parse_stream_event(
        self, event: dict[str, Any], *, structured_output: bool = False
    ) -> tuple[CanonicalStreamEvent, ...]: ...


def expect_object(value: Any, provider: str, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ProviderAdapterError(provider, path, "expected an object")
    return value


def expect_list(value: Any, provider: str, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProviderAdapterError(provider, path, "expected an array")
    return value


def expect_string(value: Any, provider: str, path: str) -> str:
    if not isinstance(value, str):
        raise ProviderAdapterError(provider, path, "expected a string")
    return value


def expect_bool(value: Any, provider: str, path: str) -> bool:
    if not isinstance(value, bool):
        raise ProviderAdapterError(provider, path, "expected a boolean")
    return value


def extensions_for_unknown_fields(
    payload: dict[str, Any],
    allowed: set[str],
    *,
    provider: str,
    policy: AdapterPolicy,
    path: str = "$",
) -> tuple[OpaqueExtension, ...]:
    extensions: list[OpaqueExtension] = []
    for name in sorted(set(payload) - allowed):
        if name not in policy.safe_extension_fields:
            raise ProviderAdapterError(provider, f"{path}.{name}", "unknown unsafe field")
        extensions.append(
            OpaqueExtension(provider=provider, name=name, value=payload[name], trusted=True)
        )
    return tuple(extensions)


def emit_extensions(
    payload: dict[str, Any],
    request: CanonicalRequest,
    *,
    provider: str,
    policy: AdapterPolicy,
) -> None:
    for extension in request.extensions:
        if extension.provider != provider:
            raise ProviderAdapterError(
                provider,
                f"$.{extension.name}",
                f"extension belongs to {extension.provider} and cannot cross providers",
            )
        if extension.name not in policy.safe_extension_fields or not extension.trusted:
            raise ProviderAdapterError(provider, f"$.{extension.name}", "extension is not trusted")
        if extension.name in payload:
            raise ProviderAdapterError(
                provider, f"$.{extension.name}", "extension collides with a field"
            )
        payload[extension.name] = validated_json(extension.value)


def read_json_text(value: Any, provider: str, path: str) -> Any:
    text = expect_string(value, provider, path)
    try:
        return validated_json(json.loads(text), path=path)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProviderAdapterError(provider, path, "expected JSON text") from exc


def compact_json(value: Any) -> str:
    return json.dumps(validated_json(value), ensure_ascii=False, separators=(",", ":"))


def enforce_storage(value: Any, provider: str, policy: AdapterPolicy, path: str) -> bool:
    store = False if value is None else expect_bool(value, provider, path)
    if store and not policy.allow_provider_storage:
        raise ProviderAdapterError(provider, path, "provider storage is disabled")
    return store


def remote_tool(
    *, provider: str, kind: str, configuration: dict[str, Any], policy: AdapterPolicy, path: str
) -> RemoteToolDefinition:
    if not policy.allow_remote_tools:
        raise ProviderAdapterError(provider, path, "remote tool execution is disabled")
    return RemoteToolDefinition(
        provider=provider,
        kind=kind,
        configuration=configuration,
        trusted=True,
    )


def emit_remote_tool(
    tool: RemoteToolDefinition, *, provider: str, policy: AdapterPolicy, path: str
) -> dict[str, Any]:
    if tool.provider != provider:
        raise ProviderAdapterError(provider, path, "remote tool belongs to another provider")
    if not policy.allow_remote_tools or not tool.trusted:
        raise ProviderAdapterError(provider, path, "remote tool execution is disabled")
    return validated_json(tool.configuration, path=path)
