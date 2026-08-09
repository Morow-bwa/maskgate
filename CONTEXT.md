# Domain language

- **Outbound boundary**: the last code path that transforms request data before HTTP serialization to a remote provider.
- **Masking session**: request- or conversation-scoped placeholder namespace plus its restoration mapping.
- **Placeholder vault**: bounded in-memory originals-to-placeholder mapping. It is never an upstream payload.
- **Provider payload**: the exact sanitized JSON handed to the remote API adapter.
- **Protocol string**: a schema identifier such as model, role, tool name, or tool call ID that cannot be freely rewritten without changing API semantics.
- **Preview-only**: local sanitization with no provider call because credentials are absent.
- **Rehydration**: local replacement of provider-returned placeholders with original values.
- **Media sanitizer**: local, bounded, fail-closed pipeline that creates a separate downloadable artifact.
- **Fail closed**: reject a request or file when MaskGate cannot prove that the supported sanitization step completed.
