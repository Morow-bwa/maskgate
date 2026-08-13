# Provider schema notes

Reviewed against official provider documentation on 2026-08-13. These notes describe the
supported Wire subset, not the full surface of any provider.

## Architecture

The Canonical Privacy IR is the Interface between privacy processing and provider Wire formats.
Each provider Module contains a pure Adapter Implementation with no network access. The Wire/IR
conversion is the Seam where unknown or unsafe structures fail closed. The Interface has enough
Depth to preserve turns, classified text, structured values, function definitions, calls, results,
structured output, and typed stream events without exposing provider details to the privacy path.
This gives Leverage across providers while keeping protocol decisions in one place for Locality.

All adapters apply these rules:

- Unknown top-level, message, content, tool, and stream fields fail closed unless a reviewed policy
  names the exact field as a safe opaque extension.
- Provider-side storage is disabled by default. Formats with a storage control emit `store: false`
  unless an explicit storage policy authorizes otherwise; formats without that field omit it.
- Remote MCP, web search, file search, URL retrieval, code execution, and other provider-executed
  tools are blocked unless an explicit trusted-remote-tool policy authorizes the exact Wire tool.
- Arbitrary media, base64, files, audio, images, video, thought payloads, and signatures are not
  treated as text. Unsupported forms fail closed instead of being copied through.
- Function arguments and structured output schemas stay structured in the IR. Adapters do not
  silently flatten or discard them.

## OpenAI Chat Completions

Supported request subset: text-only system, developer, user and assistant messages; function tools;
assistant function calls; tool results; JSON Schema response format; common scalar generation
settings; streaming and explicit storage control.

The current stream Adapter handles text, refusal text, deprecated `function_call`, modern
`tool_calls`, finish reasons, and provider errors across every choice. Unknown delta fields fail
closed. Image, audio and file content blocks remain unsupported until they can carry a locally
verified sanitized-artifact type.

Official references:

- [Create chat completion](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
- [Chat Completions streaming](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create#chat-completions-streaming)

## OpenAI Responses

Supported request subset: instructions, text message items, function calls, function call outputs,
function definitions, `text.format` JSON Schema output, typed text/function stream events, common
generation settings, and explicit storage control.

Responses storage is not accepted implicitly. The Adapter emits `store: false` by default. Hosted
web search, file search, remote MCP, computer use and similar tools are remote tools and are blocked
without reviewed policy.

Official references:

- [Migrate to the Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses)
- [Streaming Responses](https://developers.openai.com/api/docs/guides/streaming-responses)
- [Responses API reference](https://developers.openai.com/api/reference/resources/responses/methods/create)

## Anthropic Messages

Anthropic instructions use the top-level `system` field; there is no system message role. Supported
message blocks are `text`, `tool_use`, and `tool_result`. Function definitions, strict tool schemas,
tool choice, `output_config.format` JSON Schema output, and text/tool-input stream deltas are
preserved. Image, document, citation, cache-control and thinking blocks fail closed in this initial
subset.

Official references:

- [Create a Message](https://platform.claude.com/docs/en/api/messages/create)
- [Streaming Messages](https://platform.claude.com/docs/en/build-with-claude/streaming)
- [Structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
- [Define tools](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools)

## Gemini generateContent (legacy)

Supported request subset: text parts, system instruction, custom function declarations,
`functionCall`, `functionResponse`, JSON Schema response settings, common generation settings,
streamed candidate text/function data. Legacy `generateContent` has no request storage control, so
MaskGate omits `store` rather than inventing an unsupported field. Inline media, file data,
thought signatures and built-in provider tools fail closed unless a later typed path owns them.
The legacy `model` and streaming choice select the HTTP target and are never inserted into the JSON
body; the Adapter exposes that target separately so the final body guard sees the exact payload.

Official references:

- [Generate content reference](https://ai.google.dev/api/generate-content)
- [Legacy text generation](https://ai.google.dev/gemini-api/docs/generate-content/text-generation)
- [Legacy function calling](https://ai.google.dev/gemini-api/docs/generate-content/function-calling)
- [Legacy structured outputs](https://ai.google.dev/gemini-api/docs/generate-content/structured-output)

## Gemini Interactions (experimental Adapter)

Gemini Interactions is the current recommended Gemini interface, but its schema has changed during
2026. The Adapter is therefore marked experimental and versioned independently.

Supported request subset: text `input`/`user_input`/`model_output`, `system_instruction`, custom
function tools, `function_call`, `function_result`, JSON `response_format`, common
`generation_config`, and typed text/tool-argument/finish/error stream events.

Gemini stores Interactions by default upstream. MaskGate instead emits `store: false` by default.
`previous_interaction_id` is rejected unless both provider storage and the exact opaque field have
been explicitly reviewed and enabled. `labels` is accepted only as an exact safe extension. Image,
audio, video and document inputs, image/audio stream deltas, thoughts/signatures, background work,
agents, Google Search, URL context, file search, code execution and remote environments fail closed
in the default policy.

Official references:

- [Interactions overview](https://ai.google.dev/gemini-api/docs/interactions-overview)
- [Interactions reference](https://ai.google.dev/api/interactions-api)
- [Interactions streaming](https://ai.google.dev/gemini-api/docs/streaming)
- [Interactions function calling](https://ai.google.dev/gemini-api/docs/function-calling)
- [Interactions structured outputs](https://ai.google.dev/gemini-api/docs/structured-output)
- [May 2026 schema changes](https://ai.google.dev/gemini-api/docs/interactions-breaking-changes-may-2026)

## Schema drift rule

A provider adding a field or stream event does not make that field safe. The corresponding Adapter
must gain a typed IR mapping and tests before the field is accepted. Until then, fail closed is the
intended result.
