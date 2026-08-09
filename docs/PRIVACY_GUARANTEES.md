# Privacy guarantees and limits

## What MaskGate guarantees

- No provider call is attempted when provider credentials are absent or example-like.
- The provider client receives the recursively sanitized payload, not the original request model.
- Supported detected values are replaced before HTTP serialization, including values in tool arguments and custom extension fields.
- Request placeholders are random and scoped to one masking session.
- Response restoration happens locally from an in-memory mapping.
- Raw prompts, mappings, authorization headers, and provider keys are excluded from structured request logs.
- Uploaded files are processed locally and returned to the caller; they are not attached to chat requests automatically.

These properties are covered by tests, but only for the implemented detector and supported formats.

## What MaskGate does not guarantee

- Regex and OCR detection do not identify every person, secret, or indirect identifier.
- Allowlisting can intentionally expose values; operators own those rules.
- A remote model may infer identity from remaining context even when direct identifiers are removed.
- RAM-only does not protect against host compromise, swap, crash dumps, or privileged process inspection.
- Image face detection is frontal-face based. OCR quality depends on resolution, language, layout, and image quality.
- Rebuilt PDFs are visual documents without their original text/search/accessibility layer.

For high-risk data, use strict policies, review the exact outbound payload in the Playground, manually inspect sanitized files, and keep the proxy on a hardened host behind TLS and network controls.
