# Media security

MaskGate treats every uploaded document and every provider-bound encoded value as untrusted. A file is returned only after a supported local sanitizer rebuilds it. Unsupported, malformed, oversized, ambiguous, or unverifiable content fails closed.

## Supported media path

| Format | Local transformation | Defensive limits |
|---|---|---|
| DOCX | Parse an allowlisted set of OPC parts, remove external relationships and metadata, redact supported XML, rebuild a deterministic ZIP | 2,000 entries, 50 MiB aggregate uncompressed data, 200:1 per-entry compression ratio, no duplicate names or unknown opaque parts |
| PNG, JPEG, WebP, TIFF, BMP | Decode locally, reject multiple frames, redact OCR regions and faces, write a fresh single-frame PNG | 20 million source pixels and the configured upload/output byte limit |
| PDF | Rasterize every page locally, pass pixels through the image sanitizer, write a fresh PDF | 50 pages, 20 million pixels per page, 50 million pixels in total, configured output byte limit |

The default API upload limit is 10 MiB. Deployment infrastructure should enforce an equal or smaller request limit before the application. Limit values are constructor/configuration defaults, not a claim that every deployment has enough memory for concurrent worst-case inputs.

## DOCX package policy

DOCX is a ZIP-based package, so extension and MIME checks are insufficient. MaskGate rejects:

- duplicate member names, traversal paths, absolute paths, and backslash-normalized paths;
- macro, embedded-object, ActiveX, media, custom XML, and unknown opaque parts;
- excessive entry count, aggregate expansion, or individual compression ratio;
- invalid XML, sensitive member names, and sensitive text that remains after verification.

The package policy is allowlist-based. A new OPC part is unsupported until a local transformer and a regression test define how it is sanitized and verified.

## Images and PDFs

Images must decode as one supported frame. Dimensions are checked before full processing. PDF page count and rendered-pixel budgets are checked before OCR/redaction work for each page. Sanitized outputs contain rebuilt pixels rather than the original image/PDF object graph.

OCR and face detection are probabilistic. Re-running the same detector is useful regression defense, but it is not independent proof that no sensitive pixels remain. Distorted text, uncommon scripts, non-frontal faces, and adversarial images can still evade detection.

## Provider wire guard

Files and encoded data are not accepted as generic provider-extension fields. Immediately before the remote HTTP transport, the final wire guard inspects the canonical serialized JSON and rejects unclassified numeric values, unknown MaskGate tokens, base64/base64url, long hex, percent or Unicode escape evasions, and nested encoded JSON that contains sensitive data. The same rule applies to non-streaming and streaming requests.

Only a locally sanitized artifact with an explicit typed provider adapter should become eligible for remote transmission. That adapter path is intentionally not implied by generic JSON/base64 support.

## Regression evidence

- `app/tests/test_media_limits.py` builds deterministic in-memory DOCX, image, and PDF fixtures for parser and resource limits.
- `app/tests/test_wire_boundary_adversarial.py` uses `httpx.MockTransport` and proves unsafe values are rejected before either OpenAI-compatible transport path is invoked.
- `evaluation/adversarial/media_cases.json` is the versioned synthetic case inventory. It contains no production data, credentials, or user identifiers.

These checks validate implemented behavior; they do not establish DLP certification or perfect PII recall.
