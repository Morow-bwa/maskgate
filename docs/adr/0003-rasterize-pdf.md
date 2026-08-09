# ADR 0003: Rasterize sanitized PDFs

Status: accepted

## Decision

Render each PDF page to pixels, apply the image sanitizer, and build a new PDF from sanitized page images.

## Why

Overlay redaction can leave recoverable text, links, scripts, attachments, or metadata in the source document. Rebuilding from pixels removes those original structures.

## Consequences

The output loses searchable text, links, forms, accessibility tags, and vector fidelity. OCR/face misses remain possible, so high-risk outputs need manual review.
