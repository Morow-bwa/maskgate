# ADR 0009: Scoped public-data assertions

Status: accepted.

Public status is represented by an exact hashed value assertion with tenant, application,
direction, provider, purpose, expiry, and provenance. It is not a global string allowlist. Explicit
block/review rules take precedence. This supports published contacts and famous names without
making every occurrence of that value universally safe.
