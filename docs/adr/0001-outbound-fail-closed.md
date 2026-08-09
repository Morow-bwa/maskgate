# ADR 0001: Sanitize at the outbound boundary

Status: accepted

## Decision

Recursively inspect every JSON string value and object key immediately before the provider client. Known protocol identifiers are inspected and grammar-validated; if they contain detected sensitive data or cannot be validated, block the request.

## Why

Masking only `messages[].content` leaves tool arguments, metadata, extension fields, and object keys as leak channels. An actual mock-provider HTTP body test is the acceptance boundary.

## Consequences

Provider-specific opaque string fields may require an explicit validated protocol rule. Unknown strings are masked by default, which favors privacy over permissive compatibility.
