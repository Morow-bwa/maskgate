# ADR 0004: Canonical Privacy IR

Status: accepted.

Provider wire dictionaries are parsed into typed turns, text classifications, tool definitions,
tool calls/results, structured output, generation settings, and reviewed extensions. Privacy
Modules do not depend on a remote provider schema. Provider Adapters own serialization, and the
final wire guard checks the Adapter output.

Trade-off: unsupported provider features now block instead of passing through. This is intentional;
new surfaces require typed representation and tests.
