# ADR 0008: Provider Adapter and wire boundary

Status: accepted.

Only Adapter-serialized JSON may enter `FinalWirePrivacyGuard`; only the resulting sealed
`PrivacyCheckedPayload` may enter built-in HTTP transports. Cross-provider extensions and remote
tools fail closed. Tests observe exact `httpx.MockTransport` request bytes.
