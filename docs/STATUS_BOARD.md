# Privacy engineering status board

| Issue | Severity | State | Evidence | Review |
|---|---:|---|---|---|
| Reversible surrogate collisions | P0 | fixed | uniqueness and vault bijection tests | independent red team passed |
| Encoded outbound bypass | P0 | fixed | base64/hex/escape/nested JSON tests | independent red team passed |
| Numeric outbound bypass | P0 | fixed | strict provider numeric registries | independent red team passed |
| Opaque DOCX parts | P0 | fixed | OPC allowlist and unknown-part tests | independent red team passed |
| Post-Adapter wire enforcement | P0 | fixed for runtime providers | exact OpenAI/Gemini body tests | independent red team passed |
| Opaque token injection/collision | P1 | fixed | random grammar, injection, budget tests | independent red team passed |
| Structural key symmetry | P1 | fixed | key restoration/collision tests | independent red team passed |
| Output privacy | P1 | fixed for documented fields | new PII/token/metadata tests | independent red team passed |
| Streaming parity | P1 | fixed for Chat fields | every split/tool/multi-choice tests | independent red team passed |
| Conversation mapping GC | P1 | fixed | trim/irreversible/TTL/delete tests | independent red team passed |
| Structured assistant history | P1 | fixed | tool-call history test | independent red team passed |
| Detection v2 | P1 | integrated | recognizer/validator/canonicalization corpus | leader reviewed; quality limits remain |
| Policy/Risk v2 | P1 | integrated | strict schema/context/public assertion tests | leader reviewed |
| Principal/tenant isolation | P1 | integrated | cross-key conversation/vault tests | independent red team passed |
| Canonical IR/provider Adapters | P1 | integrated for OpenAI/Gemini runtime | round trips and exact body tests | leader reviewed |
| Media/resource limits | P2 | integrated | adversarial media/file tests | independent red team passed for DOCX |
| Privacy-safe metrics | P2 | integrated | label/cardinality/latency tests | leader reviewed |
| Application decomposition | P1 | completed | composition root plus route/orchestration Modules | leader reviewed |
| Protocol-key encoded false positives | P1 | fixed | OpenAI/Gemini schema-key regressions | independent red team retest passed |
| OpenAI stream envelope corruption | P1 | fixed | fixed-literal output regression | independent red team retest passed |
| Independent final red team | P0 gate | passed | 28-test adversarial matrix | 28 passed after fixes |

No confirmed P0 remains in the tested scope. A library Adapter is not marked runtime supported
until transport, response, streaming, output, and exact-body coverage all exist.
