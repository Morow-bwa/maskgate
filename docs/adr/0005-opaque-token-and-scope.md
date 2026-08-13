# ADR 0005: Opaque token format and scope

Status: accepted.

The secure default token is `<MG:` plus 26 Base32 characters encoding 128 random bits. It exposes
neither entity type nor sequence. Reserved grammar in client input is rejected. Request and
conversation scopes are explicit; conversation scope is used only when the caller requests
conversation state. Semantic placeholders remain an explicit compatibility mode.
