# Vault

`InMemoryVault` is the only enabled vault Implementation. It is the privacy-first default.

## Properties

- bijective original-to-replacement and replacement-to-original indexes;
- collision rejection;
- cryptographically random opaque tokens (`<MG:` plus 128 random bits in Base32);
- no entity type or sequence counter in opaque tokens;
- explicit item and sensitive-byte budgets;
- request/conversation deletion and TTL cleanup;
- mapping pruning when retained conversation messages no longer reference a replacement;
- no mapping serialization in debug output or logs.

Principal namespaces are derived from authenticated credentials without retaining the credential.
The conversation store key is principal namespace plus conversation ID. Different bearer keys
cannot share a vault even when they submit the same conversation ID.

## Linkability

Runtime token scope is explicit as request or conversation. Conversation scope improves model
continuity but exposes equality within that conversation to the provider. Field, turn, and tenant
scope exist in the policy vocabulary but are not enabled runtime modes. Tenant-wide tokens are not
the default and should not be introduced silently.

## Lifetime and limitations

Originals exist in process memory until the request completes or their referenced conversation
state is pruned/expired/deleted. Python does not guarantee memory zeroization. Swap, crash dumps,
privileged inspection, and host compromise remain outside the guarantee.

Multi-worker deployments do not share mappings. A future shared vault must use authenticated
encryption, tenant-separated keys, expiry, replay controls, bounded indexes, and a revised threat
model. Plaintext Redis mappings are not an acceptable Implementation.
