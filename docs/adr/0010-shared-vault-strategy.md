# ADR 0010: Shared vault is deferred

Status: accepted.

RAM-only single-process storage remains default. A plaintext network cache would add a larger trust
boundary and persistence risk. A shared Implementation is deferred until authenticated encryption,
tenant key separation, expiry, replay protection, bounded indexes, and operational key rotation are
designed and tested.
