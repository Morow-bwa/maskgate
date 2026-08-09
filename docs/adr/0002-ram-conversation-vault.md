# ADR 0002: Keep conversation mappings in process RAM

Status: accepted for the educational single-instance design

## Decision

Store masked conversation history and restoration mappings in a bounded in-process vault keyed by security identity and conversation ID.

## Why

This enables multi-turn restoration without persisting original values or operating an external database.

## Consequences

State disappears on restart and cannot be shared safely across workers. Production uses one worker. Horizontal scaling requires a separately reviewed encrypted vault and routing design.
