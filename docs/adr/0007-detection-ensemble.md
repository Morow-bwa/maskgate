# ADR 0007: Local detection ensemble

Status: accepted.

Detection uses bounded canonicalization with span provenance and pluggable local recognizers.
Validators and context may raise confidence; telemetry receives metadata only. Remote LLM
classification of raw data is prohibited. Corpus metrics are reported as corpus-specific evidence,
not universal recall claims.
