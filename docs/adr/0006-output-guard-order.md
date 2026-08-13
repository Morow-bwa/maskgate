# ADR 0006: Output guard ordering

Status: accepted.

Provider output is inspected before restoration. Only active replacements in approved semantic
fields may be restored. Unknown tokens and newly generated sensitive values are redacted. Restored
text is inspected again while active originals are explicitly authorized. Provider-safe history is
stored before rehydration, so conversation RAM contains tokens rather than restored originals.
