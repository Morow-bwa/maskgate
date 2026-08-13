from __future__ import annotations

import unicodedata
from dataclasses import dataclass

MAX_INPUT_CHARS = 256_000
MAX_OUTPUT_CHARS = 512_000
MAX_EXPANSION_RATIO = 4

_ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})


class CanonicalizationError(ValueError):
    """The input cannot be canonicalized within the configured limits."""


@dataclass(frozen=True, slots=True)
class CanonicalText:
    """A bounded canonical view with provenance back to the original text.

    Each canonical code point owns an original half-open span. Compatibility
    expansion can map several canonical code points to the same original span;
    combining sequences can map one canonical code point to several originals.
    """

    source: str
    text: str
    canonical_to_original: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if len(self.text) != len(self.canonical_to_original):
            raise ValueError("canonical provenance length does not match canonical text")

    @classmethod
    def from_text(
        cls,
        source: str,
        *,
        max_input_chars: int = MAX_INPUT_CHARS,
        max_output_chars: int = MAX_OUTPUT_CHARS,
    ) -> CanonicalText:
        if not isinstance(source, str):
            raise TypeError("canonical input must be text")
        if len(source) > max_input_chars:
            raise CanonicalizationError("input exceeds canonicalization limit")

        output: list[str] = []
        provenance: list[tuple[int, int]] = []
        index = 0
        while index < len(source):
            if source[index] in _ZERO_WIDTH:
                index += 1
                continue

            start = index
            cluster = [" " if source[index] == "\u00a0" else source[index]]
            index += 1
            while index < len(source) and unicodedata.combining(source[index]):
                cluster.append(source[index])
                index += 1

            normalized = unicodedata.normalize("NFKC", "".join(cluster))
            for character in normalized:
                if character in _ZERO_WIDTH:
                    continue
                output.append(" " if character == "\u00a0" else character)
                provenance.append((start, index))

            expansion_limit = max(1, len(source) * MAX_EXPANSION_RATIO)
            if len(output) > max_output_chars or len(output) > expansion_limit:
                raise CanonicalizationError("canonical form exceeds expansion limit")

        return cls(source, "".join(output), tuple(provenance))

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if start < 0 or end <= start or end > len(self.text):
            raise ValueError("canonical span is invalid")
        spans = self.canonical_to_original[start:end]
        return min(item[0] for item in spans), max(item[1] for item in spans)

    def original_text(self, start: int, end: int) -> str:
        original_start, original_end = self.original_span(start, end)
        return self.source[original_start:original_end]
