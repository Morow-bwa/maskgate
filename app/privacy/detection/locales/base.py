from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LocalePack:
    """Small declarative vocabulary used by deterministic context recognizers."""

    language: str
    aliases: frozenset[str]
    person_labels: tuple[str, ...]
    given_names: frozenset[str]
    organization_prefixes: tuple[str, ...]
    organization_suffixes: tuple[str, ...]
    locations: tuple[str, ...]
    street_markers: tuple[str, ...]
    house_markers: tuple[str, ...]
    unit_markers: tuple[str, ...]
    dob_labels: tuple[str, ...]
    months: tuple[tuple[str, int], ...]
    numeric_date_order: str = "DMY"
