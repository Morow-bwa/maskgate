from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from .entity_types import EntityType


@dataclass(frozen=True, slots=True)
class PatternSpec:
    entity_type: EntityType
    pattern: Pattern[str]
    capture_group: str | None = None


# Patterns intentionally target high-signal formats. Regex detection is not a
# compliance guarantee and must be supplemented for a particular organization.
PATTERNS: tuple[PatternSpec, ...] = (
    PatternSpec(
        EntityType.API_KEY,
        re.compile(
            r"(?i)\b(?:sk-[a-z0-9_-]{16,}|rk-[a-z0-9_-]{16,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
            r"xox[baprs]-[a-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b"
        ),
    ),
    PatternSpec(
        EntityType.API_KEY,
        re.compile(
            r"(?is)\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|secret|password|passwd)\s*"
            r"[:=]\s*[\"']?(?P<value>[A-Za-z0-9_./+=-]{12,})"
        ),
        capture_group="value",
    ),
    PatternSpec(
        EntityType.URL,
        re.compile(r"(?i)\bhttps?://[^\s<>\"']+"),
    ),
    PatternSpec(
        EntityType.EMAIL,
        # Allow sentence punctuation after an address; the candidate
        # normalizer removes it without allowing a partial domain match.
        re.compile(r"(?i)(?<![\w.+-])[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+(?![\w-])"),
    ),
    PatternSpec(
        EntityType.FILE_PATH,
        re.compile(
            r"(?<![\w])(?:[A-Za-z]:\\|\\\\)"
            r"(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]+?\.[A-Za-z0-9]{1,10}(?![\w])"
        ),
    ),
    PatternSpec(
        EntityType.FILE_PATH,
        re.compile(r"(?<![\w:])/(?:[^\s/<>\"']+/)+[^\s/<>\"']+"),
    ),
    PatternSpec(
        EntityType.CARD_NUMBER,
        # Keep separators between digits, but never consume whitespace after
        # the final digit. Otherwise replacement text can glue to the next
        # word: ``[REDACTED_CARD_NUMBER]и``.
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    ),
    PatternSpec(
        EntityType.INN,
        # The label makes this high-confidence and prevents ordinary 10/12
        # digit identifiers from being classified as phone numbers.
        re.compile(r"(?i)(?<![\w-])ИНН\s*(?P<value>\d{10,12})(?!\d)"),
        capture_group="value",
    ),
    PatternSpec(
        EntityType.IP_ADDRESS,
        re.compile(
            r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w])"
        ),
    ),
    PatternSpec(
        EntityType.PHONE,
        # Dots are intentionally excluded here so dotted IPv4 addresses do
        # not get classified as phone numbers during overlap resolution.
        re.compile(r"(?<!\w)(?:\+?\d[\d\s()\-]{7,}\d)(?!\w)"),
    ),
    PatternSpec(
        EntityType.MONEY,
        re.compile(
            r"(?ix)(?<!\w)"
            r"(?:\d+|\d{1,3}(?:[,.\s]\d{3})+)(?:[,.]\d{2})?\s?"
            r"(?:USD|EUR|GBP|RUB|руб\.?|долл\.?|доллар(?:ов|а|ы)?|евро|руб(?:лей|ля|ль)?)"
            r"(?!\w)"
        ),
    ),
    PatternSpec(
        EntityType.MONEY,
        re.compile(
            r"(?ix)(?<!\w)(?:"
            r"[$€£₽]\s?\d{1,3}(?:[,.\s]\d{3})*(?:[,.]\d{2})?|"
            r"\d{1,3}(?:[,.\s]\d{3})*(?:[,.]\d{2})?\s?(?:USD|EUR|GBP|RUB|руб\.?|долл\.?|евро)"
            r")(?!\w)"
        ),
    ),
    PatternSpec(
        EntityType.DOMAIN,
        re.compile(
            r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            # Permit sentence punctuation after the domain; the candidate
            # normalizer removes it without weakening the domain boundary.
            r"[a-z]{2,63}(?::\d{2,5})?(?![\w-])"
        ),
    ),
    PatternSpec(
        EntityType.PERSON,
        # Conservative title-cased two/three-token Cyrillic names. Requiring
        # lowercase letters after the initial capital prevents ordinary
        # sentence fragments from being interpreted as people. This is
        # intentionally not a general NER model; public names can be
        # explicitly allowlisted.
        re.compile(
            r"(?<![\w-])"
            r"(?!(?:Автор|Контакт|Клиент|Пользователь|Господин|Госпожа|Мистер|Миссис)\b)"
            r"(?:[А-ЯЁ][а-яё'’-]+\s+)"
            r"(?:[А-ЯЁ][а-яё'’-]+)"
            r"(?:\s+[А-ЯЁ][а-яё'’-]+)?"
            r"(?![\w-])"
        ),
    ),
)


ENTITY_PRIORITY: dict[EntityType, int] = {
    EntityType.API_KEY: 100,
    EntityType.URL: 95,
    EntityType.EMAIL: 90,
    EntityType.FILE_PATH: 85,
    EntityType.CARD_NUMBER: 80,
    EntityType.INN: 78,
    EntityType.PHONE: 75,
    EntityType.IP_ADDRESS: 70,
    EntityType.MONEY: 65,
    EntityType.DOMAIN: 60,
    EntityType.PERSON: 50,
    EntityType.ORG: 45,
    EntityType.LOCATION: 40,
    EntityType.BANK: 35,
}
