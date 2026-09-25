from __future__ import annotations

from .base import LocalePack
from .en import PACK as EN_PACK
from .ru import PACK as RU_PACK
from .uk import PACK as UK_PACK

LOCALE_PACKS: tuple[LocalePack, ...] = (EN_PACK, RU_PACK, UK_PACK)


def packs_for_locale(locale: str) -> tuple[LocalePack, ...]:
    normalized = locale.casefold().replace("_", "-")
    if normalized in {"", "und"}:
        return LOCALE_PACKS
    language = normalized.split("-", 1)[0]
    return tuple(
        pack for pack in LOCALE_PACKS if normalized in pack.aliases or language == pack.language
    )


__all__ = ["LOCALE_PACKS", "LocalePack", "packs_for_locale"]
