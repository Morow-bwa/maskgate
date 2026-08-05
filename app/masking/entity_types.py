from __future__ import annotations

from enum import StrEnum


class EntityType(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    API_KEY = "API_KEY"
    FILE_PATH = "FILE_PATH"
    MONEY = "MONEY"
    CARD_NUMBER = "CARD_NUMBER"
    PERSON = "PERSON"
    ORG = "ORG"
    BANK = "BANK"
    INN = "INN"
    SNILS = "SNILS"
    PASSPORT = "PASSPORT"
    LOCATION = "LOCATION"


SUPPORTED_REGEX_TYPES = {
    EntityType.EMAIL,
    EntityType.PHONE,
    EntityType.IP_ADDRESS,
    EntityType.URL,
    EntityType.DOMAIN,
    EntityType.API_KEY,
    EntityType.FILE_PATH,
    EntityType.MONEY,
    EntityType.CARD_NUMBER,
    EntityType.INN,
}
