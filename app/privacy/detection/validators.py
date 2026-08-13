from __future__ import annotations

import re


def _digits(value: str) -> str:
    return re.sub(r"[\s-]", "", value)


def is_valid_luhn(value: str) -> bool:
    digits = _digits(value)
    if not digits.isascii() or not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def is_valid_inn(value: str) -> bool:
    digits = _digits(value)
    if not digits.isascii() or not digits.isdigit():
        return False
    numbers = tuple(int(character) for character in digits)
    if len(numbers) == 10:
        coefficients = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        checksum = sum(
            number * coefficient
            for number, coefficient in zip(numbers[:9], coefficients, strict=True)
        )
        return checksum % 11 % 10 == numbers[9]
    if len(numbers) == 12:
        first = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        second = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        digit_11 = sum(a * b for a, b in zip(numbers[:10], first, strict=True)) % 11 % 10
        digit_12 = sum(a * b for a, b in zip(numbers[:11], second, strict=True)) % 11 % 10
        return digit_11 == numbers[10] and digit_12 == numbers[11]
    return False


def is_valid_snils(value: str) -> bool:
    digits = _digits(value)
    if not digits.isascii() or not digits.isdigit() or len(digits) != 11:
        return False
    weighted = sum(
        int(character) * weight
        for character, weight in zip(digits[:9], range(9, 0, -1), strict=True)
    )
    if weighted < 100:
        checksum = weighted
    elif weighted in {100, 101}:
        checksum = 0
    else:
        checksum = weighted % 101
        if checksum == 100:
            checksum = 0
    return checksum == int(digits[9:])


def is_valid_iban(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not 15 <= len(compact) <= 34 or not compact.isascii() or not compact.isalnum():
        return False
    if not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        encoded = character if character.isdigit() else str(ord(character) - ord("A") + 10)
        for digit in encoded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1
