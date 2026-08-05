from __future__ import annotations

from app.config import _env_int, provider_key_is_configured


def test_env_int_falls_back_for_invalid_values(monkeypatch) -> None:
    monkeypatch.setenv("MASKGATE_TEST_INT", "not-a-number")
    assert _env_int("MASKGATE_TEST_INT", 120) == 120


def test_example_provider_keys_are_not_treated_as_configured() -> None:
    assert provider_key_is_configured("") is False
    assert provider_key_is_configured("replace_me") is False
    assert provider_key_is_configured("your_key_here") is False
    assert provider_key_is_configured("real-looking-secret") is True
