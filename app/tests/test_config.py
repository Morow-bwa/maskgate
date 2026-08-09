from __future__ import annotations

from dataclasses import replace

import pytest

from app.config import _env_int, provider_key_is_configured


def test_env_int_falls_back_for_invalid_values(monkeypatch) -> None:
    monkeypatch.setenv("MASKGATE_TEST_INT", "not-a-number")
    assert _env_int("MASKGATE_TEST_INT", 120) == 120


def test_example_provider_keys_are_not_treated_as_configured() -> None:
    assert provider_key_is_configured("") is False
    assert provider_key_is_configured("replace_me") is False
    assert provider_key_is_configured("your_key_here") is False
    assert provider_key_is_configured("real-looking-secret") is True


def test_production_requires_inbound_proxy_auth(settings) -> None:
    with pytest.raises(ValueError, match="MASKGATE_API_KEYS"):
        replace(
            settings,
            app_env="production",
            require_auth=True,
            api_keys=(),
        )

    with pytest.raises(ValueError, match="REQUIRE_AUTH"):
        replace(
            settings,
            app_env="production",
            require_auth=False,
            api_keys=(),
        )


def test_production_disables_playground(settings) -> None:
    with pytest.raises(ValueError, match="ENABLE_PLAYGROUND"):
        replace(
            settings,
            app_env="production",
            require_auth=True,
            api_keys=("maskgate-test-key",),
            enable_debug_endpoints=False,
            enable_playground=True,
        )


def test_production_requires_real_provider_key_and_https_url(settings) -> None:
    production = {
        "app_env": "production",
        "require_auth": True,
        "api_keys": ("maskgate-test-key",),
        "enable_debug_endpoints": False,
        "enable_playground": False,
    }

    with pytest.raises(ValueError, match="provider API key"):
        replace(settings, **production, llm_api_key="replace-with-provider-key")

    with pytest.raises(ValueError, match="must be HTTPS"):
        replace(settings, **production, llm_base_url="http://provider.invalid/v1")

    with pytest.raises(ValueError, match="without credentials"):
        replace(
            settings,
            **production,
            llm_base_url="https://user:password@provider.invalid/v1?debug=true",
        )
