from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_list(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


def provider_key_is_configured(value: str | None) -> bool:
    """Return False for empty/example credentials so they never reach an upstream."""
    normalized = (value or "").strip().casefold()
    if not normalized:
        return False
    if normalized in {"replace_me", "replace-me", "changeme", "change_me", "your_key_here"}:
        return False
    return not normalized.startswith(("replace_", "replace-", "your_", "your-"))


@dataclass(frozen=True, slots=True)
class Settings:
    app_env: str
    app_host: str
    app_port: int
    llm_provider: str
    llm_base_url: str
    llm_api_key: str
    llm_default_model: str
    gemini_base_url: str
    gemini_api_key: str
    gemini_model: str
    upstream_timeout_seconds: float
    masking_mode: str
    mapping_ttl_seconds: int
    conversation_ttl_seconds: int
    conversation_max_messages: int
    conversation_max_chars: int
    public_email_allowlist: tuple[str, ...]
    public_email_domain_allowlist: tuple[str, ...]
    public_person_allowlist: tuple[str, ...]
    debug_masking: bool
    enable_debug_endpoints: bool
    store_raw_text: bool
    log_level: str
    block_api_keys: bool
    block_secrets: bool
    block_credit_cards: bool
    enable_playground: bool
    policy_file: Path

    @classmethod
    def from_env(cls) -> "Settings":
        # Loading .env is intentionally limited to configuration; no request data is
        # ever persisted by this application.
        load_dotenv(override=False)
        mode = os.getenv("MASKING_MODE", "placeholder").strip().lower()
        if mode not in {"placeholder", "surrogate", "redact"}:
            mode = "placeholder"
        app_env = os.getenv("APP_ENV", "local")

        return cls(
            app_env=app_env,
            app_host=os.getenv("APP_HOST", "0.0.0.0"),
            app_port=max(_env_int("APP_PORT", 8080), 1),
            llm_provider=os.getenv("LLM_PROVIDER", "openai"),
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_default_model=os.getenv("LLM_DEFAULT_MODEL", "gpt-4.1-mini"),
            gemini_base_url=os.getenv(
                "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
            ).rstrip("/"),
            gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
            upstream_timeout_seconds=max(_env_int("UPSTREAM_TIMEOUT_SECONDS", 120), 1),
            masking_mode=mode,
            mapping_ttl_seconds=max(_env_int("MAPPING_TTL_SECONDS", 3600), 1),
            conversation_ttl_seconds=max(_env_int("CONVERSATION_TTL_SECONDS", 1800), 1),
            conversation_max_messages=max(_env_int("CONVERSATION_MAX_MESSAGES", 40), 4),
            conversation_max_chars=max(_env_int("CONVERSATION_MAX_CHARS", 120000), 1000),
            public_email_allowlist=_env_list("PUBLIC_EMAIL_ALLOWLIST"),
            public_email_domain_allowlist=_env_list("PUBLIC_EMAIL_DOMAIN_ALLOWLIST"),
            public_person_allowlist=_env_list("PUBLIC_PERSON_ALLOWLIST"),
            debug_masking=_env_bool("DEBUG_MASKING", False),
            enable_debug_endpoints=_env_bool("ENABLE_DEBUG_ENDPOINTS", False),
            store_raw_text=_env_bool("STORE_RAW_TEXT", False),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            block_api_keys=_env_bool("BLOCK_API_KEYS", True),
            block_secrets=_env_bool("BLOCK_SECRETS", True),
            block_credit_cards=_env_bool("BLOCK_CREDIT_CARDS", False),
            enable_playground=_env_bool("ENABLE_PLAYGROUND", app_env == "local"),
            policy_file=Path(__file__).parent / "policies" / "default_policy.yaml",
        )
