from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


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
    enable_debug_endpoints: bool
    log_level: str
    block_api_keys: bool
    block_secrets: bool
    block_credit_cards: bool
    enable_playground: bool
    policy_file: Path
    api_keys: tuple[str, ...] = ()
    max_request_body_bytes: int = 1_048_576
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    require_auth: bool = False
    trusted_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")
    max_media_file_bytes: int = 10 * 1024 * 1024
    media_max_concurrency: int = 2
    conversation_max_count: int = 1_000
    max_upstream_response_bytes: int = 8 * 1024 * 1024
    conversation_max_mappings: int = 5_000
    conversation_max_sensitive_bytes: int = 2 * 1024 * 1024
    application_id: str = "maskgate"
    jurisdiction: str = "unspecified"
    default_purpose: str = "remote_llm_processing"
    detector_profile: str = "strict"
    policy_v2_file: Path | None = None

    def __post_init__(self) -> None:
        if self.is_production and not self.require_auth:
            raise ValueError("REQUIRE_AUTH must be true in production")
        if self.require_auth and not self.api_keys:
            raise ValueError(
                "MASKGATE_API_KEYS must contain at least one key when REQUIRE_AUTH is enabled"
            )
        if self.is_production and self.enable_debug_endpoints:
            raise ValueError("ENABLE_DEBUG_ENDPOINTS must be false in production")
        if self.is_production and self.enable_playground:
            raise ValueError("ENABLE_PLAYGROUND must be false in production")
        if self.is_production and "*" in self.trusted_hosts:
            raise ValueError("TRUSTED_HOSTS cannot contain '*' in production")
        if self.is_production:
            provider_name = self.llm_provider.strip().casefold()
            provider_secret = (
                self.gemini_api_key or self.llm_api_key
                if provider_name == "gemini"
                else self.llm_api_key
            )
            provider_url = self.gemini_base_url if provider_name == "gemini" else self.llm_base_url
            if not provider_key_is_configured(provider_secret):
                raise ValueError("A real provider API key is required in production")
            parsed = urlsplit(provider_url)
            if (
                parsed.scheme.casefold() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "The production provider URL must be HTTPS without credentials, "
                    "query, or fragment"
                )

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().casefold() in {"prod", "production"}

    @classmethod
    def from_env(cls) -> "Settings":
        # Loading .env is intentionally limited to configuration; no request data is
        # ever persisted by this application.
        load_dotenv(override=False)
        mode = os.getenv("MASKING_MODE", "placeholder").strip().lower()
        if mode not in {"placeholder", "semantic_placeholder", "surrogate", "redact"}:
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
            enable_debug_endpoints=_env_bool("ENABLE_DEBUG_ENDPOINTS", False),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            block_api_keys=_env_bool("BLOCK_API_KEYS", True),
            block_secrets=_env_bool("BLOCK_SECRETS", True),
            block_credit_cards=_env_bool("BLOCK_CREDIT_CARDS", False),
            enable_playground=_env_bool("ENABLE_PLAYGROUND", app_env == "local"),
            policy_file=Path(__file__).parent / "policies" / "default_policy.yaml",
            api_keys=_env_list("MASKGATE_API_KEYS"),
            max_request_body_bytes=max(_env_int("MAX_REQUEST_BODY_BYTES", 1_048_576), 1_024),
            rate_limit_requests=max(_env_int("RATE_LIMIT_REQUESTS", 60), 1),
            rate_limit_window_seconds=max(_env_int("RATE_LIMIT_WINDOW_SECONDS", 60), 1),
            require_auth=_env_bool(
                "REQUIRE_AUTH",
                app_env.strip().casefold() in {"prod", "production"},
            ),
            trusted_hosts=_env_list("TRUSTED_HOSTS") or ("localhost", "127.0.0.1", "testserver"),
            max_media_file_bytes=max(_env_int("MAX_MEDIA_FILE_BYTES", 10 * 1024 * 1024), 1_024),
            media_max_concurrency=max(_env_int("MEDIA_MAX_CONCURRENCY", 2), 1),
            conversation_max_count=max(_env_int("CONVERSATION_MAX_COUNT", 1_000), 1),
            max_upstream_response_bytes=max(
                _env_int("MAX_UPSTREAM_RESPONSE_BYTES", 8 * 1024 * 1024),
                1_024,
            ),
            conversation_max_mappings=max(_env_int("CONVERSATION_MAX_MAPPINGS", 5_000), 1),
            conversation_max_sensitive_bytes=max(
                _env_int("CONVERSATION_MAX_SENSITIVE_BYTES", 2 * 1024 * 1024),
                1_024,
            ),
            application_id=os.getenv("MASKGATE_APPLICATION_ID", "maskgate").strip() or "maskgate",
            jurisdiction=os.getenv("MASKGATE_JURISDICTION", "unspecified").strip() or "unspecified",
            default_purpose=os.getenv("MASKGATE_DEFAULT_PURPOSE", "remote_llm_processing").strip()
            or "remote_llm_processing",
            detector_profile=(
                os.getenv("DETECTOR_PROFILE", "strict").strip().casefold()
                if os.getenv("DETECTOR_PROFILE", "strict").strip().casefold()
                in {"fast", "balanced", "strict"}
                else "strict"
            ),
            policy_v2_file=(
                Path(os.environ["POLICY_V2_FILE"])
                if os.getenv("POLICY_V2_FILE", "").strip()
                else None
            ),
        )
