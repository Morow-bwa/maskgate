from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        app_host="127.0.0.1",
        app_port=8080,
        llm_provider="mock",
        llm_base_url="https://mock.invalid/v1",
        llm_api_key="test-key",
        llm_default_model="test-model",
        gemini_base_url="http://gemini-mock/v1beta",
        gemini_api_key="gemini-test-key",
        gemini_model="gemini-2.5-flash",
        upstream_timeout_seconds=5,
        masking_mode="placeholder",
        mapping_ttl_seconds=3600,
        conversation_ttl_seconds=1800,
        conversation_max_messages=40,
        conversation_max_chars=120000,
        public_email_allowlist=(),
        public_email_domain_allowlist=(),
        public_person_allowlist=(),
        enable_debug_endpoints=True,
        log_level="WARNING",
        block_api_keys=True,
        block_secrets=True,
        block_credit_cards=False,
        enable_playground=True,
        policy_file=Path(__file__).parents[1] / "policies" / "default_policy.yaml",
    )
