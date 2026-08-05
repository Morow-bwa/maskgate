from app.policies.policy_engine import PolicyAction, PolicyEngine


def test_default_policy_blocks_api_keys_and_redacts_cards(settings) -> None:
    policy = PolicyEngine(settings.policy_file)
    assert policy.action_for("API_KEY") is PolicyAction.BLOCK
    assert policy.action_for("CARD_NUMBER") is PolicyAction.REDACT
    assert policy.action_for("EMAIL") is PolicyAction.MASK


def test_environment_can_disable_api_key_block(settings) -> None:
    policy = PolicyEngine(settings.policy_file, block_api_keys=False)
    assert policy.action_for("API_KEY") is PolicyAction.MASK
