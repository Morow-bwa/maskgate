from app.identity import DefaultPrincipalResolver, PrincipalContext


def test_bearer_principal_never_contains_raw_credential() -> None:
    resolver = DefaultPrincipalResolver("demo")
    principal = resolver.resolve(
        authorization="Bearer very-sensitive-tenant-key",
        client_host="127.0.0.1",
    )

    assert "very-sensitive-tenant-key" not in repr(principal)
    assert "very-sensitive-tenant-key" not in principal.vault_namespace
    assert principal.application_id == "demo"
    assert principal.authentication_method == "bearer"


def test_credentials_resolve_to_isolated_namespaces() -> None:
    resolver = DefaultPrincipalResolver()

    first = resolver.resolve(authorization="Bearer tenant-a", client_host=None)
    same = resolver.resolve(authorization="bearer tenant-a", client_host=None)
    second = resolver.resolve(authorization="Bearer tenant-b", client_host=None)

    assert first == same
    assert first.vault_namespace != second.vault_namespace
    assert first.audit_id != second.audit_id
    assert first.rate_limit_key != second.rate_limit_key


def test_principal_rejects_empty_context_fields() -> None:
    try:
        PrincipalContext("", "app", "subject", "bearer")
    except ValueError as exc:
        assert "tenant_id" in str(exc)
    else:
        raise AssertionError("empty tenant must fail closed")
