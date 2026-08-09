from app.security import FixedWindowRateLimiter, rate_limit_identity


def test_rate_limiter_resets_after_window() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=10)

    assert limiter.retry_after("client", now=0.0) is None
    assert limiter.retry_after("client", now=1.0) == 9
    assert limiter.retry_after("client", now=10.0) is None


def test_bearer_identity_is_canonical_across_scheme_case() -> None:
    assert rate_limit_identity("127.0.0.1", "Bearer same-secret") == rate_limit_identity(
        "127.0.0.1", "bearer same-secret"
    )
