from __future__ import annotations

import asyncio
import hashlib
import math
import secrets
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.application import (
    AdmissionController,
    GlobalCapacityExceeded,
    OperationCapacityExceeded,
    PrincipalCapacityExceeded,
)
from app.observability import PrivacyMetric, PrivacyMetrics, PrivacyStage

PROTECTED_PATH_PREFIXES = (
    "/v1/",
    "/debug/",
    "/playground/api/",
)
MEDIA_UPLOAD_PATH = "/v1/privacy/files/anonymize"
MULTIPART_OVERHEAD_BYTES = 1024 * 1024


def requires_proxy_auth(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES)


def bearer_token_is_allowed(authorization: str | None, allowed_keys: Iterable[str]) -> bool:
    if not authorization:
        return False
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token:
        return False
    allowed = False
    # Compare every configured key so timing does not expose the matching key's
    # position when several tenant credentials are configured.
    for candidate in allowed_keys:
        allowed |= secrets.compare_digest(token, candidate)
    return allowed


def rate_limit_identity(client_host: str | None, authorization: str | None) -> str:
    if authorization:
        scheme, separator, token = authorization.partition(" ")
        canonical_secret = (
            token if separator and scheme.casefold() == "bearer" and token else authorization
        )
        digest = hashlib.sha256(canonical_secret.encode("utf-8")).hexdigest()
        return f"token:{digest}"
    return f"client:{client_host or 'unknown'}"


@dataclass(slots=True)
class _RateWindow:
    started_at: float
    count: int


class FixedWindowRateLimiter:
    """Small in-process guard; deployments should also limit at their edge."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        *,
        max_identities: int = 10_000,
    ) -> None:
        self.max_requests = max(max_requests, 1)
        self.window_seconds = max(window_seconds, 1)
        self.max_identities = max(max_identities, 1)
        self._windows: dict[str, _RateWindow] = {}
        self._lock = threading.Lock()

    def retry_after(self, identity: str, now: float | None = None) -> int | None:
        current = time.monotonic() if now is None else now
        with self._lock:
            self._remove_expired(current)
            window = self._windows.get(identity)
            if window is None:
                if len(self._windows) >= self.max_identities:
                    return self.window_seconds
                self._windows[identity] = _RateWindow(current, 1)
                return None
            if window.count >= self.max_requests:
                remaining = self.window_seconds - (current - window.started_at)
                return max(math.ceil(remaining), 1)
            window.count += 1
            return None

    def _remove_expired(self, now: float) -> None:
        expired = [
            identity
            for identity, window in self._windows.items()
            if window.started_at + self.window_seconds <= now
        ]
        for identity in expired:
            del self._windows[identity]


class _RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Reject oversized protected requests before FastAPI parses their body."""

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int,
        media_file_max_bytes: int | None = None,
    ) -> None:
        self.app = app
        self.max_bytes = max(max_bytes, 1)
        self.media_body_max_bytes = max(
            (media_file_max_bytes or self.max_bytes) + MULTIPART_OVERHEAD_BYTES,
            self.max_bytes,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not requires_proxy_auth(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        body_limit = (
            self.media_body_max_bytes if scope.get("path") == MEDIA_UPLOAD_PATH else self.max_bytes
        )
        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > body_limit:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await self._reject(scope, receive, send, error_type="invalid_content_length")
                return

        received = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > body_limit:
                    raise _RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestBodyTooLarge:
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        error_type: str = "request_too_large",
    ) -> None:
        message = (
            "Request body is too large"
            if error_type == "request_too_large"
            else "Content-Length header is invalid"
        )
        response = JSONResponse(
            status_code=413 if error_type == "request_too_large" else 400,
            content={"error": {"message": message, "type": error_type}},
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)


class AdmissionMiddleware:
    """Hold an aggregate reservation through the complete ASGI response body."""

    def __init__(
        self,
        app: ASGIApp,
        controller: AdmissionController,
        *,
        default_reservation_bytes: int,
        media_reservation_bytes: int,
        metrics: PrivacyMetrics | None = None,
    ) -> None:
        self.app = app
        self.controller = controller
        self.default_reservation_bytes = max(default_reservation_bytes, 1)
        self.media_reservation_bytes = max(media_reservation_bytes, 1)
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not requires_proxy_auth(path):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        authorization_bytes = headers.get(b"authorization")
        authorization = (
            authorization_bytes.decode("latin-1", errors="ignore")
            if authorization_bytes is not None
            else None
        )
        client = scope.get("client")
        client_host = client[0] if isinstance(client, tuple) and client else None
        identity = rate_limit_identity(client_host, authorization)
        amount = (
            self.media_reservation_bytes
            if path == MEDIA_UPLOAD_PATH
            else self.default_reservation_bytes
        )
        started = time.perf_counter()
        try:
            reservation = self.controller.reserve(identity, amount)
        except OperationCapacityExceeded:
            self._record_rejection("OPERATION")
            await self._reject(scope, receive, send, 413, "operation_capacity_exceeded")
            return
        except PrincipalCapacityExceeded:
            self._record_rejection("PRINCIPAL")
            await self._reject(scope, receive, send, 429, "principal_capacity_exceeded")
            return
        except GlobalCapacityExceeded:
            self._record_rejection("GLOBAL")
            await self._reject(scope, receive, send, 503, "global_capacity_exceeded")
            return
        try:
            await self.app(scope, receive, send)
        finally:
            reservation.release()
            if self.metrics is not None:
                self.metrics.observe(PrivacyStage.ADMISSION, time.perf_counter() - started)

    def _record_rejection(self, label: str) -> None:
        if self.metrics is not None:
            self.metrics.increment(PrivacyMetric.ADMISSION_REJECTIONS, taxonomy_label=label)

    @staticmethod
    async def _reject(
        scope: Scope,
        receive: Receive,
        send: Send,
        status_code: int,
        error_type: str,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "message": "The request cannot be admitted within configured capacity",
                    "type": error_type,
                }
            },
            headers={"Cache-Control": "no-store"},
        )
        await response(scope, receive, send)


class OperationDeadlineMiddleware:
    """Apply one absolute wall-clock bound to local work, lock wait, and provider I/O."""

    def __init__(
        self,
        app: ASGIApp,
        timeout_seconds: float,
        metrics: PrivacyMetrics | None = None,
    ) -> None:
        self.app = app
        self.timeout_seconds = max(float(timeout_seconds), 0.001)
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not requires_proxy_auth(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        response_started = False

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        started = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout_seconds):
                await self.app(scope, receive, tracked_send)
        except TimeoutError:
            if self.metrics is not None:
                self.metrics.increment(PrivacyMetric.OPERATION_TIMEOUTS)
            if response_started:
                return
            response = JSONResponse(
                status_code=504,
                content={
                    "error": {
                        "message": "The request exceeded its total execution deadline",
                        "type": "operation_timeout",
                    }
                },
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
        finally:
            if self.metrics is not None:
                self.metrics.observe(PrivacyStage.OPERATION, time.perf_counter() - started)
