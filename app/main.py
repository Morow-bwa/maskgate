from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings, provider_key_is_configured
from app.debug.routes import build_debug_router
from app.logging_config import configure_logging
from app.masking.anonymizer import MaskingSession
from app.masking.detector import RegexDetector
from app.masking.media_guard import UnsafeMediaBlocked, reject_unsanitized_media
from app.masking.rehydrator import rehydrate
from app.media.routes import build_media_router
from app.media.sanitizer import MediaSanitizer
from app.policies.policy_engine import PolicyBlocked, PolicyEngine
from app.proxy.gemini_client import GeminiClient
from app.proxy.llm_client import LLMClient, LLMUpstreamError
from app.proxy.openai_compatible import add_masking_instruction, request_to_payload
from app.proxy.outbound_sanitizer import sanitize_outbound_payload
from app.proxy.streaming import StreamingRehydrator, extract_delta_text, replace_delta_text
from app.schemas import ChatCompletionRequest
from app.security import (
    FixedWindowRateLimiter,
    RequestBodyLimitMiddleware,
    bearer_token_is_allowed,
    rate_limit_identity,
    requires_proxy_auth,
)
from app.storage.conversation_store import (
    ConversationCapacityExceeded,
    ConversationState,
    InMemoryConversationStore,
    validate_conversation_id,
)
from app.storage.mapping_store import InMemoryMappingStore

logger = logging.getLogger("maskgate")
PLAYGROUND_DIR = Path(__file__).resolve().parents[1] / "playground-react" / "dist"


@dataclass(frozen=True, slots=True)
class ChatExecution:
    status_code: int
    payload: Any
    trace: dict[str, object]


def _error_payload(message: str, error_type: str, **extra: object) -> dict[str, object]:
    return {"error": {"message": message, "type": error_type, **extra}}


def _assistant_message_from_response(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict) or not isinstance(message.get("content"), (str, list)):
        return None
    return {"role": "assistant", "content": deepcopy(message["content"])}


def _preview_response(model: str) -> dict[str, object]:
    """Return an empty success envelope for a local-only Playground preview."""
    return {
        "id": f"chatcmpl-preview-{uuid.uuid4().hex[:16]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [],
        "preview_only": True,
    }


def create_app(
    settings: Settings | None = None,
    *,
    llm_client: Any | None = None,
    ocr_adapter: Any | None = None,
    face_detector: Any | None = None,
    playground_dir: Path | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    playground_dir = playground_dir or PLAYGROUND_DIR
    configure_logging(settings.log_level)
    detector = RegexDetector()
    policy = PolicyEngine(
        settings.policy_file,
        block_api_keys=settings.block_api_keys,
        block_secrets=settings.block_secrets,
        block_credit_cards=settings.block_credit_cards,
        public_email_allowlist=settings.public_email_allowlist,
        public_email_domain_allowlist=settings.public_email_domain_allowlist,
        public_person_allowlist=settings.public_person_allowlist,
    )
    mapping_store = InMemoryMappingStore(settings.mapping_ttl_seconds)
    conversation_store = InMemoryConversationStore(
        settings.conversation_ttl_seconds,
        settings.conversation_max_messages,
        settings.conversation_max_chars,
        settings.conversation_max_count,
    )
    media_sanitizer = MediaSanitizer(
        detector,
        policy,
        settings.max_media_file_bytes,
        ocr_adapter=ocr_adapter,
        face_detector=face_detector,
    )
    if llm_client is not None:
        upstream = llm_client
    elif settings.llm_provider.lower() == "gemini":
        upstream = GeminiClient(
            settings.gemini_base_url,
            settings.gemini_api_key or settings.llm_api_key,
            settings.upstream_timeout_seconds,
            max_response_bytes=settings.max_upstream_response_bytes,
        )
    else:
        upstream = LLMClient(
            settings.llm_base_url,
            settings.llm_api_key,
            settings.upstream_timeout_seconds,
            max_response_bytes=settings.max_upstream_response_bytes,
        )
    provider_name = settings.llm_provider.lower()
    provider_secret = settings.gemini_api_key if provider_name == "gemini" else settings.llm_api_key
    if provider_name == "gemini" and not provider_secret:
        provider_secret = settings.llm_api_key
    provider_ready = llm_client is not None or provider_key_is_configured(provider_secret)
    rate_limiter = FixedWindowRateLimiter(
        settings.rate_limit_requests,
        settings.rate_limit_window_seconds,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield

    app = FastAPI(
        title="MaskGate",
        version="0.1.0",
        description="Self-hosted OpenAI-compatible privacy proxy for LLM applications.",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=settings.max_request_body_bytes,
        media_file_max_bytes=settings.max_media_file_bytes,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.trusted_hosts),
    )
    app.state.settings = settings
    app.state.detector = detector
    app.state.policy = policy
    app.state.mapping_store = mapping_store
    app.state.conversation_store = conversation_store
    app.state.llm_client = upstream
    app.state.provider_ready = provider_ready
    app.state.media_sanitizer = media_sanitizer

    @app.middleware("http")
    async def proxy_authentication(request: Request, call_next: Any) -> Response:
        if requires_proxy_auth(request.url.path):
            authorization = request.headers.get("authorization")
            if settings.api_keys and not bearer_token_is_allowed(authorization, settings.api_keys):
                return JSONResponse(
                    status_code=401,
                    content=_error_payload("Invalid or missing proxy API key", "unauthorized"),
                    headers={
                        "WWW-Authenticate": "Bearer",
                        "Cache-Control": "no-store",
                    },
                )
            security_identity = rate_limit_identity(
                request.client.host if request.client else None,
                authorization if settings.api_keys else None,
            )
            request.state.security_identity = security_identity
            retry_after = rate_limiter.retry_after(security_identity)
            if retry_after is not None:
                return JSONResponse(
                    status_code=429,
                    content=_error_payload("Rate limit exceeded", "rate_limit_exceeded"),
                    headers={
                        "Retry-After": str(retry_after),
                        "Cache-Control": "no-store",
                    },
                )
        return await call_next(request)

    # Registered after authentication so it is the outermost application
    # middleware and also decorates early 401/413/429/host-rejection responses.
    @app.middleware("http")
    async def privacy_response_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'",
        )
        if request.url.path.startswith(("/v1", "/playground/api", "/debug")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    @app.get("/health/live")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def readiness() -> JSONResponse:
        if not provider_ready:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "provider_ready": False},
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(content={"status": "ready", "provider_ready": True})

    async def execute_conversation_chat(
        request: ChatCompletionRequest,
        conversation_id: str,
        owner_id: str,
        request_id: str,
        started: float,
        requested_mode: str,
        allow_preview: bool = False,
    ) -> ChatExecution:
        try:
            state = conversation_store.get_or_create(
                conversation_id,
                owner_id,
                lambda: MaskingSession(requested_mode, policy),
            )
        except ConversationCapacityExceeded:
            return ChatExecution(
                503,
                _error_payload(
                    "Conversation capacity is temporarily exhausted",
                    "conversation_capacity_exceeded",
                ),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        base_trace: dict[str, object] = {
            "request_id": request_id,
            "masking_mode": requested_mode,
            "conversation_id": conversation_id,
            "conversation_store": "ram",
            "conversation_turn": state.turn_count + 1,
            "detected_entity_types": [],
            "detected_entities_count": 0,
            "allowlisted_entity_types": [],
            "masked_request": None,
            "upstream_response": None,
        }
        if request.stream:
            return ChatExecution(
                400,
                _error_payload(
                    "Streaming is not supported in the MVP version",
                    "unsupported_feature",
                ),
                base_trace,
            )

        async with state.lock:
            payload = request_to_payload(request)
            payload.pop("masking_mode", None)
            payload.pop("conversation_id", None)
            try:
                reject_unsanitized_media(payload)
            except UnsafeMediaBlocked as exc:
                if not state.messages and not state.session.items:
                    conversation_store.delete(conversation_id, owner_id)
                return ChatExecution(
                    400,
                    _error_payload(str(exc), "media_not_sanitized", media_type=exc.media_type),
                    {
                        **base_trace,
                        "blocked_media": True,
                        "masked_request": None,
                    },
                )
            detected_types: list[str] = []
            allowlisted_types: list[str] = []
            session = state.session.clone()

            def mask_message(text: str) -> str:
                entities = detector.detect(text)
                detected_types.extend(entity.type for entity in entities)
                allowlisted_types.extend(
                    entity.type
                    for entity in entities
                    if policy.is_public_allowlisted(entity.type, entity.text)
                )
                return session.mask_text(text, entities)

            try:
                payload = sanitize_outbound_payload(payload, mask_message)
                outbound_payload = deepcopy(payload)
                outbound_payload["messages"] = deepcopy(state.messages) + deepcopy(
                    payload.get("messages", [])
                )
                add_masking_instruction(outbound_payload, session.items)
                mapping_store.put(request_id, session.items)
                base_trace["masked_request"] = outbound_payload
            except PolicyBlocked as exc:
                if not state.messages and not state.session.items:
                    conversation_store.delete(conversation_id, owner_id)
                preview_payload = request_to_payload(request)
                preview_payload.pop("masking_mode", None)
                preview_payload.pop("conversation_id", None)
                preview_policy = PolicyEngine(
                    settings.policy_file,
                    block_api_keys=False,
                    block_secrets=False,
                    block_credit_cards=False,
                    public_email_allowlist=settings.public_email_allowlist,
                    public_email_domain_allowlist=settings.public_email_domain_allowlist,
                    public_person_allowlist=settings.public_person_allowlist,
                )
                preview_session = state.session.clone(policy=preview_policy)

                def preview_mask_message(text: str) -> str:
                    return preview_session.mask_text(text, detector.detect(text))

                preview_payload = sanitize_outbound_payload(
                    preview_payload,
                    preview_mask_message,
                    validate_protocol=False,
                )
                preview_outbound = deepcopy(preview_payload)
                preview_outbound["messages"] = deepcopy(state.messages) + deepcopy(
                    preview_payload.get("messages", [])
                )
                add_masking_instruction(preview_outbound, preview_session.items)
                unique_types = list(dict.fromkeys(detected_types + exc.entity_types))
                base_trace.update(
                    {
                        "detected_entity_types": unique_types,
                        "detected_entities_count": len(unique_types),
                        "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                        "blocked_entities": list(dict.fromkeys(exc.entity_types)),
                        "masked_request": preview_outbound,
                        "preview_only": True,
                    }
                )
                _log_request(
                    request_id=request_id,
                    model=request.model,
                    masking_mode=requested_mode,
                    detected_types=unique_types,
                    policy_result="BLOCK",
                    latency_ms=_latency_ms(started),
                    status_code=400,
                )
                return ChatExecution(
                    400,
                    _error_payload(
                        "Request blocked because sensitive data was detected",
                        "policy_block",
                        entities=list(dict.fromkeys(exc.entity_types)),
                    ),
                    base_trace,
                )

            try:
                if not provider_ready:
                    if not allow_preview:
                        return ChatExecution(
                            503,
                            _error_payload(
                                "The upstream provider is not configured",
                                "provider_not_configured",
                            ),
                            {**base_trace, "provider_ready": False},
                        )
                    base_trace.update(
                        {
                            "detected_entity_types": list(dict.fromkeys(detected_types)),
                            "detected_entities_count": len(detected_types),
                            "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                            "preview_only": True,
                            "preview_reason": "provider_not_configured",
                            "provider_ready": False,
                            "latency_ms": _latency_ms(started),
                            "status_code": 200,
                        }
                    )
                    _log_request(
                        request_id=request_id,
                        model=request.model,
                        masking_mode=requested_mode,
                        detected_types=detected_types,
                        policy_result="MASK" if session.items else "ALLOW",
                        latency_ms=_latency_ms(started),
                        status_code=200,
                    )
                    return ChatExecution(200, _preview_response(request.model), base_trace)
                result = await upstream.complete(outbound_payload)
                response_payload = rehydrate(result.payload, session.items)
                unique_types = list(dict.fromkeys(detected_types))
                base_trace.update(
                    {
                        "detected_entity_types": unique_types,
                        "detected_entities_count": len(detected_types),
                        "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                        "upstream_response": result.payload,
                        "latency_ms": _latency_ms(started),
                        "status_code": result.status_code,
                    }
                )
                if result.status_code < 400:
                    conversation_messages = deepcopy(state.messages)
                    conversation_messages.extend(deepcopy(payload.get("messages", [])))
                    assistant_message = _assistant_message_from_response(result.payload)
                    if assistant_message is not None:
                        conversation_messages.append(assistant_message)
                    conversation_store.commit(state, session, conversation_messages)
                    base_trace["conversation_message_count"] = len(state.messages)
                _log_request(
                    request_id=request_id,
                    model=request.model,
                    masking_mode=requested_mode,
                    detected_types=detected_types,
                    policy_result="ALLOW" if not session.items else "MASK",
                    latency_ms=_latency_ms(started),
                    status_code=result.status_code,
                )
                return ChatExecution(result.status_code, response_payload, base_trace)
            except LLMUpstreamError as exc:
                base_trace.update(
                    {
                        "detected_entity_types": list(dict.fromkeys(detected_types)),
                        "detected_entities_count": len(detected_types),
                        "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                        "latency_ms": _latency_ms(started),
                        "status_code": 502,
                    }
                )
                _log_request(
                    request_id=request_id,
                    model=request.model,
                    masking_mode=requested_mode,
                    detected_types=detected_types,
                    policy_result="MASK" if session.items else "ALLOW",
                    latency_ms=_latency_ms(started),
                    status_code=502,
                    error_type=exc.error_type,
                )
                return ChatExecution(502, _error_payload(exc.message, exc.error_type), base_trace)
            finally:
                mapping_store.delete(request_id)

    async def stream_chat(
        request: ChatCompletionRequest,
        conversation_id_override: str | None = None,
        owner_id: str = "local:unknown",
    ) -> Response:
        request_id = f"req_{uuid.uuid4().hex}"
        if not provider_ready:
            return JSONResponse(
                status_code=503,
                content=_error_payload(
                    "The upstream provider is not configured",
                    "provider_not_configured",
                ),
            )
        requested_mode = request.masking_mode or settings.masking_mode
        if requested_mode not in {"placeholder", "surrogate", "redact"}:
            return JSONResponse(
                status_code=422,
                content=_error_payload(
                    "masking_mode must be placeholder, surrogate, or redact",
                    "invalid_masking_mode",
                ),
            )
        try:
            conversation_id = validate_conversation_id(
                conversation_id_override or request.conversation_id
            )
        except ValueError as exc:
            return JSONResponse(
                status_code=422, content=_error_payload(str(exc), "invalid_conversation_id")
            )

        state: ConversationState | None = None
        if conversation_id:
            try:
                state = conversation_store.get_or_create(
                    conversation_id,
                    owner_id,
                    lambda: MaskingSession(requested_mode, policy),
                )
            except ConversationCapacityExceeded:
                return JSONResponse(
                    status_code=503,
                    content=_error_payload(
                        "Conversation capacity is temporarily exhausted",
                        "conversation_capacity_exceeded",
                    ),
                )
            await state.lock.acquire()

        payload = request_to_payload(request)
        payload.pop("masking_mode", None)
        payload.pop("conversation_id", None)
        try:
            reject_unsanitized_media(payload)
        except UnsafeMediaBlocked as exc:
            if state is not None:
                if not state.messages and not state.session.items:
                    conversation_store.delete(state.conversation_id, state.owner_id)
                state.lock.release()
            return JSONResponse(
                status_code=400,
                content=_error_payload(str(exc), "media_not_sanitized", media_type=exc.media_type),
            )
        session = state.session.clone() if state else MaskingSession(requested_mode, policy)
        try:
            payload = sanitize_outbound_payload(
                payload,
                lambda text: session.mask_text(text, detector.detect(text)),
            )
            outbound_payload = deepcopy(payload)
            if state is not None:
                outbound_payload["messages"] = deepcopy(state.messages) + deepcopy(
                    payload.get("messages", [])
                )
            add_masking_instruction(outbound_payload, session.items)
        except PolicyBlocked as exc:
            if state is not None:
                if not state.messages and not state.session.items:
                    conversation_store.delete(state.conversation_id, state.owner_id)
                state.lock.release()
            return JSONResponse(
                status_code=400,
                content=_error_payload(
                    "Request blocked because sensitive data was detected",
                    "policy_block",
                    entities=list(dict.fromkeys(exc.entity_types)),
                ),
            )

        if not hasattr(upstream, "complete_stream"):
            if state is not None:
                state.lock.release()
            return JSONResponse(
                status_code=501,
                content=_error_payload(
                    "The configured upstream does not support streaming",
                    "unsupported_feature",
                ),
            )

        mapping_store.put(request_id, session.items)

        async def event_generator():
            provider_text = ""
            completed = False
            rehydrator = StreamingRehydrator(session.items)
            try:
                async for event in upstream.complete_stream(outbound_payload):
                    delta = extract_delta_text(event)
                    if delta:
                        provider_text += delta
                        visible = rehydrator.push(delta)
                        event = replace_delta_text(event, visible)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

                tail = rehydrator.finish()
                if tail:
                    tail_event = {
                        "object": "chat.completion.chunk",
                        "choices": [
                            {"index": 0, "delta": {"content": tail}, "finish_reason": None}
                        ],
                    }
                    yield f"data: {json.dumps(tail_event, ensure_ascii=False)}\n\n"
                completed = True
                if state is not None:
                    conversation_messages = deepcopy(state.messages)
                    conversation_messages.extend(deepcopy(payload.get("messages", [])))
                    if provider_text:
                        conversation_messages.append(
                            {"role": "assistant", "content": provider_text}
                        )
                    conversation_store.commit(state, session, conversation_messages)
                yield "data: [DONE]\n\n"
            except LLMUpstreamError as exc:
                error_event = {"error": {"type": exc.error_type, "message": exc.message}}
                yield f"data: {json.dumps(error_event, ensure_ascii=False)}\n\n"
            finally:
                mapping_store.delete(request_id)
                if state is not None:
                    if not completed:
                        state.last_access_at = time.time()
                    state.lock.release()

        headers = {
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-MaskGate-Request-ID": request_id,
        }
        if conversation_id:
            headers["X-MaskGate-Conversation-ID"] = conversation_id
        return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)

    async def execute_chat(
        request: ChatCompletionRequest,
        conversation_id_override: str | None = None,
        owner_id: str = "local:unknown",
        allow_preview: bool = False,
    ) -> ChatExecution:
        request_id = f"req_{uuid.uuid4().hex}"
        started = time.perf_counter()
        payload = request_to_payload(request)
        requested_mode = request.masking_mode or settings.masking_mode
        if requested_mode not in {"placeholder", "surrogate", "redact"}:
            return ChatExecution(
                422,
                _error_payload(
                    "masking_mode must be placeholder, surrogate, or redact",
                    "invalid_masking_mode",
                ),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        if not provider_ready and not allow_preview:
            return ChatExecution(
                503,
                _error_payload(
                    "The upstream provider is not configured",
                    "provider_not_configured",
                ),
                {
                    "request_id": request_id,
                    "masking_mode": requested_mode,
                    "provider_ready": False,
                },
            )
        try:
            conversation_id = validate_conversation_id(
                conversation_id_override or request.conversation_id
            )
        except ValueError as exc:
            return ChatExecution(
                422,
                _error_payload(str(exc), "invalid_conversation_id"),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        if conversation_id:
            return await execute_conversation_chat(
                request,
                conversation_id,
                owner_id,
                request_id,
                started,
                requested_mode,
                allow_preview,
            )
        payload.pop("masking_mode", None)
        payload.pop("conversation_id", None)
        detected_types: list[str] = []
        allowlisted_types: list[str] = []
        session = MaskingSession(requested_mode, policy)
        base_trace: dict[str, object] = {
            "request_id": request_id,
            "masking_mode": requested_mode,
            "detected_entity_types": [],
            "detected_entities_count": 0,
            "allowlisted_entity_types": [],
            "masked_request": None,
            "upstream_response": None,
        }

        try:
            reject_unsanitized_media(payload)
        except UnsafeMediaBlocked as exc:
            return ChatExecution(
                400,
                _error_payload(str(exc), "media_not_sanitized", media_type=exc.media_type),
                {**base_trace, "blocked_media": True, "masked_request": None},
            )

        if request.stream:
            return ChatExecution(
                400,
                _error_payload(
                    "Streaming is not supported in the MVP version",
                    "unsupported_feature",
                ),
                base_trace,
            )

        try:

            def mask_message(text: str) -> str:
                entities = detector.detect(text)
                detected_types.extend(entity.type for entity in entities)
                allowlisted_types.extend(
                    entity.type
                    for entity in entities
                    if policy.is_public_allowlisted(entity.type, entity.text)
                )
                return session.mask_text(text, entities)

            payload = sanitize_outbound_payload(payload, mask_message)
            add_masking_instruction(payload, session.items)
            mapping_store.put(request_id, session.items)
            base_trace["masked_request"] = payload
        except PolicyBlocked as exc:
            unique_types = list(dict.fromkeys(detected_types + exc.entity_types))
            # The Playground can show a local-only preview of what masking would
            # produce, but this preview is never sent upstream when policy blocks.
            preview_payload = request_to_payload(request)
            preview_payload.pop("masking_mode", None)
            preview_payload.pop("conversation_id", None)
            preview_policy = PolicyEngine(
                settings.policy_file,
                block_api_keys=False,
                block_secrets=False,
                block_credit_cards=False,
                public_email_allowlist=settings.public_email_allowlist,
                public_email_domain_allowlist=settings.public_email_domain_allowlist,
                public_person_allowlist=settings.public_person_allowlist,
            )
            preview_session = MaskingSession(requested_mode, preview_policy)

            def preview_mask_message(text: str) -> str:
                return preview_session.mask_text(text, detector.detect(text))

            preview_payload = sanitize_outbound_payload(
                preview_payload,
                preview_mask_message,
                validate_protocol=False,
            )
            add_masking_instruction(preview_payload, preview_session.items)
            base_trace.update(
                {
                    "detected_entity_types": unique_types,
                    "detected_entities_count": len(unique_types),
                    "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                    "blocked_entities": list(dict.fromkeys(exc.entity_types)),
                    "masked_request": preview_payload,
                    "preview_only": True,
                }
            )
            _log_request(
                request_id=request_id,
                model=request.model,
                masking_mode=requested_mode,
                detected_types=unique_types,
                policy_result="BLOCK",
                latency_ms=_latency_ms(started),
                status_code=400,
            )
            return ChatExecution(
                400,
                _error_payload(
                    "Request blocked because sensitive data was detected",
                    "policy_block",
                    entities=list(dict.fromkeys(exc.entity_types)),
                ),
                base_trace,
            )

        try:
            if not provider_ready:
                base_trace.update(
                    {
                        "detected_entity_types": list(dict.fromkeys(detected_types)),
                        "detected_entities_count": len(detected_types),
                        "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                        "preview_only": True,
                        "preview_reason": "provider_not_configured",
                        "provider_ready": False,
                        "latency_ms": _latency_ms(started),
                        "status_code": 200,
                    }
                )
                _log_request(
                    request_id=request_id,
                    model=request.model,
                    masking_mode=requested_mode,
                    detected_types=detected_types,
                    policy_result="MASK" if session.items else "ALLOW",
                    latency_ms=_latency_ms(started),
                    status_code=200,
                )
                return ChatExecution(200, _preview_response(request.model), base_trace)
            result = await upstream.complete(payload)
            response_payload = rehydrate(result.payload, session.items)
            unique_types = list(dict.fromkeys(detected_types))
            base_trace.update(
                {
                    "detected_entity_types": unique_types,
                    "detected_entities_count": len(detected_types),
                    "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                    "upstream_response": result.payload,
                    "latency_ms": _latency_ms(started),
                    "status_code": result.status_code,
                }
            )
            _log_request(
                request_id=request_id,
                model=request.model,
                masking_mode=requested_mode,
                detected_types=detected_types,
                policy_result="ALLOW" if not detected_types else "MASK",
                latency_ms=_latency_ms(started),
                status_code=result.status_code,
            )
            return ChatExecution(result.status_code, response_payload, base_trace)
        except LLMUpstreamError as exc:
            base_trace.update(
                {
                    "detected_entity_types": list(dict.fromkeys(detected_types)),
                    "detected_entities_count": len(detected_types),
                    "allowlisted_entity_types": list(dict.fromkeys(allowlisted_types)),
                    "latency_ms": _latency_ms(started),
                    "status_code": 502,
                }
            )
            _log_request(
                request_id=request_id,
                model=request.model,
                masking_mode=requested_mode,
                detected_types=detected_types,
                policy_result="MASK" if detected_types else "ALLOW",
                latency_ms=_latency_ms(started),
                status_code=502,
                error_type=exc.error_type,
            )
            return ChatExecution(502, _error_payload(exc.message, exc.error_type), base_trace)
        finally:
            # Request mappings are intentionally deleted even when the upstream
            # fails; TTL remains a second line of defense for abandoned flows.
            mapping_store.delete(request_id)

    @app.post("/v1/chat/completions")
    async def chat_completions(
        http_request: Request,
        request: ChatCompletionRequest,
        x_maskgate_conversation_id: str | None = Header(default=None),
    ) -> Response:
        owner_id = getattr(http_request.state, "security_identity", "client:unknown")
        if request.stream:
            return await stream_chat(request, x_maskgate_conversation_id, owner_id)
        execution = await execute_chat(request, x_maskgate_conversation_id, owner_id)
        return JSONResponse(status_code=execution.status_code, content=execution.payload)

    app.include_router(
        build_media_router(
            media_sanitizer,
            max_concurrency=settings.media_max_concurrency,
        )
    )

    if settings.enable_debug_endpoints:
        app.include_router(build_debug_router(detector, policy, settings.masking_mode))

    if settings.enable_playground and playground_dir.is_dir():
        app.mount(
            "/playground/assets",
            StaticFiles(directory=playground_dir / "assets"),
            name="playground-assets",
        )

        @app.get("/playground", include_in_schema=False)
        @app.get("/playground/", include_in_schema=False)
        async def playground() -> FileResponse:
            return FileResponse(playground_dir / "index.html")

        @app.get("/playground/config", include_in_schema=False)
        async def playground_config() -> dict[str, object]:
            return {
                "provider": settings.llm_provider,
                "model": settings.gemini_model
                if provider_name == "gemini"
                else settings.llm_default_model,
                "masking_mode": settings.masking_mode,
                "conversation_store": "ram",
                "conversation_ttl_seconds": settings.conversation_ttl_seconds,
                "provider_ready": provider_ready,
            }

        @app.post("/playground/api/chat", include_in_schema=False)
        async def playground_chat(
            http_request: Request,
            request: ChatCompletionRequest,
            x_maskgate_conversation_id: str | None = Header(default=None),
        ) -> Response:
            owner_id = getattr(http_request.state, "security_identity", "client:unknown")
            if request.stream:
                return await stream_chat(request, x_maskgate_conversation_id, owner_id)
            execution = await execute_chat(
                request,
                x_maskgate_conversation_id,
                owner_id,
                allow_preview=True,
            )
            return JSONResponse(
                status_code=execution.status_code,
                content={"response": execution.payload, "trace": execution.trace},
            )

        @app.delete("/playground/api/conversations/{conversation_id}", include_in_schema=False)
        async def clear_playground_conversation(
            http_request: Request,
            conversation_id: str,
        ) -> JSONResponse:
            try:
                validated_id = validate_conversation_id(conversation_id)
            except ValueError as exc:
                return JSONResponse(
                    status_code=422,
                    content=_error_payload(str(exc), "invalid_conversation_id"),
                )
            owner_id = getattr(http_request.state, "security_identity", "client:unknown")
            conversation_store.delete(validated_id or conversation_id, owner_id)
            return JSONResponse(content={"deleted": True})

    return app


def _latency_ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1000)


def _log_request(
    *,
    request_id: str,
    model: str,
    masking_mode: str,
    detected_types: list[str],
    policy_result: str,
    latency_ms: int,
    status_code: int,
    error_type: str | None = None,
) -> None:
    values: dict[str, object] = {
        "request_id": request_id,
        # Model is client-controlled and can itself contain PII. Log only its
        # bounded shape, never the raw value or a reversible representation.
        "model_length": min(len(model), 256),
        "masking_mode": masking_mode,
        "detected_entities_count": len(detected_types),
        "detected_entity_types": list(dict.fromkeys(detected_types)),
        "policy_result": policy_result,
        "latency_ms": latency_ms,
        "status_code": status_code,
    }
    if error_type:
        values["error_type"] = error_type
    logger.info("request_completed", extra=values)


app = create_app()
