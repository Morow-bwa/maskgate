from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.chat import (
    ChatOrchestrator,
    build_chat_router,
    build_playground_chat_router,
    error_payload,
)
from app.config import Settings, provider_key_is_configured
from app.debug.routes import build_debug_router
from app.identity import DefaultPrincipalResolver, PrincipalContext
from app.logging_config import configure_logging
from app.media.routes import build_media_router
from app.media.sanitizer import MediaSanitizer
from app.observability import PrivacyMetrics
from app.policies.policy_engine import PolicyEngine
from app.privacy.detection import (
    DetectorEnsemble,
    LegacyEntityDetectorAdapter,
    ensure_terminal_capabilities,
)
from app.privacy.models import DetectorProfile
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import PrivacyPipeline
from app.privacy.policy import LegacyPolicyAdapter, PolicyEngineV2, load_policy_v2
from app.privacy.risk import PrivacyRiskEngine
from app.privacy.runtime import PrivacyRuntime
from app.privacy.wire import FinalWirePrivacyGuard
from app.providers import (
    AdapterPolicy,
    GeminiGenerateContentAdapter,
    OpenAIChatCompletionsAdapter,
    OpenAIResponsesAdapter,
)
from app.proxy.gemini_client import GeminiClient
from app.proxy.llm_client import LLMClient
from app.responses import OpenAIResponsesOrchestrator, build_responses_router
from app.security import (
    FixedWindowRateLimiter,
    RequestBodyLimitMiddleware,
    bearer_token_is_allowed,
    requires_proxy_auth,
)
from app.storage.conversation_store import InMemoryConversationStore
from app.storage.mapping_store import InMemoryMappingStore

PLAYGROUND_DIR = Path(__file__).resolve().parents[1] / "playground-react" / "dist"


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
    privacy_detector = DetectorEnsemble(profile=DetectorProfile(settings.detector_profile))
    detector = LegacyEntityDetectorAdapter(privacy_detector)
    policy = PolicyEngine(
        settings.policy_file,
        block_api_keys=settings.block_api_keys,
        block_secrets=settings.block_secrets,
        block_credit_cards=settings.block_credit_cards,
        public_email_allowlist=settings.public_email_allowlist,
        public_email_domain_allowlist=settings.public_email_domain_allowlist,
        public_person_allowlist=settings.public_person_allowlist,
    )
    policy_document = (
        load_policy_v2(settings.policy_v2_file)
        if settings.policy_v2_file is not None
        else LegacyPolicyAdapter().adapt(policy.rules)
    )
    policy_v2 = PolicyEngineV2(policy_document)
    risk_engine = PrivacyRiskEngine()
    privacy_metrics = PrivacyMetrics()
    privacy_runtime = PrivacyRuntime(
        privacy_detector,
        risk_engine,
        policy_v2,
        privacy_metrics,
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
    wire_guard = FinalWirePrivacyGuard(privacy_detector)
    output_guard = OutputPrivacyGuard(privacy_detector)
    ensure_terminal_capabilities(
        privacy_detector,
        wire=wire_guard.detector,
        output=output_guard.detector,
    )
    openai_adapter_policy = AdapterPolicy(safe_extension_fields=frozenset({"metadata", "user"}))
    ingress_adapter = OpenAIChatCompletionsAdapter(openai_adapter_policy)
    egress_adapter = (
        GeminiGenerateContentAdapter()
        if provider_name == "gemini"
        else OpenAIChatCompletionsAdapter(openai_adapter_policy)
    )
    privacy_pipeline = PrivacyPipeline(
        upstream,
        provider_name,
        wire_guard,
        output_guard,
        ingress_adapter=ingress_adapter,
        egress_adapter=egress_adapter,
    )
    responses_orchestrator = OpenAIResponsesOrchestrator(
        settings=settings,
        upstream=upstream,
        provider_ready=provider_ready and provider_name in {"openai", "mock"},
        adapter=OpenAIResponsesAdapter(),
        privacy_runtime=privacy_runtime,
        policy=policy,
        wire_guard=wire_guard,
        output_guard=output_guard,
    )
    rate_limiter = FixedWindowRateLimiter(
        settings.rate_limit_requests,
        settings.rate_limit_window_seconds,
    )
    principal_resolver = DefaultPrincipalResolver(settings.application_id)
    chat_orchestrator = ChatOrchestrator(
        settings=settings,
        detector=detector,
        policy=policy,
        privacy_runtime=privacy_runtime,
        mapping_store=mapping_store,
        conversation_store=conversation_store,
        upstream=upstream,
        provider_name=provider_name,
        provider_ready=provider_ready,
        privacy_pipeline=privacy_pipeline,
        output_guard=output_guard,
        principal_resolver=principal_resolver,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def sweep_expired_state() -> None:
            while True:
                await asyncio.sleep(
                    min(settings.mapping_ttl_seconds, settings.conversation_ttl_seconds, 60)
                )
                mapping_store.cleanup()
                conversation_store.cleanup()

        sweeper = asyncio.create_task(sweep_expired_state())
        try:
            yield
        finally:
            sweeper.cancel()
            try:
                await sweeper
            except asyncio.CancelledError:
                pass

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
    app.state.privacy_detector = privacy_detector
    app.state.privacy_pipeline = privacy_pipeline
    app.state.policy = policy
    app.state.policy_v2 = policy_v2
    app.state.risk_engine = risk_engine
    app.state.privacy_metrics = privacy_metrics
    app.state.privacy_runtime = privacy_runtime
    app.state.mapping_store = mapping_store
    app.state.conversation_store = conversation_store
    app.state.llm_client = upstream
    app.state.provider_ready = provider_ready
    app.state.media_sanitizer = media_sanitizer
    app.state.principal_resolver = principal_resolver
    app.state.chat_orchestrator = chat_orchestrator
    app.state.responses_orchestrator = responses_orchestrator

    @app.middleware("http")
    async def proxy_authentication(request: Request, call_next: Any) -> Response:
        if requires_proxy_auth(request.url.path):
            authorization = request.headers.get("authorization")
            if settings.api_keys and not bearer_token_is_allowed(authorization, settings.api_keys):
                return JSONResponse(
                    status_code=401,
                    content=error_payload("Invalid or missing proxy API key", "unauthorized"),
                    headers={
                        "WWW-Authenticate": "Bearer",
                        "Cache-Control": "no-store",
                    },
                )
            principal = principal_resolver.resolve(
                authorization=authorization if settings.api_keys else None,
                client_host=request.client.host if request.client else None,
            )
            request.state.principal = principal
            request.state.security_identity = principal.vault_namespace
            retry_after = rate_limiter.retry_after(principal.rate_limit_key)
            if retry_after is not None:
                return JSONResponse(
                    status_code=429,
                    content=error_payload("Rate limit exceeded", "rate_limit_exceeded"),
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

    def request_principal(request: Request) -> PrincipalContext:
        principal = getattr(request.state, "principal", None)
        if isinstance(principal, PrincipalContext):
            return principal
        return principal_resolver.resolve(
            authorization=None,
            client_host=request.client.host if request.client else None,
        )

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

    app.include_router(build_chat_router(chat_orchestrator, request_principal))
    app.include_router(build_responses_router(responses_orchestrator, request_principal))

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

        app.include_router(build_playground_chat_router(chat_orchestrator, request_principal))

    return app


app = create_app()
