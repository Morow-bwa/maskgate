from __future__ import annotations

import json
import logging
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.config import Settings
from app.identity import DefaultPrincipalResolver, PrincipalContext
from app.masking.anonymizer import MaskingSession
from app.masking.media_guard import UnsafeMediaBlocked, reject_unsanitized_media
from app.policies.policy_engine import PolicyBlocked, PolicyEngine
from app.privacy.models import PrivacyAction, TokenScope
from app.privacy.output_guard import OutputPrivacyGuard
from app.privacy.pipeline import PrivacyPipeline, ProviderOutputViolation
from app.privacy.runtime import PrivacyRequestContext, PrivacyRuntime
from app.privacy.wire import WirePrivacyViolation
from app.proxy.llm_client import LLMUpstreamError
from app.proxy.openai_compatible import add_masking_instruction, request_to_payload
from app.proxy.outbound_sanitizer import sanitize_outbound_payload
from app.proxy.streaming import BufferedStreamingOutputGuard
from app.schemas import ChatCompletionRequest
from app.storage.conversation_store import (
    ConversationCapacityExceeded,
    ConversationState,
    InMemoryConversationStore,
    validate_conversation_id,
)
from app.storage.mapping_store import InMemoryMappingStore

logger = logging.getLogger("maskgate")

PUBLIC_INVALID_CONVERSATION_ID_MESSAGE = (
    "conversation_id must contain 8-128 letters, digits, '_' or '-'"
)
PUBLIC_UNSANITIZED_MEDIA_MESSAGE = (
    "Image or screen content requires local OCR/redaction before it can be sent upstream"
)

@dataclass(frozen=True, slots=True)
class ChatExecution:
    status_code: int
    payload: Any
    trace: dict[str, object]


def error_payload(message: str, error_type: str, **extra: object) -> dict[str, object]:
    return {"error": {"message": message, "type": error_type, **extra}}


def _assistant_message_from_response(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict) or message.get("role") != "assistant":
        return None
    preserved: dict[str, Any] = {"role": "assistant"}
    for key in ("content", "refusal", "function_call", "tool_calls"):
        if key in message:
            preserved[key] = deepcopy(message[key])
    if len(preserved) == 1:
        return None
    return preserved


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


def _role_for_path(
    payload: dict[str, Any],
    path: tuple[str | int, ...],
) -> str | None:
    if len(path) < 2 or path[0] != "messages" or not isinstance(path[1], int):
        return None
    messages = payload.get("messages")
    if not isinstance(messages, list) or not 0 <= path[1] < len(messages):
        return None
    message = messages[path[1]]
    if not isinstance(message, dict):
        return None
    role = message.get("role")
    return role if isinstance(role, str) else None


class ChatOrchestrator:
    """Own the complete chat privacy and provider execution lifecycle."""

    def __init__(
        self,
        *,
        settings: Settings,
        detector: Any,
        policy: PolicyEngine,
        privacy_runtime: PrivacyRuntime,
        mapping_store: InMemoryMappingStore,
        conversation_store: InMemoryConversationStore,
        upstream: Any,
        provider_name: str,
        provider_ready: bool,
        privacy_pipeline: PrivacyPipeline,
        output_guard: OutputPrivacyGuard,
        principal_resolver: DefaultPrincipalResolver,
    ) -> None:
        self._settings = settings
        self._detector = detector
        self._policy = policy
        self._privacy_runtime = privacy_runtime
        self._mapping_store = mapping_store
        self._conversation_store = conversation_store
        self._upstream = upstream
        self._provider_name = provider_name
        self._provider_ready = provider_ready
        self._privacy_pipeline = privacy_pipeline
        self._output_guard = output_guard
        self._principal_resolver = principal_resolver

    def _new_masking_session(self, mode: str) -> MaskingSession:
        return MaskingSession(
            mode,
            self._policy,
            max_mappings=self._settings.conversation_max_mappings,
            max_sensitive_bytes=self._settings.conversation_max_sensitive_bytes,
        )

    def clear_conversation(
        self,
        conversation_id: str,
        principal: PrincipalContext,
    ) -> None:
        validated_id = validate_conversation_id(conversation_id)
        self._conversation_store.delete(
            validated_id or conversation_id,
            principal.vault_namespace,
        )

    async def _execute_conversation_chat(
        self,
        request: ChatCompletionRequest,
        conversation_id: str,
        principal: PrincipalContext,
        request_id: str,
        started: float,
        requested_mode: str,
        allow_preview: bool = False,
    ) -> ChatExecution:
        try:
            state = self._conversation_store.get_or_create(
                conversation_id,
                principal.vault_namespace,
                lambda: self._new_masking_session(requested_mode),
            )
        except ConversationCapacityExceeded:
            return ChatExecution(
                503,
                error_payload(
                    "Conversation capacity is temporarily exhausted",
                    "conversation_capacity_exceeded",
                ),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        if state.session.mode != requested_mode:
            return ChatExecution(
                409,
                error_payload(
                    "A conversation cannot change its masking mode",
                    "conversation_mode_mismatch",
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
                error_payload(
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
                    self._conversation_store.delete(conversation_id, principal.vault_namespace)
                return ChatExecution(
                    400,
                    error_payload(
                        PUBLIC_UNSANITIZED_MEDIA_MESSAGE,
                        "media_not_sanitized",
                        media_type=exc.media_type,
                    ),
                    {
                        **base_trace,
                        "blocked_media": True,
                        "masked_request": None,
                    },
                )
            detected_types: list[str] = []
            allowlisted_types: list[str] = []
            allowlisted_values: list[str] = []
            session = state.session.clone()
            source_payload = deepcopy(payload)
            privacy_request = PrivacyRequestContext(
                route="/v1/chat/completions",
                provider=self._provider_name,
                model=request.model,
                jurisdiction=self._settings.jurisdiction,
                purpose=self._settings.default_purpose,
                token_scope=TokenScope.CONVERSATION,
            )

            def mask_message_at_path(text: str, path: tuple[str | int, ...]) -> str:
                result = self._privacy_runtime.transform_text(
                    text,
                    session=session,
                    principal=principal,
                    request=privacy_request,
                    json_path=path,
                    role=_role_for_path(source_payload, path),
                )
                detected_types.extend(item.entity_type for item in result.detections)
                allowlisted_types.extend(
                    detection.entity_type
                    for detection, decision in zip(
                        result.detections, result.decisions, strict=True
                    )
                    if decision.action is PrivacyAction.ALLOW
                )
                allowlisted_values.extend(result.approved_originals)
                return result.text

            def mask_message(text: str) -> str:
                return mask_message_at_path(text, ())

            try:
                payload = sanitize_outbound_payload(
                    payload,
                    mask_message,
                    mask_text_at_path=mask_message_at_path,
                )
                outbound_payload = deepcopy(payload)
                outbound_payload["messages"] = deepcopy(state.messages) + deepcopy(
                    payload.get("messages", [])
                )
                add_masking_instruction(outbound_payload, session.items)
                checked_payload = self._privacy_pipeline.prepare(
                    outbound_payload,
                    session,
                    allowlisted_values,
                )
                self._mapping_store.put(request_id, session.items)
                base_trace["masked_request"] = checked_payload.payload
            except WirePrivacyViolation:
                if not state.messages and not state.session.items:
                    self._conversation_store.delete(
                        conversation_id,
                        principal.vault_namespace,
                    )
                base_trace.update(
                    {
                        "wire_rejected": True,
                        "masked_request": None,
                    }
                )
                return ChatExecution(
                    400,
                    error_payload(
                        "Final wire privacy validation rejected the provider request",
                        "wire_privacy_violation",
                    ),
                    base_trace,
                )
            except PolicyBlocked as exc:
                if not state.messages and not state.session.items:
                    self._conversation_store.delete(
                        conversation_id,
                        principal.vault_namespace,
                    )
                if "RESERVED_TOKEN" in exc.entity_types:
                    base_trace.update(
                        {
                            "blocked_entities": exc.entity_types,
                            "masked_request": None,
                            "preview_only": True,
                        }
                    )
                    return ChatExecution(
                        400,
                        error_payload(
                            "Request blocked because reserved token syntax was detected",
                            "policy_block",
                            entities=exc.entity_types,
                        ),
                        base_trace,
                    )
                preview_payload = request_to_payload(request)
                preview_payload.pop("masking_mode", None)
                preview_payload.pop("conversation_id", None)
                preview_policy = PolicyEngine(
                    self._settings.policy_file,
                    block_api_keys=False,
                    block_secrets=False,
                    block_credit_cards=False,
                    public_email_allowlist=self._settings.public_email_allowlist,
                    public_email_domain_allowlist=(
                        self._settings.public_email_domain_allowlist
                    ),
                    public_person_allowlist=self._settings.public_person_allowlist,
                )
                preview_session = state.session.clone(policy=preview_policy)

                def preview_mask_message(text: str) -> str:
                    return preview_session.mask_text(text, self._detector.detect(text))

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
                        "allowlisted_entity_types": list(
                            dict.fromkeys(allowlisted_types)
                        ),
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
                    error_payload(
                        "Request blocked because sensitive data was detected",
                        "policy_block",
                        entities=list(dict.fromkeys(exc.entity_types)),
                    ),
                    base_trace,
                )

            try:
                if not self._provider_ready:
                    if not allow_preview:
                        return ChatExecution(
                            503,
                            error_payload(
                                "The upstream provider is not configured",
                                "provider_not_configured",
                            ),
                            {**base_trace, "provider_ready": False},
                        )
                    base_trace.update(
                        {
                            "detected_entity_types": list(dict.fromkeys(detected_types)),
                            "detected_entities_count": len(detected_types),
                            "allowlisted_entity_types": list(
                                dict.fromkeys(allowlisted_types)
                            ),
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
                    return ChatExecution(
                        200,
                        _preview_response(request.model),
                        base_trace,
                    )
                result = await self._privacy_pipeline.complete(checked_payload)
                response_payload = self._privacy_pipeline.process_output(
                    result.payload,
                    session.items,
                )
                unique_types = list(dict.fromkeys(detected_types))
                base_trace.update(
                    {
                        "detected_entity_types": unique_types,
                        "detected_entities_count": len(detected_types),
                        "allowlisted_entity_types": list(
                            dict.fromkeys(allowlisted_types)
                        ),
                        "upstream_response": result.payload,
                        "latency_ms": _latency_ms(started),
                        "status_code": result.status_code,
                    }
                )
                if result.status_code < 400:
                    conversation_messages = deepcopy(state.messages)
                    conversation_messages.extend(
                        deepcopy(payload.get("messages", []))
                    )
                    safe_history_payload = self._output_guard.sanitize_for_history(
                        result.payload,
                        session.items,
                    )
                    assistant_message = _assistant_message_from_response(
                        safe_history_payload
                    )
                    if assistant_message is not None:
                        conversation_messages.append(assistant_message)
                    self._conversation_store.commit(
                        state,
                        session,
                        conversation_messages,
                    )
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
                return ChatExecution(
                    result.status_code,
                    response_payload,
                    base_trace,
                )
            except (LLMUpstreamError, ProviderOutputViolation) as exc:
                base_trace.update(
                    {
                        "detected_entity_types": list(dict.fromkeys(detected_types)),
                        "detected_entities_count": len(detected_types),
                        "allowlisted_entity_types": list(
                            dict.fromkeys(allowlisted_types)
                        ),
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
                return ChatExecution(
                    502,
                    error_payload(exc.message, exc.error_type),
                    base_trace,
                )
            finally:
                self._mapping_store.delete(request_id)

    async def stream_chat(
        self,
        request: ChatCompletionRequest,
        conversation_id_override: str | None = None,
        principal: PrincipalContext | None = None,
        allow_mode_override: bool = False,
    ) -> Response:
        active_principal = principal or self._principal_resolver.resolve(
            authorization=None,
            client_host=None,
        )
        request_id = f"req_{uuid.uuid4().hex}"
        if not self._provider_ready:
            return JSONResponse(
                status_code=503,
                content=error_payload(
                    "The upstream provider is not configured",
                    "provider_not_configured",
                ),
            )
        requested_mode = (
            request.masking_mode
            if allow_mode_override and request.masking_mode
            else self._settings.masking_mode
        )
        if requested_mode not in {
            "placeholder",
            "semantic_placeholder",
            "surrogate",
            "redact",
        }:
            return JSONResponse(
                status_code=422,
                content=error_payload(
                    "masking_mode is not supported",
                    "invalid_masking_mode",
                ),
            )
        try:
            conversation_id = validate_conversation_id(
                conversation_id_override or request.conversation_id
            )
        except ValueError:
            return JSONResponse(
                status_code=422,
                content=error_payload(
                    PUBLIC_INVALID_CONVERSATION_ID_MESSAGE,
                    "invalid_conversation_id",
                ),
            )

        state: ConversationState | None = None
        if conversation_id:
            try:
                state = self._conversation_store.get_or_create(
                    conversation_id,
                    active_principal.vault_namespace,
                    lambda: self._new_masking_session(requested_mode),
                )
            except ConversationCapacityExceeded:
                return JSONResponse(
                    status_code=503,
                    content=error_payload(
                        "Conversation capacity is temporarily exhausted",
                        "conversation_capacity_exceeded",
                    ),
                )
            if state.session.mode != requested_mode:
                return JSONResponse(
                    status_code=409,
                    content=error_payload(
                        "A conversation cannot change its masking mode",
                        "conversation_mode_mismatch",
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
                    self._conversation_store.delete(
                        state.conversation_id,
                        state.owner_id,
                    )
                state.lock.release()
            return JSONResponse(
                status_code=400,
                content=error_payload(
                    PUBLIC_UNSANITIZED_MEDIA_MESSAGE,
                    "media_not_sanitized",
                    media_type=exc.media_type,
                ),
            )
        session = (
            state.session.clone()
            if state is not None
            else self._new_masking_session(requested_mode)
        )
        stream_allowlisted_values: list[str] = []
        source_payload = deepcopy(payload)
        privacy_request = PrivacyRequestContext(
            route="/v1/chat/completions",
            provider=self._provider_name,
            model=request.model,
            jurisdiction=self._settings.jurisdiction,
            purpose=self._settings.default_purpose,
            token_scope=(
                TokenScope.CONVERSATION
                if state is not None
                else TokenScope.REQUEST
            ),
        )
        try:

            def mask_stream_text_at_path(
                text: str,
                path: tuple[str | int, ...],
            ) -> str:
                result = self._privacy_runtime.transform_text(
                    text,
                    session=session,
                    principal=active_principal,
                    request=privacy_request,
                    json_path=path,
                    role=_role_for_path(source_payload, path),
                )
                stream_allowlisted_values.extend(result.approved_originals)
                return result.text

            def mask_stream_text(text: str) -> str:
                return mask_stream_text_at_path(text, ())

            payload = sanitize_outbound_payload(
                payload,
                mask_stream_text,
                mask_text_at_path=mask_stream_text_at_path,
            )
            outbound_payload = deepcopy(payload)
            if state is not None:
                outbound_payload["messages"] = deepcopy(state.messages) + deepcopy(
                    payload.get("messages", [])
                )
            add_masking_instruction(outbound_payload, session.items)
            checked_payload = self._privacy_pipeline.prepare(
                outbound_payload,
                session,
                stream_allowlisted_values,
                stream=True,
            )
        except WirePrivacyViolation:
            if state is not None:
                if not state.messages and not state.session.items:
                    self._conversation_store.delete(
                        state.conversation_id,
                        state.owner_id,
                    )
                state.lock.release()
            return JSONResponse(
                status_code=400,
                content=error_payload(
                    "Final wire privacy validation rejected the provider request",
                    "wire_privacy_violation",
                ),
            )
        except PolicyBlocked as exc:
            if state is not None:
                if not state.messages and not state.session.items:
                    self._conversation_store.delete(
                        state.conversation_id,
                        state.owner_id,
                    )
                state.lock.release()
            return JSONResponse(
                status_code=400,
                content=error_payload(
                    "Request blocked because sensitive data was detected",
                    "policy_block",
                    entities=list(dict.fromkeys(exc.entity_types)),
                ),
            )

        if not hasattr(self._upstream, "complete_stream"):
            if state is not None:
                state.lock.release()
            return JSONResponse(
                status_code=501,
                content=error_payload(
                    "The configured upstream does not support streaming",
                    "unsupported_feature",
                ),
            )

        self._mapping_store.put(request_id, session.items)

        async def event_generator():
            completed = False
            stream_output_guard = BufferedStreamingOutputGuard(
                self._output_guard,
                session.items,
            )
            try:
                async for event in self._privacy_pipeline.stream(checked_payload):
                    safe_event = stream_output_guard.push(event)
                    yield f"data: {json.dumps(safe_event, ensure_ascii=False)}\n\n"

                provider_text = stream_output_guard.provider_text()
                for final_event in stream_output_guard.finish_events():
                    yield f"data: {json.dumps(final_event, ensure_ascii=False)}\n\n"
                completed = True
                if state is not None:
                    conversation_messages = deepcopy(state.messages)
                    conversation_messages.extend(deepcopy(payload.get("messages", [])))
                    if provider_text:
                        conversation_messages.append(
                            {"role": "assistant", "content": provider_text}
                        )
                    self._conversation_store.commit(state, session, conversation_messages)
                yield "data: [DONE]\n\n"
            except (LLMUpstreamError, ProviderOutputViolation) as exc:
                error_event = {"error": {"type": exc.error_type, "message": exc.message}}
                yield f"data: {json.dumps(error_event, ensure_ascii=False)}\n\n"
            finally:
                self._mapping_store.delete(request_id)
                if state is not None:
                    if not completed:
                        self._conversation_store.touch(state)
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
        self,
        request: ChatCompletionRequest,
        conversation_id_override: str | None = None,
        principal: PrincipalContext | None = None,
        allow_preview: bool = False,
    ) -> ChatExecution:
        active_principal = principal or self._principal_resolver.resolve(
            authorization=None,
            client_host=None,
        )
        request_id = f"req_{uuid.uuid4().hex}"
        started = time.perf_counter()
        payload = request_to_payload(request)
        requested_mode = (
            request.masking_mode
            if allow_preview and request.masking_mode
            else self._settings.masking_mode
        )
        if requested_mode not in {
            "placeholder",
            "semantic_placeholder",
            "surrogate",
            "redact",
        }:
            return ChatExecution(
                422,
                error_payload(
                    "masking_mode is not supported",
                    "invalid_masking_mode",
                ),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        if not self._provider_ready and not allow_preview:
            return ChatExecution(
                503,
                error_payload(
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
        except ValueError:
            return ChatExecution(
                422,
                error_payload(
                    PUBLIC_INVALID_CONVERSATION_ID_MESSAGE,
                    "invalid_conversation_id",
                ),
                {"request_id": request_id, "masking_mode": requested_mode},
            )
        if conversation_id:
            return await self._execute_conversation_chat(
                request,
                conversation_id,
                active_principal,
                request_id,
                started,
                requested_mode,
                allow_preview,
            )
        payload.pop("masking_mode", None)
        payload.pop("conversation_id", None)
        detected_types: list[str] = []
        allowlisted_types: list[str] = []
        allowlisted_values: list[str] = []
        session = self._new_masking_session(requested_mode)
        source_payload = deepcopy(payload)
        privacy_request = PrivacyRequestContext(
            route="/v1/chat/completions",
            provider=self._provider_name,
            model=request.model,
            jurisdiction=self._settings.jurisdiction,
            purpose=self._settings.default_purpose,
            token_scope=TokenScope.REQUEST,
        )
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
                error_payload(
                    PUBLIC_UNSANITIZED_MEDIA_MESSAGE,
                    "media_not_sanitized",
                    media_type=exc.media_type,
                ),
                {**base_trace, "blocked_media": True, "masked_request": None},
            )

        if request.stream:
            return ChatExecution(
                400,
                error_payload(
                    "Streaming is not supported in the MVP version",
                    "unsupported_feature",
                ),
                base_trace,
            )

        try:

            def mask_message_at_path(text: str, path: tuple[str | int, ...]) -> str:
                result = self._privacy_runtime.transform_text(
                    text,
                    session=session,
                    principal=active_principal,
                    request=privacy_request,
                    json_path=path,
                    role=_role_for_path(source_payload, path),
                )
                detected_types.extend(item.entity_type for item in result.detections)
                allowlisted_types.extend(
                    detection.entity_type
                    for detection, decision in zip(
                        result.detections, result.decisions, strict=True
                    )
                    if decision.action is PrivacyAction.ALLOW
                )
                allowlisted_values.extend(result.approved_originals)
                return result.text

            def mask_message(text: str) -> str:
                return mask_message_at_path(text, ())

            payload = sanitize_outbound_payload(
                payload,
                mask_message,
                mask_text_at_path=mask_message_at_path,
            )
            add_masking_instruction(payload, session.items)
            checked_payload = self._privacy_pipeline.prepare(payload, session, allowlisted_values)
            self._mapping_store.put(request_id, session.items)
            base_trace["masked_request"] = checked_payload.payload
        except WirePrivacyViolation:
            base_trace.update(
                {
                    "wire_rejected": True,
                    "masked_request": None,
                }
            )
            return ChatExecution(
                400,
                error_payload(
                    "Final wire privacy validation rejected the provider request",
                    "wire_privacy_violation",
                ),
                base_trace,
            )
        except PolicyBlocked as exc:
            unique_types = list(dict.fromkeys(detected_types + exc.entity_types))
            if "RESERVED_TOKEN" in exc.entity_types:
                base_trace.update(
                    {
                        "detected_entity_types": unique_types,
                        "blocked_entities": exc.entity_types,
                        "masked_request": None,
                        "preview_only": True,
                    }
                )
                return ChatExecution(
                    400,
                    error_payload(
                        "Request blocked because reserved token syntax was detected",
                        "policy_block",
                        entities=exc.entity_types,
                    ),
                    base_trace,
                )
            # The Playground can show a local-only preview of what masking would
            # produce, but this preview is never sent upstream when policy blocks.
            preview_payload = request_to_payload(request)
            preview_payload.pop("masking_mode", None)
            preview_payload.pop("conversation_id", None)
            preview_policy = PolicyEngine(
                self._settings.policy_file,
                block_api_keys=False,
                block_secrets=False,
                block_credit_cards=False,
                public_email_allowlist=self._settings.public_email_allowlist,
                public_email_domain_allowlist=self._settings.public_email_domain_allowlist,
                public_person_allowlist=self._settings.public_person_allowlist,
            )
            preview_session = MaskingSession(requested_mode, preview_policy)

            def preview_mask_message(text: str) -> str:
                return preview_session.mask_text(text, self._detector.detect(text))

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
                error_payload(
                    "Request blocked because sensitive data was detected",
                    "policy_block",
                    entities=list(dict.fromkeys(exc.entity_types)),
                ),
                base_trace,
            )

        try:
            if not self._provider_ready:
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
            result = await self._privacy_pipeline.complete(checked_payload)
            response_payload = self._privacy_pipeline.process_output(result.payload, session.items)
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
        except (LLMUpstreamError, ProviderOutputViolation) as exc:
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
            return ChatExecution(502, error_payload(exc.message, exc.error_type), base_trace)
        finally:
            # Request mappings are intentionally deleted even when the upstream
            # fails; TTL remains a second line of defense for abandoned flows.
            self._mapping_store.delete(request_id)


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
