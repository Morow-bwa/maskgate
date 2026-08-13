from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response

from app.chat.orchestrator import ChatOrchestrator, error_payload
from app.identity import PrincipalContext
from app.schemas import ChatCompletionRequest

PrincipalLookup = Callable[[Request], PrincipalContext]


def build_chat_router(
    orchestrator: ChatOrchestrator,
    request_principal: PrincipalLookup,
) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/chat/completions")
    async def chat_completions(
        http_request: Request,
        request: ChatCompletionRequest,
        x_maskgate_conversation_id: str | None = Header(default=None),
    ) -> Response:
        principal = request_principal(http_request)
        if request.stream:
            return await orchestrator.stream_chat(
                request,
                x_maskgate_conversation_id,
                principal,
            )
        execution = await orchestrator.execute_chat(
            request,
            x_maskgate_conversation_id,
            principal,
        )
        return JSONResponse(
            status_code=execution.status_code,
            content=execution.payload,
        )

    return router


def build_playground_chat_router(
    orchestrator: ChatOrchestrator,
    request_principal: PrincipalLookup,
) -> APIRouter:
    router = APIRouter()

    @router.post("/playground/api/chat", include_in_schema=False)
    async def playground_chat(
        http_request: Request,
        request: ChatCompletionRequest,
        x_maskgate_conversation_id: str | None = Header(default=None),
    ) -> Response:
        principal = request_principal(http_request)
        if request.stream:
            return await orchestrator.stream_chat(
                request,
                x_maskgate_conversation_id,
                principal,
                allow_mode_override=True,
            )
        execution = await orchestrator.execute_chat(
            request,
            x_maskgate_conversation_id,
            principal,
            allow_preview=True,
        )
        return JSONResponse(
            status_code=execution.status_code,
            content={"response": execution.payload, "trace": execution.trace},
        )

    @router.delete(
        "/playground/api/conversations/{conversation_id}",
        include_in_schema=False,
    )
    async def clear_playground_conversation(
        http_request: Request,
        conversation_id: str,
    ) -> JSONResponse:
        try:
            orchestrator.clear_conversation(
                conversation_id,
                request_principal(http_request),
            )
        except ValueError as exc:
            return JSONResponse(
                status_code=422,
                content=error_payload(str(exc), "invalid_conversation_id"),
            )
        return JSONResponse(content={"deleted": True})

    return router
