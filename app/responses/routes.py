from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse

from app.identity import PrincipalContext

from .orchestrator import OpenAIResponsesOrchestrator

PrincipalLookup = Callable[[Request], PrincipalContext]


def build_responses_router(
    orchestrator: OpenAIResponsesOrchestrator,
    request_principal: PrincipalLookup,
) -> APIRouter:
    router = APIRouter()

    @router.post("/v1/responses")
    async def create_response(
        http_request: Request,
        payload: dict[str, Any] = Body(...),
    ) -> JSONResponse:
        execution = await orchestrator.execute(payload, request_principal(http_request))
        return JSONResponse(status_code=execution.status_code, content=execution.payload)

    return router
