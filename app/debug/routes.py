from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.masking.anonymizer import MaskingSession
from app.masking.detector import RegexDetector
from app.policies.policy_engine import PolicyBlocked, PolicyEngine
from app.schemas import DebugMaskRequest, DebugTextRequest


def build_debug_router(
    detector: RegexDetector,
    policy: PolicyEngine,
    default_mode: str,
) -> APIRouter:
    router = APIRouter(prefix="/debug")

    @router.post("/analyze")
    async def analyze(request: DebugTextRequest) -> dict[str, object]:
        entities = detector.detect(request.text)
        return {"entities": [entity.to_dict() for entity in entities]}

    @router.post("/mask")
    async def mask(request: DebugMaskRequest) -> JSONResponse:
        mode = (request.mode or default_mode).strip().lower()
        if mode not in {"placeholder", "surrogate", "redact"}:
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "message": "mode must be placeholder, surrogate, or redact",
                        "type": "invalid_masking_mode",
                    }
                },
            )
        entities = detector.detect(request.text)
        session = MaskingSession(mode, policy)
        try:
            masked = session.mask_text(request.text, entities)
        except PolicyBlocked as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "Request blocked because sensitive data was detected",
                        "type": "policy_block",
                        "entities": exc.entity_types,
                    }
                },
            )
        return JSONResponse(
            content={
                "masked_text": masked,
                "mapping": [item.to_dict() for item in session.items],
            }
        )

    return router
