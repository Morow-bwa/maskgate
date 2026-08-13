from __future__ import annotations

from functools import partial

import anyio
from fastapi import APIRouter, File, UploadFile
from fastapi.responses import JSONResponse, Response

from app.media.sanitizer import MediaSanitizer
from app.media.types import MediaSanitizationError
from app.policies.policy_engine import PolicyBlocked


def build_media_router(sanitizer: MediaSanitizer, *, max_concurrency: int = 2) -> APIRouter:
    router = APIRouter(prefix="/v1/privacy/files", tags=["privacy-files"])
    work_limiter = anyio.CapacityLimiter(max(max_concurrency, 1))

    @router.post("/anonymize")
    async def anonymize_file(file: UploadFile = File(...)) -> Response:
        try:
            content = await file.read(sanitizer.max_file_bytes + 1)
            work = partial(
                sanitizer.sanitize,
                content,
                file.filename or "document",
                file.content_type,
            )
            result = await anyio.to_thread.run_sync(work, limiter=work_limiter)
        except MediaSanitizationError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"message": exc.message, "type": exc.error_type}},
                headers={"Cache-Control": "no-store"},
            )
        except PolicyBlocked as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "File blocked because sensitive data was detected",
                        "type": "policy_block",
                        "entities": exc.entity_types,
                    }
                },
                headers={"Cache-Control": "no-store"},
            )
        finally:
            await file.close()

        return Response(
            content=result.content,
            media_type=result.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{result.filename}"',
                "Cache-Control": "no-store",
                "X-MaskGate-Redactions": str(result.redactions),
                "X-MaskGate-Entity-Types": ",".join(result.entity_types),
            },
        )

    return router
