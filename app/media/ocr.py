from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Protocol

from app.media.types import MediaSanitizationError


@dataclass(frozen=True, slots=True)
class OCRLine:
    box: tuple[int, int, int, int]
    text: str
    confidence: float


class OCRAdapter(Protocol):
    def extract(self, image: Any) -> list[OCRLine]: ...


class RapidOCRAdapter:
    """Lazy, process-local RapidOCR adapter with serialized model access."""

    def __init__(self) -> None:
        self._engine: Any | None = None
        self._lock = threading.Lock()

    def extract(self, image: Any) -> list[OCRLine]:
        try:
            import numpy as np
            from rapidocr import RapidOCR
        except ImportError as exc:
            raise MediaSanitizationError(
                "media_dependency_missing",
                "Local OCR dependencies are not installed; install maskgate[media]",
                503,
            ) from exc

        try:
            with self._lock:
                if self._engine is None:
                    self._engine = RapidOCR()
                result = self._engine(np.asarray(image.convert("RGB")))
        except Exception as exc:
            raise MediaSanitizationError(
                "ocr_failed",
                "Local OCR could not verify the image",
                422,
            ) from exc

        boxes = getattr(result, "boxes", None)
        texts = getattr(result, "txts", None)
        scores = getattr(result, "scores", None)
        if boxes is None or texts is None:
            return []

        output: list[OCRLine] = []
        score_values = scores if scores is not None else [0.0] * len(texts)
        for points, text, score in zip(boxes, texts, score_values, strict=True):
            if not text:
                continue
            xs = [float(point[0]) for point in points]
            ys = [float(point[1]) for point in points]
            output.append(
                OCRLine(
                    (
                        max(int(min(xs)), 0),
                        max(int(min(ys)), 0),
                        max(int(max(xs)), 0),
                        max(int(max(ys)), 0),
                    ),
                    str(text),
                    float(score),
                )
            )
        return output
