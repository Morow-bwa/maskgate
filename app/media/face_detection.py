from __future__ import annotations

import threading
from typing import Any, Protocol

from app.media.types import MediaSanitizationError

FaceBox = tuple[int, int, int, int]


class FaceDetector(Protocol):
    def detect(self, image: Any) -> list[FaceBox]: ...


class OpenCVFaceDetector:
    """Lazy local frontal-face detector; image pixels never leave the process."""

    def __init__(self) -> None:
        self._cascade: Any | None = None
        self._lock = threading.Lock()

    def detect(self, image: Any) -> list[FaceBox]:
        try:
            import cv2
            import numpy as np
        except ImportError as exc:
            raise MediaSanitizationError(
                "media_dependency_missing",
                "Local face detection dependencies are not installed; install maskgate[media]",
                503,
            ) from exc

        try:
            with self._lock:
                if self._cascade is None:
                    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                    self._cascade = cv2.CascadeClassifier(cascade_path)
                    if self._cascade.empty():
                        raise RuntimeError("OpenCV face cascade is unavailable")
                rgb = np.asarray(image.convert("RGB"))
                gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
                faces = self._cascade.detectMultiScale(
                    gray,
                    scaleFactor=1.1,
                    minNeighbors=5,
                    minSize=(30, 30),
                )
        except Exception as exc:
            raise MediaSanitizationError(
                "face_detection_failed",
                "Local face detection could not verify the image",
                422,
            ) from exc

        return [(int(x), int(y), int(x + width), int(y + height)) for x, y, width, height in faces]
