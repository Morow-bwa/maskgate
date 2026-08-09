from __future__ import annotations

import warnings
from io import BytesIO

from PIL import Image, ImageDraw, UnidentifiedImageError

from app.media.face_detection import FaceDetector
from app.media.ocr import OCRAdapter
from app.media.text_redactor import TextRedactor
from app.media.types import (
    MediaSanitizationError,
    MediaSanitizationResult,
    safe_output_stem,
)

ALLOWED_IMAGE_FORMATS = {"BMP", "JPEG", "PNG", "TIFF", "WEBP"}


class ImageSanitizer:
    def __init__(
        self,
        redactor: TextRedactor,
        ocr: OCRAdapter,
        face_detector: FaceDetector,
        *,
        max_pixels: int = 20_000_000,
        verification_passes: int = 1,
    ) -> None:
        self.redactor = redactor
        self.ocr = ocr
        self.face_detector = face_detector
        self.max_pixels = max(max_pixels, 1)
        self.verification_passes = max(verification_passes, 1)

    def sanitize(self, content: bytes, filename: str) -> MediaSanitizationResult:
        image = self._open_verified(content)
        sanitized, redactions, entity_types = self.sanitize_image(image)
        output = BytesIO()
        sanitized.save(output, format="PNG", optimize=True)
        safe_stem = safe_output_stem(filename, "image")
        return MediaSanitizationResult(
            output.getvalue(),
            "image/png",
            f"{safe_stem}.masked.png",
            redactions,
            entity_types,
        )

    def sanitize_image(self, image: Image.Image) -> tuple[Image.Image, int, tuple[str, ...]]:
        sanitized = image.convert("RGB").copy()
        lines = self.ocr.extract(sanitized)
        faces = self.face_detector.detect(sanitized)
        draw = ImageDraw.Draw(sanitized)
        redactions = 0
        entity_types: list[str] = []

        for line in lines:
            result = self.redactor.redact(line.text)
            if not result.count:
                continue
            left, top, right, bottom = line.box
            left = max(left - 3, 0)
            top = max(top - 3, 0)
            right = min(right + 3, sanitized.width)
            bottom = min(bottom + 3, sanitized.height)
            if right <= left or bottom <= top:
                raise MediaSanitizationError(
                    "ocr_failed",
                    "OCR returned an invalid text region",
                    422,
                )
            draw.rectangle((left, top, right, bottom), fill=(0, 0, 0))
            redactions += result.count
            entity_types.extend(result.entity_types)

        for left, top, right, bottom in faces:
            left = max(left - 5, 0)
            top = max(top - 5, 0)
            right = min(right + 5, sanitized.width)
            bottom = min(bottom + 5, sanitized.height)
            if right <= left or bottom <= top:
                raise MediaSanitizationError(
                    "face_detection_failed",
                    "Face detection returned an invalid region",
                    422,
                )
            draw.rectangle((left, top, right, bottom), fill=(0, 0, 0))
            redactions += 1
            entity_types.append("FACE")

        for _ in range(self.verification_passes):
            remaining = self.ocr.extract(sanitized)
            if any(self.redactor.has_sensitive_text(line.text) for line in remaining):
                raise MediaSanitizationError(
                    "redaction_verification_failed",
                    "Sensitive text remains visible after image redaction",
                    422,
                )

        if self.face_detector.detect(sanitized):
            raise MediaSanitizationError(
                "redaction_verification_failed",
                "A face remains visible after image redaction",
                422,
            )

        return sanitized, redactions, tuple(dict.fromkeys(entity_types))

    def _open_verified(self, content: bytes) -> Image.Image:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(content)) as probe:
                    if probe.format not in ALLOWED_IMAGE_FORMATS:
                        raise MediaSanitizationError(
                            "unsupported_media_type",
                            "Image format is not supported",
                            415,
                        )
                    if getattr(probe, "n_frames", 1) != 1:
                        raise MediaSanitizationError(
                            "unsupported_media_type",
                            "Animated or multi-frame images are not supported",
                            415,
                        )
                    if probe.width * probe.height > self.max_pixels:
                        raise MediaSanitizationError(
                            "unsafe_image",
                            "Image dimensions exceed the safety limit",
                            413,
                        )
                    probe.verify()

                with Image.open(BytesIO(content)) as source:
                    source.load()
                    return source.convert("RGB").copy()
        except MediaSanitizationError:
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise MediaSanitizationError(
                "unsafe_image",
                "Image dimensions exceed the safety limit",
                413,
            ) from exc
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise MediaSanitizationError("invalid_image", "File is not a valid image") from exc
