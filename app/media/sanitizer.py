from __future__ import annotations

from pathlib import PurePath

from app.masking.detector import RegexDetector
from app.media.docx_sanitizer import DOCX_MEDIA_TYPE, DocxSanitizer
from app.media.face_detection import FaceDetector, OpenCVFaceDetector
from app.media.ocr import OCRAdapter, RapidOCRAdapter
from app.media.text_redactor import TextRedactor
from app.media.types import MediaSanitizationError, MediaSanitizationResult
from app.policies.policy_engine import PolicyEngine


class MediaSanitizer:
    """Dispatch supported file bytes to local, fail-closed sanitizers."""

    def __init__(
        self,
        detector: RegexDetector,
        policy: PolicyEngine,
        max_file_bytes: int,
        *,
        ocr_adapter: OCRAdapter | None = None,
        face_detector: FaceDetector | None = None,
    ) -> None:
        self.max_file_bytes = max(max_file_bytes, 1)
        redactor = TextRedactor(detector, policy)
        self.docx = DocxSanitizer(redactor)
        self.image = None
        self.pdf = None
        try:
            from app.media.image_sanitizer import ImageSanitizer
            from app.media.pdf_sanitizer import PdfSanitizer

            self.image = ImageSanitizer(
                redactor,
                ocr_adapter or RapidOCRAdapter(),
                face_detector or OpenCVFaceDetector(),
            )
            self.pdf = PdfSanitizer(
                self.image,
                max_output_bytes=self.max_file_bytes,
            )
        except ImportError:
            pass

    def sanitize(
        self,
        content: bytes,
        filename: str,
        declared_media_type: str | None,
    ) -> MediaSanitizationResult:
        if not content:
            raise MediaSanitizationError("empty_file", "Uploaded file is empty")
        if len(content) > self.max_file_bytes:
            raise MediaSanitizationError(
                "file_too_large", "Uploaded file exceeds the file limit", 413
            )

        suffix = PurePath(filename or "").suffix.casefold()
        if suffix == ".docx" and content.startswith(b"PK"):
            result = self.docx.sanitize(content, filename)
            return self._validated_output(result)
        if declared_media_type == DOCX_MEDIA_TYPE and content.startswith(b"PK"):
            result = self.docx.sanitize(content, filename or "document.docx")
            return self._validated_output(result)
        if content.startswith(b"%PDF-"):
            if self.pdf is None:
                raise MediaSanitizationError(
                    "media_dependency_missing",
                    "PDF anonymization requires the maskgate[media] extra",
                    503,
                )
            result = self.pdf.sanitize(content, filename or "document.pdf")
            return self._validated_output(result)
        if self._looks_like_image(content):
            if self.image is None:
                raise MediaSanitizationError(
                    "media_dependency_missing",
                    "Image anonymization requires the maskgate[media] extra",
                    503,
                )
            result = self.image.sanitize(content, filename or "image")
            return self._validated_output(result)
        raise MediaSanitizationError(
            "unsupported_media_type",
            "Supported file types are DOCX, PDF, PNG, JPEG, WEBP, TIFF, and BMP",
            415,
        )

    def _validated_output(self, result: MediaSanitizationResult) -> MediaSanitizationResult:
        if len(result.content) > self.max_file_bytes:
            raise MediaSanitizationError(
                "sanitized_file_too_large",
                "Sanitized file exceeds the output size limit",
                413,
            )
        return result

    @staticmethod
    def _looks_like_image(content: bytes) -> bool:
        return (
            content.startswith(b"\x89PNG\r\n\x1a\n")
            or content.startswith(b"\xff\xd8\xff")
            or content.startswith((b"II*\x00", b"MM\x00*", b"BM"))
            or (content.startswith(b"RIFF") and content[8:12] == b"WEBP")
        )
