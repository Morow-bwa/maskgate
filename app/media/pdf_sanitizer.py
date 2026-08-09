from __future__ import annotations

from io import BytesIO
from time import struct_time

import pypdfium2 as pdfium

from app.media.image_sanitizer import ImageSanitizer
from app.media.types import (
    MediaSanitizationError,
    MediaSanitizationResult,
    safe_output_stem,
)


class PdfSanitizer:
    """Rasterize every page, redact pixels locally, then build a fresh PDF."""

    def __init__(
        self,
        image_sanitizer: ImageSanitizer,
        *,
        max_pages: int = 50,
        render_scale: float = 2.0,
        max_page_pixels: int = 20_000_000,
        max_total_pixels: int = 50_000_000,
        max_output_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.image_sanitizer = image_sanitizer
        self.max_pages = max(max_pages, 1)
        self.render_scale = max(render_scale, 1.0)
        self.max_page_pixels = max(max_page_pixels, 1)
        self.max_total_pixels = max(max_total_pixels, 1)
        self.max_output_bytes = max(max_output_bytes, 1)

    def sanitize(self, content: bytes, filename: str) -> MediaSanitizationResult:
        if not content.startswith(b"%PDF-"):
            raise MediaSanitizationError("invalid_pdf", "File is not a valid PDF")

        pages = []
        redactions = 0
        entity_types: list[str] = []
        document = None
        try:
            document = pdfium.PdfDocument(content)
            if not 1 <= len(document) <= self.max_pages:
                raise MediaSanitizationError(
                    "unsafe_pdf",
                    f"PDF must contain between 1 and {self.max_pages} pages",
                    413,
                )
            total_pixels = 0
            for page_number in range(len(document)):
                page = document[page_number]
                try:
                    width, height = page.get_size()
                    rendered_pixels = int(width * self.render_scale) * int(
                        height * self.render_scale
                    )
                    total_pixels += rendered_pixels
                    if rendered_pixels > self.max_page_pixels:
                        raise MediaSanitizationError(
                            "unsafe_pdf",
                            "Rendered PDF page exceeds the pixel safety limit",
                            413,
                        )
                    if total_pixels > self.max_total_pixels:
                        raise MediaSanitizationError(
                            "unsafe_pdf",
                            "Rendered PDF exceeds the total pixel safety limit",
                            413,
                        )
                    image = page.render(
                        scale=self.render_scale,
                        rotation=0,
                        draw_annots=True,
                        maybe_alpha=False,
                        rev_byteorder=True,
                    ).to_pil()
                    try:
                        sanitized, count, found_types = self.image_sanitizer.sanitize_image(image)
                    finally:
                        image.close()
                    pages.append(sanitized)
                    redactions += count
                    entity_types.extend(found_types)
                finally:
                    page.close()
        except MediaSanitizationError:
            for sanitized_page in pages:
                sanitized_page.close()
            raise
        except Exception as exc:
            for sanitized_page in pages:
                sanitized_page.close()
            raise MediaSanitizationError(
                "invalid_pdf",
                "PDF could not be safely rendered",
                422,
            ) from exc
        finally:
            if document is not None:
                document.close()

        output = BytesIO()
        # Pillow's PDF writer accepts ``time.struct_time`` for PDF date fields.
        # A fixed value keeps output reproducible without copying source metadata.
        fixed_time = struct_time((1980, 1, 1, 0, 0, 0, 1, 1, 0))
        first, *remaining = pages
        try:
            first.save(
                output,
                format="PDF",
                save_all=True,
                append_images=remaining,
                resolution=72 * self.render_scale,
                title="Sanitized by MaskGate",
                author="",
                subject="",
                keywords="",
                creator="MaskGate",
                producer="MaskGate",
                creationDate=fixed_time,
                modDate=fixed_time,
            )
        finally:
            for image in pages:
                image.close()

        if output.tell() > self.max_output_bytes:
            raise MediaSanitizationError(
                "sanitized_file_too_large",
                "Sanitized PDF exceeds the output size limit",
                413,
            )

        safe_stem = safe_output_stem(filename, "document")
        return MediaSanitizationResult(
            output.getvalue(),
            "application/pdf",
            f"{safe_stem}.masked.pdf",
            redactions,
            tuple(dict.fromkeys(entity_types)),
        )
