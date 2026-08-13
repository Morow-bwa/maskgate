from __future__ import annotations

import warnings
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from PIL import Image

from app.masking.detector import RegexDetector
from app.media.docx_sanitizer import DocxSanitizer
from app.media.image_sanitizer import ImageSanitizer
from app.media.pdf_sanitizer import PdfSanitizer
from app.media.text_redactor import TextRedactor
from app.media.types import MediaSanitizationError
from app.policies.policy_engine import PolicyEngine

CONTENT_TYPES = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="rels" '
    b'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    b'<Default Extension="xml" ContentType="application/xml"/>'
    b'<Override PartName="/word/document.xml" '
    b'ContentType="application/vnd.openxmlformats-officedocument.'
    b'wordprocessingml.document.main+xml"/>'
    b"</Types>"
)
ROOT_RELS = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" '
    b'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    b'relationships/officeDocument" Target="word/document.xml"/>'
    b"</Relationships>"
)
DOCUMENT = b"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Safe synthetic fixture</w:t></w:r></w:p></w:body>
</w:document>"""


class NoTextOCR:
    def extract(self, image: Image.Image) -> list[object]:
        return []


class NoFaces:
    def detect(self, image: Image.Image) -> list[tuple[int, int, int, int]]:
        return []


@pytest.fixture
def redactor(settings) -> TextRedactor:
    policy = PolicyEngine(
        settings.policy_file,
        block_api_keys=False,
        block_secrets=False,
        block_credit_cards=False,
    )
    return TextRedactor(RegexDetector(), policy)


@pytest.fixture
def image_sanitizer(redactor: TextRedactor) -> ImageSanitizer:
    return ImageSanitizer(redactor, NoTextOCR(), NoFaces())


def _docx(
    extras: tuple[tuple[str, bytes], ...] = (),
    *,
    duplicate_document: bool = False,
) -> bytes:
    output = BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("_rels/.rels", ROOT_RELS)
            archive.writestr("word/document.xml", DOCUMENT)
            if duplicate_document:
                archive.writestr("word/document.xml", DOCUMENT)
            for name, content in extras:
                archive.writestr(name, content)
    return output.getvalue()


def _pdf(page_count: int = 1, size: tuple[int, int] = (100, 100)) -> bytes:
    pages = [Image.new("RGB", size, "white") for _ in range(page_count)]
    output = BytesIO()
    try:
        pages[0].save(output, format="PDF", save_all=True, append_images=pages[1:])
    finally:
        for page in pages:
            page.close()
    return output.getvalue()


def test_docx_rejects_duplicate_zip_entries(redactor: TextRedactor) -> None:
    sanitizer = DocxSanitizer(redactor)

    with pytest.raises(MediaSanitizationError, match="duplicate ZIP entries") as exc_info:
        sanitizer.sanitize(_docx(duplicate_document=True), "duplicate.docx")

    assert exc_info.value.error_type == "unsafe_docx"


def test_docx_rejects_entry_count_over_budget(redactor: TextRedactor) -> None:
    sanitizer = DocxSanitizer(redactor, max_entries=3)
    payload = _docx((("word/styles.xml", b"<w:styles xmlns:w='urn:test'/>",),))

    with pytest.raises(MediaSanitizationError, match="too many ZIP entries") as exc_info:
        sanitizer.sanitize(payload, "too-many-parts.docx")

    assert exc_info.value.error_type == "unsafe_docx"


def test_docx_rejects_uncompressed_content_over_budget(redactor: TextRedactor) -> None:
    sanitizer = DocxSanitizer(redactor, max_uncompressed_bytes=128)

    with pytest.raises(MediaSanitizationError, match="uncompressed content") as exc_info:
        sanitizer.sanitize(_docx(), "expanded.docx")

    assert exc_info.value.error_type == "unsafe_docx"


def test_docx_rejects_unsafe_compression_ratio(redactor: TextRedactor) -> None:
    sanitizer = DocxSanitizer(redactor, max_compression_ratio=2)
    compressible_xml = (
        b"<w:styles xmlns:w='urn:test'><w:name w:val='"
        + (b"A" * 16_384)
        + b"'/></w:styles>"
    )
    payload = _docx((("word/styles.xml", compressible_xml),))

    with pytest.raises(MediaSanitizationError, match="compression ratio") as exc_info:
        sanitizer.sanitize(payload, "compression-bomb.docx")

    assert exc_info.value.error_type == "unsafe_docx"


def test_docx_rejects_unknown_opaque_parts(redactor: TextRedactor) -> None:
    sanitizer = DocxSanitizer(redactor)
    payload = _docx((("attachments/private.bin", b"synthetic opaque bytes"),))

    with pytest.raises(MediaSanitizationError, match="opaque or unsupported") as exc_info:
        sanitizer.sanitize(payload, "opaque.docx")

    assert exc_info.value.error_type == "unsupported_docx_content"
    assert exc_info.value.status_code == 415


def test_image_rejects_dimensions_over_pixel_budget(redactor: TextRedactor) -> None:
    source = BytesIO()
    Image.new("RGB", (20, 20), "white").save(source, format="PNG")
    sanitizer = ImageSanitizer(redactor, NoTextOCR(), NoFaces(), max_pixels=399)

    with pytest.raises(MediaSanitizationError, match="dimensions") as exc_info:
        sanitizer.sanitize(source.getvalue(), "oversized.png")

    assert exc_info.value.error_type == "unsafe_image"
    assert exc_info.value.status_code == 413


def test_image_rejects_multiframe_input(redactor: TextRedactor) -> None:
    source = BytesIO()
    frames = [Image.new("RGB", (16, 16), color) for color in ("white", "black")]
    try:
        frames[0].save(source, format="TIFF", save_all=True, append_images=frames[1:])
    finally:
        for frame in frames:
            frame.close()
    sanitizer = ImageSanitizer(redactor, NoTextOCR(), NoFaces())

    with pytest.raises(MediaSanitizationError, match="multi-frame") as exc_info:
        sanitizer.sanitize(source.getvalue(), "multipage.tiff")

    assert exc_info.value.error_type == "unsupported_media_type"
    assert exc_info.value.status_code == 415


def test_pdf_rejects_page_count_over_budget(image_sanitizer: ImageSanitizer) -> None:
    sanitizer = PdfSanitizer(image_sanitizer, max_pages=1, render_scale=1)

    with pytest.raises(MediaSanitizationError, match="between 1 and 1 pages") as exc_info:
        sanitizer.sanitize(_pdf(page_count=2), "too-many-pages.pdf")

    assert exc_info.value.error_type == "unsafe_pdf"
    assert exc_info.value.status_code == 413


def test_pdf_rejects_page_over_pixel_budget(image_sanitizer: ImageSanitizer) -> None:
    sanitizer = PdfSanitizer(
        image_sanitizer,
        render_scale=1,
        max_page_pixels=1_000,
        max_total_pixels=1_000_000,
    )

    with pytest.raises(MediaSanitizationError, match="page exceeds") as exc_info:
        sanitizer.sanitize(_pdf(size=(100, 100)), "wide-page.pdf")

    assert exc_info.value.error_type == "unsafe_pdf"
    assert exc_info.value.status_code == 413


def test_pdf_rejects_total_pixels_over_budget(image_sanitizer: ImageSanitizer) -> None:
    sanitizer = PdfSanitizer(
        image_sanitizer,
        max_pages=2,
        render_scale=1,
        max_page_pixels=20_000,
        max_total_pixels=15_000,
    )

    with pytest.raises(MediaSanitizationError, match="total pixel") as exc_info:
        sanitizer.sanitize(_pdf(page_count=2, size=(100, 100)), "pixel-budget.pdf")

    assert exc_info.value.error_type == "unsafe_pdf"
    assert exc_info.value.status_code == 413
