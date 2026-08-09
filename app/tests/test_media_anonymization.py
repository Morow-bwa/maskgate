from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pypdfium2 as pdfium
from fastapi.testclient import TestClient
from PIL import Image

from app.main import create_app
from app.media.ocr import OCRLine


def _docx_with_email() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8"?>
            <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
              <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
              <Default Extension="xml" ContentType="application/xml"/>
              <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
              <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
            </Types>""",
        )
        archive.writestr(
            "_rels/.rels",
            """<?xml version="1.0" encoding="UTF-8"?>
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
            </Relationships>""",
        )
        archive.writestr(
            "word/document.xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
              <w:body><w:p w:rsidR="00ABCDEF"><w:r><w:t>Contact private.user@example.com today.</w:t></w:r></w:p></w:body>
            </w:document>""",
        )
        archive.writestr(
            "docProps/core.xml",
            """<?xml version="1.0" encoding="UTF-8"?>
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:creator>Private Author</dc:creator><cp:lastModifiedBy>Private Author</cp:lastModifiedBy>
            </cp:coreProperties>""",
        )
    return buffer.getvalue()


def test_docx_anonymization_redacts_content_and_scrubs_metadata(settings) -> None:
    client = TestClient(create_app(settings, llm_client=object()))

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={
            "file": (
                "customer.docx",
                _docx_with_email(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert response.headers["x-maskgate-redactions"] == "1"
    with ZipFile(BytesIO(response.content)) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
        metadata = archive.read("docProps/core.xml").decode("utf-8")
    assert "private.user@example.com" not in document
    assert "Private Author" not in metadata
    assert "rsidR" not in document


class FakeOCR:
    def __init__(self) -> None:
        self.calls = 0

    def extract(self, image: Image.Image) -> list[OCRLine]:
        self.calls += 1
        if self.calls == 1:
            return [OCRLine((10, 10, 190, 50), "image.user@example.com", 0.99)]
        return []


def test_image_anonymization_burns_detected_text_into_pixels(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (220, 80), "white").save(source, format="PNG", author="Private Author")
    client = TestClient(
        create_app(
            settings,
            llm_client=object(),
            ocr_adapter=FakeOCR(),
        )
    )

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("screenshot.png", source.getvalue(), "image/png")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.headers["x-maskgate-redactions"] == "1"
    assert response.headers["x-maskgate-entity-types"] == "EMAIL"
    with Image.open(BytesIO(response.content)) as sanitized:
        assert sanitized.format == "PNG"
        assert sanitized.getpixel((20, 20)) == (0, 0, 0)
        assert "author" not in sanitized.info


def test_pdf_anonymization_rasterizes_and_removes_original_metadata(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (220, 80), "white").save(
        source,
        format="PDF",
        resolution=72,
        author="Private Author",
    )
    client = TestClient(
        create_app(
            settings,
            llm_client=object(),
            ocr_adapter=FakeOCR(),
        )
    )

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("statement.pdf", source.getvalue(), "application/pdf")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.headers["x-maskgate-redactions"] == "1"
    assert b"Private Author" not in response.content
    pdf = pdfium.PdfDocument(response.content)
    assert len(pdf) == 1
    rendered = pdf[0].render(scale=1).to_pil().convert("RGB")
    assert rendered.getpixel((20, 20)) == (0, 0, 0)
