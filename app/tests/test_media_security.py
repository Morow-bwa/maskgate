from __future__ import annotations

from dataclasses import replace
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient
from PIL import Image

from app.main import create_app
from app.media.ocr import OCRLine

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
ROOT_RELS = b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""


def _docx(document_xml: bytes, extras: dict[str, bytes] | None = None) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", ROOT_RELS)
        archive.writestr("word/document.xml", document_xml)
        for name, content in (extras or {}).items():
            archive.writestr(name, content)
    return output.getvalue()


def _simple_document(text: str = "Hello") -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
        f"{text}</w:t></w:r></w:p></w:body></w:document>"
    ).encode()


class NoTextOCR:
    def extract(self, image: Image.Image) -> list[OCRLine]:
        return []


class PersistentSensitiveOCR:
    def extract(self, image: Image.Image) -> list[OCRLine]:
        return [OCRLine((5, 5, 80, 25), "still.private@example.com", 0.99)]


class OneFaceDetector:
    def __init__(self) -> None:
        self.calls = 0

    def detect(self, image: Image.Image) -> list[tuple[int, int, int, int]]:
        self.calls += 1
        return [(10, 10, 60, 60)] if self.calls == 1 else []


def test_docx_redacts_split_runs_attributes_links_and_metadata(settings) -> None:
    document = b"""<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:body><w:sdt><w:sdtPr><w:tag w:val="tag.user@example.com"/></w:sdtPr>
      <w:sdtContent><w:p><w:r><w:t>split.user@</w:t></w:r>
      <w:r><w:t>example.com</w:t></w:r></w:p></w:sdtContent></w:sdt></w:body>
    </w:document>"""
    relationships = b"""<?xml version="1.0" encoding="UTF-8"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId9" TargetMode="External"
        Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
        Target="https://private.example.com/?email=link.user@example.com"/>
    </Relationships>"""
    app_properties = b"""<?xml version="1.0" encoding="UTF-8"?>
    <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
      <Company>Private Company</Company><Manager>Private Manager</Manager>
    </Properties>"""
    client = TestClient(create_app(settings, llm_client=object()))

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={
            "file": (
                "details.docx",
                _docx(
                    document,
                    {
                        "word/_rels/document.xml.rels": relationships,
                        "word/styles.xml": b"""<?xml version="1.0" encoding="UTF-8"?>
                        <w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                          <w:style w:type="paragraph" w:styleId="style.user@example.com">
                            <w:name w:val="style.user@example.com"/>
                          </w:style>
                        </w:styles>""",
                        "docProps/app.xml": app_properties,
                    },
                ),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )

    assert response.status_code == 200
    with ZipFile(BytesIO(response.content)) as archive:
        story = archive.read("word/document.xml").decode()
        rels = archive.read("word/_rels/document.xml.rels").decode()
        metadata = archive.read("docProps/app.xml").decode()
        styles = archive.read("word/styles.xml").decode()
    assert "split.user@example.com" not in story
    assert "tag.user@example.com" not in story
    assert "private.example.com" not in rels
    assert "link.user@example.com" not in rels
    assert "Private Company" not in metadata
    assert "Private Manager" not in metadata
    assert "style.user@example.com" not in styles


def test_docx_rejects_unsafe_zip_paths(settings) -> None:
    client = TestClient(create_app(settings, llm_client=object()))
    payload = _docx(_simple_document(), {"../outside.txt": b"not extracted"})

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("unsafe.docx", payload, "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "unsafe_docx"


def test_docx_rejects_embedded_content_that_cannot_be_verified(settings) -> None:
    client = TestClient(create_app(settings, llm_client=object()))
    payload = _docx(_simple_document(), {"word/embeddings/object.bin": b"opaque"})

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("embedded.docx", payload, "application/octet-stream")},
    )

    assert response.status_code == 415
    assert response.json()["error"]["type"] == "unsupported_docx_content"


def test_docx_rejects_unknown_opaque_package_parts(settings) -> None:
    source = BytesIO()
    with ZipFile(source, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
        )
        archive.writestr("attachments/private.bin", b"alice@example.com")

    client = TestClient(create_app(settings, llm_client=object()))
    response = client.post(
        "/v1/privacy/files/anonymize",
        files={
            "file": (
                "unsafe.docx",
                source.getvalue(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )

    assert response.status_code == 415
    assert response.json()["error"]["type"] == "unsupported_docx_content"


def test_media_policy_block_is_not_silently_downgraded_to_redaction(settings) -> None:
    client = TestClient(create_app(settings, llm_client=object()))
    payload = _docx(_simple_document("sk-test-abcdefghijklmnop"))

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("secret.docx", payload, "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "policy_block"
    assert response.json()["error"]["entities"] == ["API_KEY"]


def test_media_upload_uses_its_own_body_limit(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (96, 96), "white").save(source, format="BMP")
    media_settings = replace(
        settings,
        max_request_body_bytes=1_024,
        max_media_file_bytes=64 * 1_024,
    )
    client = TestClient(create_app(media_settings, llm_client=object(), ocr_adapter=NoTextOCR()))

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("large.bmp", source.getvalue(), "image/bmp")},
    )

    assert len(source.getvalue()) > media_settings.max_request_body_bytes
    assert response.status_code == 200


def test_image_redaction_fails_closed_when_verification_still_detects_pii(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (100, 40), "white").save(source, format="PNG")
    client = TestClient(
        create_app(
            settings,
            llm_client=object(),
            ocr_adapter=PersistentSensitiveOCR(),
        )
    )

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("persistent.png", source.getvalue(), "image/png")},
    )

    assert response.status_code == 422
    assert response.json()["error"]["type"] == "redaction_verification_failed"


def test_image_anonymization_burns_detected_faces_into_pixels(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (100, 80), "white").save(source, format="PNG")
    client = TestClient(
        create_app(
            settings,
            llm_client=object(),
            ocr_adapter=NoTextOCR(),
            face_detector=OneFaceDetector(),
        )
    )

    response = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("портрет.png", source.getvalue(), "image/png")},
    )

    assert response.status_code == 200
    assert response.headers["x-maskgate-redactions"] == "1"
    assert response.headers["x-maskgate-entity-types"] == "FACE"
    assert response.headers["content-disposition"] == 'attachment; filename="image.masked.png"'
    with Image.open(BytesIO(response.content)) as sanitized:
        assert sanitized.getpixel((20, 20)) == (0, 0, 0)


def test_media_endpoint_rejects_unknown_and_malformed_files(settings) -> None:
    client = TestClient(create_app(settings, llm_client=object(), ocr_adapter=NoTextOCR()))

    unknown = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("notes.txt", b"private.user@example.com", "text/plain")},
    )
    invalid_pdf = client.post(
        "/v1/privacy/files/anonymize",
        files={"file": ("broken.pdf", b"%PDF-not-really-a-pdf", "application/pdf")},
    )

    assert unknown.status_code == 415
    assert unknown.json()["error"]["type"] == "unsupported_media_type"
    assert invalid_pdf.status_code == 422
    assert invalid_pdf.json()["error"]["type"] == "invalid_pdf"
