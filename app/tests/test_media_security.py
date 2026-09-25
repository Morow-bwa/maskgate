from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.identity import DefaultPrincipalResolver
from app.main import create_app
from app.media.ocr import OCRLine
from app.media.types import MediaSanitizationResult

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


class NoFaces:
    def detect(self, image: Image.Image) -> list[tuple[int, int, int, int]]:
        return []


class SlowNativeOCR:
    def __init__(self) -> None:
        self.completed = threading.Event()

    def extract(self, image: Image.Image) -> list[OCRLine]:
        time.sleep(0.08)
        self.completed.set()
        return []


class BlockingNativeOCR:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def extract(self, image: Image.Image) -> list[OCRLine]:
        self.started.set()
        self.release.wait(timeout=1)
        return []


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


def test_strict_media_upload_above_starlette_spool_threshold_stays_in_memory(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (1_024, 512), "white").save(source, format="BMP")
    content = source.getvalue()
    configured = replace(settings, max_media_file_bytes=3 * 1024 * 1024)
    app = create_app(
        configured,
        llm_client=object(),
        ocr_adapter=NoTextOCR(),
        face_detector=NoFaces(),
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/privacy/files/anonymize",
            files={"file": ("above-spool.bmp", content, "image/bmp")},
        )

    assert len(content) > 1024 * 1024
    assert response.status_code == 200
    assert response.headers["x-maskgate-upload-storage"] == "memory"
    assert app.state.admission.snapshot()["active_operations"] == 0


def test_media_route_rejects_extra_files_and_malformed_multipart(settings) -> None:
    app = create_app(settings, llm_client=object(), ocr_adapter=NoTextOCR())

    with TestClient(app) as client:
        extra = client.post(
            "/v1/privacy/files/anonymize",
            files=[
                ("file", ("first.txt", b"one", "text/plain")),
                ("extra", ("second.txt", b"two", "text/plain")),
            ],
        )
        malformed = client.post(
            "/v1/privacy/files/anonymize",
            content=b"--broken\r\nraw-body-without-valid-parts",
            headers={"Content-Type": "multipart/form-data; boundary=broken"},
        )

        assert extra.status_code == 400
        assert extra.json()["error"]["type"] == "invalid_upload_count"
        assert malformed.status_code in {400, 422}
        assert app.state.admission.snapshot()["active_operations"] == 0


def test_media_policy_uses_verified_tenant_context(settings, tmp_path) -> None:
    first_key = "media-tenant-a"
    second_key = "media-tenant-b"
    resolver = DefaultPrincipalResolver(settings.application_id)
    tenant_a = resolver.resolve(
        authorization=f"Bearer {first_key}",
        client_host="testclient",
    ).tenant_id
    tenant_b = resolver.resolve(
        authorization=f"Bearer {second_key}",
        client_host="testclient",
    ).tenant_id
    policy_path = tmp_path / "media-policy.yaml"
    policy_path.write_text(
        f"""
version: 2
defaults:
  action: BLOCK
  reason: no_media_rule
rules:
  - id: tenant-a-block-email
    priority: 200
    action: BLOCK
    reason: tenant_a_rejects_email
    conditions:
      entity_types: [EMAIL]
      tenants: [{tenant_a}]
      routes: [/v1/privacy/files/anonymize]
      providers: [local-media]
  - id: tenant-b-redact-email
    priority: 100
    action: REDACT
    reason: tenant_b_redacts_email
    conditions:
      entity_types: [EMAIL]
      tenants: [{tenant_b}]
      routes: [/v1/privacy/files/anonymize]
      providers: [local-media]
public_data_assertions: []
""".strip(),
        encoding="utf-8",
    )
    configured = replace(
        settings,
        api_keys=(first_key, second_key),
        policy_v2_file=policy_path,
    )
    app = create_app(configured, llm_client=object())
    content = _docx(_simple_document("media.owner@example.com"))

    with TestClient(app) as client:
        blocked = client.post(
            "/v1/privacy/files/anonymize",
            headers={"Authorization": f"Bearer {first_key}"},
            files={"file": ("tenant-a.docx", content, "application/octet-stream")},
        )
        redacted = client.post(
            "/v1/privacy/files/anonymize",
            headers={"Authorization": f"Bearer {second_key}"},
            files={"file": ("tenant-b.docx", content, "application/octet-stream")},
        )

    assert blocked.status_code == 400
    assert blocked.json()["error"]["type"] == "policy_block"
    assert redacted.status_code == 200
    assert b"media.owner@example.com" not in redacted.content


def test_native_ocr_finishes_under_bounded_worker_even_after_request_deadline(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (64, 64), "white").save(source, format="PNG")
    ocr = SlowNativeOCR()
    configured = replace(
        settings,
        operation_timeout_seconds=0.03,
        media_max_concurrency=1,
    )
    app = create_app(
        configured,
        llm_client=object(),
        ocr_adapter=ocr,
        face_detector=NoFaces(),
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/privacy/files/anonymize",
            files={"file": ("slow.png", source.getvalue(), "image/png")},
        )

    assert response.status_code == 504
    assert ocr.completed.wait(timeout=1)
    assert app.state.admission.snapshot()["active_operations"] == 0


def test_media_route_reads_through_the_configured_file_limit(settings) -> None:
    configured = replace(settings, max_media_file_bytes=1_024)
    app = create_app(configured, llm_client=object(), ocr_adapter=NoTextOCR())

    with TestClient(app) as client:
        response = client.post(
            "/v1/privacy/files/anonymize",
            files={"file": ("too-large.bmp", b"BM" + b"x" * 1_023, "image/bmp")},
        )

    assert response.status_code == 413
    assert response.json()["error"]["type"] == "file_too_large"
    assert app.state.admission.snapshot()["active_operations"] == 0


def test_media_output_limit_never_returns_oversized_sanitizer_bytes(settings) -> None:
    configured = replace(settings, max_media_file_bytes=1_024)
    app = create_app(configured, llm_client=object())
    app.state.media_sanitizer.docx.sanitize = lambda content, filename: MediaSanitizationResult(
        content=b"x" * 1_025,
        media_type="application/octet-stream",
        filename="oversized.bin",
        redactions=0,
        entity_types=(),
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/privacy/files/anonymize",
            files={"file": ("small.docx", _docx(_simple_document()), "application/octet-stream")},
        )

    assert response.status_code == 413
    assert response.json()["error"]["type"] == "sanitized_file_too_large"
    assert response.content != b"x" * 1_025


@pytest.mark.anyio
async def test_cancelled_media_request_releases_admission_after_native_work(settings) -> None:
    source = BytesIO()
    Image.new("RGB", (64, 64), "white").save(source, format="PNG")
    ocr = BlockingNativeOCR()
    app = create_app(
        replace(settings, media_max_concurrency=1),
        llm_client=object(),
        ocr_adapter=ocr,
        face_detector=NoFaces(),
    )
    transport = httpx.ASGITransport(app=app, client=("testclient", 50_000))

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        request = asyncio.create_task(
            client.post(
                "/v1/privacy/files/anonymize",
                files={"file": ("blocked.png", source.getvalue(), "image/png")},
            )
        )
        started = await asyncio.to_thread(ocr.started.wait, 1)
        assert started
        request.cancel()
        await asyncio.sleep(0)
        ocr.release.set()
        with pytest.raises(asyncio.CancelledError):
            await request

    assert app.state.admission.snapshot()["active_operations"] == 0
