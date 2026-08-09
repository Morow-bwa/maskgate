from __future__ import annotations

from io import BytesIO
from pathlib import PurePosixPath
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from defusedxml import ElementTree as SafeElementTree

from app.media.text_redactor import TextRedactor
from app.media.types import (
    MediaSanitizationError,
    MediaSanitizationResult,
    safe_output_stem,
)
from app.policies.policy_engine import PolicyAction

DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
TEXT_TAGS = {"t", "delText", "instrText"}
BLOCKED_ENTRY_PREFIXES = (
    "customXml/",
    "word/activeX/",
    "word/embeddings/",
    "word/media/",
)


class DocxSanitizer:
    def __init__(
        self,
        redactor: TextRedactor,
        *,
        max_entries: int = 2_000,
        max_uncompressed_bytes: int = 50 * 1024 * 1024,
        max_compression_ratio: int = 200,
    ) -> None:
        self.redactor = redactor
        self.max_entries = max_entries
        self.max_uncompressed_bytes = max_uncompressed_bytes
        self.max_compression_ratio = max_compression_ratio

    def sanitize(self, content: bytes, filename: str) -> MediaSanitizationResult:
        entries = self._read_validated_entries(content)
        redactions = 0
        entity_types: list[str] = []

        for name, data in list(entries.items()):
            if name.startswith("docProps/") and name.endswith(".xml"):
                entries[name] = self._scrub_metadata(data, name)
            elif name.endswith(".rels"):
                updated, count = self._scrub_external_relationships(data, name)
                entries[name] = updated
                redactions += count
            elif self._is_story_part(name):
                updated, count, found_types = self._redact_story_part(data, name)
                entries[name] = updated
                redactions += count
                entity_types.extend(found_types)
            elif name.startswith("word/") and name.endswith(".xml"):
                updated, count, found_types = self._redact_generic_xml(data, name)
                entries[name] = updated
                redactions += count
                entity_types.extend(found_types)

        self._verify(entries)
        output = self._write_deterministic_zip(entries)
        safe_stem = safe_output_stem(filename, "document")
        return MediaSanitizationResult(
            content=output,
            media_type=DOCX_MEDIA_TYPE,
            filename=f"{safe_stem}.masked.docx",
            redactions=redactions,
            entity_types=tuple(dict.fromkeys(entity_types)),
        )

    def _read_validated_entries(self, content: bytes) -> dict[str, bytes]:
        try:
            with ZipFile(BytesIO(content)) as archive:
                infos = archive.infolist()
                if len(infos) > self.max_entries:
                    raise MediaSanitizationError(
                        "unsafe_docx", "DOCX contains too many ZIP entries"
                    )
                names = [info.filename for info in infos]
                if len(names) != len(set(names)):
                    raise MediaSanitizationError(
                        "unsafe_docx", "DOCX contains duplicate ZIP entries"
                    )
                total_size = 0
                for info in infos:
                    self._validate_entry(info)
                    total_size += info.file_size
                    if total_size > self.max_uncompressed_bytes:
                        raise MediaSanitizationError(
                            "unsafe_docx",
                            "DOCX uncompressed content exceeds the safety limit",
                        )
                entries = {info.filename: archive.read(info) for info in infos if not info.is_dir()}
        except BadZipFile as exc:
            raise MediaSanitizationError(
                "invalid_docx", "File is not a valid DOCX archive"
            ) from exc

        if "[Content_Types].xml" not in entries or "word/document.xml" not in entries:
            raise MediaSanitizationError("invalid_docx", "Required DOCX parts are missing")
        return entries

    def _validate_entry(self, info: ZipInfo) -> None:
        normalized = info.filename.replace("\\", "/")
        path = PurePosixPath(normalized)
        if normalized.startswith("/") or ".." in path.parts or normalized != info.filename:
            raise MediaSanitizationError("unsafe_docx", "DOCX contains an unsafe ZIP path")
        filename_entities = self.redactor.detector.detect(normalized)
        if any(
            entity.type != "DOMAIN"
            and self.redactor.policy.action_for_entity(entity.type, entity.text)
            is not PolicyAction.ALLOW
            for entity in filename_entities
        ):
            raise MediaSanitizationError(
                "unsafe_docx", "DOCX contains sensitive data in a ZIP part name"
            )
        if normalized.startswith(BLOCKED_ENTRY_PREFIXES) or normalized.casefold().endswith(
            "vbaproject.bin"
        ):
            raise MediaSanitizationError(
                "unsupported_docx_content",
                "DOCX contains embedded media, custom XML, objects, or macros",
                415,
            )
        if info.file_size and info.compress_size == 0:
            raise MediaSanitizationError("unsafe_docx", "DOCX contains an invalid ZIP entry")
        if info.compress_size and info.file_size / info.compress_size > self.max_compression_ratio:
            raise MediaSanitizationError("unsafe_docx", "DOCX compression ratio is unsafe")

    @staticmethod
    def _is_story_part(name: str) -> bool:
        if not name.startswith("word/") or not name.endswith(".xml"):
            return False
        basename = PurePosixPath(name).name
        return basename in {
            "document.xml",
            "footnotes.xml",
            "endnotes.xml",
            "comments.xml",
        } or basename.startswith(("header", "footer"))

    def _redact_story_part(self, data: bytes, name: str) -> tuple[bytes, int, tuple[str, ...]]:
        root = self._parse_xml(data, name)
        redactions = 0
        entity_types: list[str] = []

        for element in root.iter():
            for attribute in list(element.attrib):
                if self._local_name(attribute).startswith("rsid"):
                    del element.attrib[attribute]
                    continue
                result = self.redactor.redact(element.attrib[attribute])
                if result.count:
                    element.attrib[attribute] = result.text
                    redactions += result.count
                    entity_types.extend(result.entity_types)
            if self._local_name(element.tag) == "comment":
                for attribute in list(element.attrib):
                    if self._local_name(attribute) in {"author", "initials", "date"}:
                        element.attrib[attribute] = ""

        for paragraph in (item for item in root.iter() if self._local_name(item.tag) == "p"):
            nodes = [item for item in paragraph.iter() if self._local_name(item.tag) in TEXT_TAGS]
            if not nodes:
                continue
            segments = [node.text or "" for node in nodes]
            result = self.redactor.redact("".join(segments))
            if not result.count:
                continue
            redactions += result.count
            entity_types.extend(result.entity_types)
            offset = 0
            for node, segment in zip(nodes, segments, strict=True):
                node.text = result.text[offset : offset + len(segment)]
                offset += len(segment)

        return self._serialize(root), redactions, tuple(entity_types)

    def _redact_generic_xml(self, data: bytes, name: str) -> tuple[bytes, int, tuple[str, ...]]:
        root = self._parse_xml(data, name)
        redactions = 0
        entity_types: list[str] = []
        text_slots: list[tuple[object, str, str]] = []

        for element in root.iter():
            for attribute in list(element.attrib):
                result = self.redactor.redact(element.attrib[attribute])
                if result.count:
                    element.attrib[attribute] = result.text
                    redactions += result.count
                    entity_types.extend(result.entity_types)
            if element.text:
                text_slots.append((element, "text", element.text))
            if element.tail:
                text_slots.append((element, "tail", element.tail))

        combined = "".join(value for _, _, value in text_slots)
        result = self.redactor.redact(combined)
        if result.count:
            redactions += result.count
            entity_types.extend(result.entity_types)
            offset = 0
            for element, slot, original in text_slots:
                setattr(element, slot, result.text[offset : offset + len(original)])
                offset += len(original)

        return self._serialize(root), redactions, tuple(entity_types)

    def _scrub_metadata(self, data: bytes, name: str) -> bytes:
        root = self._parse_xml(data, name)
        for element in root.iter():
            if element is not root:
                element.text = ""
            for attribute in list(element.attrib):
                element.attrib[attribute] = ""
        return self._serialize(root)

    def _scrub_external_relationships(self, data: bytes, name: str) -> tuple[bytes, int]:
        root = self._parse_xml(data, name)
        count = 0
        for relation in root.iter():
            if self._local_name(relation.tag) != "Relationship":
                continue
            target_mode = next(
                (
                    value
                    for key, value in relation.attrib.items()
                    if self._local_name(key) == "TargetMode"
                ),
                "",
            )
            if target_mode.casefold() != "external":
                for key, value in relation.attrib.items():
                    local_key = self._local_name(key)
                    if local_key == "Type" and value.startswith(
                        (
                            "http://schemas.openxmlformats.org/",
                            "http://purl.oclc.org/ooxml/",
                        )
                    ):
                        continue
                    entities = self.redactor.detector.detect(value)
                    if any(
                        entity.type != "DOMAIN"
                        and self.redactor.policy.action_for_entity(entity.type, entity.text)
                        is not PolicyAction.ALLOW
                        for entity in entities
                    ):
                        raise MediaSanitizationError(
                            "redaction_verification_failed",
                            "Sensitive data remains in a DOCX relationship",
                        )
                continue
            for key in list(relation.attrib):
                if self._local_name(key) == "Target":
                    relation.attrib[key] = "urn:maskgate:redacted"
                    count += 1
        return self._serialize(root), count

    def _verify(self, entries: dict[str, bytes]) -> None:
        for name, data in entries.items():
            if not (
                self._is_story_part(name) or (name.startswith("word/") and name.endswith(".xml"))
            ):
                continue
            root = self._parse_xml(data, name)
            for element in root.iter():
                if element.text and self.redactor.has_sensitive_text(element.text):
                    raise MediaSanitizationError(
                        "redaction_verification_failed",
                        "Sensitive text remains in the sanitized DOCX",
                    )
                if any(
                    self.redactor.has_sensitive_text(value) for value in element.attrib.values()
                ):
                    raise MediaSanitizationError(
                        "redaction_verification_failed",
                        "Sensitive metadata remains in the sanitized DOCX",
                    )

    @staticmethod
    def _parse_xml(data: bytes, name: str):
        try:
            return SafeElementTree.fromstring(data)
        except Exception as exc:
            raise MediaSanitizationError(
                "invalid_docx", f"Invalid XML in DOCX part: {name}"
            ) from exc

    @staticmethod
    def _serialize(root) -> bytes:
        return SafeElementTree.tostring(root, encoding="utf-8", xml_declaration=True)

    @staticmethod
    def _local_name(value: str) -> str:
        return value.rsplit("}", 1)[-1]

    @staticmethod
    def _write_deterministic_zip(entries: dict[str, bytes]) -> bytes:
        output = BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as archive:
            for name in sorted(entries):
                info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, entries[name])
        return output.getvalue()
