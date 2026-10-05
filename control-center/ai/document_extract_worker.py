#!/usr/bin/env python3
"""Private, bounded document-to-text worker. It never evaluates document content."""
from __future__ import annotations

import argparse
import codecs
import ctypes
import errno
from html.parser import HTMLParser
import json
import os
import platform
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
from hashlib import sha256
from pathlib import PurePosixPath

MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_COMMAND_STDOUT_BYTES = MAX_OUTPUT_BYTES * 2
MAX_XML_PART_BYTES = 16 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_ZIP_RATIO = 100
MAX_WARNING_COUNT = 16
MAX_XLS_CELLS = 1_000_000
CPU_SECONDS = 60
ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
TEXT_ENCODING = "utf-8"

FORMATS = frozenset(("pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "rtf", "epub", "doc", "xls"))
ODF_MIMES = {
    "odt": (b"application/vnd.oasis.opendocument.text", b"application/vnd.oasis.opendocument.text-template"),
    "ods": (b"application/vnd.oasis.opendocument.spreadsheet", b"application/vnd.oasis.opendocument.spreadsheet-template"),
    "odp": (b"application/vnd.oasis.opendocument.presentation", b"application/vnd.oasis.opendocument.presentation-template"),
}
XML_DOCTYPE = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
XML_ENCODING = re.compile(br"<\?xml[^>]{0,256}\bencoding\s*=\s*['\"]([^'\"]+)['\"]", re.I)

class ExtractionError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)

class OutputLimitReached(Exception):
    pass

class Writer:
    def __init__(self, target: str):
        self.target = target
        self.temp = f"{target}.worker-{uuid.uuid4().hex}.tmp"
        self.handle = os.open(self.temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.bytes = 0
        self.units = 0

    def write(self, value: str):
        if not isinstance(value, str):
            return
        clean = "\t".join(" ".join(part.replace("\x00", " ").split()) for part in value.split("\t"))
        if not clean.strip():
            return
        data = (clean + "\n").encode(TEXT_ENCODING)
        if self.bytes + len(data) > MAX_OUTPUT_BYTES:
            room = MAX_OUTPUT_BYTES - self.bytes
            if room > 0:
                # `room` can end after a complete multibyte code point and
                # before the next leading byte. Strip by decoding a prefix,
                # not only trailing continuation bytes, or a leading byte can
                # survive and later decode as U+FFFD.
                partial = data[:room].decode(TEXT_ENCODING, "ignore").encode(TEXT_ENCODING)
                if partial:
                    os.write(self.handle, partial)
                    self.bytes += len(partial)
            raise OutputLimitReached()
        os.write(self.handle, data)
        self.bytes += len(data)
        self.units += 1

    def finish(self):
        os.fsync(self.handle)
        os.close(self.handle)
        self.handle = None
        os.replace(self.temp, self.target)

    def discard(self):
        if self.handle is not None:
            try: os.close(self.handle)
            except OSError: pass
            self.handle = None
        try: os.unlink(self.temp)
        except FileNotFoundError: pass

def result(*, fmt, state, writer, skipped=0, warnings=()):
    unique = []
    for warning in warnings:
        if isinstance(warning, str) and re.fullmatch(r"[A-Z0-9_]{1,64}", warning) and warning not in unique:
            unique.append(warning)
    if len(unique) > MAX_WARNING_COUNT:
        unique = unique[:MAX_WARNING_COUNT]
    return {"ok": True, "format": fmt, "coverage": {"state": state, "unitsRead": writer.units, "unitsSkipped": skipped, "warnings": unique}}

def emit(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()

def set_limits():
    # macOS developer tests do not expose a usable RLIMIT_AS. Production uses
    # Linux and fails closed if the process limits cannot be installed.
    if sys.platform != "linux":
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES)
        )
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
    except (ValueError, OSError):
        raise ExtractionError("DOCUMENT_RESOURCE_GUARD")

def install_linux_network_guard():
    """Block socket creation and connection after startup without adding Python packages."""
    if sys.platform != "linux":
        return
    machine = platform.machine().lower()
    blocked = {
        "x86_64": (41, 42), "amd64": (41, 42),
        "aarch64": (198, 203), "arm64": (198, 203),
    }.get(machine)
    if not blocked:
        raise ExtractionError("NETWORK_GUARD_UNAVAILABLE")
    # BPF: load syscall nr; deny socket/connect; otherwise allow.
    BPF_LD_W_ABS = 0x20
    BPF_JMP_JEQ_K = 0x15
    BPF_RET_K = 0x06
    SECCOMP_RET_ALLOW = 0x7fff0000
    SECCOMP_RET_ERRNO = 0x00050000 | errno.EPERM
    PR_SET_NO_NEW_PRIVS = 38
    PR_SET_SECCOMP = 22
    SECCOMP_MODE_FILTER = 2
    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]
    filters = [SockFilter(BPF_LD_W_ABS, 0, 0, 0)]
    for number in blocked:
        filters.extend((SockFilter(BPF_JMP_JEQ_K, 0, 1, number), SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO)))
    filters.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    raw = (SockFilter * len(filters))(*filters)
    program = SockFprog(len(filters), raw)
    libc = ctypes.CDLL(None, use_errno=True)
    # prctl is variadic in libc. Without explicit machine-word arguments,
    # ctypes can narrow the filter pointer on 64-bit Alpine/Python builds.
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong)
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0) != 0:
        raise ExtractionError("NETWORK_GUARD_UNAVAILABLE")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise ExtractionError("NETWORK_GUARD_UNAVAILABLE")

def open_source(path: str):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 1 or info.st_size > MAX_SOURCE_BYTES:
            raise ExtractionError("INVALID_DOCUMENT_SOURCE")
        return fd, info.st_size
    except Exception:
        os.close(fd)
        raise

def check_abort():
    return

def zip_safety(path: str):
    # Called only after Node's low-level ZIP validation. Keep worker validation too
    # so it does not rely on a caller for per-member read limits.
    archive = zipfile.ZipFile(path, "r")
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ZIP_ENTRIES:
        archive.close(); raise ExtractionError("DOCUMENT_ZIP_STRUCTURE")
    total = 0; total_xml = 0
    for info in infos:
        if info.flag_bits & 0x1:
            archive.close(); raise ExtractionError("DOCUMENT_ENCRYPTED")
        if info.file_size < 0 or info.compress_size < 0:
            archive.close(); raise ExtractionError("DOCUMENT_ZIP_STRUCTURE")
        if info.filename.lower().endswith((".xml", ".xhtml", ".html", ".opf")):
            if info.file_size > MAX_XML_PART_BYTES:
                archive.close(); raise ExtractionError("DOCUMENT_XML_LIMIT")
            total_xml += info.file_size
            if total_xml > MAX_TOTAL_XML_BYTES:
                archive.close(); raise ExtractionError("DOCUMENT_XML_LIMIT")
        if info.file_size and info.file_size / max(1, info.compress_size) > MAX_ZIP_RATIO:
            archive.close(); raise ExtractionError("DOCUMENT_ZIP_BOMB")
        total += info.file_size
        if total > 1024 * 1024 * 1024:
            archive.close(); raise ExtractionError("DOCUMENT_ZIP_BOMB")
    return archive

def safe_member(archive, name: str):
    if not isinstance(name, str) or name.startswith("/") or "\\" in name or ".." in PurePosixPath(name).parts:
        raise ExtractionError("DOCUMENT_ZIP_STRUCTURE")
    try: info = archive.getinfo(name)
    except KeyError: raise ExtractionError("DOCUMENT_STRUCTURE")
    if info.file_size > MAX_XML_PART_BYTES:
        raise ExtractionError("DOCUMENT_XML_LIMIT")
    return info

def checked_xml_stream(archive, name: str):
    info = safe_member(archive, name)
    source = archive.open(info, "r")
    # Force DTD/entity rejection before ElementTree consumes the stream. The
    # wrapper retains a small rolling probe so declarations cannot straddle chunks.
    class Guarded:
        def __init__(self, inner): self.inner = inner; self.tail = b""; self.prefix = b""; self.encoding_checked = False
        def read(self, size=-1):
            data = self.inner.read(size)
            if len(self.prefix) < 512:
                self.prefix = (self.prefix + data)[:512]
            # Entity declarations in UTF-16/32 contain NUL bytes and would
            # evade the byte DTD guard below. The extractor accepts UTF-8 XML
            # only, so reject other BOMs/declarations before ElementTree sees
            # them.
            if not self.encoding_checked and (len(self.prefix) >= 4 or not data or b"?>" in self.prefix or len(self.prefix) == 512):
                if self.prefix.startswith((b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
                    raise ExtractionError("DOCUMENT_UNSAFE_XML")
                declared = XML_ENCODING.search(self.prefix)
                if declared and declared.group(1).lower().replace(b"_", b"-") not in (b"utf-8", b"utf8"):
                    raise ExtractionError("DOCUMENT_UNSAFE_XML")
                self.encoding_checked = True
            probe = self.tail + data
            if XML_DOCTYPE.search(probe): raise ExtractionError("DOCUMENT_UNSAFE_XML")
            self.tail = probe[-32:]
            return data
        def close(self): self.inner.close()
    return Guarded(source)

def local_name(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

def semantic_blocks(archive, member: str, writer: Writer, tags):
    """Stream semantic blocks, retaining nested text until their parent ends."""
    source = checked_xml_stream(archive, member); stack = []; count = 0
    try:
        for event, element in ET.iterparse(source, events=("start", "end")):
            tag = local_name(element.tag)
            if event == "start":
                stack.append(tag); continue
            if tag in tags:
                value = " ".join("".join(element.itertext()).split())
                if value: writer.write(value); count += 1
                element.clear()
            elif not any(ancestor in tags for ancestor in stack[:-1]):
                element.clear()
            stack.pop()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return count

def extract_docx_part(archive, member: str, writer: Writer):
    source = checked_xml_stream(archive, member); stack = []; count = 0
    try:
        for event, element in ET.iterparse(source, events=("start", "end")):
            tag = local_name(element.tag)
            if event == "start": stack.append(tag); continue
            if tag == "tr":
                cells = []
                for candidate in element.iter():
                    if local_name(candidate.tag) != "tc": continue
                    parts = [" ".join("".join(paragraph.itertext()).split()) for paragraph in candidate.iter() if local_name(paragraph.tag) == "p"]
                    cells.append(" ".join(part for part in parts if part))
                value = "	".join(cells)
                if value.strip(): writer.write(value); count += 1
                element.clear()
            elif tag == "p" and "tr" not in stack[:-1]:
                value = " ".join("".join(element.itertext()).split())
                if value: writer.write(value); count += 1
                element.clear()
            elif not any(ancestor in ("p", "tr") for ancestor in stack[:-1]): element.clear()
            stack.pop()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return count

def extract_slide_text(archive, member: str, writer: Writer):
    source = checked_xml_stream(archive, member); count = 0
    try:
        for event, element in ET.iterparse(source, events=("end",)):
            if local_name(element.tag) == "t":
                value = " ".join("".join(element.itertext()).split())
                if value: writer.write(value); count += 1
            element.clear()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return count

def parse_relationships(archive, member: str):
    source = checked_xml_stream(archive, member); result = {}
    try:
        for _, element in ET.iterparse(source, events=("end",)):
            if local_name(element.tag) == "Relationship":
                identifier, target = element.attrib.get("Id"), element.attrib.get("Target")
                if identifier and target and element.attrib.get("TargetMode", "Internal") == "Internal": result[identifier] = target
            element.clear()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return result

def resolve_part(base_member: str, target: str):
    if not target or "://" in target or "\\" in target: raise ExtractionError("DOCUMENT_STRUCTURE")
    raw = target.lstrip("/") if target.startswith("/") else (PurePosixPath(base_member).parent / target).as_posix()
    parts = []
    for part in raw.split("/"):
        if not part or part == ".": continue
        if part == "..":
            if not parts: raise ExtractionError("DOCUMENT_STRUCTURE")
            parts.pop(); continue
        parts.append(part)
    if not parts: raise ExtractionError("DOCUMENT_STRUCTURE")
    return "/".join(parts)


def has_visual_parts(names):
    return any(name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".wmf", ".emf"))
               or "/media/" in name.lower() or "/charts/" in name.lower() or "/drawings/" in name.lower() for name in names)

def extract_docx(path: str, writer: Writer):
    archive = zip_safety(path)
    try:
        names = {info.filename for info in archive.infolist()}
        if "[Content_Types].xml" not in names or "word/document.xml" not in names: raise ExtractionError("DOCUMENT_STRUCTURE")
        parts = ["word/document.xml"] + sorted(name for name in names if re.fullmatch(r"word/(?:header|footer|footnotes|endnotes|comments)\d*\.xml", name))
        for part in parts: extract_docx_part(archive, part, writer)
        warnings = (["MACROS_NOT_EXECUTED"] if any(name.startswith("word/vba") for name in names) else []) + (["VISUAL_CONTENT_NOT_ANALYZED"] if has_visual_parts(names) else [])
        empty = writer.units == 0
        return result(fmt="docx", state="partial" if empty else "complete", writer=writer, skipped=1 if empty else 0,
                      warnings=warnings + (["NO_EXTRACTABLE_TEXT"] if empty else []))
    finally: archive.close()

def shared_strings(archive):
    names = {info.filename for info in archive.infolist()}
    if "xl/sharedStrings.xml" not in names: return []
    values = []
    source = checked_xml_stream(archive, "xl/sharedStrings.xml")
    try:
        for event, element in ET.iterparse(source, events=("end",)):
            if local_name(element.tag) == "si":
                values.append("".join(element.itertext()))
                if len(values) > 250_000: raise ExtractionError("DOCUMENT_SHARED_STRINGS_LIMIT")
                element.clear()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return values

def workbook_sheets(archive):
    rels = parse_relationships(archive, "xl/_rels/workbook.xml.rels")
    source = checked_xml_stream(archive, "xl/workbook.xml"); sheets = []
    try:
        for _, element in ET.iterparse(source, events=("end",)):
            if local_name(element.tag) == "sheet":
                relation = next((value for key, value in element.attrib.items() if key.endswith("}id") or key == "r:id"), None)
                target = rels.get(relation or "")
                if target: sheets.append((element.attrib.get("name", "Foglio"), resolve_part("xl/workbook.xml", target)))
            element.clear()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return sheets

def extract_xlsx(path: str, writer: Writer):
    archive = zip_safety(path)
    try:
        names = {info.filename for info in archive.infolist()}
        if "[Content_Types].xml" not in names or "xl/workbook.xml" not in names or "xl/_rels/workbook.xml.rels" not in names: raise ExtractionError("DOCUMENT_STRUCTURE")
        strings, sheets = shared_strings(archive), workbook_sheets(archive)
        if not sheets: raise ExtractionError("DOCUMENT_STRUCTURE")
        saw_formula = False
        for sheet_name, sheet in sheets:
            if sheet not in names: raise ExtractionError("DOCUMENT_STRUCTURE")
            writer.write(f"[Foglio: {sheet_name}]")
            source = checked_xml_stream(archive, sheet)
            try:
                for event, element in ET.iterparse(source, events=("end",)):
                    if local_name(element.tag) != "row": continue
                    cells = []
                    for cell in element.iter():
                        if local_name(cell.tag) != "c": continue
                        cell_type = cell.attrib.get("t", ""); reference = cell.attrib.get("r", "cella")
                        values = [child.text or "" for child in cell.iter() if local_name(child.tag) in ("v", "t")]
                        raw = "".join(values)
                        if cell_type == "s" and raw.isdigit() and int(raw) < len(strings): raw = strings[int(raw)]
                        if any(local_name(child.tag) == "f" for child in cell.iter()): saw_formula = True
                        if raw.strip(): cells.append(f"{reference}: {raw}")
                    if cells: writer.write("	".join(cells))
                    element.clear()
            except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
            finally: source.close()
        # Numeric values are intentionally emitted exactly as stored. Styles
        # are not interpreted, so Excel serial dates and display formats must
        # never be presented as rendered spreadsheet values.
        warnings = (["MACROS_NOT_EXECUTED"] if any(name.startswith("xl/vba") for name in names) else []) + (["CACHED_FORMULA_VALUES"] if saw_formula else []) + ["SPREADSHEET_FORMATTING_NOT_RENDERED"] + (["VISUAL_CONTENT_NOT_ANALYZED"] if has_visual_parts(names) else [])
        empty = writer.units == 0
        return result(fmt="xlsx", state="partial" if empty else "complete", writer=writer, skipped=1 if empty else 0,
                      warnings=warnings + (["NO_EXTRACTABLE_TEXT"] if empty else []))
    finally: archive.close()

def presentation_slides(archive):
    rels = parse_relationships(archive, "ppt/_rels/presentation.xml.rels")
    source = checked_xml_stream(archive, "ppt/presentation.xml"); slides = []
    try:
        for _, element in ET.iterparse(source, events=("end",)):
            if local_name(element.tag) == "sldId":
                relation = next((value for key, value in element.attrib.items() if key.endswith("}id") or key == "r:id"), None)
                target = rels.get(relation or "")
                if target: slides.append(resolve_part("ppt/presentation.xml", target))
            element.clear()
    except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
    finally: source.close()
    return slides

def extract_pptx(path: str, writer: Writer):
    archive = zip_safety(path)
    try:
        names = {info.filename for info in archive.infolist()}
        if "[Content_Types].xml" not in names or "ppt/presentation.xml" not in names or "ppt/_rels/presentation.xml.rels" not in names: raise ExtractionError("DOCUMENT_STRUCTURE")
        slides = presentation_slides(archive)
        if not slides: raise ExtractionError("DOCUMENT_STRUCTURE")
        for index, slide in enumerate(slides, 1):
            if slide not in names: raise ExtractionError("DOCUMENT_STRUCTURE")
            writer.write(f"[Diapositiva {index}]")
            extract_slide_text(archive, slide, writer)
            rel_member = str(PurePosixPath(slide).parent / "_rels" / (PurePosixPath(slide).name + ".rels"))
            if rel_member in names:
                for target in parse_relationships(archive, rel_member).values():
                    note = resolve_part(slide, target)
                    if note in names and note.startswith("ppt/notesSlides/"):
                        writer.write(f"[Note diapositiva {index}]")
                        extract_slide_text(archive, note, writer)
        warnings = (["MACROS_NOT_EXECUTED"] if any(name.startswith("ppt/vba") for name in names) else []) + (["VISUAL_CONTENT_NOT_ANALYZED"] if has_visual_parts(names) else [])
        empty = writer.units == 0
        return result(fmt="pptx", state="partial" if empty else "complete", writer=writer, skipped=1 if empty else 0,
                      warnings=warnings + (["NO_EXTRACTABLE_TEXT"] if empty else []))
    finally: archive.close()

def extract_odf(path: str, fmt: str, writer: Writer):
    archive = zip_safety(path)
    try:
        try: mime = archive.read("mimetype")
        except KeyError: raise ExtractionError("DOCUMENT_STRUCTURE")
        if mime not in ODF_MIMES[fmt]: raise ExtractionError("TYPE_MISMATCH")
        semantic_blocks(archive, "content.xml", writer, ("p", "h"))
        # ODS cells may use repeated rows/cells and style-driven date/number
        # formatting. This bounded extractor preserves visible text but does
        # not reconstruct the worksheet grid.
        empty = writer.units == 0
        if fmt == "ods":
            return result(fmt=fmt, state="partial", writer=writer, skipped=1 + (1 if empty else 0),
                          warnings=["ODS_CELLS_NOT_RECONSTRUCTED", "SPREADSHEET_FORMATTING_NOT_RENDERED"] + (["NO_EXTRACTABLE_TEXT"] if empty else []))
        return result(fmt=fmt, state="partial" if empty else "complete", writer=writer, skipped=1 if empty else 0,
                      warnings=["NO_EXTRACTABLE_TEXT"] if empty else [])
    finally: archive.close()

def extract_epub(path: str, writer: Writer):
    archive = zip_safety(path); skipped = 0
    try:
        try: mime = archive.read("mimetype")
        except KeyError: raise ExtractionError("DOCUMENT_STRUCTURE")
        if mime != b"application/epub+zip": raise ExtractionError("TYPE_MISMATCH")
        container = checked_xml_stream(archive, "META-INF/container.xml")
        rootfile = None
        try:
            for _, element in ET.iterparse(container, events=("end",)):
                if local_name(element.tag) == "rootfile": rootfile = element.attrib.get("full-path")
                element.clear()
        except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
        finally: container.close()
        if not rootfile: raise ExtractionError("DOCUMENT_STRUCTURE")
        opf = checked_xml_stream(archive, rootfile); manifest = {}; spine = []
        try:
            for _, element in ET.iterparse(opf, events=("end",)):
                tag = local_name(element.tag)
                if tag == "item": manifest[element.attrib.get("id", "")] = element.attrib.get("href", "")
                elif tag == "itemref": spine.append(element.attrib.get("idref", ""))
                element.clear()
        except ET.ParseError: raise ExtractionError("DOCUMENT_XML_INVALID")
        finally: opf.close()
        base = str(PurePosixPath(rootfile).parent)
        for identifier in spine:
            href = manifest.get(identifier)
            if not href or href.startswith("/") or "://" in href or ".." in PurePosixPath(href).parts: skipped += 1; continue
            member = str(PurePosixPath(base) / href) if base != "." else href
            try: semantic_blocks(archive, member, writer, ("p", "h1", "h2", "h3", "li", "title"))
            except ExtractionError: skipped += 1
        if not spine: raise ExtractionError("DOCUMENT_STRUCTURE")
        empty = writer.units == 0
        return result(fmt="epub", state="partial" if skipped or empty else "complete", writer=writer, skipped=skipped + (1 if empty else 0),
                      warnings=(["EPUB_PARTS_SKIPPED"] if skipped else []) + (["NO_EXTRACTABLE_TEXT"] if empty else []))
    finally: archive.close()

def xls_column(index):
    value = index + 1; result = ""
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(65 + remainder) + result
    return result

def extract_xls(path: str, writer: Writer):
    try:
        import xlrd
    except ImportError:
        raise ExtractionError("DOCUMENT_UNSUPPORTED")
    try:
        workbook = xlrd.open_workbook(path, on_demand=True, formatting_info=False)
    except Exception:
        raise ExtractionError("DOCUMENT_MALFORMED")
    cells_seen = 0; limited = False
    try:
        for sheet_index in range(workbook.nsheets):
            sheet = workbook.sheet_by_index(sheet_index)
            writer.write(f"[Foglio: {sheet.name}]")
            for row in range(sheet.nrows):
                values = []
                for column in range(sheet.ncols):
                    cells_seen += 1
                    if cells_seen > MAX_XLS_CELLS:
                        limited = True; break
                    cell = sheet.cell(row, column)
                    if cell.value in ("", None): continue
                    value = str(cell.value)
                    values.append(f"{xls_column(column)}{row + 1}: {value}")
                if values: writer.write("\t".join(values))
                if limited: break
            if limited: break
    finally:
        try: workbook.release_resources()
        except Exception: pass
    empty = writer.units == 0
    return result(fmt="xls", state="partial" if limited or empty else "complete", writer=writer,
                  skipped=(1 if limited else 0) + (1 if empty else 0), warnings=["CACHED_FORMULA_VALUES", "SPREADSHEET_FORMATTING_NOT_RENDERED", "XLS_EMBEDDED_FEATURES_IGNORED"] + (["XLS_CELL_LIMIT"] if limited else []) + (["NO_EXTRACTABLE_TEXT"] if empty else []))

class UnrtfHtmlText(HTMLParser):
    """Consumes only converter-produced markup; entities become Unicode text."""
    BLOCK_TAGS = frozenset(("br", "div", "li", "p", "tr", "h1", "h2", "h3", "h4", "h5", "h6"))
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.BLOCK_TAGS: self.parts.append("\n")
    def handle_endtag(self, tag):
        if tag.lower() in self.BLOCK_TAGS: self.parts.append("\n")
    def handle_data(self, data):
        self.parts.append(data)
    def text(self):
        return "".join(self.parts)

def unrtf_html_text(raw: bytes):
    # The HTML profile uses entities for legacy RTF code pages. Keep valid
    # UTF-8 intact (including astral characters); only malformed UTF-8 falls
    # back to the RTF's conventional Windows-1252 output encoding.
    try: html = raw.decode(TEXT_ENCODING, "strict")
    except UnicodeDecodeError: html = raw.decode("cp1252", "strict")
    parser = UnrtfHtmlText()
    try: parser.feed(html); parser.close()
    except Exception: raise ExtractionError("DOCUMENT_MALFORMED")
    return parser.text()

def native_utf8_decoder():
    """One decoder per command stream: pipe chunks are not UTF-8 boundaries."""
    return codecs.getincrementaldecoder(TEXT_ENCODING)("strict")

def fixed_command(format_name):
    # Docker packaging chooses these fixed, root-owned paths. No shell is used.
    return {
        "pdf": ("/usr/bin/pdftotext", ["-enc", "UTF-8"]),
        # The plain-text profile is ASCII and has limited charset conversion.
        # HTML retains encoded Unicode entities; UnrtfHtmlText reduces it to
        # plain private text without exposing markup or writing pictures.
        "rtf": ("/usr/bin/unrtf", ["--nopict", "--html"]),
        "doc": ("/usr/bin/antiword", ["-w", "0"]),
    }.get(format_name)

def extract_command(path: str, fmt: str, writer: Writer):
    spec = fixed_command(fmt)
    if not spec: raise ExtractionError("DOCUMENT_UNSUPPORTED")
    binary, options = spec
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK): raise ExtractionError("DOCUMENT_UNSUPPORTED")
    command = [binary, *options, path, "-"] if fmt == "pdf" else [binary, *options, path]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    text_seen = False; pages = 0; empty_pages = 0; carry = ""; rtf_raw = bytearray(); rtf_output_limited = False
    decoder = None if fmt == "rtf" else native_utf8_decoder()
    def write_page(value):
        nonlocal pages, empty_pages, text_seen
        pages += 1; clean = " ".join(value.split())
        if clean:
            text_seen = True; writer.write(f"[Pagina {pages}]"); writer.write(clean)
        else: empty_pages += 1
    def consume_text(text):
        nonlocal text_seen, carry
        if fmt == "pdf":
            carry += text
            while "\f" in carry:
                page, carry = carry.split("\f", 1); write_page(page)
        elif text.strip():
            text_seen = True; writer.write(text)
    try:
        while True:
            data = process.stdout.read(64 * 1024)
            if not data: break
            if fmt == "rtf":
                room = MAX_COMMAND_STDOUT_BYTES - len(rtf_raw)
                if room <= 0:
                    rtf_output_limited = True
                    if process.poll() is None: process.kill()
                    break
                rtf_raw.extend(data[:room])
                if len(data) > room:
                    rtf_output_limited = True
                    if process.poll() is None: process.kill()
                    break
                continue
            consume_text(decoder.decode(data, final=False))
        if fmt == "rtf":
            text = unrtf_html_text(bytes(rtf_raw))
            if text.strip():
                text_seen = True; writer.write(text)
        else:
            consume_text(decoder.decode(b"", final=True))
        if fmt == "pdf" and (carry.strip() or pages == 0): write_page(carry)
        exit_code = process.wait(timeout=CPU_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(); raise ExtractionError("DOCUMENT_TIMEOUT")
    except BaseException:
        if process.poll() is None: process.kill(); process.wait()
        raise
    finally:
        if process.stdout: process.stdout.close()
    if rtf_output_limited: raise OutputLimitReached()
    if exit_code != 0: raise ExtractionError("DOCUMENT_MALFORMED")
    if fmt == "pdf":
        if not text_seen: return result(fmt=fmt, state="image_only", writer=writer, warnings=["IMAGE_ONLY_PDF", "OCR_NOT_AVAILABLE", "VISUAL_CONTENT_NOT_ANALYZED"])
        warnings = ["VISUAL_CONTENT_NOT_ANALYZED"] + (["PDF_PAGES_WITHOUT_TEXT"] if empty_pages else [])
        return result(fmt=fmt, state="partial" if empty_pages else "complete", writer=writer, skipped=empty_pages, warnings=warnings)
    return result(fmt=fmt, state="complete" if text_seen else "partial", writer=writer, skipped=0 if text_seen else 1,
                  warnings=[] if text_seen else ["NO_EXTRACTABLE_TEXT"])

def extract(path: str, fmt: str, writer: Writer):
    if fmt == "docx": return extract_docx(path, writer)
    if fmt == "xlsx": return extract_xlsx(path, writer)
    if fmt == "pptx": return extract_pptx(path, writer)
    if fmt in ODF_MIMES: return extract_odf(path, fmt, writer)
    if fmt == "epub": return extract_epub(path, writer)
    if fmt == "xls": return extract_xls(path, writer)
    return extract_command(path, fmt, writer)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input")
    parser.add_argument("--output")
    parser.add_argument("--format", choices=sorted(FORMATS))
    parser.add_argument("--network-guard-self-test", action="store_true")
    args = parser.parse_args()
    writer = None
    try:
        set_limits()
        install_linux_network_guard()
        if args.network_guard_self_test:
            if sys.platform != "linux":
                emit({"ok": True, "networkGuard": "not-required"}); return 0
            import socket
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except OSError as error:
                if error.errno == errno.EPERM:
                    emit({"ok": True, "networkGuard": "denied"}); return 0
                raise ExtractionError("NETWORK_GUARD_UNAVAILABLE")
            raise ExtractionError("NETWORK_GUARD_UNAVAILABLE")
        if not args.input or not args.output or not args.format:
            raise ExtractionError("DOCUMENT_ARGUMENTS")
        # Validate source after sandboxing; all normal extraction paths are guarded.
        fd, _ = open_source(args.input); os.close(fd)
        writer = Writer(args.output)
        try:
            payload = extract(args.input, args.format, writer)
        except OutputLimitReached:
            payload = result(fmt=args.format, state="partial", writer=writer, warnings=["EXTRACTED_TEXT_TRUNCATED"])
        writer.finish()
        emit(payload)
    except ExtractionError as error:
        if writer: writer.discard()
        emit({"ok": False, "code": error.code})
        return 2
    except (OSError, zipfile.BadZipFile, ValueError):
        if writer: writer.discard()
        emit({"ok": False, "code": "DOCUMENT_INVALID"})
        return 2
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        emit({"ok": False, "code": "DOCUMENT_WORKER_FAILED"})
        exit_code = 2
    sys.exit(exit_code)
