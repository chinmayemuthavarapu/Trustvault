"""Upload validation.

The file's type is decided from its bytes, not from the client's Content-Type
header and not from the filename alone. The extension must agree with what the
bytes say. Formats that can carry active content are refused or inspected.
"""
import io
import re
import unicodedata
import zipfile

ALLOWED = {
    # ext: (file_type, description)
    "pdf": ("pdf", "PDF"),
    "docx": ("docx", "Word document"),
    "xlsx": ("xlsx", "Excel workbook"),
    "pptx": ("pptx", "PowerPoint deck"),
    "txt": ("text", "Plain text"),
    "csv": ("text", "CSV"),
    "md": ("text", "Markdown"),
    "png": ("png", "PNG image"),
    "jpg": ("jpeg", "JPEG image"),
    "jpeg": ("jpeg", "JPEG image"),
}

_OOXML_DIR = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}
_MAX_ZIP_ENTRIES = 2000
_MAX_UNCOMPRESSED = 200 * 1024 * 1024
_MAX_RATIO = 100

# PDF names that run code or open things when the file is viewed.
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA|OpenAction|AA)\b")


class UploadRejected(ValueError):
    pass


def clean_filename(name: str) -> str:
    """Display-only name. It is never used to build a filesystem path."""
    name = unicodedata.normalize("NFC", name or "")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    # Drop control characters and bidi overrides (e.g. "invoice‮fdp.exe").
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    name = name.strip().strip(".")
    if not name:
        raise UploadRejected("The file has no usable name.")
    if len(name) > 180:
        stem, dot, ext = name.rpartition(".")
        name = (stem[:170] + dot + ext) if dot else name[:180]
    return name


def extension(name: str) -> str:
    if "." not in name:
        raise UploadRejected("The file needs an extension, such as .pdf or .docx.")
    return name.rsplit(".", 1)[1].lower()


def _check_zip(data: bytes, ext: str) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise UploadRejected("The file is not a valid Office document.")
    infos = zf.infolist()
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise UploadRejected("The Office document has too many parts.")
    total = 0
    names = set()
    for info in infos:
        total += info.file_size
        if info.compress_size and info.file_size / max(info.compress_size, 1) > _MAX_RATIO:
            raise UploadRejected("The Office document is compressed suspiciously (possible zip bomb).")
        if info.filename.startswith("/") or ".." in info.filename.split("/"):
            raise UploadRejected("The Office document contains unsafe paths.")
        names.add(info.filename)
    if total > _MAX_UNCOMPRESSED:
        raise UploadRejected("The Office document expands to more than 200 MB.")
    if "[Content_Types].xml" not in names or not any(n.startswith(_OOXML_DIR[ext]) for n in names):
        raise UploadRejected(f"The file is not a real .{ext} document.")
    lowered = {n.lower() for n in names}
    if any(n.endswith("vbaproject.bin") or n.endswith(".bin") and "vba" in n for n in lowered):
        raise UploadRejected("Documents containing macros are not accepted.")
    if any("activex" in n for n in lowered):
        raise UploadRejected("Documents containing ActiveX controls are not accepted.")


def _check_text(data: bytes) -> None:
    if b"\x00" in data:
        raise UploadRejected("Text files must not contain binary data.")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise UploadRejected("Text files must be UTF-8.")


def detect_and_validate(filename: str, data: bytes, max_bytes: int) -> tuple[str, str]:
    """Returns (clean_name, file_type). Raises UploadRejected with a user-facing reason."""
    name = clean_filename(filename)
    ext = extension(name)
    if ext not in ALLOWED:
        allowed = ", ".join(sorted("." + e for e in ALLOWED))
        raise UploadRejected(f"Files of type .{ext} are not accepted. Allowed: {allowed}.")
    if len(data) == 0:
        raise UploadRejected("The file is empty.")
    if len(data) > max_bytes:
        raise UploadRejected(f"The file is larger than {max_bytes // (1024 * 1024)} MB.")
    file_type = ALLOWED[ext][0]
    if file_type == "pdf":
        if not data.startswith(b"%PDF-"):
            raise UploadRejected("The file does not look like a PDF.")
        m = _PDF_ACTIVE.search(data)
        if m:
            raise UploadRejected(f"PDFs with active content ({m.group(1).decode()}) are not accepted.")
    elif file_type in _OOXML_DIR:
        if not data.startswith(b"PK\x03\x04"):
            raise UploadRejected(f"The file is not a real .{ext} document.")
        _check_zip(data, ext)
    elif file_type == "png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise UploadRejected("The file is not a PNG image.")
    elif file_type == "jpeg":
        if not data.startswith(b"\xff\xd8\xff"):
            raise UploadRejected("The file is not a JPEG image.")
    elif file_type == "text":
        _check_text(data)
    return name, file_type


_TEXT_FIELD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")


def clean_text(value, field: str, max_len: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise UploadRejected(f"{field} must be text.")
    value = _TEXT_FIELD.sub("", unicodedata.normalize("NFC", value)).strip()
    if required and not value:
        raise UploadRejected(f"{field} is required.")
    if len(value) > max_len:
        raise UploadRejected(f"{field} must be at most {max_len} characters.")
    return value
