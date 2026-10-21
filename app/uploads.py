import os
import re

from fastapi import HTTPException, UploadFile

# extension -> the content type WE decide to serve it as
ALLOWED = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain; charset=utf-8",
}
MAGIC = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
}


def sanitize_filename(raw: str | None) -> str:
    """Keep only the last path piece and only safe characters."""
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    name = re.sub(r"\.{2,}", ".", name).strip(". ")
    stem, ext = os.path.splitext(name)
    return stem[:90] + ext[:10].lower()


def clean_category(raw: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9 _-]", "", raw or "").strip()[:50] or "general"


def read_limited(file: UploadFile, limit: int) -> bytes:
    """Read in small pieces and stop as soon as the file is too big."""
    chunks, total = [], 0
    while chunk := file.file.read(64 * 1024):
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, "File too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _content_matches(ext: str, data: bytes) -> bool:
    if ext == ".txt":
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return any(data.startswith(m) for m in MAGIC[ext])


def validate_upload(filename: str | None, data: bytes) -> tuple[str, str]:
    """Returns (clean_name, content_type) or raises an error."""
    name = sanitize_filename(filename)
    ext = os.path.splitext(name)[1]
    if ext not in ALLOWED:
        raise HTTPException(415, "File type not allowed")
    if len(data) == 0:
        raise HTTPException(400, "File is empty")
    if not _content_matches(ext, data):
        raise HTTPException(400, "File content does not match its extension")
    return name, ALLOWED[ext]