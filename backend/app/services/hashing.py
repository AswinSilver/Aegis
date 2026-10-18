from __future__ import annotations

import hashlib
import mimetypes
from pathlib import PurePath
from typing import BinaryIO


MAX_HASH_BYTES = 10 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def _detected_file_type(prefix: bytes) -> str:
    """Return a conservative magic-byte classification for common evidence.

    This intentionally reports only a small, well-known signature set and
    falls back to a text/binary distinction.  The filename extension is kept
    separately and is never treated as proof of the file type.
    """

    signatures = (
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\x1f\x8b", "gzip stream"),
        (b"\x7fELF", "ELF binary"),
        (b"MZ", "PE/Windows executable header"),
        (b"SQLite format 3\x00", "SQLite database"),
    )
    for signature, label in signatures:
        if prefix.startswith(signature):
            return label
    try:
        prefix.decode("utf-8")
    except UnicodeDecodeError:
        return "binary data"
    return "UTF-8 text or unknown text format"


class EvidenceTooLargeError(ValueError):
    pass


def hash_stream(stream: BinaryIO, filename: str | None = None, content_type: str | None = None) -> dict:
    """Hash a local stream without executing, persisting, or forwarding its contents."""

    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    size = 0
    prefix = bytearray()
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_HASH_BYTES:
            raise EvidenceTooLargeError(f"file exceeds the {MAX_HASH_BYTES // (1024 * 1024)} MB limit")
        for digest in digests.values():
            digest.update(chunk)
        if len(prefix) < 512:
            prefix.extend(chunk[: 512 - len(prefix)])

    safe_name = PurePath(filename or "evidence").name
    guessed_type = mimetypes.guess_type(safe_name)[0] if safe_name else None
    content_type_value = content_type or guessed_type or "application/octet-stream"
    return {
        "metadata": {
            "filename": safe_name,
            "content_type": content_type_value,
            "mime_type": content_type_value,
            "size_bytes": size,
            "size": size,
            "extension": PurePath(safe_name).suffix.lower() or None,
            "detected_file_type": _detected_file_type(bytes(prefix)),
        },
        "hashes": {name: digest.hexdigest() for name, digest in digests.items()},
        "source": "local_stream",
        "executed": False,
        "uploaded_externally": False,
    }
