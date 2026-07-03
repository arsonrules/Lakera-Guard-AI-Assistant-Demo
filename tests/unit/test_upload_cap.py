"""Offline tests for the bounded upload reader (memory-DoS guard)."""
import pytest
from fastapi import HTTPException

from backend.main import _read_capped


class _StubUpload:
    """Minimal UploadFile stand-in: serves `data` in chunks via async read(size)."""
    def __init__(self, data: bytes):
        self._buf = data
        self._pos = 0

    async def read(self, size: int = -1) -> bytes:
        if self._pos >= len(self._buf):
            return b""
        end = len(self._buf) if size is None or size < 0 else self._pos + size
        chunk = self._buf[self._pos:end]
        self._pos = end
        return chunk


async def test_reads_content_under_cap():
    data = b"hello world"
    assert await _read_capped(_StubUpload(data), 1024) == data


async def test_allows_content_exactly_at_cap():
    data = b"A" * 100
    assert await _read_capped(_StubUpload(data), 100) == data


async def test_rejects_content_over_cap():
    data = b"A" * 101
    with pytest.raises(HTTPException) as exc:
        await _read_capped(_StubUpload(data), 100)
    assert exc.value.status_code == 413


async def test_rejects_large_content_without_buffering_all():
    # A body far larger than the cap must abort, not read the whole thing.
    stub = _StubUpload(b"A" * (5 * 1024 * 1024))
    with pytest.raises(HTTPException) as exc:
        await _read_capped(stub, 64 * 1024)
    assert exc.value.status_code == 413
    # Stopped early: consumed at most cap + one 64 KB chunk, not the full 5 MB.
    assert stub._pos <= 64 * 1024 + 64 * 1024
