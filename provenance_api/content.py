"""Process-local, content-addressed chunk storage and assembly.

A chunk upload session is opened lazily by the first accepted chunk for a
resource; the first chunk fixes the total chunk count and the target digest.
Chunks are held in process memory only and are discarded when the process
stops. Nothing here is written to disk and no concurrency control, resumable
upload or cross-resource operation is promised.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


class ContentError(ValueError):
    """An operation on a chunk session or finished content was rejected.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(slots=True)
class _Session:
    total_chunks: int
    digest: str
    chunks: dict[int, bytes] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ContentStore:
    """In-process chunk sessions keyed by resource id.

    Stored separately from the resource registry: a finished content record
    never mutates a resource, and registry state never changes because of an
    upload or assembly.
    """

    _sessions: dict[str, _Session] = field(default_factory=dict)
    _finished: dict[str, bytes] = field(default_factory=dict)

    def reset(self) -> None:
        self._sessions.clear()
        self._finished.clear()

    def is_complete(self, resource_id: str) -> bool:
        return resource_id in self._finished

    def get_content(self, resource_id: str) -> bytes | None:
        return self._finished.get(resource_id)

    def put_chunk(
        self, resource_id: str, index: int, total_chunks: int, digest: str, data: bytes
    ) -> bool:
        """Accept one chunk for a resource.

        The first chunk fixes ``total_chunks`` and the target ``digest``.
        Returns ``True`` when a new chunk was stored and ``False`` when an
        identical chunk for the same index was submitted again (idempotent
        resubmission). Raises :class:`ContentError` on any conflict; a raised
        error never changes stored bytes.
        """

        if resource_id in self._finished:
            raise ContentError(
                "content_already_complete",
                "Content for this resource is already complete.",
            )

        session = self._sessions.get(resource_id)
        if session is None:
            session = _Session(total_chunks=total_chunks, digest=digest)
            # Store only after every in-memory value is ready, so a failure to
            # build the session cannot leave a partial record.
            self._sessions[resource_id] = session
        else:
            if session.total_chunks != total_chunks or session.digest != digest:
                raise ContentError(
                    "chunk_conflict",
                    "Chunk metadata must match the first chunk for this resource.",
                )

        existing = session.chunks.get(index)
        if existing is not None:
            if existing != data:
                raise ContentError(
                    "chunk_conflict",
                    "A different chunk was already stored for this index.",
                )
            return False

        session.chunks[index] = data
        return True

    def assemble(self, resource_id: str) -> tuple[str, int]:
        """Concatenate every chunk in index order and verify the SHA-256.

        Returns ``(digest, byte_count)`` and marks the content complete.
        Raises :class:`ContentError` with ``content_already_complete`` for a
        repeated assembly, ``chunks_incomplete`` while any index is missing,
        or ``digest_mismatch`` when the assembled digest differs from the
        registered target; a mismatch never produces finished content.
        """

        if resource_id in self._finished:
            raise ContentError(
                "content_already_complete",
                "Content for this resource is already complete.",
            )

        session = self._sessions.get(resource_id)
        if session is None or any(
            index not in session.chunks for index in range(session.total_chunks)
        ):
            raise ContentError(
                "chunks_incomplete",
                "Not all chunks have been received yet.",
            )

        assembled = b"".join(
            session.chunks[index] for index in range(session.total_chunks)
        )
        digest = hashlib.sha256(assembled).hexdigest()
        if digest != session.digest:
            raise ContentError(
                "digest_mismatch",
                "The assembled content does not match the registered digest.",
            )

        self._finished[resource_id] = assembled
        return digest, len(assembled)
