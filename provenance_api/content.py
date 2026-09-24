"""Process-local, content-addressed chunk storage and assembly.

A chunk session is opened implicitly by the first accepted chunk for a
resource. The first chunk fixes the total chunk count and the target digest
for the whole content; later chunks must repeat both. Assembling
concatenates the chunks in index order, computes SHA-256 and, on success,
marks the resource content complete.

Everything lives in the current process memory: sessions, chunks and
completed content are lost on restart. There is intentionally no resume
protocol, no concurrency locking and no cross-resource batching.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


class ContentError(ValueError):
    """A chunk upload, assembly or content read could not proceed.

    ``code`` is the stable, client-facing error code.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(slots=True)
class _Session:
    """Upload state for one resource, completed or still in progress."""

    total: int
    digest: str
    chunks: dict[int, bytes] = field(default_factory=dict)
    complete: bool = False
    content: bytes = b""


class ContentStore:
    """In-process chunk sessions keyed by resource id."""

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}

    def reset(self) -> None:
        self._sessions = {}

    def is_complete(self, resource_id: str) -> bool:
        session = self._sessions.get(resource_id)
        return session is not None and session.complete

    def add_chunk(
        self,
        resource_id: str,
        total: int,
        digest: str,
        registered_digest: str,
        index: int,
        data: bytes,
    ) -> tuple[bool, int]:
        """Store one chunk.

        ``total`` is a positive integer, ``digest`` the 64-character lowercase
        hex target digest advertised by this request, ``registered_digest``
        the resource's registered digest and ``index`` satisfies
        ``0 <= index < total``.

        Returns ``(created, received)`` where ``created`` is ``True`` when a
        new chunk was stored (HTTP 201) and ``False`` when the same chunk was
        submitted again byte-for-byte (HTTP 200, idempotent); ``received`` is
        the number of distinct chunk indices now held. Raises
        :class:`ContentError` for:

        - ``content_already_complete`` after the content has been assembled;
        - ``digest_conflict`` when the first chunk targets a digest other than
          the registered one (no session is created, no bytes are stored);
        - ``chunk_conflict`` when later chunk metadata (total or digest)
          differs from the first chunk, or when the same index already holds
          different bytes.
        """

        session = self._sessions.get(resource_id)
        if session is not None and session.complete:
            raise ContentError(
                "content_already_complete",
                "Content for this resource is already complete.",
            )

        if session is None:
            if digest != registered_digest:
                raise ContentError(
                    "digest_conflict",
                    "Target digest does not match the registered resource "
                    "digest.",
                )
            session = _Session(total=total, digest=digest)
            self._sessions[resource_id] = session
        elif session.total != total or session.digest != digest:
            # The first chunk fixes total count and target digest. Its digest
            # equals the registered digest, so a later mismatch is a deviation
            # from the established upload rather than a new target proposal.
            raise ContentError(
                "chunk_conflict",
                "Chunk metadata conflicts with the first chunk.",
            )

        existing = session.chunks.get(index)
        if existing is not None:
            if existing != data:
                raise ContentError(
                    "chunk_conflict",
                    "Different bytes were already submitted for this index.",
                )
            return False, len(session.chunks)

        session.chunks[index] = data
        return True, len(session.chunks)

    def assemble(self, resource_id: str) -> tuple[str, int]:
        """Concatenate all chunks in order and finalize the content.

        Returns ``(digest, size)`` for the completed content. Raises
        :class:`ContentError` with ``chunks_incomplete`` when any index is
        missing (received chunks are retained), ``digest_mismatch`` when the
        assembled SHA-256 differs from the registered target digest (no
        content is produced), or ``content_already_complete`` afterwards.
        """

        session = self._sessions.get(resource_id)
        if session is None:
            raise ContentError(
                "chunks_incomplete",
                "No chunks have been received for this resource.",
            )
        if session.complete:
            raise ContentError(
                "content_already_complete",
                "Content for this resource is already complete.",
            )

        if len(session.chunks) != session.total or any(
            index not in session.chunks for index in range(session.total)
        ):
            raise ContentError(
                "chunks_incomplete",
                "Not all chunks have been received; assembly is refused.",
            )

        content = b"".join(session.chunks[index] for index in range(session.total))
        digest = hashlib.sha256(content).hexdigest()
        if digest != session.digest:
            # Keep the received chunks; do not produce finalized content.
            raise ContentError(
                "digest_mismatch",
                "Assembled content does not match the registered digest.",
            )

        session.complete = True
        session.content = content
        return digest, len(content)

    def get_content(self, resource_id: str) -> bytes:
        """Return the finalized raw bytes.

        Raises ``content_not_complete`` until assembly succeeds.
        """

        session = self._sessions.get(resource_id)
        if session is None or not session.complete:
            raise ContentError(
                "content_not_complete",
                "Content for this resource is not complete.",
            )
        return session.content
