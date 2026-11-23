"""Long-term memory, encrypted at rest (C13) and labelled with provenance (C12).

Each memory's ciphertext is bound to its id *and* its trust label (AES-GCM associated data),
so someone editing the database cannot relabel an untrusted memory as trusted: the edited
row simply fails to decrypt and is reported as unreadable.
"""

import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime

from bastion.common import utc_now
from bastion.security.crypto import DecryptionError, FieldCipher
from bastion.tools.base import Trust

_WORD = re.compile(r"[a-z0-9]{3,}")


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    created_at: str
    trust: Trust
    source: str
    content: str


@dataclass(frozen=True)
class MemoryMatches:
    records: tuple[MemoryRecord, ...]
    unreadable: int


MAX_MEMORIES = 2_000
MAX_UNTRUSTED_MEMORIES = 200


class MemoryFullError(Exception):
    """Storing another memory would exceed a cap."""


def _context(memory_id: str, trust: str) -> str:
    return f"memory:{memory_id}:{trust}"


class MemoryBank:
    def __init__(
        self, conn: sqlite3.Connection, cipher: FieldCipher, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self._conn = conn
        self._cipher = cipher
        self._clock = clock

    def _count(self, trust: Trust | None = None) -> int:
        if trust is None:
            row = self._conn.execute("SELECT COUNT(*) FROM memories").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM memories WHERE trust = ?", (trust.value,)
            ).fetchone()
        return int(row[0])

    def add(self, content: str, *, trust: Trust, source: str) -> MemoryRecord:
        # Caps stop injected content from flooding memory (and crowding out real memories).
        if self._count() >= MAX_MEMORIES:
            raise MemoryFullError(f"memory is full ({MAX_MEMORIES} entries); delete some first")
        if trust is Trust.UNTRUSTED and self._count(Trust.UNTRUSTED) >= MAX_UNTRUSTED_MEMORIES:
            raise MemoryFullError("too many memories from untrusted conversations")
        record = MemoryRecord(
            id=secrets.token_hex(6),
            created_at=self._clock().isoformat(),
            trust=trust,
            source=source,
            content=content,
        )
        sealed = self._cipher.encrypt(content, context=_context(record.id, trust.value))
        self._conn.execute(
            "INSERT INTO memories (id, created_at, trust, source, content) VALUES (?, ?, ?, ?, ?)",
            (record.id, record.created_at, trust.value, source, sealed),
        )
        return record

    def _decrypted(self) -> Iterator[MemoryRecord | None]:
        rows = self._conn.execute(
            "SELECT id, created_at, trust, source, content FROM memories ORDER BY created_at DESC"
        )
        for memory_id, created_at, trust, source, sealed in rows:
            try:
                content = self._cipher.decrypt(sealed, context=_context(memory_id, trust))
            except DecryptionError:
                yield None
                continue
            yield MemoryRecord(memory_id, created_at, Trust(trust), source, content)

    def search(self, query: str, limit: int) -> MemoryMatches:
        terms = set(_WORD.findall(query.lower()))
        scored: list[tuple[int, MemoryRecord]] = []
        unreadable = 0
        for record in self._decrypted():
            if record is None:
                unreadable += 1
                continue
            score = sum(term in record.content.lower() for term in terms) if terms else 1
            if score:
                scored.append((score, record))
        # Trusted memories always rank above untrusted ones, so planted entries cannot crowd
        # them out; then by score. The sort is stable, so newest first within a tie.
        scored.sort(key=lambda pair: (pair[1].trust is Trust.UNTRUSTED, -pair[0]))
        return MemoryMatches(tuple(record for _, record in scored[:limit]), unreadable)

    def delete(self, memory_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        return cursor.rowcount > 0
