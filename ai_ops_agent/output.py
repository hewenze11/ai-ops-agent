"""Bounded raw-byte spool; errors/limits are never reported as complete output."""
import hashlib
import os
from pathlib import Path

ARCHIVE_LIMIT = 64 * 1024 * 1024
CHUNK_BYTES = 65536


class Spool:
    def __init__(self, directory, stream, limit=ARCHIVE_LIMIT):
        self.path = Path(directory) / stream
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.file = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        self.size, self.limit = 0, limit
        self.complete = True
        self.digest = hashlib.sha256()

    def write(self, data):
        accepted = data[:max(0, self.limit - self.size)]
        if len(accepted) < len(data):
            self.complete = False
        try:
            self.file.write(accepted)
            self.digest.update(accepted)
            self.size += len(accepted)
        except OSError:
            self.complete = False

    def close(self):
        try:
            self.file.flush()
            os.fsync(self.file.fileno())
        except OSError:
            self.complete = False
        finally:
            self.file.close()
        # Hash actual persisted bytes, not a potentially failed buffered write.
        digest = hashlib.sha256()
        size = 0
        with self.path.open('rb') as f:
            while data := f.read(CHUNK_BYTES):
                digest.update(data)
                size += len(data)
        if size != self.size:
            self.complete = False
        return {'size': size, 'sha256': digest.hexdigest(), 'complete': self.complete}
