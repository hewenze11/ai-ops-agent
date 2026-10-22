"""Credential store, endpoint side (docs §42, §46, §47).

The product promise this module implements is narrow and literal:

    a secret discovered on a managed host stays on that host unless its owner
    explicitly lets it out.

So the plaintext lives here, encrypted with a key that never leaves the machine.
The control plane holds a *handle*: an id, a name, a note, where it was found.
A federated control plane may hold that handle too; neither holds the value.

Two things this is NOT:
  * Not protection against root on this host. Root can read the key file. The
    threat model is accidental leakage: a server backup, a VM snapshot, a
    support bundle. Those now contain ciphertext only.
  * Not a vault. There is no HSM, no KEK rotation ceremony, no remote unseal.
    Enterprise deployments are expected to point at a real vault (§46.1).

Storage shape (``credentials.json``, mode 0600, owned by the service account)::

    {"version": 1, "master_id": null,
     "credentials": {"cred-xxx": {"id", "name", "note", "source", "created_at",
                                  "used_at", "share": {"<master_id>": true},
                                  "secret": {"nonce": b64, "data": b64}}}}

``master_id`` is the controller this host is *owned* by (own mode). A host has at
most one. In own mode the value is also pushed upstream so the owner can manage
it centrally; in cooperative mode nothing leaves until each credential is
explicitly shared for that controller id.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STORE_NAME = 'credentials.json'
KEY_NAME = 'credentials.key'
FILE_MODE = 0o600

# A credential may only be injected into declared sinks (§42.1 item 1). Without
# this, "inject the db password" and "inject the db password into curl -d" are
# the same operation, and the second one is exfiltration.
class CredentialError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _atomic_write(path: Path, data: bytes, mode: int = FILE_MODE):
    """Write with the final mode from the first byte, then rename.

    ``tempfile`` + ``os.replace`` closes the window where a crash leaves a
    truncated store, and creating the file 0600 before writing means the
    plaintext-looking bytes are never readable by another local account.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix='.' + path.name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / STORE_NAME
        self.key_path = self.directory / KEY_NAME
        self._cached_key = None

    # -- key -------------------------------------------------------------
    def _key(self):
        if self._cached_key is not None:
            return self._cached_key
        try:
            data = self.key_path.read_bytes()
        except FileNotFoundError:
            data = b''
        if len(data) == 32:
            self._cached_key = data
            return data
        key = secrets.token_bytes(32)
        _atomic_write(self.key_path, key)
        self._cached_key = key
        return key

    # -- load/save -------------------------------------------------------
    def _load(self):
        try:
            raw = self.path.read_text(encoding='utf-8')
        except FileNotFoundError:
            return {'version': 1, 'master_id': None, 'credentials': {}}
        try:
            data = json.loads(raw)
        except ValueError:
            raise CredentialError('STORE_CORRUPT')
        if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('credentials'), dict):
            raise CredentialError('STORE_CORRUPT')
        data.setdefault('master_id', None)
        return data

    def _save(self, data):
        _atomic_write(self.path, json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1).encode('utf-8'))

    # -- crypto ----------------------------------------------------------
    def _encrypt(self, value: str) -> dict:
        nonce = os.urandom(12)
        blob = AESGCM(self._key()).encrypt(nonce, value.encode('utf-8'), None)
        return {'nonce': base64.b64encode(nonce).decode(), 'data': base64.b64encode(blob).decode()}

    def _decrypt(self, sealed: dict) -> str:
        try:
            nonce = base64.b64decode(sealed['nonce'])
            blob = base64.b64decode(sealed['data'])
            return AESGCM(self._key()).decrypt(nonce, blob, None).decode('utf-8')
        except (KeyError, TypeError, ValueError):
            raise CredentialError('CREDENTIAL_UNREADABLE')

    # -- own / cooperative mode -----------------------------------------
    def master_id(self):
        return self._load().get('master_id')

    def bind_owner(self, controller_id):
        """Own mode: this host belongs to that controller. One owner, ever."""
        with self._lock():
            data = self._load()
            current = data.get('master_id')
            if current and current != controller_id:
                # Re-binding silently would move every shared secret to a new
                # controller. Require an explicit unbind first.
                raise CredentialError('OWNER_ALREADY_BOUND')
            data['master_id'] = controller_id
            self._save(data)
        return controller_id

    def unbind_owner(self):
        with self._lock():
            data = self._load()
            data['master_id'] = None
            for entry in data['credentials'].values():
                entry['share'] = {}
            self._save(data)

    def _lock(self):
        return _FileLock(self.directory / '.credentials.lock')

    def trusting(self, controller_id):
        """Whether this controller may receive plaintext at all."""
        return self.master_id() is not None and self.master_id() == controller_id

    def may_share(self, controller_id, credential_id):
        data = self._load()
        if self.trusting(controller_id):
            return True
        entry = data['credentials'].get(credential_id)
        return bool(entry and entry.get('share', {}).get(controller_id) is True)

    # -- records ---------------------------------------------------------
    def register(self, value, name='', note='', source='', credential_id=None):
        """Store a discovered secret and return its handle.

        The id is derived from the value so re-discovering the same secret does
        not create a second entry (a read of the same file twice is not two
        secrets, and duplicates make the credential page useless).
        """
        if not isinstance(value, str) or not value:
            raise CredentialError('EMPTY_VALUE')
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()
        credential_id = credential_id or 'cred-' + digest[:16]
        with self._lock():
            data = self._load()
            existing = data['credentials'].get(credential_id)
            if existing is not None:
                # Keep the first discovery location: that is where the operator
                # will go to fix it. Refresh the value in case it rotated.
                existing['secret'] = self._encrypt(value)
                existing['used_at'] = existing.get('used_at')
                if source and not existing.get('source'):
                    existing['source'] = source
                self._save(data)
                return self.public(existing)
            entry = {'id': credential_id, 'name': name or credential_id, 'note': note,
                     'source': source, 'created_at': time.time(), 'used_at': None,
                     'share': {}, 'secret': self._encrypt(value)}
            data['credentials'][credential_id] = entry
            self._save(data)
            return self.public(entry)

    @staticmethod
    def public(entry):
        """Handle view: everything except the value."""
        return {k: entry.get(k) for k in ('id', 'name', 'note', 'source', 'created_at', 'used_at')} | {
            'share': sorted(k for k, v in (entry.get('share') or {}).items() if v is True)}

    def listing(self):
        data = self._load()
        return [self.public(entry) for entry in sorted(data['credentials'].values(), key=lambda e: e['created_at'])]

    def get(self, credential_id):
        entry = self._load()['credentials'].get(credential_id)
        return self.public(entry) if entry else None

    def reveal(self, credential_id):
        """Return the plaintext. Callers must be local CLI commands or the
        injection path — never a value that is handed to a model."""
        entry = self._load()['credentials'].get(credential_id)
        if entry is None:
            raise CredentialError('CREDENTIAL_UNKNOWN')
        value = self._decrypt(entry['secret'])
        with self._lock():
            data = self._load()
            if credential_id in data['credentials']:
                data['credentials'][credential_id]['used_at'] = time.time()
                self._save(data)
        return value

    def share(self, credential_id, controller_id, allowed=True):
        with self._lock():
            data = self._load()
            entry = data['credentials'].get(credential_id)
            if entry is None:
                raise CredentialError('CREDENTIAL_UNKNOWN')
            if allowed:
                entry.setdefault('share', {})[controller_id] = True
            else:
                entry.setdefault('share', {}).pop(controller_id, None)
            self._save(data)
            return self.public(entry)

    def revoke_controller(self, controller_id):
        """The managed host's veto: stop trusting a controller entirely."""
        with self._lock():
            data = self._load()
            if data.get('master_id') == controller_id:
                data['master_id'] = None
            for entry in data['credentials'].values():
                entry.get('share', {}).pop(controller_id, None)
            self._save(data)

    def destroy(self, credential_id):
        with self._lock():
            data = self._load()
            if data['credentials'].pop(credential_id, None) is None:
                raise CredentialError('CREDENTIAL_UNKNOWN')
            self._save(data)

    def literals(self):
        """Plaintext values, for exact-match redaction of tool output.

        Exact match beats a pattern: once we know a value, masking *that value*
        cannot miss and cannot over-match (§42.1 item 2).
        """
        values = []
        for entry in self._load()['credentials'].values():
            try:
                values.append(self._decrypt(entry['secret']))
            except CredentialError:
                continue
        return tuple(v for v in values if len(v) >= 4)


class _FileLock:
    """Serialize store mutation between the worker thread and the CLI.

    Both processes edit the same JSON file; a lost update on the ``share`` map
    would silently widen or narrow what leaves the host.
    """
    def __init__(self, path):
        self.path = path
        self.fd = None

    def __enter__(self):
        import fcntl
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *args):
        import fcntl
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def apply_injections(argv, params, store, controller_id):
    """Replace ``cred:<id>`` placeholders inside declared sink parameters.

    Only the parameter named by the action's own schema is eligible (see
    ``sinks`` below). The model composes ``cred:xxx`` in a place the engine
    expects a secret; it never composes a command line containing one.
    """
    result = {}
    for key, value in params.items():
        if isinstance(value, str) and value.startswith('cred:'):
            credential_id = value[5:]
            if key not in SINKS:
                raise CredentialError('CREDENTIAL_SINK_NOT_DECLARED')
            if not store.may_share(controller_id, credential_id):
                raise CredentialError('CREDENTIAL_NOT_SHARED:' + credential_id[:64])
            if key == 'path':
                # A file credential is materialized by the underlying tool via
                # its own path parameter; the value itself is a path, not text.
                result[key] = value
                continue
            result[key] = store.reveal(credential_id)
        else:
            result[key] = value
    return result


# Parameters a credential may be injected into. Deliberately tiny: every entry
# is a field whose whole purpose is "the secret goes here". Adding one is a
# security decision, not a feature flag.
SINKS = frozenset({'content', 'line'})


def mask_literals(text, literals):
    if not text:
        return text
    for literal in literals or ():
        if literal and len(literal) >= 4:
            text = text.replace(literal, '[REDACTED]')
    return text
