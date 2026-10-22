"""Read-only channel, endpoint side (gate 2).

docs/readonly-and-authorization.md §39.2: the whitelist check and argv
validation must happen *here*, at the execve endpoint, independently of the
control plane. A compromised or buggy control plane must not be able to turn a
readonly task into an arbitrary exec.

Therefore this module does NOT trust ``program``/``args`` from the wire:
- program must be an exact member of the local absolute-path whitelist,
- every argv token is re-validated here,
- realpath is resolved immediately before execve and must not have escaped,
- no shell is ever involved (no ``sh -c``, no ``Popen(shell=True)``).

Output is redacted *before* it leaves this machine: the readonly path is the
one place where a whole file's contents travel upstream, so masking happens
here rather than relying on the control plane alone (§48).
"""
from __future__ import annotations

import os
import re
import subprocess

# Must stay in sync with ai_ops/readonly_tools.py; a mismatch only ever fails
# closed (the Agent refuses), never opens the surface wider.
WHITELIST = {
    'read_file': '/usr/bin/cat',
    'list_dir': '/usr/bin/ls',
    'file_stat': '/usr/bin/stat',
    'disk_usage': '/usr/bin/df',
    'memory_info': '/usr/bin/free',
    'process_list': '/usr/bin/ps',
    'service_status': '/usr/bin/systemctl',
    'journal_logs': '/usr/bin/journalctl',
    'k8s_get': '/usr/bin/kubectl',
    'k8s_logs': '/usr/bin/kubectl',
}

FORBIDDEN_ARG_PREFIXES = (
    '-fprintf', '-fprint', '-fls', '--output', '--log-file', '--output-',
    '--exec', '-exec', '-execdir', '--compress-program', '--to-command',
)
SAFE_ARGV_TOKENS = frozenset({'--number', '--output=short-iso', 'wide'})
FORBIDDEN_ARG_TOKENS = frozenset({'-o', '--output'})
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}

MASK = '[REDACTED]'


class Rejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_READONLY_TOOLS = frozenset(WHITELIST)


def _real(path):
    try:
        return os.path.realpath(path, strict=True)
    except (OSError, ValueError):
        raise Rejected('PATH_NOT_READABLE')


def validate(task):
    """Re-validate a readonly task and return (program, argv) for execve."""
    tool = task.get('tool')
    program = task.get('program')
    args = task.get('args')
    if tool not in _READONLY_TOOLS:
        raise Rejected('TOOL_UNKNOWN')
    # The wire program must be exactly the whitelisted path for this tool, not
    # merely "something that exists": that closes the "point PROGRAMS at your
    # own binary" gap without needing a separate allowlist file.
    if program != WHITELIST[tool]:
        raise Rejected('PROGRAM_NOT_WHITELISTED')
    try:
        st = os.stat(program)
    except OSError:
        raise Rejected('PROGRAM_MISSING')
    if not os.access(program, os.X_OK):
        raise Rejected('PROGRAM_NOT_EXECUTABLE')
    if st.st_mode & 0o6000:
        raise Rejected('PROGRAM_SETID')  # never exec a setuid/setgid helper
    if not isinstance(args, list) or not 1 <= len(args) <= 64:
        raise Rejected('ARGV_INVALID')
    for arg in args:
        if not isinstance(arg, str) or not arg or '\x00' in arg or '\n' in arg:
            raise Rejected('ARGV_INVALID')
        low = arg.lower()
        if arg in SAFE_ARGV_TOKENS:
            continue
        if arg in FORBIDDEN_ARG_TOKENS:
            raise Rejected('ARGV_INVALID')
        if any(low.startswith(prefix) for prefix in FORBIDDEN_ARG_PREFIXES):
            raise Rejected('ARGV_INVALID')
    # Every absolute-path token must resolve to itself. This is the TOCTOU
    # mitigation from §39.4: a symlink swapped between check and exec either
    # fails here or, at worst, points at a path we also allow (sudoers + the
    # read-only account are the second line of defence).
    for arg in args:
        if arg.startswith('/'):
            if _real(arg) != arg:
                # /etc/nginx/nginx.conf -> /etc/nginx/nginx.conf is fine; a
                # symlink is not, because the audit record must name the file
                # that was actually read.
                raise Rejected('PATH_SYMLINKED')
    return program, list(args)


_VALUE_GROUP = re.compile(r'(?:[=:]\s*)(["\']?)([^\s,;"\'#]{4,})\1')


def _discovered_values(text):
    """Pull the actual secret value out of a matched line.

    The store keys on the value, so the value is what we need — but only ever
    the part after the ``=``/``:``, never the whole line (which would store the
    variable name as part of the secret, and then fail to match it later).
    """
    found = []
    for pattern, _replacement in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            inner = _VALUE_GROUP.search(match.group(0))
            value = inner.group(2) if inner else match.group(0)
            if 4 <= len(value) <= 4096:
                found.append(value)
    return found


_SECRET_PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----', re.S), MASK),
    (re.compile(r'(?i)(authorization\s*:\s*)(?:bearer|basic|token)?\s*[A-Za-z0-9._~+/=-]{8,}'), r'\1' + MASK),
    (re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^/\s:@]+)(@)'), r'\1' + MASK + r'\3'),
    (re.compile(r'(?i)(["\']?[A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*["\']?\s*[=:]\s*)("[^"]*"|\'[^\']*\'|[^\s,;"\']+)'), r'\1' + MASK),
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})'), MASK),
]


def redact(text, literals=()):
    """Mask secret-shaped text and known credential literals.

    ``literals`` are exact strings the Agent holds locally (its own credential
    store); the control plane never sees them (§47).
    """
    if not text:
        return text
    for literal in literals or ():
        if literal and len(literal) >= 4:
            text = text.replace(literal, MASK)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def execute(task, allowed_users, cancel_event=None, credentials=None):
    """Run one readonly task. Returns a result dict shaped like execute()."""
    claim_id = task.get('claim_id')
    run_as = task.get('run_as')
    if run_as not in (task.get('execution_users') or []) or run_as not in allowed_users:
        return _failed(claim_id, 'USER_NOT_ALLOWED')
    try:
        import pwd
        account = pwd.getpwnam(run_as)
    except (ImportError, KeyError):
        return _failed(claim_id, 'USER_NOT_FOUND')
    try:
        program, argv = validate(task)
    except Rejected as error:
        return _failed(claim_id, 'READONLY_REJECTED:' + error.code)
    timeout = task.get('timeout_seconds', 60)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        return _failed(claim_id, 'INVALID_TIMEOUT')
    if cancel_event is not None and cancel_event.is_set():
        return {'claim_id': claim_id, 'status': 'cancelled', 'exit_code': None,
                'stdout': '', 'stderr': '', 'error_code': 'CANCELLED_BEFORE_EXECUTION'}

    env = dict(ENV, HOME=account.pw_dir, USER=run_as, LOGNAME=run_as)
    identity = {}
    if os.geteuid() == 0:
        identity = {'user': account.pw_uid, 'group': account.pw_gid,
                    'extra_groups': os.getgrouplist(run_as, account.pw_gid), 'umask': 0o077}
    try:
        # argv list, no shell: nothing here can be re-parsed as a command.
        proc = subprocess.run([program] + argv, cwd='/', env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, start_new_session=True, **identity)
    except subprocess.TimeoutExpired:
        return _failed(claim_id, 'READONLY_TIMEOUT', status='failed')
    except PermissionError:
        return _failed(claim_id, 'CANNOT_SWITCH_USER')
    except OSError as error:
        return _failed(claim_id, 'READONLY_EXEC_FAILED:' + type(error).__name__)
    limit = 65536
    out = proc.stdout[:limit].decode('utf-8', 'replace')
    err = proc.stderr[:limit].decode('utf-8', 'replace')
    truncated = len(proc.stdout) > limit or len(proc.stderr) > limit
    # Discovery happens BEFORE masking, because masking destroys the value
    # (§42). The source comes from the task's own argv, so the handle records
    # the file that was actually read, not one the model named.
    discovered = []
    if credentials is not None:
        try:
            source = next((a for a in argv if a.startswith('/')), '')
            for value in _discovered_values(out) + _discovered_values(err):
                handle = credentials.register(value, source=source)
                if handle not in discovered:
                    discovered.append(handle)
        except Exception:
            # Discovery is an inventory feature; it must never break a read.
            discovered = []
    # Exact-match masking of known credential values first (§42.1 item 2): a
    # pattern can miss a value that is shaped like nothing in particular, but a
    # value we already hold cannot be missed. The literals never leave this host
    # — the control plane only ever sends handles (§47).
    literals = list(credentials.literals()) if credentials is not None else []
    literals.extend(task.get('_credential_literals') or [])
    return {'claim_id': claim_id, 'status': 'succeeded' if proc.returncode == 0 else 'failed',
            'exit_code': proc.returncode,
            # Readonly output is masked at the source: it is a whole file body.
            'stdout': redact(out, literals), 'stderr': redact(err, literals),
            'error_code': None if proc.returncode == 0 else 'READONLY_EXIT_' + str(proc.returncode),
            'output_truncated': truncated,
            # Handles only. The model sees ``cred-xxxx`` and a name; it never
            # sees the value, which is what makes this channel safe.
            'credentials': discovered}


def _failed(claim_id, code, status='failed'):
    return {'claim_id': claim_id, 'status': status, 'exit_code': None,
            'stdout': '', 'stderr': '', 'error_code': code, 'output_truncated': False}
