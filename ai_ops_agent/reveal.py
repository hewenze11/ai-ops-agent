"""Operator-initiated reveal, endpoint side (docs §51.4).

The feature exists so an operator can see one secret value during an incident
without pasting it into a chat transcript. The whole design problem is
therefore: how does the Agent know this read is the operator's, and not the
model's?

The answer is that a reveal is **not a flag on a readonly task**. It is a
separate task kind, and only the control plane's admin endpoints can create
one -- there is no model-facing tool that produces a ``reveal`` task, for the
same reason §41 gives for credential handles: an AI that can take off its own
blindfold is not wearing one.

What this module will and will not do
------------------------------------
* It re-runs a read the turn was *already allowed to read*. The path comes
  from the stored sensitive hit on the control plane, but this side does not
  trust that: the incoming argv is revalidated by ``readonly.validate`` exactly
  as a normal read would be, so a reveal can never reach a path or a tool the
  readonly whitelist does not already allow.
* It runs as the same unprivileged account, under the same root refusal, with
  the same timeout and the same no-shell execve.
* It returns the **unmasked** bytes, but only for ``read_file``. Reveal of a
  whole directory listing or a journal stream would make "unlock this one file"
  into "unlock the log universe", so those are refused rather than silently
  truncated.
* It also reports the secret-shaped segments it would have masked in a normal
  read. That way the operator's view is still auditable: they see the value
  *and* the fact that it looked like a secret.

One structural limit worth stating plainly: the reveal result travels the same
API response that normal task results use, and this module cannot police what
the control plane does with it afterwards. Keeping it out of the model's
context is enforced on the control plane side (§51.4), where the model's
message history actually lives.
"""
from __future__ import annotations

import os
import subprocess

from . import readonly
from .readonly import Rejected, MASK

# A reveal is a human reading one file. Anything larger than this is not a
# value being inspected, it is a dump.
MAX_REVEAL_BYTES = 256 * 1024

# Only these tools may be revealed. See the module docstring: "unlock this
# file" must not become "unlock everything the readonly channel can reach".
REVEALABLE_TOOLS = frozenset({'read_file'})


def _failed(claim_id, code, status='failed'):
    return {'claim_id': claim_id, 'status': status, 'exit_code': None,
            'stdout': '', 'stderr': '', 'error_code': code, 'output_truncated': False}


def check(task, allowed_users):
    """Everything that decides *whether* this reveal may run.

    Split from ``execute`` so the decisions can be tested anywhere. On the dev
    machine there is no ``pwd`` module, so a refusal decided here is the only
    part of this path that can be exercised honestly off-Linux.

    Returns an error code string, or None when the task may proceed.
    """
    run_as = task.get('run_as')
    if run_as not in (task.get('execution_users') or []) or run_as not in allowed_users:
        return 'USER_NOT_ALLOWED'
    tool = task.get('tool')
    if tool not in REVEALABLE_TOOLS:
        # Refuse to widen. A directory listing or a log stream revealed in full
        # is a different feature with a different threat model.
        return 'REVEAL_TOOL_NOT_ALLOWED'
    return None


def _account_exit(run_as):
    """The refusal codes that depend on the local account database."""
    try:
        import pwd
        account = pwd.getpwnam(run_as)
    except (ImportError, KeyError):
        return None, 'USER_NOT_FOUND'
    # A reveal is the highest-value read this Agent performs, so the root floor
    # applies with no exceptions: root can read every private key on the box and
    # this path hands the bytes back without masking.
    if account.pw_uid == 0:
        return None, 'REVEAL_USER_ROOT'
    return account, None


def execute(task, allowed_users, cancel_event=None, credentials=None,
            allow_root_readonly=False):
    """Re-run one stored read with masking disabled. Operator-facing only."""
    claim_id = task.get('claim_id')
    refusal = check(task, allowed_users)
    if refusal:
        return _failed(claim_id, refusal)
    run_as = task['run_as']
    account, refusal = _account_exit(run_as)
    if refusal:
        return _failed(claim_id, refusal)
    tool = task.get('tool')
    try:
        # Same validation as a normal read, deliberately: the reveal path adds
        # no new argv surface. If readonly.validate would refuse it, so do we.
        program, argv = readonly.validate(task)
    except Rejected as error:
        return _failed(claim_id, 'READONLY_REJECTED:' + error.code)

    timeout = task.get('timeout_seconds', 60)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        return _failed(claim_id, 'INVALID_TIMEOUT')
    if cancel_event is not None and cancel_event.is_set():
        return {'claim_id': claim_id, 'status': 'cancelled', 'exit_code': None,
                'stdout': '', 'stderr': '', 'error_code': 'CANCELLED_BEFORE_EXECUTION'}

    env = dict(readonly.ENV, HOME=account.pw_dir, USER=run_as, LOGNAME=run_as)
    identity = {}
    if os.geteuid() == 0:
        identity = {'user': account.pw_uid, 'group': account.pw_gid,
                    'extra_groups': os.getgrouplist(run_as, account.pw_gid),
                    'umask': 0o077}
    try:
        proc = subprocess.run([program] + argv, cwd='/', env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout,
                              start_new_session=True, **identity)
    except subprocess.TimeoutExpired:
        return _failed(claim_id, 'READONLY_TIMEOUT', status='failed')
    except PermissionError:
        return _failed(claim_id, 'CANNOT_SWITCH_USER')
    except OSError as error:
        return _failed(claim_id, 'READONLY_EXEC_FAILED:' + type(error).__name__)

    truncated = len(proc.stdout) > MAX_REVEAL_BYTES
    # Unmasked on purpose -- that is the entire point of this path.
    out = proc.stdout[:MAX_REVEAL_BYTES].decode('utf-8', 'replace')
    err = proc.stderr[:MAX_REVEAL_BYTES].decode('utf-8', 'replace')
    # Tell the operator what the normal read would have hidden, so the reveal
    # is auditable rather than an unexplained wall of plaintext.
    masked_rules = _rule_count(out) + _rule_count(err)
    return {'claim_id': claim_id,
            'status': 'succeeded' if proc.returncode == 0 else 'failed',
            'exit_code': proc.returncode,
            'stdout': out, 'stderr': err,
            'error_code': None if proc.returncode == 0 else 'READONLY_EXIT_' + str(proc.returncode),
            'output_truncated': truncated,
            # Not a credential handle: this is the operator's view, and the
            # values are already in the body. Registering them would put the
            # secret into the handle store as a side effect of looking at it.
            'credentials': [],
            'revealed_segments': masked_rules}


def _rule_count(text):
    """How many secret-shaped segments a normal read would have masked."""
    if not text:
        return 0
    return sum(len(pattern.findall(text)) for pattern, _ in readonly._SECRET_PATTERNS)
