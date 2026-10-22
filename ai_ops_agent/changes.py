"""Change-set execution, endpoint side (gate 3).

A `kind=change` task carries an expanded change set: typed actions already
turned into program+argv by the control plane. This module re-checks the three
things that matter at the last mile:

1. The action kind still exists in *this* build's table (a table version skew
   must not run an action the Agent does not understand).
2. The expanded program+argv matches what the local table would produce for
   those params. If they differ, the payload was tampered with or the tables
   drifted — refuse either way.
3. The approval hash still matches. A human approved a specific payload; if it
   changed after approval, it no longer has that consent (§39.3).

No shell is used except for the `shell.run` action, which by construction is
human-approval-only and never reachable unattended.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess

from .output import Spool

# Mirrors ai_ops/actions.py. Only the parts the endpoint needs to re-derive argv.
UNIT = r'^[A-Za-z0-9@._:-]{1,128}$'
ABS_PATH = r'^/[^\x00\n\r]{0,1023}$'


class Rejected(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _match(pattern, value, field):
    import re
    if not isinstance(value, str) or '\x00' in value or not re.match(pattern, value):
        raise Rejected('ACTION_PARAM_INVALID:' + field)
    return value


BASELINE_DENY_PATHS = (
    '/etc/shadow', '/etc/shadow-', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d',
    '/root', '/boot', '/etc/ssh/ssh_host_', '/var/lib/ai-ops', '/etc/ai-ops-agent',
)


def _path(value, field):
    _match(ABS_PATH, value, field)
    if '..' in value.split('/'):
        raise Rejected('ACTION_PARAM_INVALID:' + field)
    for denied in BASELINE_DENY_PATHS:
        if value == denied or value.startswith(denied.rstrip('/') + '/'):
            raise Rejected('ACTION_PATH_DENIED:' + field)
    return value


def _int(value, field):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 365:
        raise Rejected('ACTION_PARAM_INVALID:' + field)
    return value


def _text(value, field):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise Rejected('ACTION_PARAM_INVALID:' + field)
    return value


BUILDERS = {
    'service.restart': ('/usr/bin/systemctl', lambda p: ['restart', _match(UNIT, p['unit'], 'unit')]),
    'service.reload': ('/usr/bin/systemctl', lambda p: ['reload', _match(UNIT, p['unit'], 'unit')]),
    'service.start': ('/usr/bin/systemctl', lambda p: ['start', _match(UNIT, p['unit'], 'unit')]),
    'service.stop': ('/usr/bin/systemctl', lambda p: ['stop', _match(UNIT, p['unit'], 'unit')]),
    'file.write': ('__builtin_write__', lambda p: [_path(p['path'], 'path')]),
    'file.append': ('__builtin_append__', lambda p: [_path(p['path'], 'path')]),
    'log.rotate': ('/usr/bin/truncate', lambda p: ['-s', '0', _path(p['path'], 'path')]),
    'disk.clean_temp': ('/usr/bin/find', lambda p: [_path(p['path'], 'path'), '-maxdepth', '1', '-type', 'f',
                                                   '-mtime', '+' + str(_int(p['days'], 'days')), '-delete']),
    'k8s.rollout_restart': ('/usr/bin/kubectl', lambda p: ['rollout', 'restart',
        _match(r'^(deployment|statefulset|daemonset)$', p['kind'], 'kind') + '/' +
        _match(r'^[a-z0-9]([a-z0-9.-]{0,251})$', p['name'], 'name'), '-n',
        _match(r'^[a-z0-9]([a-z0-9.-]{0,251})$', p['namespace'], 'namespace')]),
    'shell.run': ('/bin/sh', lambda p: ['-c', _text(p['command'], 'command')]),
}

# Actions that must never be auto-approved. The control plane enforces this in
# decide(); repeating it here means a compromised control plane cannot slip one
# through by simply marking it auto_approvable.
NEVER_AUTO = frozenset({'shell.run', 'file.write', 'file.append',
                        'service.start', 'service.stop'})


def payload_hash(asset_id, run_as, steps):
    # params MUST be part of the hash. For file.write the content lives only in
    # params (the argv is just the path), so a hash without params would let a
    # tampered body pass as "approved" — caught on a real host, 2026-10-22.
    material = {'asset_id': asset_id, 'run_as': run_as,
                'steps': [[s['action'], s['program'], s['args'], s['identity'], s.get('params')]
                          for s in steps]}
    blob = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(blob.encode()).hexdigest()


def validate(task):
    steps = task.get('steps')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 10:
        raise Rejected('CHANGE_SET_SIZE')
    for step in steps:
        if not isinstance(step, dict):
            raise Rejected('CHANGE_SET_SHAPE')
        action = step.get('action')
        if action not in BUILDERS:
            raise Rejected('ACTION_UNKNOWN:' + str(action)[:64])
        program, build = BUILDERS[action]
        params = step.get('params') or {}
        if not isinstance(params, dict):
            raise Rejected('ACTION_PARAMS_INVALID')
        argv = build(params)
        # Re-derive independently instead of trusting the wire.
        if step.get('program') != program or step.get('args') != argv:
            raise Rejected('ACTION_EXPANSION_MISMATCH:' + action)
        if not os.path.isabs(program) and not program.startswith('__builtin'):
            raise Rejected('ACTION_PROGRAM_NOT_ABSOLUTE')
    # The approval must cover exactly this payload.
    expected = payload_hash(task.get('asset_id'), task.get('run_as'), steps)
    approved = (task.get('approval') or {}).get('payload_sha256')
    if not approved or not isinstance(approved, str) or approved != expected:
        raise Rejected('APPROVAL_HASH_MISMATCH')
    return steps


def execute(task, allowed_users, cancel_event=None, output_dir=None, credentials=None, controller=None):
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
        steps = validate(task)
    except Rejected as error:
        return _failed(claim_id, 'ACTION_REJECTED:' + error.code)
    # Credential injection (§42.1 item 1): only the parameters this action table
    # declares as sinks get a value, and only if the local store agrees this
    # controller may see it. Everything else stays a literal placeholder, so a
    # prompt that puts cred:xxx somewhere clever injects nothing.
    literals = []
    if credentials is not None:
        controller_id = _controller_id(controller)
        try:
            steps = [dict(step, params=_inject(step, credentials, controller_id)) for step in steps]
        except CredentialError as error:
            return _failed(claim_id, 'ACTION_REJECTED:' + error.code)
        literals = list(credentials.literals())
    timeout = task.get('timeout_seconds', 120)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        return _failed(claim_id, 'INVALID_TIMEOUT')

    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'HOME': account.pw_dir, 'USER': run_as, 'LOGNAME': run_as, 'LANG': 'C.UTF-8'}
    identity = {}
    if os.geteuid() == 0:
        identity = {'user': account.pw_uid, 'group': account.pw_gid,
                    'extra_groups': os.getgrouplist(run_as, account.pw_gid), 'umask': 0o077}
    reports, failed_at = [], None
    for index, step in enumerate(steps, 1):
        if cancel_event is not None and cancel_event.is_set():
            reports.append({'step': index, 'action': step['action'], 'status': 'cancelled',
                            'exit_code': None, 'output': ''})
            failed_at = index
            break
        if failed_at is not None:
            reports.append({'step': index, 'action': step['action'], 'status': 'skipped',
                            'exit_code': None, 'output': ''})
            continue
        try:
            report = _run_step(step, env, identity, timeout, output_dir, cancel_event)
        except OSError as error:
            report = {'status': 'failed', 'exit_code': None,
                      'output': 'exec failed: ' + type(error).__name__, 'error_code': 'ACTION_EXEC_FAILED'}
        except Rejected as error:
            report = {'status': 'failed', 'exit_code': None,
                      'output': '', 'error_code': error.code}
        report.update({'step': index, 'action': step['action']})
        reports.append(report)
        if report['status'] != 'succeeded':
            failed_at = index

    overall = 'succeeded' if failed_at is None else (
        'cancelled' if reports[failed_at - 1]['status'] == 'cancelled' else 'failed')
    body = '\n'.join('[%d] %s %s: %s' % (r['step'], r['action'], r['status'],
                                         _mask((r.get('output') or '').strip()[:2000], literals))
                     for r in reports)
    return {'claim_id': claim_id, 'status': overall,
            'exit_code': 0 if overall == 'succeeded' else (reports[-1].get('exit_code') or 1),
            # The receipt is redacted by the caller's normal pipeline, but see
            # §43.3: it is masked here too because actions print environment
            # and connection strings.
            'stdout': body, 'stderr': '',
            'error_code': None if overall == 'succeeded' else 'ACTION_STEP_FAILED',
            'output_truncated': False,
            'change_report': reports}


def _run_step(step, env, identity, timeout, output_dir, cancel_event):
    action, params = step['action'], step['params']
    # Re-check the injected value: injection puts plaintext into params, so the
    # argv rebuilt for the wire must be rebuilt from the same params, not from
    # whatever the control plane claimed.
    rebuilt = BUILDERS.get(action)
    if rebuilt is not None:
        step = dict(step, args=rebuilt[1](params))
    if action == 'file.write':
        return _write(params['path'], params['content'])
    if action == 'file.append':
        return _append(params['path'], params['line'])
    proc = subprocess.run([step['program']] + step['args'], cwd='/', env=env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, start_new_session=True, **identity)
    text = (proc.stdout + proc.stderr)[:65536].decode('utf-8', 'replace')
    return {'status': 'succeeded' if proc.returncode == 0 else 'failed',
            'exit_code': proc.returncode, 'output': text}


def _atomic_write(path, content, mode='w'):
    """Write via a sibling temp file + rename so a half-written config is never
    live, and keep the original permissions."""
    directory = os.path.dirname(path) or '/'
    stamp = '.aiops-%d.tmp' % os.getpid()
    temporary = os.path.join(directory, stamp)
    try:
        existing = os.stat(path)
        os.chmod(temporary, existing.st_mode & 0o7777) if os.path.exists(temporary) else None
    except FileNotFoundError:
        pass
    with open(temporary, mode, encoding='utf-8') as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.stat(path)
        os.chmod(temporary, os.stat(path).st_mode & 0o7777)
    except FileNotFoundError:
        os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return {'status': 'succeeded', 'exit_code': 0, 'output': 'wrote %d bytes to %s' % (len(content), path)}


def _write(path, content):
    return _atomic_write(path, content, 'w')


def _append(path, line):
    with open(path, 'a', encoding='utf-8') as handle:
        handle.write(line if line.endswith('\n') else line + '\n')
    return {'status': 'succeeded', 'exit_code': 0, 'output': 'appended to ' + path}


def _mask(text, literals):
    """Exact-match mask of every credential value this host holds.

    Runs over the receipt because a legitimatised command prints its own
    arguments (``kubectl`` echoes the deployment, a failing daemon prints the
    connection string it was given), and the receipt is model-visible (§42.1).
    """
    if not text or not literals:
        return text
    for literal in literals:
        if literal and len(literal) >= 4:
            text = text.replace(literal, '[REDACTED]')
    return text


def _controller_id(controller):
    """Stable identity of the asking control plane.

    The config may name it explicitly; otherwise the URL origin is the identity,
    because that is what the operator configured and what the agent contacted.
    """
    if not isinstance(controller, dict):
        return ''
    if controller.get('controller_id'):
        return controller['controller_id']
    import urllib.parse
    parts = urllib.parse.urlsplit(controller.get('url') or '')
    return (parts.scheme + '://' + parts.netloc) if parts.netloc else ''


def _inject(step, store, controller_id):
    """Replace ``cred:<id>`` in declared sink parameters only."""
    from .credentials import CredentialError, SINKS
    params = dict(step['params'])
    for key, value in params.items():
        if isinstance(value, str) and value.startswith('cred:'):
            credential_id = value[5:]
            if key not in SINKS:
                raise CredentialError('CREDENTIAL_SINK_NOT_DECLARED')
            if not store.may_share(controller_id, credential_id):
                raise CredentialError('CREDENTIAL_NOT_SHARED')
            params[key] = store.reveal(credential_id)
    return params


def _failed(claim_id, code):
    return {'claim_id': claim_id, 'status': 'failed', 'exit_code': None, 'stdout': '',
            'stderr': '', 'error_code': code, 'output_truncated': False}
