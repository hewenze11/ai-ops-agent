"""Endpoint-side readonly channel: independent validation + redaction (gate 2).

The control plane's check is not trusted here; these tests pin the Agent's own
rules (docs/readonly-and-authorization.md §39.2, §48).
"""
import os

import pytest

from ai_ops_agent import readonly


def task(**overrides):
    base = {'claim_id': 'c' * 24, 'tool': 'read_file', 'program': '/usr/bin/cat',
            'args': ['--number', '--', '/etc/hostname'], 'run_as': 'nobody',
            'execution_users': ['nobody'], 'timeout_seconds': 10}
    base.update(overrides)
    return base


def test_program_must_be_exactly_the_whitelisted_path():
    # A control plane bug (or a hostile one) must not be able to point the
    # tool at a different binary, even an absolute one.
    with pytest.raises(readonly.Rejected) as error:
        readonly.validate(task(program='/bin/cat'))
    assert error.value.code == 'PROGRAM_NOT_WHITELISTED'
    with pytest.raises(readonly.Rejected):
        readonly.validate(task(tool='read_file', program='/usr/bin/bash'))


def test_unknown_tool_and_unknown_kind_shapes_are_rejected():
    with pytest.raises(readonly.Rejected):
        readonly.validate(task(tool='exec_shell', program='/usr/bin/sh', args=['-c', 'id']))


@pytest.mark.parametrize('args', [
    ['--number', '--', '/etc/passwd', '-fprintf'],   # output redirection
    ['--number', '--', 'relative/path'],
    ['--number', '--', '/etc/pass\nwd'],
    [],
    'not-a-list',
])
def test_bad_argv_rejected(args):
    with pytest.raises(readonly.Rejected):
        readonly.validate(task(args=args))


def test_shell_metacharacters_are_not_interpreted(monkeypatch):
    # Because argv is exec'd directly, these are inert. The validator only has
    # to stop them from being *output redirection*; ';' stays a literal arg.
    import types
    fake = types.SimpleNamespace(st_mode=0o100755, st_size=0)
    monkeypatch.setattr(readonly.os, 'stat', lambda path: fake)
    monkeypatch.setattr(readonly.os, 'access', lambda path, mode: True)
    monkeypatch.setattr(readonly, '_real', lambda path: path)
    program, argv = readonly.validate(task(args=['--number', '--', '/tmp/a;id']))
    assert argv[-1] == '/tmp/a;id'


def test_redaction_masks_secret_shapes_and_local_literals():
    text = ('password=hunter2\nAuthorization: Bearer abcdefghijklmnop\n'
            'ghp_' + 'A' * 30 + '\nurl=redis://user:s3cret@127.0.0.1:6379\nlocal=hunter2')
    masked = readonly.redact(text, literals=('hunter2',))
    assert 'hunter2' not in masked
    assert 'abcdefghijklmnop' not in masked
    assert 'A' * 30 not in masked
    assert 's3cret' not in masked
    assert '[REDACTED]' in masked


def test_short_literals_are_not_masked_into_noise():
    # A 2-char "credential" would shred ordinary words; ignore those.
    assert readonly.redact('installation complete', literals=('in',)) == 'installation complete'


def _is_root():
    return hasattr(os, 'geteuid') and os.geteuid() == 0


@pytest.mark.skipif(not _is_root(), reason='needs root to switch accounts for real exec')
def test_real_exec_reads_file_without_a_shell():
    result = readonly.execute(task(run_as='nobody', execution_users=['nobody'],
                                   args=['--number', '--', '/etc/hostname']), ['nobody'])
    assert result['status'] == 'succeeded', result
    assert result['exit_code'] == 0


def test_dispatch_refuses_unknown_kind_and_never_falls_back_to_shell(monkeypatch):
    from ai_ops_agent import agent
    called = []
    monkeypatch.setattr(agent, 'execute', lambda *a, **k: called.append('shell'))
    result = agent.dispatch({'claim_id': 'c' * 24, 'kind': 'change-set-v9'}, ['nobody'])
    assert called == []
    assert result['error_code'].startswith('UNSUPPORTED_KIND')


def test_dispatch_routes_readonly_without_touching_shell(monkeypatch):
    from ai_ops_agent import agent
    seen = []
    monkeypatch.setattr(agent, 'execute', lambda *a, **k: seen.append('shell'))
    monkeypatch.setattr(readonly, 'execute', lambda *a, **k: seen.append('readonly') or {'status': 'failed'})
    agent.dispatch({'claim_id': 'c' * 24, 'kind': 'readonly'}, ['nobody'])
    assert seen == ['readonly']


def test_readonly_refuses_to_run_as_root_by_default(monkeypatch):
    """§7 floor: unless allowed_users holds root AND the config opts in, a
    readonly call for root is refused here, not upstream. A regex is not a
    permission model."""
    pwd = pytest.importorskip('pwd')
    try:
        pwd.getpwnam('root')
    except KeyError:
        pytest.skip('no root account on this platform')
    task = {'claim_id': 'c' * 24, 'kind': 'readonly', 'run_as': 'root',
            'execution_users': ['root'], 'tool': 'read_file',
            'program': readonly.WHITELIST['read_file'], 'args': ['--', '/etc/passwd']}
    monkeypatch.setattr(readonly.os, 'geteuid', lambda: 0)
    result = readonly.execute(task, ['root'], allow_root_readonly=False)
    assert result['error_code'] == 'READONLY_USER_ROOT'


def test_dispatch_passes_the_root_flag_through(monkeypatch):
    from ai_ops_agent import agent
    seen = {}
    monkeypatch.setattr(readonly, 'execute', lambda *a, **k: seen.update(k) or {'status': 'failed'})
    agent.dispatch({'claim_id': 'c' * 24, 'kind': 'readonly'}, ['nobody'], allow_root_readonly=True)
    assert seen['allow_root_readonly'] is True
