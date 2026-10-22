"""Linux behaviour of the readonly identity floor (§7).

Windows/dev platforms skip these: they exercise real accounts and a real
execve, which is the only way to know the floor exists.
"""
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='needs real accounts and execve')

from ai_ops_agent import agent, readonly  # noqa: E402


def _account(name):
    import pwd
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def _readonly_task(run_as, path='/etc/hostname'):
    return {'claim_id': 'c' * 24, 'kind': 'readonly', 'run_as': run_as,
            'execution_users': [run_as], 'tool': 'read_file',
            'program': readonly.WHITELIST['read_file'], 'args': ['--', path]}


def test_readonly_as_root_is_refused_unless_opted_in():
    if _account('root') is None:
        pytest.skip('no root account')
    result = readonly.execute(_readonly_task('root', '/etc/shadow'), ['root'])
    assert result['status'] == 'failed'
    assert result['error_code'] == 'READONLY_USER_ROOT'


def test_readonly_as_root_runs_when_opted_in(monkeypatch):
    """Opting in must not be a no-op: the same call then really executes."""
    if _account('root') is None:
        pytest.skip('no root account')
    task = _readonly_task('root', '/etc/hostname')
    if os.geteuid() != 0:
        # A non-root process cannot switch, but it can still run as itself.
        pytest.skip('needs root to switch into root explicitly')
    result = readonly.execute(task, ['root'], allow_root_readonly=True)
    assert result['status'] == 'succeeded', result
    assert result['stdout'].strip()


def test_config_refuses_the_flag_without_a_root_account():
    config = {'asset_id': 'h1', 'allowed_users': ['nobody_nonexistent_user_'],
              'journal_dir': '/tmp', 'controllers': [], 'allow_root_readonly': True,
              'url': 'https://control.example.com', 'token': 't' * 32}
    with pytest.raises(ValueError):
        agent.validate_config(config)


def test_config_refuses_a_non_boolean_flag():
    config = {'asset_id': 'h1', 'allowed_users': ['root'], 'journal_dir': '/tmp',
              'controllers': [], 'allow_root_readonly': 'yes', 'url': 'https://x', 'token': 't'}
    with pytest.raises(ValueError):
        agent.validate_config(config)


def test_config_default_is_off():
    """A config written before this flag existed must keep the old behaviour of
    the read channel being able to run only as its listed accounts, and root
    only if it was listed."""
    config = {'asset_id': 'h1', 'allowed_users': ['root'], 'journal_dir': '/tmp',
              'controllers': [], 'url': 'https://x', 'token': 't'}
    assert agent.validate_config(config).get('allow_root_readonly') is None
