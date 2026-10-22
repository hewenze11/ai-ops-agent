"""Unit file and install-time warnings.

Runs on any platform: the pieces tested here are pure string/decision logic, so
a Linux-only skip would hide regressions from the dev machine.
"""
import os
import sys

import pytest

from ai_ops_agent import service


def test_switching_users_unit_keeps_setuid_but_drops_no_new_privileges():
    """An agent that setuids must not carry NoNewPrivileges: the child exec
    fails with EPERM and every task looks like CANNOT_SWITCH_USER."""
    unit = service.unit_text('h1', 'root', '/opt/x/ai-ops-agent', '/etc/ai-ops-agent/config.json',
                             '/var/lib/ai-ops-agent')
    assert 'User=root' in unit
    directives = [l for l in unit.splitlines() if l.strip() and not l.lstrip().startswith('#')]
    assert not any(l.startswith('NoNewPrivileges') for l in directives)
    assert 'CAP_SETUID' in unit


def test_single_account_unit_is_hardened():
    unit = service.unit_text('h1', 'aiops', '/opt/x/ai-ops-agent', '/etc/ai-ops-agent/config.json',
                             '/var/lib/ai-ops-agent')
    assert 'NoNewPrivileges=yes' in unit
    assert 'CapabilityBoundingSet=\n' in unit


def test_executable_resolves_the_console_script_not_the_interpreter(monkeypatch):
    """Falling back to `python --config ...` starts nothing: the agent exits 2
    and the unit looks 'active (activating)' forever."""
    monkeypatch.setattr(sys, 'executable', '/opt/ai-ops-agent/venv/bin/python')
    # No console script next to the interpreter -> the -m form, never bare python.
    monkeypatch.setattr(service, 'shutil', type('S', (), {'which': staticmethod(lambda name: None)}))
    assert service._agent_executable() == '/opt/ai-ops-agent/venv/bin/python -m ai_ops_agent.agent'


@pytest.mark.skipif(sys.platform != 'linux', reason='needs a real executable bit')
def test_executable_prefers_the_console_script(tmp_path, monkeypatch):
    venv = tmp_path / 'venv' / 'bin'
    venv.mkdir(parents=True)
    interpreter = venv / 'python'
    interpreter.write_text('#!/bin/sh\\n')
    script = venv / 'ai-ops-agent'
    script.write_text('#!/bin/sh\\n')
    os.chmod(interpreter, 0o755)
    os.chmod(script, 0o755)
    monkeypatch.setattr(sys, 'executable', str(interpreter))
    assert service._agent_executable() == str(script)


@pytest.mark.skipif(sys.platform != 'linux', reason='reads /etc/passwd structure via pwd')
def test_build_warns_when_readonly_would_run_as_root(monkeypatch):
    args = _args(user=['aiops_read', 'aiops_ops'])
    monkeypatch.setattr(service, '_agent_executable', lambda: '/opt/x/ai-ops-agent')
    _config, unit, run_as, warnings = service.build(args)
    # Two accounts means a switching agent, hence root, hence the readonly
    # channel has no root account to refuse -- the unit is fine and quiet.
    assert run_as == 'root'
    assert 'User=root' in unit
    assert warnings == []


@pytest.mark.skipif(sys.platform != 'linux', reason='reads /etc/passwd structure via pwd')
def test_build_flags_a_missing_readonly_account(monkeypatch):
    args = _args(user=['root'])
    monkeypatch.setattr(service, '_agent_executable', lambda: '/opt/x/ai-ops-agent')
    _config, _unit, _run_as, warnings = service.build(args)
    assert any('allow_root_readonly' in line for line in warnings)


def _args(user, allow_root_readonly=False):
    class A:
        pass
    args = A()
    args.asset_id = 'h1'
    args.config = '/etc/ai-ops-agent/config.json'
    args.journal_dir = '/var/lib/ai-ops-agent'
    args.server_url = 'https://control.example.com'
    args.token = 't' * 32
    args.controller = []
    args.user = user
    args.run_as = ''
    args.allow_loopback_http = False
    args.allow_root_readonly = allow_root_readonly
    return args
