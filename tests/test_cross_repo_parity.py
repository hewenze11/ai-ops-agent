"""Cross-repository agreement between the two argv derivations.

The control plane and the Agent each own a copy of the readonly table and a
copy of the derivation logic. That duplication is deliberate (§39.2: an
endpoint that trusts code shipped by the thing it is checking is not checking
anything), but duplication drifts. A one-sided edit is exactly how a security
path rots: the Agent starts refusing tasks the control plane happily sends, or
worse, accepts an argv the other side would never produce.

This test is the guard. It lives in the Agent repo because the Agent is the
side that must fail closed, and it skips (rather than fails) when the control
plane source is not checked out next to it -- CI for this repo alone has no
reason to know about the other one.
"""
import importlib.util
from pathlib import Path

import pytest

from ai_ops_agent import readonly

CONTROL_PLANE = Path(__file__).resolve().parents[2] / 'ai-ops' / 'ai_ops' / 'readonly_tools.py'


def _load_control_plane():
    if not CONTROL_PLANE.exists():
        pytest.skip('control-plane source not present next to this repo')
    spec = importlib.util.spec_from_file_location('_cp_readonly_tools', CONTROL_PLANE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_program_table_is_identical():
    cp = _load_control_plane()
    assert cp.PROGRAMS == readonly.WHITELIST, (
        'the two readonly program tables disagree; one side will refuse what '
        'the other sends')


CASES = [
    ('read_file', {'path': '/etc/hosts'}),
    ('read_file', {'path': '/var/log/../log/syslog'}),
    ('list_dir', {'path': '/var'}),
    ('list_dir', {'path': '/', 'long': True}),
    ('file_stat', {'path': '/etc/passwd'}),
    ('disk_usage', {'path': '/var'}),
    ('memory_info', {}),
    ('process_list', {}),
    ('service_status', {'unit': 'nginx.service'}),
    ('journal_logs', {}),
    ('journal_logs', {'lines': 10, 'unit': 'ssh.service'}),
    ('k8s_get', {'kind': 'pods'}),
    ('k8s_get', {'kind': 'pods', 'name': 'web-1', 'namespace': 'prod'}),
    ('k8s_logs', {'name': 'web-1'}),
    ('k8s_logs', {'name': 'web-1', 'namespace': 'prod', 'lines': 50}),
]


@pytest.mark.parametrize('tool,params', CASES)
def test_both_sides_derive_the_same_argv(tool, params):
    cp = _load_control_plane()
    _program, control_argv = cp.build(tool, params)
    agent_argv = readonly.derive_argv(tool, params)
    assert agent_argv == control_argv, (
        '%s(%r): control plane produces %r, Agent produces %r'
        % (tool, params, control_argv, agent_argv))


@pytest.mark.parametrize('tool,params', CASES)
def test_agent_program_matches_the_control_plane_selection(tool, params):
    cp = _load_control_plane()
    control_program, _argv = cp.build(tool, params)
    assert readonly.WHITELIST[tool] == control_program
