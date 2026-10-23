"""Endpoint-side cross-check of params against argv.

Before this existed, the two sides agreed by convention: the Agent validated
``args`` against its whitelist, but never checked that ``args`` follow from the
``params`` the model actually chose. A buggy or hostile control plane could
send parameters the model never asked for, or an argv that follows from no
parameters at all.

The control plane now sends ``params`` with every readonly task (so that the
SSH connector can re-derive argv without an Agent). The Agent re-derives the
same way, independently. Two derivations, one comparison -- the same shape of
check that makes the change-set path trustworthy.
"""
import pytest

from ai_ops_agent import readonly


def task(**overrides):
    base = {'claim_id': 'c' * 24, 'tool': 'read_file', 'program': '/usr/bin/cat',
            'args': ['--number', '--', '/etc/hostname'], 'run_as': 'nobody',
            'execution_users': ['nobody'], 'timeout_seconds': 10}
    base.update(overrides)
    return base


# --- derivation itself ------------------------------------------------------

def test_read_file_derivation():
    assert readonly.derive_argv('read_file', {'path': '/etc/hosts'}) == \
        ['--number', '--', '/etc/hosts']


def test_list_dir_short_and_long():
    assert readonly.derive_argv('list_dir', {'path': '/var'}) == ['-a', '--', '/var']
    assert readonly.derive_argv('list_dir', {'path': '/var', 'long': True}) == \
        ['-la', '--', '/var']


def test_memory_info_takes_no_parameters():
    assert readonly.derive_argv('memory_info', {}) == ['-m']


def test_journal_defaults_to_200_lines():
    assert readonly.derive_argv('journal_logs', {}) == \
        ['--no-pager', '-n', '200', '--output=short-iso']


def test_journal_unit_is_appended_in_order():
    assert readonly.derive_argv('journal_logs', {'lines': 5, 'unit': 'nginx.service'}) == \
        ['--no-pager', '-n', '5', '-u', 'nginx.service', '--output=short-iso']


def test_k8s_get_places_a_name_before_the_namespace():
    assert readonly.derive_argv('k8s_get', {'kind': 'pods', 'name': 'web',
                                           'namespace': 'prod'}) == \
        ['get', 'pods', 'web', '-n', 'prod', '-o', 'wide']


# --- derivation refuses bad input -------------------------------------------

@pytest.mark.parametrize('path', ['relative/path', '', 'a' * 2000])
def test_non_absolute_paths_rejected(path):
    with pytest.raises(readonly.Rejected):
        readonly.derive_argv('read_file', {'path': path})


def test_path_escaping_the_root_is_rejected():
    with pytest.raises(readonly.Rejected, match='PATH_ESCAPES_ROOT'):
        readonly.derive_argv('read_file', {'path': '/../../etc/shadow'})


def test_dot_segments_are_normalised_not_rejected():
    """`/etc/../etc/hosts` names a real, permitted file, so it normalises to
    `/etc/hosts` rather than failing. Both sides must agree on this."""
    assert readonly.derive_argv('read_file', {'path': '/etc/../etc/hosts'}) == \
        ['--number', '--', '/etc/hosts']


def test_newline_in_path_rejected():
    with pytest.raises(readonly.Rejected):
        readonly.derive_argv('read_file', {'path': '/etc/hosts\nid'})


def test_bad_unit_rejected():
    with pytest.raises(readonly.Rejected, match='UNIT_INVALID'):
        readonly.derive_argv('service_status', {'unit': 'a b'})


def test_line_count_is_bounded():
    with pytest.raises(readonly.Rejected, match='LINES_INVALID'):
        readonly.derive_argv('journal_logs', {'lines': 0})
    with pytest.raises(readonly.Rejected, match='LINES_INVALID'):
        readonly.derive_argv('journal_logs', {'lines': 2001})


def test_bool_is_not_an_integer_line_count():
    """``True`` would pass a naive isinstance check and become 'True' in argv."""
    with pytest.raises(readonly.Rejected, match='LINES_INVALID'):
        readonly.derive_argv('journal_logs', {'lines': True})


def test_non_dict_params_rejected():
    with pytest.raises(readonly.Rejected, match='PARAMS_INVALID'):
        readonly.derive_argv('read_file', ['/etc/hosts'])


def test_unknown_tool_derives_nothing():
    """Returning None lets validate() fall back to argv-only checking for a tool
    this build does not know how to derive. Unknown tools are rejected before
    that point, so this branch is a guard, not a hole."""
    assert readonly.derive_argv('teleport', {'path': '/x'}) is None


# --- the cross-check in validate() ------------------------------------------

def test_validate_rejects_argv_that_params_do_not_produce(monkeypatch):
    """The decisive case: params say one file, argv names another."""
    monkeypatch.setattr(readonly.os, 'stat', lambda p: type('S', (), {'st_mode': 0o100755})())
    monkeypatch.setattr(readonly.os, 'access', lambda p, m: True)
    bad = task(params={'path': '/etc/hostname'},
               args=['--number', '--', '/etc/shadow'])
    with pytest.raises(readonly.Rejected, match='ARGV_NOT_DERIVED_FROM_PARAMS'):
        readonly.validate(bad)


def test_validate_accepts_matching_params_and_argv(monkeypatch):
    monkeypatch.setattr(readonly.os, 'stat', lambda p: type('S', (), {'st_mode': 0o100755})())
    monkeypatch.setattr(readonly.os, 'access', lambda p, m: True)
    monkeypatch.setattr(readonly, '_real', lambda p: p)
    good = task(params={'path': '/etc/hostname'},
                args=['--number', '--', '/etc/hostname'])
    program, argv = readonly.validate(good)
    assert program == '/usr/bin/cat'
    assert argv == ['--number', '--', '/etc/hostname']


def test_validate_still_works_without_params(monkeypatch):
    """A pre-1.3 style task carries no params. It keeps working: the argv
    whitelist check is still in force, so nothing widens."""
    monkeypatch.setattr(readonly.os, 'stat', lambda p: type('S', (), {'st_mode': 0o100755})())
    monkeypatch.setattr(readonly.os, 'access', lambda p, m: True)
    monkeypatch.setattr(readonly, '_real', lambda p: p)
    legacy = task(args=['--number', '--', '/etc/hostname'])
    assert readonly.validate(legacy)[1] == ['--number', '--', '/etc/hostname']


def test_validate_rejects_tampered_params_even_when_args_look_fine(monkeypatch):
    """Params themselves are validated by the derivation, so an impossible
    params set fails here rather than producing a surprising argv."""
    monkeypatch.setattr(readonly.os, 'stat', lambda p: type('S', (), {'st_mode': 0o100755})())
    monkeypatch.setattr(readonly.os, 'access', lambda p, m: True)
    tampered = task(params={'path': '/../../etc/shadow'},
                    args=['--number', '--', '/etc/shadow'])
    with pytest.raises(readonly.Rejected, match='PATH_ESCAPES_ROOT'):
        readonly.validate(tampered)
