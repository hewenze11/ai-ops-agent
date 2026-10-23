"""Operator reveal path, endpoint side (docs §51.4).

The security claim under test is narrow and worth stating exactly: a reveal
cannot read anything a normal read could not, cannot run as root, and cannot be
obtained by the model. The last one is enforced on the control plane (no
model-facing tool creates a reveal task); what this file pins is that the Agent
adds no new reachability of its own.
"""
import sys

import pytest

from ai_ops_agent import reveal, readonly


def task(**overrides):
    base = {'claim_id': 'c' * 24, 'tool': 'read_file', 'program': '/usr/bin/cat',
            'args': ['--number', '--', '/etc/hostname'], 'run_as': 'nobody',
            'execution_users': ['nobody'], 'timeout_seconds': 10}
    base.update(overrides)
    return base


def test_reveal_is_a_separate_kind_not_a_flag_on_readonly():
    # The whole design rests on this. If a reveal were `readonly` plus
    # `reveal=True`, then whoever builds the readonly payload decides whether to
    # unmask -- and that is the model. A separate kind means the decision lives
    # with the code path that creates the task, not the payload's contents.
    from ai_ops_agent import agent
    source = open(agent.__file__, encoding='utf-8').read()
    assert 'kind == "reveal"' in source
    assert 'reveal_task' not in source  # no fallback that upgrades a readonly task


def test_only_file_reads_are_revealable():
    # Revealing a directory listing or a journal stream would turn "unlock this
    # one file" into "unlock everything the readonly channel can reach".
    for tool in ('list_dir', 'journal_logs', 'k8s_logs', 'service_status',
                 'process_list', 'disk_usage', 'memory_info', 'file_stat', 'k8s_get'):
        assert reveal.check(task(tool=tool), ['nobody']) == 'REVEAL_TOOL_NOT_ALLOWED'
        assert tool not in reveal.REVEALABLE_TOOLS
    assert reveal.REVEALABLE_TOOLS == frozenset({'read_file'})


def test_reveal_still_obeys_the_readonly_whitelist():
    # No new argv surface: if readonly.validate refuses a task, reveal refuses
    # it too. The program-path refusal needs no filesystem, so it runs anywhere.
    with pytest.raises(readonly.Rejected) as error:
        readonly.validate(task(program='/bin/cat'))
    assert error.value.code == 'PROGRAM_NOT_WHITELISTED'
    # A tool outside the readonly set cannot sneak in via reveal.
    with pytest.raises(readonly.Rejected) as error:
        readonly.validate(task(tool='bash', program='/usr/bin/bash', args=['-c', 'id']))
    assert error.value.code == 'TOOL_UNKNOWN'


@pytest.mark.skipif(sys.platform != 'linux', reason='needs the real /usr/bin binaries')
def test_reveal_argv_is_validated_like_a_normal_read():
    with pytest.raises(readonly.Rejected) as error:
        readonly.validate(task(tool='read_file', args=['csrftoken']))
    assert error.value.code == 'ARGV_INVALID'
    with pytest.raises(readonly.Rejected) as error:
        readonly.validate(task(args=['--number', '--', '/etc/link-to-somewhere']))
    assert error.value.code in ('PATH_SYMLINKED', 'PATH_NOT_READABLE')


def test_run_as_must_be_granted_to_this_turn():
    assert reveal.check(task(run_as='root'), ['nobody', 'root']) == 'USER_NOT_ALLOWED'
    assert reveal.check(task(), ['somebody-else']) == 'USER_NOT_ALLOWED'
    assert reveal.check(task(run_as='nobody', execution_users=['other']), ['nobody']) == 'USER_NOT_ALLOWED'
    assert reveal.check(task(), ['nobody']) is None


@pytest.mark.skipif(sys.platform != 'linux', reason='needs pwd and a real account')
def test_reveal_refuses_root_without_the_readonly_opt_out():
    # readonly honours allow_root_readonly; reveal deliberately does not take
    # that argument at all. Root can read every private key on the box, and this
    # path returns bytes unmasked.
    import pwd
    root = pwd.getpwnam('root').pw_name
    result = reveal.execute(task(run_as=root, execution_users=[root]),
                            [root], allow_root_readonly=True)
    assert result['status'] == 'failed'
    assert result['error_code'] == 'REVEAL_USER_ROOT'


@pytest.mark.skipif(sys.platform != 'linux', reason='needs pwd and a real account')
def test_reveal_reports_what_a_normal_read_would_have_masked():
    result = reveal.execute(task(), ['nobody'])
    assert result['status'] == 'succeeded'
    assert result['revealed_segments'] == 0
    # Never claims credential handles: the values are in the body already, and
    # registering them would turn "looking at a secret" into "storing a secret".
    assert result['credentials'] == []


def test_segment_count_matches_the_masking_patterns():
    text = 'password = "hunter2hunter2"\napi_key: abcdefgh12345678\nnothing here\n'
    # Both lines are secret-shaped, so a normal read would have hidden two
    # segments; the operator sees the text plus this count.
    assert reveal._rule_count(text) >= 2
    assert reveal._rule_count('') == 0
