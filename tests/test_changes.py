"""Endpoint-side change sets: independent argv re-derivation + approval binding."""
import pytest

from ai_ops_agent import changes


def base(**overrides):
    step = {'action': 'service.reload', 'params': {'unit': 'nginx'},
            'program': '/usr/bin/systemctl', 'args': ['reload', 'nginx'],
            'identity': 'systemd:nginx'}
    task = {'claim_id': 'c' * 24, 'asset_id': 'web1', 'run_as': 'nobody',
            'execution_users': ['nobody'], 'steps': [step], 'timeout_seconds': 30}
    task['approval'] = {'payload_sha256': changes.payload_hash('web1', 'nobody', [step])}
    task.update(overrides)
    return task


def test_valid_change_passes():
    assert changes.validate(base())[0]['args'] == ['reload', 'nginx']


def test_argv_is_rederived_not_trusted():
    # A tampered control plane swapping the argv must be caught even though the
    # approval hash was recomputed for the tampered steps: the local builder
    # disagrees with the wire, so the payload is refused.
    task = base()
    task['steps'][0]['args'] = ['stop', 'nginx']
    task['approval'] = {'payload_sha256': changes.payload_hash('web1', 'nobody', task['steps'])}
    with pytest.raises(changes.Rejected) as error:
        changes.validate(task)
    assert 'ACTION_EXPANSION_MISMATCH' in error.value.code


def test_swapped_program_is_refused():
    task = base()
    task['steps'][0]['program'] = '/usr/bin/reboot'
    with pytest.raises(changes.Rejected):
        changes.validate(task)


def test_approval_hash_must_match_the_exact_payload():
    task = base()
    task['approval'] = {'payload_sha256': 'f' * 64}
    with pytest.raises(changes.Rejected) as error:
        changes.validate(task)
    assert error.value.code == 'APPROVAL_HASH_MISMATCH'
    # Approval for host A must not unlock host B.
    other = base(asset_id='web2')
    with pytest.raises(changes.Rejected):
        changes.validate(other)


def test_tampering_with_a_content_field_is_caught():
    # Regression from a real host run: file.write carries its body in params,
    # so a hash that ignored params would have accepted a swapped body.
    step = {'action': 'file.write', 'params': {'path': '/tmp/x.conf', 'content': 'safe'},
            'program': '__builtin_write__', 'args': ['/tmp/x.conf'], 'identity': 'file:/tmp/x.conf'}
    task = {'claim_id': 'c' * 24, 'asset_id': 'w', 'run_as': 'nobody',
            'execution_users': ['nobody'], 'steps': [step], 'timeout_seconds': 30,
            'approval': {'payload_sha256': changes.payload_hash('w', 'nobody', [step])}}
    changes.validate(task)  # untouched payload is fine
    task['steps'][0]['params']['content'] = 'malicious'
    with pytest.raises(changes.Rejected) as error:
        changes.validate(task)
    assert error.value.code == 'APPROVAL_HASH_MISMATCH'


def test_unapproved_change_is_refused():
    task = base()
    task['approval'] = {}
    with pytest.raises(changes.Rejected):
        changes.validate(task)


def test_unknown_action_on_the_agent_is_refused():
    task = base()
    task['steps'][0]['action'] = 'firewall.disable'
    with pytest.raises(changes.Rejected) as error:
        changes.validate(task)
    assert 'ACTION_UNKNOWN' in error.value.code


def test_baseline_denied_paths_are_enforced_here_too():
    # Even with a perfectly matching hash, /etc/shadow is not writable.
    step = {'action': 'file.write', 'params': {'path': '/etc/shadow', 'content': 'x'},
            'program': '__builtin_write__', 'args': ['/etc/shadow'], 'identity': 'file:/etc/shadow'}
    task = {'claim_id': 'c' * 24, 'asset_id': 'w', 'run_as': 'nobody',
            'execution_users': ['nobody'], 'steps': [step], 'timeout_seconds': 30,
            'approval': {'payload_sha256': changes.payload_hash('w', 'nobody', [step])}}
    with pytest.raises(changes.Rejected) as error:
        changes.validate(task)
    assert 'ACTION_PATH_DENIED' in error.value.code


def test_shell_run_is_never_auto_approved():
    assert 'shell.run' in changes.NEVER_AUTO
    assert 'file.write' in changes.NEVER_AUTO


def test_change_set_size_is_bounded():
    task = base()
    task['steps'] = task['steps'] * 11
    with pytest.raises(changes.Rejected):
        changes.validate(task)


def test_credential_injection_happens_after_the_hash_check():
    """Order matters and is easy to break.

    validate() hashes the *original* params, which contain the placeholder
    ``cred:xxx``. Injection replaces that placeholder with the plaintext. If
    injection ran first, the hash would be computed over a payload nobody
    approved, and every credential-injecting change set would fail -- or, worse,
    an implementation that "fixed" that by hashing after injection would let the
    plaintext decide the hash.

    So: validate() must be usable on the raw task, and the injected copy must
    never be what gets hashed.
    """
    step = {'action': 'file.write', 'params': {'path': '/tmp/x', 'content': 'cred:abc'},
            'program': '__builtin_write__', 'args': ['/tmp/x'], 'identity': None}
    task = {'claim_id': 'c' * 24, 'asset_id': 'web1', 'run_as': 'nobody',
            'execution_users': ['nobody'], 'steps': [step], 'timeout_seconds': 30}
    task['approval'] = {'payload_sha256': changes.payload_hash('web1', 'nobody', [step])}
    assert changes.validate(task) == [step]
    # A payload whose hash was taken over the injected content must NOT validate
    # against the placeholder-bearing step: the two are different bytes.
    injected = dict(step, params={'path': '/tmp/x', 'content': 'real-secret-value'})
    task['approval'] = {'payload_sha256': changes.payload_hash('web1', 'nobody', [injected])}
    with pytest.raises(changes.Rejected, match='APPROVAL_HASH_MISMATCH'):
        changes.validate(task)
