"""Credential store, endpoint side (§42, §46, §47).

The properties under test are the product promises, not the API surface:
  * the value never appears in the handle the control plane receives,
  * a host belongs to at most one owner, and re-binding is not silent,
  * a cooperative controller receives plaintext only after a per-credential
    share, and revocation removes it,
  * injection happens only in declared sinks,
  * tool output is masked by exact match, not by pattern guessing.
"""
import json
import os
import stat
import sys

import pytest

from ai_ops_agent.credentials import CredentialError, Store, apply_injections

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='POSIX permissions and flock')


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / 'credentials')


def test_handle_never_contains_the_value(store):
    handle = store.register('postgres://app:pw123456@db/app', name='db', source='/etc/app/env')
    assert 'pw123456' not in json.dumps(handle)
    assert handle['id'].startswith('cred-')
    assert handle['source'] == '/etc/app/env'


def test_store_files_are_private(store):
    store.register('a-secret-value', name='x')
    for path in (store.path, store.key_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path


def test_plaintext_is_not_written_to_disk_in_the_clear(store):
    store.register('super-secret-literal-42', name='x')
    assert 'super-secret-literal-42' not in store.path.read_text()


def test_rediscovering_the_same_value_reuses_the_handle(store):
    first = store.register('same-value-here', source='/etc/a')
    second = store.register('same-value-here', source='/etc/b')
    assert first['id'] == second['id']
    assert len(store.listing()) == 1
    # The first source is kept: that is where the operator goes to fix it.
    assert second['source'] == '/etc/a'


def test_owner_binding_is_exclusive_and_not_silently_rebindable(store):
    store.bind_owner('master-a')
    assert store.trusting('master-a')
    with pytest.raises(CredentialError) as error:
        store.bind_owner('master-b')
    assert error.value.code == 'OWNER_ALREADY_BOUND'
    assert store.master_id() == 'master-a'


def test_cooperative_controller_needs_an_explicit_share(store):
    handle = store.register('coop-value-abc', name='x')
    store.bind_owner('master-a')
    assert not store.may_share('master-b', handle['id'])
    store.share(handle['id'], 'master-b')
    assert store.may_share('master-b', handle['id'])
    store.share(handle['id'], 'master-b', allowed=False)
    assert not store.may_share('master-b', handle['id'])


def test_revoking_a_controller_removes_ownership_and_all_shares(store):
    handle = store.register('value-to-revoke', name='x')
    store.bind_owner('master-a')
    store.share(handle['id'], 'master-a')
    store.revoke_controller('master-a')
    assert store.master_id() is None
    assert not store.may_share('master-a', handle['id'])


def test_destroy_removes_the_entry_and_the_value(store):
    handle = store.register('to-be-destroyed', name='x')
    store.destroy(handle['id'])
    assert store.listing() == []
    with pytest.raises(CredentialError):
        store.reveal(handle['id'])


def test_injection_only_touches_declared_sinks(store):
    handle = store.register('inject-me-12345', name='x')
    store.bind_owner('master-a')
    assert apply_injections({'content': 'cred:' + handle['id']}, {'content': 'cred:' + handle['id']},
                            store, 'master-a')['content'] == 'inject-me-12345'
    with pytest.raises(CredentialError) as error:
        apply_injections({'path': 'cred:' + handle['id']}, {'path': 'cred:' + handle['id']},
                         store, 'master-a')
    assert error.value.code == 'CREDENTIAL_SINK_NOT_DECLARED'


def test_injection_is_refused_for_an_unshared_credential(store):
    handle = store.register('not-shared-value', name='x')
    store.bind_owner('master-a')
    with pytest.raises(CredentialError) as error:
        apply_injections({'content': 'cred:' + handle['id']}, {'content': 'cred:' + handle['id']},
                         store, 'master-b')
    assert error.value.code.startswith('CREDENTIAL_NOT_SHARED')


def test_literals_are_available_for_exact_match_masking(store):
    store.register('exact-match-value', name='x')
    assert 'exact-match-value' in store.literals()
