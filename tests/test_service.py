import sys

import pytest
from ai_ops_agent.service import unit_text


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux-only installer')
def test_unit_never_embeds_token():
    text = unit_text('asset-1', 'ops_read', '/opt/venv/bin/ai-ops-agent', '/etc/ai-ops-agent/config.json', '/var/lib/ai-ops-agent')
    assert 'ai-ops-agent' in text and 'User=ops_read' in text
    assert 'token' not in text.lower() and 'Bearer' not in text
    # Single-user (non-root) mode keeps the strictest hardening.
    assert 'NoNewPrivileges=yes' in text


def test_unit_when_running_as_root_allows_user_switching():
    # Running as root to switch accounts MUST NOT carry NoNewPrivileges=yes:
    # that forbids setgroups/setgid in the child, so every command would fail
    # with "Operation not permitted". It keeps a bounded capability set instead.
    text = unit_text('a', 'root', '/opt/venv/bin/ai-ops-agent', '/etc/x.json', '/var/lib/y')
    assert 'User=root' in text
    assert 'NoNewPrivileges=yes' not in text
    assert 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' in text


def test_unit_is_systemd_parseable_shape():
    text = unit_text('a', 'u', '/bin/true', '/etc/x.json', '/var/lib/y')
    for section in ('[Unit]', '[Service]', '[Install]'):
        assert section in text
    assert text.count('ExecStart=') == 1


def test_parse_controller_multi_form():
    from ai_ops_agent.service import _parse_controller
    entry = _parse_controller('team-a=https://ops-a.example.com,tok-' + 'x' * 40, False)
    assert entry == {'name': 'team-a', 'url': 'https://ops-a.example.com',
                     'token': 'tok-' + 'x' * 40, 'enabled': True}
    off = _parse_controller('team-b=https://ops-b.example.com,' + 'y' * 40 + ',disabled', False)
    assert off['enabled'] is False


def test_parse_controller_rejects_bad_shape():
    import pytest
    from ai_ops_agent.service import _parse_controller
    with pytest.raises(SystemExit):
        _parse_controller('missing-equals-sign', False)
    with pytest.raises(SystemExit):
        _parse_controller('only-url=https://x.example.com', False)
