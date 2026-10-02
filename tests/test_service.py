import sys

import pytest
from ai_ops_agent.service import unit_text


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux-only installer')
def test_unit_never_embeds_token():
    text = unit_text('asset-1', 'ops_read', '/opt/venv/bin/ai-ops-agent', '/etc/ai-ops-agent/config.json', '/var/lib/ai-ops-agent')
    assert 'ai-ops-agent' in text and 'User=ops_read' in text
    assert 'token' not in text.lower() and 'Bearer' not in text
    assert 'NoNewPrivileges=yes' in text


def test_unit_is_systemd_parseable_shape():
    text = unit_text('a', 'u', '/bin/true', '/etc/x.json', '/var/lib/y')
    for section in ('[Unit]', '[Service]', '[Install]'):
        assert section in text
    assert text.count('ExecStart=') == 1
