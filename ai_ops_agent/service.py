"""Explicit Linux service installation. Never hides secret or destructive steps."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

UNIT = """[Unit]
Description=AI Ops execution agent (asset {asset_id})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
ExecStart={executable} --config {config}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths={journal}
StateDirectory=ai-ops-agent
AmbientCapabilities=
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"""


def unit_text(asset_id, user, executable, config, journal):
    return UNIT.format(asset_id=asset_id, user=user, executable=executable, config=config, journal=journal)


def _agent_executable():
    """Absolute path to the agent entry point for the systemd unit.

    `shutil.which` misses the venv when PATH is not inherited (e.g. a bare
    `sudo bash`); falling back to the bare interpreter would drop the entry
    point and start `python --config ...` with no module (exit status 2).
    Resolve the console script next to the running interpreter first, then
    PATH, then a `-m` invocation as a last resort.
    """
    candidate = Path(sys.executable).with_name('ai-ops-agent')
    if candidate.exists():
        return str(candidate)
    found = shutil.which('ai-ops-agent')
    return found or (sys.executable + ' -m ai_ops_agent.agent')


def build(args):
    if sys.platform != "linux":
        raise SystemExit('Service installation is Linux-only')
    if os.geteuid() != 0 and args.user:
        raise SystemExit('Switching users requires installing as root; re-run with sudo')
    # Run user: the account the agent daemon runs AS. Switching into other
    # accounts requires root, so with more than one allowed account (or an
    # explicit --run-as) the unit must run as root, and the 0600 config must be
    # owned by that same user or the agent refuses to read it.
    run_as = getattr(args, 'run_as', None) or (args.user[0] if len(args.user) == 1 else 'root')
    config = {'allow_loopback_http': args.allow_loopback_http, 'server_url': args.server_url,
              'asset_id': args.asset_id, 'agent_token': args.token,
              'allowed_users': args.user, 'journal_dir': str(Path(args.journal_dir).resolve())}
    return config, unit_text(args.asset_id, run_as, _agent_executable(), args.config, config['journal_dir']), run_as


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/ai-ops-agent/config.json')
    parser.add_argument('--unit', default='/etc/systemd/system/ai-ops-agent.service')
    parser.add_argument('--server-url', required=True)
    parser.add_argument('--asset-id', required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--user', action='append', required=True, help='native allowed execution account; repeatable')
    parser.add_argument('--run-as', default='', help='account the agent daemon runs as (default: the only --user, else root)')
    parser.add_argument('--journal-dir', default='/var/lib/ai-ops-agent')
    parser.add_argument('--allow-loopback-http', action='store_true')
    parser.add_argument('--print-only', action='store_true')
    parser.add_argument('--no-start', action='store_true')
    args = parser.parse_args()
    config, unit, run_as = build(args)
    if args.print_only:
        print(json.dumps(config, indent=2, ensure_ascii=False).replace(config['agent_token'], '[token omitted from print]'))
        print(unit)
        return
    path = Path(args.config)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and args.token == 'REPLACE':
        raise SystemExit('Refusing to overwrite existing configuration')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    # The config is read BY the run user, so it must be owned by that same user
    # (the agent checks owner==euid), not by the first execution account.
    owner_uid = _uid(run_as) if run_as else 0
    os.chown(path, owner_uid, -1)
    os.chmod(path, 0o600)
    Path(args.journal_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(args.journal_dir, owner_uid, -1)
    Path(args.unit).write_text(unit)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    if not args.no_start:
        subprocess.run(['systemctl', 'enable', '--now', 'ai-ops-agent'], check=True)
    print(json.dumps({'config': args.config, 'unit': args.unit, 'started': not args.no_start,
                      'hint': 'Token stored only in the 0600 config file; it was not printed.'}))


def _uid(name):
    import pwd
    return pwd.getpwnam(name).pw_uid


if __name__ == '__main__':
    main()
