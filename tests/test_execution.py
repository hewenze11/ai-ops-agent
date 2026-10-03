import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest
from ai_ops_agent.agent import Worker, execute, atomic_json
from ai_ops_agent.output import Spool
from test_agent import task, config, linux


def test_spool_preserves_bytes_and_reports_cap(tmp_path):
    spool = Spool(tmp_path, 'stdout', limit=100)
    spool.write(bytes(range(200)))
    ref = spool.close()
    assert ref == {'size': 100, 'sha256': hashlib.sha256(bytes(range(100))).hexdigest(), 'complete': False}
    assert (tmp_path / 'stdout').read_bytes() == bytes(range(100))


def test_spool_disk_failure_is_not_complete(tmp_path):
    spool = Spool(tmp_path, 'stdout')
    class Broken:
        def write(self, data):
            raise OSError('disk full')
        def flush(self):
            pass
        def fileno(self):
            raise OSError('disk full')
        def close(self):
            pass
    spool.file.close()
    spool.file = Broken()
    spool.write(b'not-written')
    assert not spool.close()['complete']


def test_upload_retry_no_command_replay(tmp_path, monkeypatch):
    t = task()
    folder = tmp_path / t['id']
    spool = Spool(folder, 'stdout'); spool.write(b'abc')
    ref = spool.close()
    empty = Spool(folder, 'stderr').close()
    result = {'claim_id': t['claim_id'], 'status': 'succeeded', 'exit_code': 0, 'output_archives': {'stdout': ref, 'stderr': empty}}
    journal = tmp_path / (t['id'] + '.json')
    atomic_json(journal, {'phase': 'result_ready', 'task': t, 'result': result})
    calls = []
    fail = [True]
    def request(cfg, path, body):
        calls.append(path)
        if path.endswith('/finalize') and fail[0]:
            fail[0] = False
            raise OSError('simulated lost acknowledgement')
        return {'accepted': True, 'next_offset': 3}
    monkeypatch.setattr('ai_ops_agent.agent.request', request)
    monkeypatch.setattr('ai_ops_agent.agent.execute', lambda *a: pytest.fail('must not re-execute'))
    worker = Worker(config(tmp_path))
    with pytest.raises(OSError):
        worker.flush_pending()
    assert json.loads(journal.read_text())['phase'] == 'result_ready'
    worker.flush_pending()
    assert json.loads(journal.read_text())['phase'] == 'acknowledged'
    assert sum(p.endswith('/chunks') for p in calls) == 2


def test_local_archive_tampering_stops_submission(tmp_path, monkeypatch):
    t = task()
    spool = Spool(tmp_path / t['id'], 'stdout'); spool.write(b'abc')
    ref = spool.close()
    spool.path.write_bytes(b'xyz')
    monkeypatch.setattr('ai_ops_agent.agent.request', lambda *a: pytest.fail('do not submit corrupt archive'))
    with pytest.raises(RuntimeError):
        Worker(config(tmp_path)).send_result(t, {'output_archives': {'stdout': ref}})


@linux
def test_real_large_binary_stdout_stderr(tmp_path):
    import pwd
    user = pwd.getpwuid(os.geteuid()).pw_name
    cmd = "python3 -c \"import os; os.write(1,bytes(range(256))*800); os.write(2,b'error'*20000)\""
    result = execute(task(user=user, command=cmd), [user], output_dir=tmp_path)
    assert result['status'] == 'succeeded'
    assert result['output_truncated']
    assert (tmp_path / 'stdout').read_bytes() == bytes(range(256)) * 800
    assert (tmp_path / 'stderr').read_bytes() == b'error' * 20000
    assert all(ref['complete'] for ref in result['output_archives'].values())


@linux
def test_real_cancel_kills_process_group(tmp_path):
    import pwd
    user = pwd.getpwuid(os.geteuid()).pw_name
    cancelled = threading.Event()
    timer = threading.Timer(0.5, cancelled.set); timer.start()
    start = time.monotonic()
    result = execute(task(user=user, command='sleep 30 & echo $!; wait', timeout_seconds=40), [user], cancelled, tmp_path)
    timer.join()
    assert time.monotonic() - start < 5
    assert result['status'] == 'cancelled'
    pid = int(result['stdout'].strip())
    stat = '/proc/' + str(pid) + '/stat'
    # A killed orphan can remain a zombie until PID1 reaps it; it is not running.
    from pathlib import Path
    assert not Path(stat).exists() or Path(stat).read_text().split()[2] == 'Z'


@linux
def test_escaped_daemon_is_reclaimed(tmp_path):
    # A command may deliberately escape its process group with setsid. Only
    # cgroup-level cleanup can reclaim it; the process-group fallback cannot.
    import pwd
    import uuid as _uuid
    from ai_ops_agent.agent import _cgroup_available
    if not _cgroup_available():
        pytest.skip("cgroup cleanup requires a writable cgroup v2")
    user = pwd.getpwuid(os.geteuid()).pw_name
    marker = "/tmp/ai-ops-escape-" + _uuid.uuid4().hex[:8]
    cmd = "setsid sh -c 'echo $$ > %s; sleep 900' >/dev/null 2>&1 & echo started; sleep 5" % marker
    result = execute(task(user=user, command=cmd, timeout_seconds=1), [user], output_dir=tmp_path)
    assert result['error_code'] == 'EXECUTION_TIMEOUT'
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not Path(marker).exists():
        time.sleep(0.1)
    assert Path(marker).exists(), "escape marker was never written"
    pid = int(Path(marker).read_text().strip())
    time.sleep(1.5)
    stat = "/proc/%d/stat" % pid
    # The escaped sleep must be gone (or a reaped zombie), never still running.
    assert not Path(stat).exists() or Path(stat).read_text().split()[2] == 'Z'
    Path(marker).unlink(missing_ok=True)


@linux
def test_cancel_before_launch(tmp_path):
    import pwd
    user = pwd.getpwuid(os.geteuid()).pw_name
    cancel = threading.Event(); cancel.set()
    result = execute(task(user=user, command='echo must-not-run'), [user], cancel, tmp_path)
    assert result['status'] == 'cancelled'
    assert not (tmp_path / 'stdout').read_bytes()


@linux
def test_timeout_keeps_partial_archive(tmp_path):
    import pwd
    user = pwd.getpwuid(os.geteuid()).pw_name
    result = execute(task(user=user, command='printf before-timeout; sleep 20', timeout_seconds=1), [user], output_dir=tmp_path)
    assert result['error_code'] == 'EXECUTION_TIMEOUT'
    assert (tmp_path / 'stdout').read_bytes() == b'before-timeout'
