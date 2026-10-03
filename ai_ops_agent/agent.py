import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PROTOCOL = "1.1"
AGENT_VERSION = "0.1.0.dev2"
OUTPUT_LIMIT = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Redirect rejected; credential cannot be forwarded")


def validate_config(config):
    import re
    url = urllib.parse.urlsplit(config["server_url"])
    if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("server_url must contain only scheme, host and port")
    loopback = url.hostname in ("127.0.0.1", "localhost", "::1")
    if not url.hostname or (url.scheme != "https" and not (url.scheme == "http" and loopback and config.get("allow_loopback_http") is True)):
        raise ValueError("HTTPS required, except explicit loopback development HTTP")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", config["asset_id"]):
        raise ValueError("Invalid asset_id")
    if not isinstance(config.get("allowed_users"), list) or not config["allowed_users"]:
        raise ValueError("Local allowed_users must not be empty")
    if len(config.get("agent_token", "")) < 32:
        raise ValueError("Invalid agent token")
    if not Path(config["journal_dir"]).is_absolute():
        raise ValueError("journal_dir must be absolute")
    return config


def read_config(path):
    if sys.platform != "linux":
        raise RuntimeError("Execution agent requires Linux")
    path = Path(path)
    st = path.stat()
    if st.st_mode & 0o077 or st.st_uid != os.geteuid():
        raise ValueError("Config must be owned by the current user and mode 0600 or stricter")
    return validate_config(json.loads(path.read_text()))


def request(config, path, body, timeout=30):
    req = urllib.request.Request(config["server_url"].rstrip("/") + path,
        data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + config["agent_token"], "Content-Type": "application/json"})
    # Never use environment-configured proxies for a credential-bearing request.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(2_000_001)
    except urllib.error.HTTPError as error:
        # A conflict means the control plane already holds a different, durable
        # outcome (for example a human resolved an unknown execution). That is a
        # settled fact, not a transport failure: surface it so the caller can
        # stop retrying instead of wedging the worker.
        if error.code in (409, 410):
            raise ControlRejected(error.code, path)
        raise
    if len(raw) > 2_000_000:
        raise ValueError("Oversized control response")
    return json.loads(raw)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)
    if sys.platform == "linux":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def failure(task, code, status="failed"):
    return {"claim_id": task["claim_id"], "status": status, "exit_code": None,
            "stdout": "", "stderr": "", "error_code": code, "output_truncated": False}


class ControlRejected(Exception):
    """The control plane durably rejected this report, so retrying cannot help."""

    def __init__(self, status, path):
        super().__init__("control rejected %s with %s" % (path, status))
        self.status = status


def execute(task, allowed_users, cancel_event=None, output_dir=None):
    if sys.platform != "linux":
        return failure(task, "UNSUPPORTED_PLATFORM")
    import pwd
    actual = task.get("run_as")
    if actual not in task.get("execution_users", []) or actual not in allowed_users:
        return failure(task, "USER_NOT_ALLOWED")
    try:
        account = pwd.getpwnam(actual)
    except KeyError:
        return failure(task, "USER_NOT_FOUND")
    if os.geteuid() != 0 and os.geteuid() != account.pw_uid:
        return failure(task, "CANNOT_SWITCH_USER")
    if not isinstance(task.get("command"), str) or not 1 <= len(task["command"]) <= 16000:
        return failure(task, "INVALID_COMMAND")
    timeout = task.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        return failure(task, "INVALID_TIMEOUT")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": account.pw_dir,
           "USER": actual, "LOGNAME": actual, "LANG": "C.UTF-8"}
    identity = {}
    if os.geteuid() == 0:
        identity = {"user": account.pw_uid, "group": account.pw_gid,
                    "extra_groups": os.getgrouplist(actual, account.pw_gid), "umask": 0o077}
    proc = None
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]
    cancel_event = cancel_event or threading.Event()
    stop_drain = threading.Event()
    from .output import Spool
    spools = [Spool(output_dir, s) for s in ('stdout', 'stderr')] if output_dir else []

    def drain(stream, index):
        import select
        try:
            while not stop_drain.is_set():
                if not select.select([stream], [], [], 0.2)[0]:
                    continue
                chunk = os.read(stream.fileno(), 8192)
                if not chunk:
                    return
                remaining = OUTPUT_LIMIT - len(buffers[index])
                buffers[index].extend(chunk[:max(remaining, 0)])
                if len(chunk) > remaining:
                    truncated[index] = True
                if spools:
                    spools[index].write(chunk)
            truncated[index] = True
            if spools:
                spools[index].complete = False
        except OSError:
            truncated[index] = True
            if spools:
                spools[index].complete = False
        finally:
            stream.close()

    def with_archives(result):
        if spools:
            result['output_archives'] = {name: spool.close() for name, spool in zip(('stdout', 'stderr'), spools)}
        return result

    try:
        if cancel_event.is_set():
            return with_archives(failure(task, 'CANCELLED_BEFORE_EXECUTION', 'cancelled'))
        proc = subprocess.Popen(["/bin/sh", "-c", task["command"]], cwd=account.pw_dir if Path(account.pw_dir).is_dir() else "/",
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, **identity)
        threads = [threading.Thread(target=drain, args=(stream, i), daemon=True)
                   for i, stream in enumerate((proc.stdout, proc.stderr))]
        for thread in threads:
            thread.start()
        timed_out, cancelled = False, False
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if cancel_event.is_set():
                    cancelled = True
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                cancel_event.wait(0.1)
        finally:
            # Terminate remaining children in the same group, even if a shell
            # exits early. Daemonized/escaped children require future cgroups.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for thread in threads:
            thread.join(timeout=2)
        incomplete = any(thread.is_alive() for thread in threads)
        stop_drain.set()
        for thread in threads:
            thread.join()
        return with_archives({"claim_id": task["claim_id"], "status": 'cancelled' if cancelled else ("failed" if timed_out or incomplete or proc.returncode != 0 else "succeeded"),
                "exit_code": proc.returncode,
                "stdout": bytes(buffers[0]).decode("utf-8", "replace"),
                "stderr": bytes(buffers[1]).decode("utf-8", "replace"),
                "error_code": 'CANCELLED_BY_OPERATOR' if cancelled else ("EXECUTION_TIMEOUT" if timed_out else ("OUTPUT_STREAM_NOT_CLOSED" if incomplete else None)),
                "output_truncated": any(truncated) or incomplete})
    except OSError:
        return with_archives(failure(task, "PROCESS_START_FAILED"))


class Worker:
    def __init__(self, config):
        self.config = validate_config(config)
        self.journal = Path(config["journal_dir"])
        self.journal.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.prefix = "/api/v1/agents/" + config["asset_id"]
        self.instance_id = str(uuid.uuid4())

    def heartbeat(self):
        request(self.config, self.prefix + '/heartbeat', {'instance_id': self.instance_id, 'agent_version': AGENT_VERSION, 'protocol_version': PROTOCOL}, timeout=3)

    def upload_outputs(self, task, result):
        import base64
        import hashlib
        from .output import CHUNK_BYTES
        for stream, manifest in (result.get('output_archives') or {}).items():
            if stream not in ('stdout', 'stderr'):
                raise ValueError('Invalid output stream')
            path = self.journal / task['id'] / stream
            digest = hashlib.sha256()
            size = 0
            with path.open('rb') as f:
                while data := f.read(CHUNK_BYTES):
                    digest.update(data)
                    size += len(data)
            if manifest['sha256'] != digest.hexdigest() or manifest['size'] != size:
                raise RuntimeError('Local output changed; command will NOT replay')
            prefix = self.prefix + '/tasks/' + task['id'] + '/output/' + stream
            offset = 0
            with path.open('rb') as f:
                while data := f.read(CHUNK_BYTES):
                    ack = request(self.config, prefix + '/chunks', {'claim_id': task['claim_id'], 'offset': offset, 'data': base64.b64encode(data).decode()})
                    if ack.get('accepted') is not True or ack.get('next_offset') != offset + len(data):
                        raise RuntimeError('Output chunk not acknowledged')
                    offset += len(data)
            ack = request(self.config, prefix + '/finalize', {'claim_id': task['claim_id'], **manifest})
            if ack.get('accepted') is not True:
                raise RuntimeError('Output finalize not acknowledged')

    def send_result(self, task, result):
        self.upload_outputs(task, result)
        response = request(self.config, self.prefix + "/tasks/" + task["id"] + "/result", result)
        if response.get("accepted") is not True:
            raise RuntimeError("Result not acknowledged")

    def flush_pending(self):
        for path in sorted(self.journal.glob("*.json")):
            entry = json.loads(path.read_text())
            if entry["phase"] == "acknowledged":
                continue
            if entry["phase"] == "started":
                # Crash window is deliberately UNKNOWN, never replay a command.
                entry["phase"] = "result_ready"
                entry["result"] = failure(entry["task"], "AGENT_RESTART_EXECUTION_UNKNOWN", "unknown")
                atomic_json(path, entry)
            try:
                self.send_result(entry["task"], entry["result"])
            except ControlRejected:
                # The control plane already holds a durable outcome for this task
                # (for example a human resolved an unknown execution). Retrying
                # would never succeed, so settle the journal entry and move on
                # instead of blocking every later claim on this asset.
                pass
            entry["phase"] = "acknowledged"
            atomic_json(path, entry)

    def once(self):
        self.heartbeat()
        self.flush_pending()
        response = request(self.config, self.prefix + "/claim", {"protocol_version": PROTOCOL})
        if response.get("protocol_version") != PROTOCOL:
            raise RuntimeError("Incompatible protocol")
        task = response.get("task")
        if task is None:
            return False
        # UUID normalization prevents remote paths from becoming local filenames.
        if str(uuid.UUID(task["id"])) != task["id"] or task.get("asset_id") != self.config["asset_id"]:
            raise ValueError("Invalid task identity")
        path = self.journal / (task["id"] + ".json")
        if path.exists():
            # A duplicate delivery must never launch a second process.
            old = json.loads(path.read_text())
            if old["task"] != task:
                raise RuntimeError("Task identity collision")
            self.send_result(task, old.get("result") or failure(task, "DUPLICATE_DELIVERY_UNKNOWN", "unknown"))
            return False
        entry = {"phase": "started", "task": task}
        atomic_json(path, entry)
        stop, cancelled = threading.Event(), threading.Event()

        def control():
            response = request(self.config, self.prefix + '/tasks/' + task['id'] + '/control', {'claim_id': task['claim_id']}, timeout=3)
            if response.get('cancel_requested') is True:
                cancelled.set()

        # Check a queued cancellation before starting any native process.
        control()

        def monitor():
            while not stop.wait(2):
                try:
                    self.heartbeat()
                    control()
                except Exception:
                    # Disconnection is NOT evidence that execution stopped.
                    # Local timeout still applies; journal preserves the result.
                    pass

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        try:
            result = execute(task, self.config['allowed_users'], cancelled, self.journal / task['id'])
            entry.update(phase='result_ready', result=result)
            atomic_json(path, entry)
            self.send_result(task, result)
            entry['phase'] = 'acknowledged'
            atomic_json(path, entry)
        finally:
            stop.set()
            thread.join(timeout=7)
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = read_config(args.config)
    # One process per journal. A second worker must not corrupt crash recovery.
    import fcntl
    folder = Path(config["journal_dir"])
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = open(folder / "agent.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    worker = Worker(config)
    while True:
        try:
            worked = worker.once()
            if args.once:
                break
            if not worked:
                time.sleep(3)
        except Exception as exc:
            # No raw response bodies, headers, configuration, or secret values.
            print("agent iteration failed: " + type(exc).__name__, file=sys.stderr, flush=True)
            if args.once:
                raise SystemExit(1)
            time.sleep(5)


if __name__ == "__main__":
    main()
