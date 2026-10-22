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

PROTOCOL = "1.3"
AGENT_VERSION = "0.1.0.dev4"
OUTPUT_LIMIT = 65536
# Task kinds this build understands. A task with any other kind is refused
# rather than being run down a guessed path (fail closed, docs/protocol-v13.md).
KINDS = ("shell", "readonly", "change")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Redirect rejected; credential cannot be forwarded")


def _validate_endpoint(url_text, token, allow_loopback_http):
    """A controller endpoint must be a bare HTTPS origin with a real token."""
    url = urllib.parse.urlsplit(url_text)
    if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("controller url must contain only scheme, host and port")
    loopback = url.hostname in ("127.0.0.1", "localhost", "::1")
    if not url.hostname or (url.scheme != "https" and not (url.scheme == "http" and loopback and allow_loopback_http is True)):
        raise ValueError("HTTPS required, except explicit loopback development HTTP")
    if len(token) < 32:
        raise ValueError("Invalid controller token")


def controllers_of(config):
    """Normalize config into a list of enabled controllers.

    `controllers` (multi-controller, protocol 1.2) is preferred. The legacy
    single `server_url` / `agent_token` pair is accepted and becomes one
    controller named "default" so older configs keep working unchanged.
    """
    raw = config.get("controllers")
    if raw is None:
        _validate_endpoint(config.get("server_url"), config.get("agent_token") or "", config.get("allow_loopback_http"))
        return [{"name": "default", "url": config["server_url"],
                 "token": config["agent_token"], "enabled": True,
                 "trust": 'own' if config.get('own') is True else 'cooperative',
                 "controller_id": config.get('controller_id') if isinstance(config.get('controller_id'), str) else None}]
    if not isinstance(raw, list) or not raw:
        raise ValueError("controllers must be a non-empty list")
    names, result = set(), []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each controller must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            raise ValueError("Invalid controller name")
        if name in names:
            raise ValueError("Duplicate controller name")
        names.add(name)
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("controller enabled must be a boolean")
        _validate_endpoint(item.get("url"), item.get("token") or "", config.get("allow_loopback_http"))
        result.append({"name": name, "url": item["url"], "token": item["token"], "enabled": enabled,
                       # own/cooperative is a property of THIS pairing (§47.2),
                       # not of the agent: the same host may be owned by one
                       # control plane and merely cooperate with another.
                       "trust": 'own' if item.get('own') is True else 'cooperative',
                       "controller_id": item.get('controller_id') if isinstance(item.get('controller_id'), str) else None})
    if not any(c["enabled"] for c in result):
        raise ValueError("At least one controller must be enabled")
    return result


def _url_of(config):
    return config.get("url") or config["server_url"]


def _token_of(config):
    return config.get("token") or config["agent_token"]


def validate_config(config):
    import re
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", config.get("asset_id", "")):
        raise ValueError("Invalid asset_id")
    if not isinstance(config.get("allowed_users"), list) or not config["allowed_users"]:
        raise ValueError("Local allowed_users must not be empty")
    if not isinstance(config.get("allow_root_readonly", False), bool):
        raise ValueError("allow_root_readonly must be true or false")
    if config.get("allow_root_readonly") is True:
        import pwd as _pwd
        if not any(_pwd.getpwnam(u).pw_uid == 0 for u in config["allowed_users"] if u):
            raise ValueError("allow_root_readonly is set but no allowed account is root")
    if not Path(config["journal_dir"]).is_absolute():
        raise ValueError("journal_dir must be absolute")
    controllers_of(config)
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
    """POST to a controller endpoint.

    `config` here is a single controller view carrying `url` and `token`
    (see Worker.controllers). Kept name `config` for backward compatibility
    with tests that monkeypatch this function with a 3-arg signature.
    """
    req = urllib.request.Request(_url_of(config).rstrip("/") + path,
        data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + _token_of(config), "Content-Type": "application/json"})
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


def _cgroup_root():
    """Return the writable cgroup v2 root we can create task cgroups under."""
    candidate = "/sys/fs/cgroup"
    if os.path.ismount(candidate) and os.access(candidate, os.W_OK):
        return candidate
    return None


def _cgroup_available():
    """True when cgroup v2 is mounted and writable, and cgroup.kill exists."""
    root = _cgroup_root()
    if root is None:
        return False
    return os.path.exists(os.path.join(root, "cgroup.kill"))


def _task_cgroup_name():
    return "ai-ops-task-%d-%s" % (os.getpid(), uuid.uuid4().hex[:8])


def _kill_cgroup(path):
    """Kill every process in the cgroup (covers setsid escapes), then remove it."""
    try:
        with open(os.path.join(path, "cgroup.kill"), "w") as handle:
            handle.write("1")
    except OSError:
        pass
    for _ in range(50):
        try:
            os.rmdir(path)
            return
        except OSError:
            time.sleep(0.1)


class ControlRejected(Exception):
    """The control plane durably rejected this report, so retrying cannot help."""

    def __init__(self, status, path):
        super().__init__("control rejected %s with %s" % (path, status))
        self.status = status


def dispatch(task, allowed_users, cancel_event=None, output_dir=None, credentials=None, controller=None,
             allow_root_readonly=False):
    """Route a claimed task to the right executor by its ``kind``.

    - missing kind   -> "shell": tasks from a pre-1.3 control plane.
    - "readonly"     -> stdlib-only execve path, no shell, redacted output.
    - "change"       -> structured action set, argv rebuilt locally.
    - anything else  -> refused. Never fall back to shell: that would turn an
                        unknown future task type into an unvalidated command.

    ``credentials`` is the local store; ``controller`` says which control plane
    asked, because whether plaintext may leave this host is a property of that
    pairing, not of the task (§47.2).
    """
    kind = task.get("kind", "shell")
    if kind == "shell":
        return execute(task, allowed_users, cancel_event, output_dir)
    if kind == "readonly":
        from . import readonly
        return readonly.execute(task, allowed_users, cancel_event, credentials=credentials,
                               allow_root_readonly=allow_root_readonly)
    if kind == "change":
        from . import changes
        return changes.execute(task, allowed_users, cancel_event, output_dir,
                               credentials=credentials, controller=controller)
    return failure(task, "UNSUPPORTED_KIND:" + str(kind)[:40])


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

    def _spawn(cwd):
        return subprocess.Popen(["/bin/sh", "-c", task["command"]], cwd=cwd,
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, **identity)

    try:
        if cancel_event.is_set():
            return with_archives(failure(task, 'CANCELLED_BEFORE_EXECUTION', 'cancelled'))
        # Prefer the account's home as cwd, but a hardened sandbox
        # (ProtectHome) can make it un-enterable AFTER the uid drop, which
        # surfaces as a PermissionError from Popen. Fall back to / and then to a
        # root-owned scratch dir so a restricted home never blocks execution.
        candidates = [account.pw_dir if Path(account.pw_dir).is_dir() else "/", "/"]
        cgroup = None
        if _cgroup_available():
            cgroup = os.path.join(_cgroup_root(), _task_cgroup_name())
            try:
                os.mkdir(cgroup, 0o755)
            except OSError:
                cgroup = None
        proc = None
        last_error = None
        for cwd in candidates:
            if not isinstance(cwd, str) or not cwd:
                continue
            if not Path(cwd).is_dir():
                continue
            try:
                proc = _spawn(cwd)
                break
            except PermissionError as error:
                last_error = error
                continue
        if proc is None:
            raise last_error or OSError("no usable working directory")
        if cgroup is not None:
            # Move the fresh process into its own cgroup; descendants inherit it.
            # This is what lets us reclaim a child that escapes its process group.
            try:
                with open(os.path.join(cgroup, "cgroup.procs"), "w") as handle:
                    handle.write(str(proc.pid))
            except OSError:
                _kill_cgroup(cgroup)
                cgroup = None
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
            # Reclaim every descendant. When a task cgroup is available, kill it
            # (covers setsid daemons); otherwise fall back to the process group,
            # which at least covers ordinary children.
            if cgroup is not None:
                _kill_cgroup(cgroup)
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
        config = validate_config(config)
        self.config = config
        self.asset_id = config["asset_id"]
        self.allowed_users = config["allowed_users"]
        # Whether the read channel may run as root. Off unless the operator put
        # a root account in allowed_users AND passed allow_root_readonly (§7).
        self.allow_root_readonly = config.get("allow_root_readonly", False) is True
        self.journal = Path(config["journal_dir"])
        self.journal.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Credentials live next to the journal, owned by the service account,
        # encrypted with a key that never leaves this host (§47.1).
        from .credentials import Store
        self.credentials = Store(config.get('credential_dir') or (self.journal.parent / 'credentials'))
        self.prefix = "/api/v1/agents/" + self.asset_id
        self.instance_id = str(uuid.uuid4())
        self.controllers = controllers_of(config)
        # Short bookkeeping lock only: a slow controller never blocks another.
        self._heartbeat_lock = threading.Lock()
        self._heartbeat_state = {c['name']: {'seq': 0, 'results': {}, 'telemetry': True} for c in self.controllers}
        # Execution-level mutex shared across ALL controllers: at any moment this
        # agent runs at most one command, so it reports one busy owner.
        self.busy_by = None
        self.busy_task = None

    def _default_controller(self):
        for controller in self.controllers:
            if controller["enabled"] is True:
                return controller
        return self.controllers[0]

    def heartbeat(self, controller=None):
        if controller is None:
            controller = self._default_controller()
        body = {'instance_id': self.instance_id, 'agent_version': AGENT_VERSION,
                'protocol_version': PROTOCOL, 'busy': self.busy_by is not None}
        if self.busy_by is not None:
            body['busy_by'] = self.busy_by
            body['busy_task'] = self.busy_task
        name = controller['name']
        with self._heartbeat_lock:
            state = self._heartbeat_state[name]
            if state['seq'] >= 9007199254740991:
                raise RuntimeError('Heartbeat sequence exhausted; restart Agent')
            state['seq'] += 1  # Reserve before I/O, including all failed sends.
            seq = state['seq']
            if state['telemetry']:
                body['heartbeat_telemetry'] = {
                    'session_id': self.instance_id, 'controller': name, 'attempt_seq': seq,
                    'previous_results': [{'attempt_seq': n, 'outcome': outcome}
                        for n, outcome in sorted(state['results'].items()) if seq-10 <= n < seq]}
        outcome = 'unconfirmed'
        try:
            response = request(controller, self.prefix + '/heartbeat', body, timeout=3)
            if isinstance(response, dict) and response.get('accepted') is True:
                outcome = 'acknowledged'
            return response
        except urllib.error.HTTPError as error:
            # Old strict 1.2 services reject only the new optional field. Never
            # downgrade on auth failures, timeouts, or invalid nested telemetry.
            unsupported = False
            if error.code == 422 and 'heartbeat_telemetry' in body:
                try:
                    detail = json.loads(error.read(8193)).get('detail', [])
                    unsupported = isinstance(detail, list) and len(detail) == 1 and detail[0].get('type') == 'extra_forbidden' and detail[0].get('loc') == ['body', 'heartbeat_telemetry']
                except (ValueError, TypeError, AttributeError):
                    pass
            if not unsupported:
                raise
            with self._heartbeat_lock:
                state['telemetry'] = False
            # A real second HTTP attempt: reserve another sequence, no hidden
            # retry masquerading as the failed first attempt's ACK.
            return self.heartbeat(controller)
        finally:
            with self._heartbeat_lock:
                # Late completion cannot re-grow the bounded sender window.
                floor = state['seq'] - 9
                if seq >= floor:
                    state['results'][seq] = outcome
                state['results'] = {n: r for n, r in state['results'].items() if n >= floor}

    def upload_outputs(self, controller, task, result):
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
                    ack = request(controller, prefix + '/chunks', {'claim_id': task['claim_id'], 'offset': offset, 'data': base64.b64encode(data).decode()})
                    if ack.get('accepted') is not True or ack.get('next_offset') != offset + len(data):
                        raise RuntimeError('Output chunk not acknowledged')
                    offset += len(data)
            ack = request(controller, prefix + '/finalize', {'claim_id': task['claim_id'], **manifest})
            if ack.get('accepted') is not True:
                raise RuntimeError('Output finalize not acknowledged')

    def send_result(self, *args):
        """send_result(task, result) or send_result(controller, task, result).

        The 2-arg form resolves the owning controller from the journal entry (or
        the first enabled controller when the task is not journalled), keeping
        older callers working.
        """
        if len(args) == 2:
            task, result = args
            controller = self._controller_for_task(task)
        elif len(args) == 3:
            controller, task, result = args
        else:
            raise TypeError('send_result expects (task, result) or (controller, task, result)')
        self.upload_outputs(controller, task, result)
        response = request(controller, self.prefix + "/tasks/" + task["id"] + "/result", result)
        if response.get("accepted") is not True:
            raise RuntimeError("Result not acknowledged")

    def _controller_for_task(self, task):
        entry = self.journal / (str(task.get("id")) + ".json")
        if entry.exists():
            controller = self._controller_for_journal(entry)
            if controller is not None:
                return controller
        return self._default_controller()

    def _controller_for_journal(self, entry_path):
        """Resolve the controller a journalled task belongs to, by name.

        Task files record which controller delivered them, so a result is never
        reported to the wrong control plane after a restart or config change.
        A journal written before multi-controller support (no name) resolves to
        the single/default controller so upgrades keep reporting old work.
        """
        try:
            name = json.loads(entry_path.read_text()).get("controller")
        except (OSError, ValueError):
            return None
        if name is None:
            return self._default_controller()
        for controller in self.controllers:
            if controller["name"] == name:
                return controller
        return None

    def flush_pending(self):
        for path in sorted(self.journal.glob("*.json")):
            entry = json.loads(path.read_text())
            if entry["phase"] == "acknowledged":
                continue
            controller = self._controller_for_journal(path)
            if controller is None:
                # The owning controller is gone or disabled. Do NOT replay the
                # command and do NOT report it elsewhere; keep the journal for
                # an operator. This is the local control point for a blocked
                # controller.
                continue
            if entry["phase"] == "started":
                # Crash window is deliberately UNKNOWN, never replay a command.
                entry["phase"] = "result_ready"
                entry["result"] = failure(entry["task"], "AGENT_RESTART_EXECUTION_UNKNOWN", "unknown")
                atomic_json(path, entry)
            try:
                self.send_result(controller, entry["task"], entry["result"])
            except ControlRejected:
                # The control plane already holds a durable outcome for this task
                # (for example a human resolved an unknown execution). Retrying
                # would never succeed, so settle the journal entry and move on
                # instead of blocking every later claim on this asset.
                pass
            entry["phase"] = "acknowledged"
            atomic_json(path, entry)

    def once(self):
        """One pass over every enabled controller.

        Returns True if at least one controller delivered work in this pass.
        """
        self.flush_pending()
        worked = False
        for controller in self.controllers:
            if controller["enabled"] is not True:
                continue
            if self._once(controller):
                worked = True
                break
        return worked

    def _once(self, controller):
        try:
            self.heartbeat(controller)
        except ControlRejected:
            return False
        response = request(controller, self.prefix + "/claim",
                           {"protocol_version": PROTOCOL, "controller": controller["name"]})
        if response.get("protocol_version") not in (PROTOCOL, "1.1", "1.2"):
            raise RuntimeError("Incompatible protocol")
        task = response.get("task")
        if task is None:
            return False
        # UUID normalization prevents remote paths from becoming local filenames.
        if str(uuid.UUID(task["id"])) != task["id"] or task.get("asset_id") != self.asset_id:
            raise ValueError("Invalid task identity")
        path = self.journal / (task["id"] + ".json")
        if path.exists():
            # A duplicate delivery must never launch a second process.
            old = json.loads(path.read_text())
            if old["task"] != task:
                raise RuntimeError("Task identity collision")
            self.send_result(controller, task, old.get("result") or failure(task, "DUPLICATE_DELIVERY_UNKNOWN", "unknown"))
            return False
        entry = {"phase": "started", "task": task, "controller": controller["name"]}
        atomic_json(path, entry)
        stop, cancelled = threading.Event(), threading.Event()

        def control():
            response = request(controller, self.prefix + '/tasks/' + task['id'] + '/control', {'claim_id': task['claim_id']}, timeout=3)
            if response.get('cancel_requested') is True:
                cancelled.set()

        # Check a queued cancellation before starting any native process.
        control()
        # Announce the busy owner BEFORE execution so every other controller
        # sees it and queues its own work instead of racing.
        self.busy_by, self.busy_task = controller["name"], task["id"]

        def monitor():
            while not stop.wait(2):
                for other in self.controllers:
                    if other["enabled"] is not True:
                        continue
                    try:
                        self.heartbeat(other)
                        if other is controller:
                            control()
                    except Exception:
                        # Disconnection is NOT evidence that execution stopped.
                        # Local timeout still applies; journal preserves the result.
                        pass

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        try:
            result = dispatch(task, self.allowed_users, cancelled, self.journal / task['id'],
                              credentials=self.credentials, controller=controller,
                              allow_root_readonly=getattr(self, 'allow_root_readonly', False))
            entry.update(phase='result_ready', result=result)
            atomic_json(path, entry)
            self.send_result(controller, task, result)
            entry['phase'] = 'acknowledged'
            atomic_json(path, entry)
        finally:
            stop.set()
            thread.join(timeout=7)
            self.busy_by, self.busy_task = None, None
        return True


def credential_cli(argv):
    """``cred`` subcommands. These run on the managed host, by its owner.

    This is where the managed machine exercises its veto (§46.2): it can list
    what is stored, reveal a value locally, decide per control plane whether the
    plaintext may leave, and destroy it. None of it requires the control plane to
    be reachable, which is the point.
    """
    from .credentials import CredentialError, Store
    parser = argparse.ArgumentParser(prog='ai-ops-agent cred')
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('list', 'share', 'unshare', 'revoke', 'destroy'):
        one = sub.add_parser(name)
        one.add_argument('--config', required=True)
        if name in ('share', 'unshare', 'revoke'):
            one.add_argument('--controller')
        if name in ('share', 'unshare', 'destroy'):
            one.add_argument('--id')
    reveal = sub.add_parser('reveal')
    reveal.add_argument('--config', required=True)
    reveal.add_argument('--id', required=True)
    args = parser.parse_args(argv)
    config = read_config(args.config)
    store = Store(config.get('credential_dir') or (Path(config['journal_dir']).parent / 'credentials'))
    try:
        if args.action == 'list':
            print(json.dumps({'owner': store.master_id(), 'credentials': store.listing()},
                             ensure_ascii=False, indent=2))
        elif args.action == 'reveal':
            # Deliberately stdout and local-only: this is the operator looking at
            # their own machine, not a model.
            print(store.reveal(args.id))
        elif args.action == 'share':
            print(json.dumps(store.share(args.id, args.controller, True), ensure_ascii=False))
        elif args.action == 'unshare':
            print(json.dumps(store.share(args.id, args.controller, False), ensure_ascii=False))
        elif args.action == 'revoke':
            store.revoke_controller(args.controller)
            print('revoked ' + args.controller)
        elif args.action == 'destroy':
            store.destroy(args.id)
            print('destroyed ' + args.id)
    except CredentialError as error:
        print('error: ' + error.code, file=sys.stderr)
        return 2
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'cred':
        raise SystemExit(credential_cli(sys.argv[2:]))
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
