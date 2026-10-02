import json
import os
import sys
import uuid
import pytest
from ai_ops_agent.agent import Worker, atomic_json, execute, validate_config


def config(tmp_path):
    return {"server_url": "http://127.0.0.1:8765", "allow_loopback_http": True,
            "asset_id": "test", "agent_token": "test-agent-token-not-real-1234567890",
            "allowed_users": ["nobody"], "journal_dir": str(tmp_path.resolve())}


def task(user="nobody", command="id -un", **kwargs):
    result = {"id": str(uuid.uuid4()), "asset_id": "test", "claim_id": "claim-not-real-1234567890",
              "execution_users": [user], "run_as": user, "command": command, "timeout_seconds": 5}
    result.update(kwargs)
    return result


def test_public_plaintext_rejected(tmp_path):
    c = config(tmp_path)
    c["server_url"] = "http://example.com"
    with pytest.raises(ValueError):
        validate_config(c)


def test_url_embedded_credentials_rejected(tmp_path):
    c = config(tmp_path)
    c["server_url"] = "https://user:secret@example.com"
    with pytest.raises(ValueError):
        validate_config(c)


def test_config_refuses_empty_users(tmp_path):
    c = config(tmp_path)
    c["allowed_users"] = []
    with pytest.raises(ValueError):
        validate_config(c)


def test_atomic_journal(tmp_path):
    file = tmp_path / "entry.json"
    atomic_json(file, {"phase": "started"})
    assert json.loads(file.read_text())["phase"] == "started"
    assert not file.with_suffix(".tmp").exists()


def test_crash_recovery_reports_unknown_not_execute(tmp_path, monkeypatch):
    c = config(tmp_path)
    t = task()
    atomic_json(tmp_path / (t["id"] + ".json"), {"phase": "started", "task": t})
    calls = []
    monkeypatch.setattr("ai_ops_agent.agent.request", lambda config, path, body: calls.append(body) or {"accepted": True})
    monkeypatch.setattr("ai_ops_agent.agent.execute", lambda *args: pytest.fail("Must not replay crashed task"))
    Worker(c).flush_pending()
    assert calls[0]["status"] == "unknown"
    assert json.loads((tmp_path / (t["id"] + ".json")).read_text())["phase"] == "acknowledged"


def test_saved_result_retried_without_execution(tmp_path, monkeypatch):
    t = task()
    result = {"claim_id": t["claim_id"], "status": "succeeded", "exit_code": 0}
    atomic_json(tmp_path / (t["id"] + ".json"), {"phase": "result_ready", "task": t, "result": result})
    calls = []
    monkeypatch.setattr("ai_ops_agent.agent.request", lambda config, path, body: calls.append(body) or {"accepted": True})
    Worker(config(tmp_path)).flush_pending()
    assert calls == [result]


def test_rejects_task_path_injection(tmp_path, monkeypatch):
    t = task()
    t["id"] = "../../outside"
    monkeypatch.setattr("ai_ops_agent.agent.request", lambda *args: {"protocol_version": "1.0", "task": t})
    with pytest.raises(ValueError):
        Worker(config(tmp_path)).once()


linux = pytest.mark.skipif(sys.platform != "linux", reason="Real account execution requires Linux")


@linux
def test_account_not_allowed():
    assert execute(task(user="root"), ["nobody"])["error_code"] == "USER_NOT_ALLOWED"


@linux
def test_missing_user_fails_without_fallback():
    name = "ai_ops_missing_" + uuid.uuid4().hex[:8]
    assert execute(task(user=name), [name])["error_code"] == "USER_NOT_FOUND"


@linux
def test_real_current_user():
    import pwd
    current = pwd.getpwuid(os.geteuid()).pw_name
    result = execute(task(user=current), [current])
    assert result["status"] == "succeeded"
    assert result["stdout"].strip() == current


@linux
def test_output_limit_and_timeout():
    import pwd
    current = pwd.getpwuid(os.geteuid()).pw_name
    result = execute(task(user=current, command="yes x | head -c 100000"), [current])
    assert len(result["stdout"]) <= 65536
    assert result["output_truncated"] is True
    result = execute(task(user=current, command="sleep 10", timeout_seconds=1), [current])
    assert result["error_code"] == "EXECUTION_TIMEOUT"


@linux
def test_environment_does_not_inherit_secret(monkeypatch):
    import pwd
    current = pwd.getpwuid(os.geteuid()).pw_name
    monkeypatch.setenv("SENSITIVE_TEST_TOKEN", "do-not-inherit-this")
    result = execute(task(user=current, command="printf '%s' \"${SENSITIVE_TEST_TOKEN-unset}\""), [current])
    assert result["stdout"] == "unset"


@linux
def test_nonroot_native_account_if_root():
    if os.geteuid() != 0:
        pytest.skip("Root required for cross-user execution")
    result = execute(task(user="nobody"), ["nobody"])
    assert result["status"] == "succeeded"
    assert result["stdout"].strip() == "nobody"
