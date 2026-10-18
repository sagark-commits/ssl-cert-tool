"""Studio service layer and task runner: tested without any window."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from conftest import DOMAIN, cert_pem, key_pem, posix_only
from fake_remote import FakeRemote
from ssl_deploy.deployer import CopyItem, SSLDeployer
from ssl_ui import services as svc
from ssl_ui.runner import GuiTerminal, StreamToLog, TaskRunner


# ---------------------------------------------------------------------------
# inspect / generate
# ---------------------------------------------------------------------------

def test_inspect_lists_the_chain_leaf_first_with_expiry_and_key_match(cert_dir):
    view = svc.inspect_paths([cert_dir])
    assert [c.role for c in view.certs][0] == "LEAF" and view.certs[0].cn == DOMAIN
    assert view.certs[0].days_left > 60 and not view.certs[0].expired
    assert DOMAIN in view.certs[0].names
    assert view.ready and view.leaf_cn == DOMAIN
    assert any(match is True for _name, match in view.keys)


def test_inspect_flags_a_key_that_does_not_belong(cert_dir, pki):
    other, _ = pki.leaf()
    for f in cert_dir.glob("*.key"):
        f.unlink()
    for f in cert_dir.glob("asterisk*"):
        f.unlink()
    (cert_dir / "stranger.key").write_bytes(key_pem(other))
    view = svc.inspect_paths([cert_dir])
    assert not view.ready and view.keys == [("stranger.key", False)]


def test_inspect_needs_input_and_reports_missing_paths(tmp_path):
    with pytest.raises(svc.UiError, match="at least one"):
        svc.inspect_paths([])
    with pytest.raises(svc.UiError, match="Not found"):
        svc.inspect_paths([tmp_path / "nope"])


def test_generate_builds_the_artifacts_and_reports_them(cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")  # same result whether or not this machine has Java
    view = svc.generate_artifacts([cert_dir], tmp_path / "out", "longenough1", "app-key")
    assert view.domain == DOMAIN and view.key_cert_match and view.jks == "built-in"
    names = {name for name, _size in view.files}
    assert {f"main_{DOMAIN}.crt", f"{DOMAIN}.key", f"{DOMAIN}.jks", "keystore.p12"} <= names
    assert all(size > 0 for _n, size in view.files)
    assert view.output_dir == tmp_path / "out" / DOMAIN


def test_generate_explains_what_is_wrong(cert_dir, tmp_path, pki):
    with pytest.raises(svc.UiError, match="keystore password"):
        svc.generate_artifacts([cert_dir], tmp_path / "o", "  ", "a")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(svc.UiError, match="No certificate files"):
        svc.generate_artifacts([empty], tmp_path / "o", "longenough1", "a")
    other, _ = pki.leaf()
    only_cert = tmp_path / "only"
    only_cert.mkdir()
    (only_cert / "c.crt").write_bytes((cert_dir / f"main_{DOMAIN}.crt").read_bytes())
    with pytest.raises(svc.UiError, match="No private key"):
        svc.generate_artifacts([only_cert], tmp_path / "o", "longenough1", "a")
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(key_pem(other))
    with pytest.raises(svc.UiError, match="does not match"):
        svc.generate_artifacts([only_cert], tmp_path / "o", "longenough1", "a", key_path=wrong)


def test_generate_with_an_encrypted_key(cert_dir, tmp_path, leaf, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    key, _ = leaf
    for f in cert_dir.glob("*.key"):
        f.unlink()
    for f in cert_dir.glob("asterisk*"):
        f.unlink()
    enc = tmp_path / "enc.key"
    enc.write_bytes(key_pem(key, b"pass-phrase-1"))
    with pytest.raises(svc.UiError, match="passphrase"):
        svc.generate_artifacts([cert_dir], tmp_path / "o", "longenough1", "a", key_path=enc)
    assert svc.generate_artifacts([cert_dir], tmp_path / "o", "longenough1", "a", key_path=enc, key_password="pass-phrase-1").key_cert_match


def test_keystore_info_reads_what_generate_wrote(cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    view = svc.generate_artifacts([cert_dir], tmp_path / "out", "longenough1", "app-key")
    info = svc.keystore_info(view.output_dir / f"{DOMAIN}.jks", "longenough1")
    assert info.alias == "app-key" and info.domain == DOMAIN and not info.expired and info.chain[0][1] == "leaf"
    with pytest.raises(svc.UiError, match="Invalid password"):
        svc.keystore_info(view.output_dir / f"{DOMAIN}.jks", "wrong")
    p12 = svc.keystore_info(view.output_dir / "keystore.p12", "longenough1")
    assert p12.domain == DOMAIN


# ---------------------------------------------------------------------------
# routes and plans
# ---------------------------------------------------------------------------

SSH_CONFIG = (
    "Host bastion\n  HostName 203.0.113.9\n  Port 40222\n  User jumpuser\n"
    "Host app-1\n  HostName 10.128.0.7\n  Port 142\n  User deploy\n  ProxyJump bastion\n"
)


def test_route_preview_follows_the_ssh_config_chain(tmp_path):
    cfg = tmp_path / "ssh_config"
    cfg.write_text(SSH_CONFIG, encoding="utf-8")
    view = svc.preview_route("app-1", ssh_config_path=cfg)
    assert view.error is None and view.names == ["bastion", "app-1"]
    assert view.hops[0] == "jumpuser@203.0.113.9:40222" and view.hops[-1] == "deploy@10.128.0.7:142"


def test_route_preview_for_adhoc_hosts_and_errors(tmp_path):
    cfg = tmp_path / "none"
    adhoc = svc.preview_route("deploy@10.0.0.5:2222", via="ops@bastion.example.com", ssh_config_path=cfg)
    assert adhoc.hops == ["ops@bastion.example.com:22", "deploy@10.0.0.5:2222"]
    assert "Enter a host" in svc.preview_route("", ssh_config_path=cfg).error
    assert "cannot understand" in svc.preview_route("a b", ssh_config_path=cfg).error
    assert "cannot understand" in svc.preview_route("nope@@", ssh_config_path=cfg).error


def test_ssh_aliases_skip_wildcards(tmp_path):
    cfg = tmp_path / "ssh_config"
    cfg.write_text(SSH_CONFIG + "Host *\n  ServerAliveInterval 30\nHost lab-*\n  User x\n", encoding="utf-8")
    assert svc.ssh_aliases(cfg) == ["app-1", "bastion"]
    assert svc.ssh_aliases(tmp_path / "missing") == []


def test_load_plan_describes_servers_services_and_routes(tmp_path):
    cfg = tmp_path / "plan.yaml"
    cfg.write_text(
        "domain: example.com\nservers:\n  web:\n    host: 10.0.0.1\n    services: [crm, tomcat]\n"
        "  broken:\n    ssh_alias: nope\n    services: []\n"
        "services:\n  crm:\n    type: apache\n    ssl_dir: /etc/ssl/\n"
        "  tomcat:\n    type: jks\n    remote_path: /app/x.jks\n",
        encoding="utf-8",
    )
    plan = svc.load_plan(cfg, ssh_config_path=tmp_path / "none")
    web, broken = plan.servers
    assert plan.domain == "example.com" and web.route == ["root@10.0.0.1:22"]
    assert web.services == [("crm", "apache", "/etc/ssl/"), ("tomcat", "jks", "/app/x.jks")]
    assert broken.error and "not found in ~/.ssh/config" in broken.error
    with pytest.raises(svc.UiError, match="not found"):
        svc.load_plan(tmp_path / "missing.yaml")


# ---------------------------------------------------------------------------
# running deploy / copy / rollback through the real deployer (fake remote host)
# ---------------------------------------------------------------------------

def _inject(monkeypatch, remote):
    monkeypatch.setattr(SSLDeployer, "connect_server", lambda self, name, force=False: remote)


def test_run_copy_end_to_end(tmp_path, cert_dir, monkeypatch):
    remote = FakeRemote(tmp_path / "remote")
    _inject(monkeypatch, remote)
    items = [CopyItem(cert_dir / f"main_{DOMAIN}.crt", "/srv/ssl/site.crt"), CopyItem(cert_dir / f"{DOMAIN}.key", "/srv/ssl/site.key")]
    outcome = svc.run_copy(items, terminal=GuiTerminal(lambda l, m: None), host="deploy@10.0.0.5", dry_run=False)
    assert outcome.ok and [r.status for r in outcome.rows] == ["success", "success"]
    assert remote.exists("/srv/ssl/site.crt")


def test_run_copy_failure_is_reported_with_everything_restored(tmp_path, cert_dir, monkeypatch):
    remote = FakeRemote(tmp_path / "remote")
    remote.write("/srv/ssl/site.crt", b"OLD")
    remote.script_results["nginx -t"] = (1, "", "bad")
    _inject(monkeypatch, remote)
    outcome = svc.run_copy([CopyItem(cert_dir / f"main_{DOMAIN}.crt", "/srv/ssl/site.crt")], terminal=GuiTerminal(lambda l, m: None),
                           host="deploy@10.0.0.5", check_cmd="nginx -t", dry_run=False)
    assert not outcome.ok and outcome.rows[-1].status == "failed"
    assert remote.read("/srv/ssl/site.crt") == b"OLD" and outcome.hint


def test_run_copy_validates_before_doing_anything(cert_dir):
    term = GuiTerminal(lambda l, m: None)
    with pytest.raises(svc.UiError, match="at least one"):
        svc.run_copy([], terminal=term, host="h")
    with pytest.raises(svc.UiError, match="target host"):
        svc.run_copy([CopyItem(cert_dir / "chain.crt", "/x/y")], terminal=term, host="")
    with pytest.raises(svc.UiError, match="deploy config"):
        svc.run_copy([CopyItem(cert_dir / "chain.crt", "/x/y")], terminal=term, server="web")


def test_run_deploy_dry_run_and_real(tmp_path, cert_dir, monkeypatch):
    cfg = tmp_path / "deploy.yaml"
    cfg.write_text(
        f"domain: {DOMAIN}\nbackup_dir: /var/b\nservers:\n  web:\n    host: 10.0.0.1\n    services: [c]\n"
        "services:\n  c:\n    type: custom\n    file_mappings:\n      certificate: /srv/a.crt\n      private_key: /srv/a.key\n",
        encoding="utf-8",
    )
    remote = FakeRemote(tmp_path / "remote")
    _inject(monkeypatch, remote)
    logs = []
    term = GuiTerminal(lambda level, text: logs.append((level, text)))
    dry = svc.run_deploy(cfg, cert_dir, svc.DeployOptions(dry_run=True), terminal=term)
    assert dry.ok and remote.files() == [] and any(level == "cmd" for level, _t in logs)
    real = svc.run_deploy(cfg, cert_dir, svc.DeployOptions(dry_run=False), terminal=term)
    assert real.ok and remote.exists("/srv/a.crt") and real.hint
    bad = svc.run_deploy(cfg, cert_dir, svc.DeployOptions(dry_run=False, server="nope"), terminal=term)
    assert not bad.ok and bad.aborted


def test_run_deploy_rejects_bad_inputs(tmp_path):
    term = GuiTerminal(lambda l, m: None)
    with pytest.raises(svc.UiError, match="Config not found"):
        svc.run_deploy(tmp_path / "x.yaml", tmp_path, svc.DeployOptions(), terminal=term)
    cfg = tmp_path / "c.yaml"
    cfg.write_text("servers: {}\n", encoding="utf-8")
    with pytest.raises(svc.UiError, match="folder not found"):
        svc.run_deploy(cfg, tmp_path / "nope", svc.DeployOptions(), terminal=term)


def test_run_rollback_restores_the_previous_files(tmp_path, cert_dir, monkeypatch):
    cfg = tmp_path / "deploy.yaml"
    cfg.write_text(
        f"domain: {DOMAIN}\nbackup_dir: /var/b\nservers:\n  web:\n    host: 10.0.0.1\n    services: [c]\n"
        "services:\n  c:\n    type: custom\n    file_mappings:\n      certificate: /srv/a.crt\n",
        encoding="utf-8",
    )
    remote = FakeRemote(tmp_path / "remote")
    remote.write("/srv/a.crt", b"OLD")
    _inject(monkeypatch, remote)
    term = GuiTerminal(lambda l, m: None)
    assert svc.run_deploy(cfg, cert_dir, svc.DeployOptions(dry_run=False), terminal=term).ok
    outcome = svc.run_rollback(cfg, terminal=term, dry_run=False)
    assert outcome.ok and remote.read("/srv/a.crt") == b"OLD"
    with pytest.raises(svc.UiError, match="No server matched"):
        svc.run_rollback(cfg, terminal=term, server="nope", dry_run=False)


def test_env_status_reports_the_basics(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "a.yaml").write_text("x: 1", encoding="utf-8")
    (tmp_path / "configs" / "template.yaml").write_text("x: 1", encoding="utf-8")
    env = svc.env_status(tmp_path / "configs", ssh_config=tmp_path / "none")
    assert env.version and env.configs == ["a.yaml"] and env.ssh_config is None and env.ssh_aliases == []


# ---------------------------------------------------------------------------
# GuiTerminal / StreamToLog / TaskRunner
# ---------------------------------------------------------------------------

def test_gui_terminal_maps_tool_output_to_log_levels():
    seen = []
    term = GuiTerminal(lambda level, text: seen.append((level, text)))
    term.step(1, 4, "Parsing")
    term.success("done")
    term.warn("careful")
    term.error("bad")
    term.info("fyi")
    for line in ("[ok] key matches", "[FAIL] mismatch", "[WARN] soon", "[DRY-RUN] Would upload x", "plain"):
        term.detail(line)
    assert [lvl for lvl, _ in seen] == ["step", "success", "warn", "error", "info", "success", "error", "warn", "cmd", "detail"]
    assert seen[0][1] == "[1/4] Parsing"
    term.disable()  # must exist and do nothing


def test_stream_to_log_splits_lines_and_classifies():
    seen = []
    stream = StreamToLog(lambda level, text: seen.append((level, text)))
    stream.write("  [warn] Skipped x.p12: bad\nplain line\npartial")
    stream.write(" end\n")
    stream.flush()
    assert seen == [("warn", "  [warn] Skipped x.p12: bad"), ("info", "plain line"), ("info", "partial end")]


class FakeScheduler:
    def after(self, ms, fn=None, *args):
        return None


def make_runner(prompt=lambda hop: "typed"):
    events = {"log": [], "state": []}
    runner = TaskRunner(
        FakeScheduler(),
        on_log=lambda level, text: events["log"].append((level, text)),
        on_state=lambda busy, label: events["state"].append((busy, label)),
        ask_password_ui=prompt,
    )
    return runner, events


def wait_for(predicate, runner, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        runner.pump()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_runner_runs_a_task_off_thread_and_reports_back():
    runner, events = make_runner()
    done = []
    main = threading.current_thread()
    where = []

    def job(ctx):
        where.append(threading.current_thread())
        ctx.log("info", "working")
        print("printed by library code")
        return 42

    assert runner.run("Inspect", job, lambda result, error: done.append((result, error)))
    assert wait_for(lambda: done, runner)
    assert done == [(42, None)] and where[0] is not main
    assert ("info", "working") in events["log"] and ("info", "printed by library code") in events["log"]
    assert events["state"] == [(True, "Inspect"), (False, "")] and not runner.busy


def test_runner_refuses_a_second_task_while_busy():
    runner, _ = make_runner()
    gate = threading.Event()
    done = []
    assert runner.run("one", lambda ctx: gate.wait(5), lambda r, e: done.append(1))
    assert runner.run("two", lambda ctx: None, lambda r, e: None) is False
    gate.set()
    assert wait_for(lambda: done, runner)
    assert runner.run("three", lambda ctx: None, lambda r, e: done.append(3))


def test_runner_hands_exceptions_to_the_ui_instead_of_dying():
    runner, events = make_runner()
    done = []

    def boom(ctx):
        raise svc.UiError("fix this")

    runner.run("x", boom, lambda r, e: done.append(e))
    assert wait_for(lambda: done, runner)
    assert isinstance(done[0], svc.UiError) and str(done[0]) == "fix this"
    assert not any(level == "detail" and "Traceback" in text for level, text in events["log"])  # expected errors: no traceback noise

    done.clear()
    runner.run("y", lambda ctx: 1 / 0, lambda r, e: done.append(e))
    assert wait_for(lambda: done, runner)
    assert isinstance(done[0], ZeroDivisionError)
    assert any("Traceback" in text for _l, text in events["log"])  # unexpected errors keep their traceback


def test_password_prompt_blocks_the_worker_until_the_ui_answers():
    asked = []

    def ui_prompt(hop):
        asked.append(hop["host"])
        return "s3cret"

    runner, events = make_runner(ui_prompt)
    done = []
    runner.run("deploy", lambda ctx: ctx.ask_password({"user": "u", "host": "10.1.1.1", "port": 22}), lambda r, e: done.append(r))
    assert wait_for(lambda: done, runner)
    assert done == ["s3cret"] and asked == ["10.1.1.1"]
    assert "s3cret" not in " ".join(text for _l, text in events["log"])  # the password never reaches the log


def test_cancelled_password_prompt_returns_none_and_a_crashing_dialog_cannot_hang_the_worker():
    runner, _ = make_runner(lambda hop: None)
    done = []
    runner.run("a", lambda ctx: ctx.ask_password({"host": "h"}), lambda r, e: done.append(r))
    assert wait_for(lambda: done, runner) and done == [None]

    def broken(hop):
        raise RuntimeError("dialog failed")

    runner2, _ = make_runner(broken)
    done2 = []
    runner2.run("b", lambda ctx: ctx.ask_password({"host": "h"}), lambda r, e: done2.append(r))
    assert wait_for(lambda: done2, runner2) and done2 == [None]


def test_a_failing_done_callback_does_not_kill_the_pump():
    runner, events = make_runner()
    ran = []

    def bad_done(result, error):
        raise ValueError("ui bug")

    runner.run("x", lambda ctx: 1, bad_done)
    assert wait_for(lambda: any("Internal error" in t for _l, t in events["log"]), runner)
    assert runner.run("again", lambda ctx: 2, lambda r, e: ran.append(r))
    assert wait_for(lambda: ran, runner)
