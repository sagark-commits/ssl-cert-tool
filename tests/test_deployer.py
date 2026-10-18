"""Deployer behaviour against a fake remote host (atomic, verified, reversible)."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest
import yaml

from conftest import DOMAIN, cert_pem, key_pem, now, posix_only
from fake_remote import FakeRemote
from ssl_cert_tool.platform import Terminal
from ssl_deploy.deployer import (
    ConfigError,
    DeploymentStatus,
    SSLDeployer,
    load_deploy_config,
)

SSL = "/etc/app/ssl"
BACKUPS = "/var/backups/ssl"

BASE_CONFIG = {
    "domain": DOMAIN,
    "backup_dir": BACKUPS,
    "keystore": {"password": "s3cretpass", "alias": "app"},
    "servers": {"web": {"host": "10.0.0.1", "user": "root", "services": ["crm"]}},
    "services": {
        "crm": {
            "type": "apache",
            "ssl_dir": SSL,
            "cert_file": "server.crt",
            "key_file": "server.key",
            "chain_file": "chain.crt",
            "restart": "systemctl reload httpd",
        }
    },
}


def build(tmp_path, cert_dir, config=None, remote=None, **kwargs):
    cfg = copy.deepcopy(config or BASE_CONFIG)
    cfg_path = tmp_path / "deploy.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    term = Terminal()
    term.disable()
    deployer = SSLDeployer(cfg_path, cert_dir, terminal=term, **kwargs)
    assert deployer.load_config()
    remote = remote or FakeRemote(tmp_path / "remote")
    remote.script_results.setdefault("systemctl reload httpd", (0, "", ""))
    deployer.ssh_connections["web"] = remote
    return deployer, remote


def mode_of(remote: FakeRemote, path: str) -> int:
    return os.stat(remote.map(path)).st_mode & 0o777


def leftovers(remote: FakeRemote):
    return [f for f in remote.files() if ".ssl-auto-" in f]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_fresh_deploy_writes_files_restarts_and_leaves_no_temp_files(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir)
    d.deploy_all()
    assert d.failed_count == 0, [r.message for r in d.results]
    assert remote.read(f"{SSL}/server.key") == (cert_dir / f"{DOMAIN}.key").read_bytes()
    assert remote.read(f"{SSL}/server.crt") == (cert_dir / f"main_{DOMAIN}.crt").read_bytes()
    assert remote.read(f"{SSL}/chain.crt") == (cert_dir / "chain.crt").read_bytes()
    assert remote.ran("systemctl reload httpd")
    assert leftovers(remote) == []


@posix_only
def test_private_key_is_0600_and_cert_is_0644(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir)
    d.deploy_all()
    assert mode_of(remote, f"{SSL}/server.key") == 0o600
    assert mode_of(remote, f"{SSL}/server.crt") == 0o644


def test_existing_file_is_backed_up_then_replaced(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.crt", b"OLD-CERT")
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert remote.read(f"{SSL}/server.crt") != b"OLD-CERT"
    backup = f"{BACKUPS}/web/{d.timestamp}{SSL}/server.crt"
    assert remote.read(backup) == b"OLD-CERT"


def test_a_second_deploy_in_the_same_second_cannot_overwrite_the_original_backup(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.crt", b"ORIGINAL")
    first, remote = build(tmp_path, cert_dir, remote=remote)
    first.timestamp = "20260101_000000"
    first.deploy_all()
    assert remote.read(f"{SSL}/server.crt") != b"ORIGINAL"

    second, remote = build(tmp_path, cert_dir, remote=remote)  # same snapshot folder
    second.timestamp = "20260101_000000"
    second.deploy_all()
    backup = f"{BACKUPS}/web/20260101_000000{SSL}/server.crt"
    assert remote.read(backup) == b"ORIGINAL"  # the first (true original) backup survives
    rollback, _ = build(tmp_path, cert_dir, remote=remote)
    assert rollback.rollback_server("web").status == DeploymentStatus.ROLLED_BACK
    assert remote.read(f"{SSL}/server.crt") == b"ORIGINAL"


def test_dry_run_touches_nothing(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir, dry_run=True)
    d.deploy_all()
    assert remote.files() == []
    assert remote.commands == []
    assert all(r.status == DeploymentStatus.SUCCESS for r in d.results)


def test_parallel_deploy_to_two_servers(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["servers"]["web2"] = {"host": "10.0.0.2", "services": ["crm"]}
    d, remote1 = build(tmp_path, cert_dir, config=cfg, parallel=True)
    remote2 = FakeRemote(tmp_path / "remote2")
    remote2.script_results["systemctl reload httpd"] = (0, "", "")
    d.ssh_connections["web2"] = remote2
    d.deploy_all()
    assert d.failed_count == 0
    assert remote1.exists(f"{SSL}/server.key") and remote2.exists(f"{SSL}/server.key")


# ---------------------------------------------------------------------------
# Failure handling: nothing half-done is left behind
# ---------------------------------------------------------------------------

def test_failure_midway_restores_files_already_replaced(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.key", b"OLD-KEY", 0o600)
    remote.write(f"{SSL}/server.crt", b"OLD-CERT")
    remote.fail_write_substr = "server.crt"  # key uploads first, then the cert fails
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    result = d.results[0]
    assert result.status == DeploymentStatus.FAILED
    assert "files restored" in result.message
    assert remote.read(f"{SSL}/server.key") == b"OLD-KEY"  # key was put back
    assert remote.read(f"{SSL}/server.crt") == b"OLD-CERT"
    assert not remote.ran("systemctl reload httpd")  # never restarted on a failed deploy
    assert leftovers(remote) == []
    assert d.failed_count == 1


def test_checksum_mismatch_is_detected_and_reverted(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.key", b"OLD-KEY", 0o600)
    remote.sha256_override = "0" * 64
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert "checksum mismatch" in d.results[0].message
    assert remote.read(f"{SSL}/server.key") == b"OLD-KEY"


def test_new_file_is_removed_when_its_service_fails(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.fail_write_substr = "server.crt"
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert not remote.exists(f"{SSL}/server.key")  # created by this run, so removed again


def test_failed_hook_blocks_restart_and_restores_files(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["hooks"] = ["exit 1"]
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.key", b"OLD-KEY", 0o600)
    d, remote = build(tmp_path, cert_dir, config=cfg, remote=remote)
    d.deploy_all()
    assert not remote.ran("systemctl reload httpd")
    assert remote.read(f"{SSL}/server.key") == b"OLD-KEY"
    assert d.failed_count == 1
    assert any(r.status == DeploymentStatus.ROLLED_BACK for r in d.results)


def test_failed_hook_without_auto_rollback_keeps_files_but_still_no_restart(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["hooks"] = ["exit 1"]
    d, remote = build(tmp_path, cert_dir, config=cfg, auto_rollback=False)
    d.deploy_all()
    assert not remote.ran("systemctl reload httpd")
    assert remote.exists(f"{SSL}/server.key")
    assert d.failed_count == 1


def test_restart_failure_is_reported_as_failure(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.script_results["systemctl reload httpd"] = (1, "", "Job for httpd failed")
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.failed_count == 1
    assert any("restart" in r.service for r in d.results)


def test_restarts_run_once_per_command_in_priority_order(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["servers"]["web"]["services"] = ["svc_a", "svc_b", "svc_c"]
    cfg["services"] = {
        "svc_a": {"type": "custom", "file_mappings": {"certificate": "/x/a.crt"}, "restart": "restart-a", "priority": 20},
        "svc_b": {"type": "custom", "file_mappings": {"certificate": "/x/b.crt"}, "restart": "restart-b", "priority": 10},
        "svc_c": {"type": "custom", "file_mappings": {"certificate": "/x/c.crt"}, "restart": "restart-a", "priority": 30},
    }
    remote = FakeRemote(tmp_path / "remote")
    remote.script_results.update({"restart-a": (0, "", ""), "restart-b": (0, "", "")})
    d, remote = build(tmp_path, cert_dir, config=cfg, remote=remote)
    d.deploy_all()
    restarts = [c for c in remote.commands if c.startswith("restart-")]
    assert restarts == ["restart-b", "restart-a"]


# ---------------------------------------------------------------------------
# JKS: password never on a command line
# ---------------------------------------------------------------------------

JKS_CONFIG = {
    "domain": DOMAIN,
    "backup_dir": BACKUPS,
    "keystore": {"password": "s3cretpass", "alias": "app"},
    "servers": {"web": {"host": "10.0.0.1", "services": ["tomcat"]}},
    "services": {"tomcat": {"type": "jks", "remote_path": "/app/ssl/app.jks"}},
}


def test_keystore_is_verified_with_password_on_stdin_not_argv(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir, config=JKS_CONFIG)
    d.deploy_all()
    assert d.failed_count == 0
    assert remote.read("/app/ssl/app.jks") == b"FAKE-JKS-BYTES"
    assert all("s3cretpass" not in c for c in remote.commands)
    assert "s3cretpass\n" in remote.stdin_sent


def test_keystore_that_does_not_open_is_reverted(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write("/app/ssl/app.jks", b"OLD-JKS", 0o600)
    remote.keytool_result = (1, "", "keytool error: Keystore was tampered with, or password was incorrect")
    d, remote = build(tmp_path, cert_dir, config=JKS_CONFIG, remote=remote)
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert "does not open" in d.results[0].message
    assert remote.read("/app/ssl/app.jks") == b"OLD-JKS"


def test_missing_keytool_on_server_only_warns(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.keytool_result = (127, "", "keytool: command not found")
    d, remote = build(tmp_path, cert_dir, config=JKS_CONFIG, remote=remote)
    d.deploy_all()
    assert d.failed_count == 0


# ---------------------------------------------------------------------------
# Injection / path safety
# ---------------------------------------------------------------------------

def custom_cfg(dest):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"] = {"crm": {"type": "custom", "file_mappings": {"certificate": dest}}}
    return cfg


def test_shell_metacharacters_in_remote_paths_are_inert(tmp_path, cert_dir):
    evil = f"{SSL}/my cert; touch pwned.crt"
    remote = FakeRemote(tmp_path / "remote")
    remote.write(evil, b"OLD")  # forces the backup (`cp`) path through quoting too
    d, remote = build(tmp_path, cert_dir, config=custom_cfg(evil), remote=remote)
    d.deploy_all()
    assert d.failed_count == 0, [r.message for r in d.results]
    assert remote.read(evil) == (cert_dir / f"main_{DOMAIN}.crt").read_bytes()
    assert not remote.exists(f"{SSL}/pwned.crt")
    assert remote.read(f"{BACKUPS}/web/{d.timestamp}{evil}") == b"OLD"


@pytest.mark.parametrize("dest", ["relative/path.crt", "~/server.crt", "/", "/tmp/a\nb.crt"])
def test_non_absolute_or_hostile_destinations_are_rejected(tmp_path, cert_dir, dest):
    d, remote = build(tmp_path, cert_dir, config=custom_cfg(dest))
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert remote.files() == []


def test_a_directory_destination_is_rejected_with_a_helpful_message(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir, config=custom_cfg(f"{SSL}/"))
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert "directory path" in d.results[0].message and "empty" in d.results[0].message
    assert remote.files() == []


def test_unowned_backup_directory_refuses_to_deploy(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote", owned=False)
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.results[0].status == DeploymentStatus.FAILED
    assert "backup directory" in d.results[0].message
    assert not remote.exists(f"{SSL}/server.key")


@posix_only
def test_key_material_is_never_deployed_group_or_world_readable(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"] = {"crm": {"type": "custom", "file_mappings": {"asterisk_pem": "/x/combined.pem"}}}
    d, remote = build(tmp_path, cert_dir, config=cfg)
    d.deploy_all()
    assert mode_of(remote, "/x/combined.pem") == 0o600


# ---------------------------------------------------------------------------
# Owner / symlink preservation
# ---------------------------------------------------------------------------

def test_owner_of_replaced_file_is_preserved(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.crt", b"OLD")
    remote.owners[str(remote.map(f"{SSL}/server.crt"))] = (0, 0)
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.failed_count == 0
    assert remote.owners[str(remote.map(f"{SSL}/server.crt"))] == (0, 0)


def test_falls_back_to_in_place_write_when_owner_cannot_be_kept(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.crt", b"OLD")
    remote.owners[str(remote.map(f"{SSL}/server.crt"))] = (0, 0)
    remote.chown_fails = True
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.failed_count == 0
    assert remote.read(f"{SSL}/server.crt") == (cert_dir / f"main_{DOMAIN}.crt").read_bytes()
    assert remote.owners[str(remote.map(f"{SSL}/server.crt"))] == (0, 0)
    assert leftovers(remote) == []


@posix_only
def test_symlinked_destination_stays_a_symlink(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write("/etc/app/live/real.crt", b"OLD")
    remote.map(SSL).mkdir(parents=True, exist_ok=True)
    os.symlink(remote.map("/etc/app/live/real.crt"), remote.map(f"{SSL}/server.crt"))
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert d.failed_count == 0
    assert remote.map(f"{SSL}/server.crt").is_symlink()
    assert remote.read("/etc/app/live/real.crt") == (cert_dir / f"main_{DOMAIN}.crt").read_bytes()


# ---------------------------------------------------------------------------
# Asterisk
# ---------------------------------------------------------------------------

ASTERISK_CONFIG = {
    "domain": DOMAIN,
    "backup_dir": BACKUPS,
    "servers": {"web": {"host": "10.0.0.1", "services": ["asterisk"]}},
    "services": {"asterisk": {"type": "asterisk", "cert_dir": "/etc/asterisk/keys/"}},
}


@posix_only
def test_asterisk_deploys_key_first_pem_with_private_mode(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir, config=ASTERISK_CONFIG)
    d.deploy_all()
    assert d.failed_count == 0, [r.message for r in d.results]
    assert mode_of(remote, "/etc/asterisk/keys/asterisk.pem") == 0o600
    assert b"PRIVATE KEY" in remote.read("/etc/asterisk/keys/asterisk.pem")


def test_asterisk_pem_without_leading_key_is_refused(tmp_path, cert_dir, leaf, pki):
    _key, cert = leaf
    (cert_dir / f"asterisk_{DOMAIN}.pem").write_bytes(cert_pem(cert) + cert_pem(pki.ca_cert))
    d, remote = build(tmp_path, cert_dir, config=ASTERISK_CONFIG)
    d.deploy_all()
    failed = [r for r in d.results if r.status == DeploymentStatus.FAILED]
    assert failed and "private key before" in failed[0].message


# ---------------------------------------------------------------------------
# Pre-deploy verification gate
# ---------------------------------------------------------------------------

def test_mismatched_key_aborts_before_any_remote_action(tmp_path, cert_dir, pki):
    other_key, _ = pki.leaf()
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(other_key))
    d, remote = build(tmp_path, cert_dir)
    d.deploy_all()
    assert d.aborted_reason and "verification" in d.aborted_reason.lower()
    assert d.failed_count == 1
    assert remote.commands == [] and remote.files() == []


def test_expired_certificate_aborts(tmp_path, cert_dir, pki):
    import datetime as dt

    key, cert = pki.leaf(not_before=now() - dt.timedelta(days=100), not_after=now() - dt.timedelta(days=1))
    (cert_dir / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key))
    d, remote = build(tmp_path, cert_dir)
    d.deploy_all()
    assert d.aborted_reason
    assert remote.files() == []


def test_skip_verify_allows_the_deploy(tmp_path, cert_dir, pki):
    other_key, _ = pki.leaf()
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(other_key))
    d, remote = build(tmp_path, cert_dir, skip_verify=True)
    d.deploy_all()
    assert d.aborted_reason is None
    assert remote.exists(f"{SSL}/server.key")


def test_no_cert_files_is_a_failure_not_a_silent_success(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    d, remote = build(tmp_path, empty)
    d.deploy_all()
    assert d.aborted_reason
    assert d.failed_count == 1


def test_file_holding_a_private_key_is_never_picked_as_a_public_cert(tmp_path, pki, leaf):
    key, _cert = leaf
    d = tmp_path / "only-key"
    d.mkdir()
    (d / "weird.crt").write_bytes(key_pem(key))
    (d / "weird.pem").write_bytes(key_pem(key))
    deployer, _ = build(tmp_path, d)
    found = deployer.validate_cert_files()
    assert "certificate" not in found and "fullchain" not in found and "chain" not in found


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def test_rollback_restores_newest_snapshot(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.key", b"OLD-KEY", 0o600)
    remote.write(f"{SSL}/server.crt", b"OLD-CERT")
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    assert remote.read(f"{SSL}/server.crt") != b"OLD-CERT"

    rb, _ = build(tmp_path, cert_dir, remote=remote)
    result = rb.rollback_server("web")
    assert result.status == DeploymentStatus.ROLLED_BACK, result.message
    assert remote.read(f"{SSL}/server.key") == b"OLD-KEY"
    assert remote.read(f"{SSL}/server.crt") == b"OLD-CERT"
    assert "restart the services" in result.message


def test_rollback_with_restart_runs_the_restart_command(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{SSL}/server.crt", b"OLD-CERT")
    d, remote = build(tmp_path, cert_dir, remote=remote)
    d.deploy_all()
    remote.commands.clear()
    rb, _ = build(tmp_path, cert_dir, remote=remote)
    result = rb.rollback_server("web", restart=True)
    assert result.status == DeploymentStatus.ROLLED_BACK
    assert remote.ran("systemctl reload httpd")


@pytest.mark.parametrize("bad", ["x; rm -rf /", "../../etc", "2026-01-01", "$(id)"])
def test_rollback_rejects_hostile_snapshot_names_without_running_anything(tmp_path, cert_dir, bad):
    d, remote = build(tmp_path, cert_dir)
    result = d.rollback_server("web", bad)
    assert result.status == DeploymentStatus.FAILED
    assert "invalid snapshot name" in result.message
    assert remote.commands == []


def test_rollback_with_no_snapshots_fails_cleanly(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir)
    result = d.rollback_server("web")
    assert result.status == DeploymentStatus.FAILED
    assert "no snapshot" in result.message


# ---------------------------------------------------------------------------
# Config handling
# ---------------------------------------------------------------------------

def test_env_references_resolve_and_missing_ones_fail(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "keystore:\n  password: ${env:KS_PASS}\nservers:\n  s:\n    host: h\n    password: ${env:SSH_PW}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KS_PASS", "from-env")
    monkeypatch.setenv("SSH_PW", "ssh-from-env")
    loaded = load_deploy_config(cfg)
    assert loaded["keystore"]["password"] == "from-env"
    assert loaded["servers"]["s"]["password"] == "ssh-from-env"
    monkeypatch.delenv("KS_PASS")
    with pytest.raises(ConfigError, match="KS_PASS"):
        load_deploy_config(cfg)


def test_ssh_defaults_block_is_applied_to_servers(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "ssh:\n  user: deploy\n  port: 2222\n  key: ~/.ssh/id_deploy\n"
        "servers:\n  a:\n    host: h1\n  b:\n    host: h2\n    user: root\n    port: 22\n",
        encoding="utf-8",
    )
    servers = load_deploy_config(cfg)["servers"]
    assert (servers["a"]["user"], servers["a"]["port"], servers["a"]["key_file"]) == ("deploy", 2222, "~/.ssh/id_deploy")
    assert (servers["b"]["user"], servers["b"]["port"]) == ("root", 22)


def test_configs_without_keystore_or_ssh_sections_load_unchanged(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("servers:\n  a:\n    host: h\nservices: {}\n", encoding="utf-8")
    loaded = load_deploy_config(cfg)
    assert "keystore" not in loaded and "ssh" not in loaded  # no phantom `None` sections


def test_passwords_are_masked_in_output(tmp_path, cert_dir):
    d, _ = build(tmp_path, cert_dir)
    assert d._mask("storepass s3cretpass done") == "storepass **** done"


def test_malformed_config_gives_a_clear_error(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("servers: [not, a, mapping]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="servers"):
        load_deploy_config(cfg)


# ---------------------------------------------------------------------------
# Live verification & preflight
# ---------------------------------------------------------------------------

def test_tls_verification_failure_is_reported(tmp_path, cert_dir, monkeypatch):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["verify_tls"] = {"port": 8443}
    monkeypatch.setattr(
        "ssl_deploy.deployer.wait_for_certificate", lambda *a, **k: (False, "still serves the old cert")
    )
    d, _ = build(tmp_path, cert_dir, config=cfg)
    d.deploy_all()
    assert any(r.service == "tls-verify" and r.status == DeploymentStatus.FAILED for r in d.results)


def test_tls_verification_success_adds_no_failure(tmp_path, cert_dir, monkeypatch):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["verify_tls"] = {"port": 8443}
    monkeypatch.setattr("ssl_deploy.deployer.wait_for_certificate", lambda *a, **k: (True, "ok"))
    d, _ = build(tmp_path, cert_dir, config=cfg)
    d.deploy_all()
    assert d.failed_count == 0


def test_preflight_reads_ameyoctl_status(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["restart"] = "ameyoctl service crm faststop && ameyoctl service crm start"
    remote = FakeRemote(tmp_path / "remote")
    remote.script_results["ameyoctl status"] = (0, "crm is RUNNING\nacp is NOT_RUNNING\n", "")
    d, remote = build(tmp_path, cert_dir, config=cfg, remote=remote)
    report = d.preflight_all()[0]
    assert report["rows"] == [{"service": "crm", "ameyoctl": "crm", "running": True}]


def test_slow_ameyoctl_status_is_a_warning_not_a_blocking_error(tmp_path, cert_dir):
    cfg = copy.deepcopy(BASE_CONFIG)
    cfg["services"]["crm"]["restart"] = "ameyoctl service crm faststop && ameyoctl service crm start"
    remote = FakeRemote(tmp_path / "remote")
    remote.timeout_on = ["ameyoctl status"]
    d, remote = build(tmp_path, cert_dir, config=cfg, remote=remote)
    report = d.preflight_all()[0]
    assert "error" not in report
    assert "no answer" in report["warning"]
    assert report["rows"] == [{"service": "crm", "ameyoctl": "crm", "running": None}]  # unknown, not "stopped"


def test_a_real_connection_failure_is_still_a_preflight_error(tmp_path, cert_dir):
    d, remote = build(tmp_path, cert_dir)
    d.ssh_connections.clear()
    d._failed_hosts["web"] = "Authentication failed."
    report = d.preflight_server("web")
    assert "SSH connection failed" in report["error"]

