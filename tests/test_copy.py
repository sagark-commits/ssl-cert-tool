# Author: Sagar K | 2026 | MIT licence
"""`copy`: scp-style push with verification, backup, atomic write and revert."""
from __future__ import annotations

import copy
import datetime as dt
import os

import pytest

from conftest import DOMAIN, cert_pem, key_pem, now, posix_only
from fake_remote import FakeRemote
from ssl_cert_tool.platform import Terminal
from ssl_deploy.deployer import CopyItem, DeploymentStatus, SSLDeployer
from ssl_deploy.verify import LEVEL_ERROR, LEVEL_WARN, verify_copy_sources

BASE = {"servers": {"web": {"host": "10.0.0.1", "user": "deploy"}}, "services": {}}
DEST = "/srv/ssl"


def make(tmp_path, remote=None, **kwargs):
    term = Terminal()
    term.disable()
    deployer = SSLDeployer("<ad-hoc>", terminal=term, config=copy.deepcopy(BASE), **kwargs)
    assert deployer.load_config()
    remote = remote or FakeRemote(tmp_path / "remote")
    deployer.ssh_connections["web"] = remote
    return deployer, remote


def items(cert_dir, **modes):
    return [
        CopyItem(cert_dir / f"main_{DOMAIN}.crt", f"{DEST}/site.crt", modes.get("crt")),
        CopyItem(cert_dir / f"{DOMAIN}.key", f"{DEST}/site.key", modes.get("key")),
    ]


def mode_of(remote, path):
    return os.stat(remote.map(path)).st_mode & 0o777


def test_copies_files_verified_and_leaves_no_temp_files(tmp_path, cert_dir):
    d, remote = make(tmp_path)
    d.copy_files("web", items(cert_dir))
    assert d.failed_count == 0, [r.message for r in d.results]
    assert remote.read(f"{DEST}/site.crt") == (cert_dir / f"main_{DOMAIN}.crt").read_bytes()
    assert remote.read(f"{DEST}/site.key") == (cert_dir / f"{DOMAIN}.key").read_bytes()
    assert [f for f in remote.files() if ".ssl-auto-" in f] == []
    assert [r.service for r in d.results] == [f"{DEST}/site.crt", f"{DEST}/site.key"]


@posix_only
def test_default_modes_are_644_for_certs_and_600_for_keys(tmp_path, cert_dir):
    d, remote = make(tmp_path)
    d.copy_files("web", items(cert_dir))
    assert mode_of(remote, f"{DEST}/site.crt") == 0o644
    assert mode_of(remote, f"{DEST}/site.key") == 0o600


@posix_only
def test_explicit_modes_are_honoured_but_keys_are_never_world_accessible(tmp_path, cert_dir):
    d, remote = make(tmp_path)
    d.copy_files("web", items(cert_dir, crt=0o640, key=0o640))
    assert mode_of(remote, f"{DEST}/site.crt") == 0o640
    assert mode_of(remote, f"{DEST}/site.key") == 0o640  # group access was asked for explicitly

    d, remote = make(tmp_path / "second")
    d.copy_files("web", items(cert_dir, key=0o644))
    assert mode_of(remote, f"{DEST}/site.key") == 0o600  # world-readable key request is overridden


def test_replaced_files_are_backed_up_into_a_per_user_folder(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{DEST}/site.crt", b"OLD-CERT")
    d, remote = make(tmp_path, remote=remote)
    d.copy_files("web", items(cert_dir))
    backup = f"/tmp/ssl-auto-backups-deploy/web/{d.timestamp}{DEST}/site.crt"
    assert remote.read(backup) == b"OLD-CERT"  # ...in a folder named for the SSH user


def test_a_failing_check_command_restores_everything(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{DEST}/site.crt", b"OLD-CERT")
    remote.write(f"{DEST}/site.key", b"OLD-KEY", 0o600)
    remote.script_results["nginx -t"] = (1, "", "nginx: [emerg] bad certificate")
    d, remote = make(tmp_path, remote=remote)
    d.copy_files("web", items(cert_dir), check_cmd="nginx -t", reload_cmd="systemctl reload nginx")
    assert d.failed_count == 1 and "check command failed" in d.results[-1].message
    assert "files restored" in d.results[-1].message
    assert remote.read(f"{DEST}/site.crt") == b"OLD-CERT" and remote.read(f"{DEST}/site.key") == b"OLD-KEY"
    assert not remote.ran("systemctl reload nginx")  # the reload never ran


def test_reload_runs_after_a_good_check_and_its_failure_is_reported_not_undone(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.script_results["nginx -t"] = (0, "", "")
    remote.script_results["systemctl reload nginx"] = (1, "", "Job for nginx.service failed")
    d, remote = make(tmp_path, remote=remote)
    d.copy_files("web", items(cert_dir), check_cmd="nginx -t", reload_cmd="systemctl reload nginx")
    assert d.failed_count == 1 and "reload command failed" in d.results[-1].message
    assert remote.exists(f"{DEST}/site.crt")  # copied files stay: the operator decides what to do


def test_a_failure_midway_restores_the_files_already_copied(tmp_path, cert_dir):
    remote = FakeRemote(tmp_path / "remote")
    remote.write(f"{DEST}/site.crt", b"OLD-CERT")
    remote.fail_write_substr = "site.key"
    d, remote = make(tmp_path, remote=remote)
    d.copy_files("web", items(cert_dir))
    assert d.failed_count == 1
    assert remote.read(f"{DEST}/site.crt") == b"OLD-CERT"
    assert not remote.exists(f"{DEST}/site.key")


# ---- pre-copy verification: nothing touches the server if the files are wrong -------------

def test_a_key_that_does_not_match_the_certificate_aborts_before_connecting(tmp_path, cert_dir, pki):
    other, _ = pki.leaf()
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(other))
    d, remote = make(tmp_path)
    d.copy_files("web", items(cert_dir))
    assert d.aborted_reason and "verification" in d.aborted_reason.lower()
    assert remote.commands == [] and remote.files() == []


def test_skip_verify_lets_a_mismatched_pair_through(tmp_path, cert_dir, pki):
    other, _ = pki.leaf()
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(other))
    d, remote = make(tmp_path, skip_verify=True)
    d.copy_files("web", items(cert_dir))
    assert d.aborted_reason is None and remote.exists(f"{DEST}/site.key")


def test_an_expired_certificate_aborts(tmp_path, cert_dir, pki):
    key, cert = pki.leaf(not_before=now() - dt.timedelta(days=90), not_after=now() - dt.timedelta(days=1))
    (cert_dir / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key))
    d, remote = make(tmp_path)
    d.copy_files("web", items(cert_dir))
    assert d.aborted_reason and remote.files() == []


def test_plain_files_are_copied_without_certificate_checks(tmp_path):
    plain = tmp_path / "notes.txt"
    plain.write_text("hello")
    d, remote = make(tmp_path)
    d.copy_files("web", [CopyItem(plain, f"{DEST}/notes.txt")])
    assert d.failed_count == 0 and remote.read(f"{DEST}/notes.txt") == b"hello"


@pytest.mark.parametrize("dest", ["relative.crt", "~/x.crt", f"{DEST}/", "/"])
def test_bad_destinations_are_rejected_before_connecting(tmp_path, cert_dir, dest):
    d, remote = make(tmp_path)
    d.copy_files("web", [CopyItem(cert_dir / f"main_{DOMAIN}.crt", dest)])
    assert d.aborted_reason and remote.commands == []


def test_a_missing_source_is_reported(tmp_path):
    d, remote = make(tmp_path)
    d.copy_files("web", [CopyItem(tmp_path / "nope.crt", f"{DEST}/x.crt")])
    assert d.aborted_reason and "not found" in d.aborted_reason and remote.commands == []


def test_dry_run_changes_nothing_and_does_not_connect(tmp_path, cert_dir):
    d, remote = make(tmp_path, dry_run=True)
    d.copy_files("web", items(cert_dir))
    assert d.failed_count == 0 and remote.commands == [] and remote.files() == []


def test_a_connection_failure_is_a_clear_failure(tmp_path, cert_dir):
    d, _ = make(tmp_path)
    d.ssh_connections.clear()
    d._failed_hosts["web"] = "Authentication failed."
    d.copy_files("web", items(cert_dir))
    assert d.aborted_reason and "Authentication failed" in d.aborted_reason


# ---- verify_copy_sources on its own ------------------------------------------------------

def test_verify_copy_sources_findings(tmp_path, cert_dir, pki):
    assert not [f for f in verify_copy_sources(list(i.src for i in items(cert_dir))) if f.level in (LEVEL_ERROR, LEVEL_WARN)]
    soon_key, soon = pki.leaf(not_after=now() + dt.timedelta(days=3))
    path = tmp_path / "soon.crt"
    path.write_bytes(cert_pem(soon))
    assert any("expires in" in f.message for f in verify_copy_sources([path]))
    enc = tmp_path / "enc.key"
    enc.write_bytes(key_pem(soon_key, b"pw123456"))
    assert any(f.level == LEVEL_ERROR for f in verify_copy_sources([enc]))
    assert not any(f.level == LEVEL_ERROR for f in verify_copy_sources([enc, path], key_password="pw123456"))
