"""End-to-end CLI behaviour: secrets handling, exit codes, archive input."""
from __future__ import annotations

import argparse
import importlib.util
import stat
import zipfile
from pathlib import Path

import pytest
import yaml

from conftest import DOMAIN, ROOT, cert_pem, key_pem, posix_only


@pytest.fixture(scope="module")
def cli():
    spec = importlib.util.spec_from_file_location("ssl_auto_cli", ROOT / "ssl-auto.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def isolated_config(tmp_path):
    """A config so tests never pick up the project's own deploy-config.yaml."""
    path = tmp_path / "isolated.yaml"
    path.write_text(yaml.safe_dump({"domain": ""}), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Secrets: env / file, never required on argv
# ---------------------------------------------------------------------------

def test_read_secret_from_env_and_file(cli, tmp_path, monkeypatch):
    monkeypatch.setenv("MY_PW", "from-env")
    assert cli.read_secret("MY_PW", None) == "from-env"
    f = tmp_path / "pw.txt"
    f.write_text("from-file\r\n", encoding="utf-8")
    assert cli.read_secret(None, f) == "from-file"  # trailing newline stripped
    assert cli.read_secret(None, None) is None


def test_read_secret_errors_are_clear(cli, tmp_path, monkeypatch):
    monkeypatch.delenv("NOPE_PW", raising=False)
    with pytest.raises(SystemExit, match="NOPE_PW"):
        cli.read_secret("NOPE_PW", None)
    empty = tmp_path / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="empty"):
        cli.read_secret(None, empty)
    with pytest.raises(SystemExit, match="cannot read"):
        cli.read_secret(None, tmp_path / "missing.txt")


def test_password_precedence_flag_then_env_then_file(cli, tmp_path, monkeypatch):
    monkeypatch.setenv("MY_PW", "env-pw")
    f = tmp_path / "pw.txt"
    f.write_text("file-pw")
    ns = lambda **kw: argparse.Namespace(**{"store_pass": None, "password_env": None, "password_file": None, **kw})
    assert cli.explicit_password(ns(store_pass="flag-pw", password_env="MY_PW")) == "flag-pw"
    assert cli.explicit_password(ns(password_env="MY_PW", password_file=f)) == "env-pw"
    assert cli.explicit_password(ns(password_file=f)) == "file-pw"
    assert cli.explicit_password(ns()) is None


def test_ask_ssh_password_builds_a_per_host_prompt_and_exports_nothing(cli, monkeypatch):
    import getpass
    import os as _os
    import sys as _sys

    monkeypatch.delenv("SSH_PASSWORD", raising=False)
    monkeypatch.setattr(_sys.stdin, "isatty", lambda: True, raising=False)
    asked = []
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": asked.append(prompt) or "typed-pw")
    args = argparse.Namespace(ask_ssh_password=True, accept_new_hostkeys=False, known_hosts=None, ssh_config=None)
    kwargs = cli.deployer_trust_kwargs(args)
    assert kwargs["host_key_policy"] is None and callable(kwargs["password_prompt"])
    assert asked == []  # nothing is asked up front: only after a host refuses keys/agent
    assert kwargs["password_prompt"]({"user": "deploy", "host": "10.1.1.1", "port": 142}) == "typed-pw"
    assert "deploy@10.1.1.1:142" in asked[0]  # the prompt says which host it is for
    assert "SSH_PASSWORD" not in _os.environ  # never leaked into the environment


def test_ask_ssh_password_refuses_without_a_terminal(cli, monkeypatch):
    import sys as _sys

    monkeypatch.setattr(_sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit, match="interactive terminal"):
        cli.deployer_trust_kwargs(argparse.Namespace(ask_ssh_password=True))


def test_flag_is_off_by_default_and_never_prompts(cli):
    assert cli.deployer_trust_kwargs(argparse.Namespace())["password_prompt"] is None


def test_key_password_comes_from_flag_or_environment(cli, monkeypatch):
    monkeypatch.delenv("SSL_KEY_PASSWORD", raising=False)
    assert cli.get_key_password(argparse.Namespace(key_password=None)) is None
    assert cli.get_key_password(argparse.Namespace(key_password="x")) == "x"
    monkeypatch.setenv("SSL_KEY_PASSWORD", "from-env")
    assert cli.get_key_password(argparse.Namespace()) == "from-env"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def test_inspect_reports_matching_key(cli, cert_dir, capsys):
    assert cli.main(["inspect", "--input", str(cert_dir), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "LEAF" in out and "matches leaf" in out


def test_generate_from_a_zip_containing_cert_and_key(cli, tmp_path, leaf, pki, isolated_config, monkeypatch, capsys):
    """Regression: certificates inside archives used to be silently dropped."""
    key, cert = leaf
    archive = tmp_path / "customer.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("server.crt", cert_pem(cert))
        zf.writestr("ca.crt", cert_pem(pki.ca_cert))
        zf.writestr("server.key", key_pem(key))
    out = tmp_path / "out"
    monkeypatch.setenv("KS_PW", "longenough1")
    rc = cli.main([
        "generate", "--input", str(archive), "--output", str(out),
        "--password-env", "KS_PW", "--config", str(isolated_config), "--no-color",
    ])
    assert rc == 0, capsys.readouterr().out
    assert (out / f"main_{DOMAIN}.crt").is_file() and (out / f"{DOMAIN}.key").is_file()


@posix_only
def test_generated_key_file_is_private(cli, cert_dir, tmp_path, isolated_config, monkeypatch):
    out = tmp_path / "out"
    monkeypatch.setenv("KS_PW", "longenough1")
    assert cli.main([
        "generate", "--input", str(cert_dir), "--output", str(out),
        "--password-env", "KS_PW", "--config", str(isolated_config), "--no-color",
    ]) == 0
    assert stat.S_IMODE((out / f"{DOMAIN}.key").stat().st_mode) == 0o600


def test_jks_is_built_and_validated_without_a_jdk(cli, cert_dir, tmp_path, isolated_config, monkeypatch, capsys):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")  # behave as if keytool is not installed
    monkeypatch.setenv("KS_PW", "longenough1")
    out = tmp_path / "out"
    rc = cli.main([
        "generate", "--input", str(cert_dir), "--output", str(out),
        "--password-env", "KS_PW", "--config", str(isolated_config), "--no-color",
    ])
    text = capsys.readouterr().out
    assert rc == 0, text
    assert "built-in JKS writer" in text
    assert "JKS password: PASS" in text
    assert "longenough1" not in text and "lo*" not in text  # no password characters echoed
    jks_path = out / f"{DOMAIN}.jks"
    assert cli.validate_jks_password(jks_path, "longenough1", "server-cert", None) is True
    assert cli.validate_jks_password(jks_path, "wrong-pass", "server-cert", None) is False
    assert cli.validate_jks_password(jks_path, "longenough1", "no-such-alias", None) is False


def test_picks_the_key_that_matches_when_several_are_supplied(cli, cert_dir, pki, tmp_path, isolated_config, monkeypatch):
    wrong, _ = pki.leaf()
    (cert_dir / "a-old.key").write_bytes(key_pem(wrong))  # sorts before the right key
    out = tmp_path / "out"
    monkeypatch.setenv("KS_PW", "longenough1")
    assert cli.main([
        "generate", "--input", str(cert_dir), "--output", str(out),
        "--password-env", "KS_PW", "--config", str(isolated_config), "--no-color",
    ]) == 0


def test_generate_with_encrypted_key_and_passphrase(cli, cert_dir, leaf, tmp_path, isolated_config, monkeypatch):
    key, _ = leaf
    for f in cert_dir.glob("*.key"):
        f.unlink()
    enc = tmp_path / "enc.key"
    enc.write_bytes(key_pem(key, b"pass-phrase-1"))
    out = tmp_path / "out"
    monkeypatch.setenv("KS_PW", "longenough1")
    assert cli.main([
        "generate", "--input", str(cert_dir), "--key", str(enc), "--key-password", "pass-phrase-1",
        "--output", str(out), "--password-env", "KS_PW", "--config", str(isolated_config), "--no-color",
    ]) == 0


def test_wrong_key_passphrase_exits_cleanly(cli, cert_dir, leaf, tmp_path, isolated_config, capsys):
    key, _ = leaf
    enc = tmp_path / "enc.key"
    enc.write_bytes(key_pem(key, b"pass-phrase-1"))
    with pytest.raises(SystemExit) as exc:
        cli.main([
            "generate", "--input", str(cert_dir), "--key", str(enc), "--key-password", "nope",
            "--output", str(tmp_path / "o"), "--config", str(isolated_config), "--no-color",
        ])
    assert exc.value.code == 1
    assert "incorrect" in capsys.readouterr().out


def test_deploy_exits_nonzero_when_there_is_nothing_to_deploy(cli, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    cfg = tmp_path / "deploy.yaml"
    cfg.write_text(yaml.safe_dump({
        "domain": DOMAIN,
        "servers": {"web": {"host": "10.0.0.1", "services": ["crm"]}},
        "services": {"crm": {"type": "custom", "file_mappings": {"certificate": "/x/a.crt"}}},
    }), encoding="utf-8")
    rc = cli.main(["deploy", "--certs", str(empty), "--config", str(cfg), "--skip-preflight", "--no-color"])
    assert rc == 1  # used to print "Deployment Complete" and exit 0


def test_validate_flags_relative_paths_and_plaintext_secrets(cli, tmp_path, capsys):
    cfg = tmp_path / "v.yaml"
    cfg.write_text(yaml.safe_dump({
        "keystore": {"password": "changeit"},
        "ssh": {"host_key_policy": "yolo"},
        "servers": {"web": {"host": "h", "password": "hunter2", "services": ["svc"]}},
        "services": {"svc": {"type": "jks", "remote_path": "relative/app.jks"}},
    }), encoding="utf-8")
    rc = cli.main(["validate", "--config", str(cfg), "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "absolute path" in out
    assert "host_key_policy" in out
    assert "SSH password" in out and "changeit" in out
    assert "hunter2" not in out  # never echo the secret itself


def test_plan_masks_passwords_embedded_in_hooks_and_restarts(cli, tmp_path, capsys):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(yaml.safe_dump({
        "domain": DOMAIN,
        "keystore": {"password": "supersecret1"},
        "servers": {"web": {"host": "h", "services": ["svc"]}},
        "services": {"svc": {
            "type": "custom", "file_mappings": {"certificate": "/x/a.crt"},
            "hooks": ["keytool -storepass supersecret1 -list"],
            "restart": "restart-it --pw supersecret1",
        }},
    }), encoding="utf-8")
    assert cli.main(["plan", "--config", str(cfg), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "supersecret1" not in out
    assert out.count("****") >= 2


def test_validate_flags_destinations_that_are_directories(cli, tmp_path, capsys):
    cfg = tmp_path / "d.yaml"
    cfg.write_text(yaml.safe_dump({
        "servers": {"web": {"host": "h", "services": ["a", "b"]}},
        "services": {
            "a": {"type": "jks", "remote_path": "/dacx/ssl/"},
            "b": {"type": "custom", "file_mappings": {"chain": ["/dacx/ssl/ok.crt", "/dacx/ssl/"]}},
        },
    }), encoding="utf-8")
    assert cli.main(["validate", "--config", str(cfg), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "ends with '/'" in out and "is a directory" in out


def test_init_rejects_a_domain_that_could_inject_yaml(cli, tmp_path):
    target = tmp_path / "cfg.yaml"
    rc = cli.main(["init", "-o", str(target), "-d", 'evil"\nservers: {}'])
    assert rc == 1 and not target.exists()
    assert cli.main(["init", "-o", str(target), "-d", "ok.example.com"]) == 0
    assert 'domain: "ok.example.com"' in target.read_text(encoding="utf-8")


def test_unexpected_errors_become_one_line_and_exit_1(cli, monkeypatch, cert_dir, capsys):
    def boom(args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "cmd_inspect", boom)
    monkeypatch.delenv("SSL_AUTO_DEBUG", raising=False)
    assert cli.main(["inspect", "--input", str(cert_dir)]) == 1
    err = capsys.readouterr().err
    assert "kaboom" in err and "Traceback" not in err


def test_keyboard_interrupt_exits_130(cli, monkeypatch, cert_dir):
    def interrupted(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_inspect", interrupted)
    assert cli.main(["inspect", "--input", str(cert_dir)]) == 130


# ---------------------------------------------------------------------------
# copy (scp-like), including ssh-config aliases and jump hosts
# ---------------------------------------------------------------------------

def test_copy_file_specs_parse_windows_paths_and_modes(cli):
    item = cli.parse_copy_file(r"C:\certs\site.crt:/etc/nginx/ssl/site.crt:640")
    assert str(item.src).endswith("site.crt") and item.dest == "/etc/nginx/ssl/site.crt" and item.mode == 0o640
    item = cli.parse_copy_file("C:/certs/site.crt:/srv/x.crt")
    assert item.dest == "/srv/x.crt" and item.mode is None
    item = cli.parse_copy_file("rel/site.key:/srv/site.key:600")
    assert item.mode == 0o600
    for bad in ("nodest.crt", "a.crt:relative/path", "a.crt:/x:999"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_copy_file(bad)


@pytest.fixture
def fake_server(monkeypatch, tmp_path):
    from fake_remote import FakeRemote

    remote = FakeRemote(tmp_path / "remote")
    monkeypatch.setattr(cli_deployer_class(), "connect_server", lambda self, name, force=False: remote)
    return remote


def cli_deployer_class():
    from ssl_deploy.deployer import SSLDeployer

    return SSLDeployer


def test_copy_to_an_ad_hoc_host_end_to_end(cli, cert_dir, fake_server, capsys):
    rc = cli.main([
        "copy", "--host", "deploy@10.0.0.5:2222",
        "--file", f"{cert_dir / f'main_{DOMAIN}.crt'}:/srv/ssl/site.crt",
        "--file", f"{cert_dir / f'{DOMAIN}.key'}:/srv/ssl/site.key:600",
        "--no-color",
    ])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Copy Complete" in out and fake_server.exists("/srv/ssl/site.crt")
    assert any("ssl-auto-backups-deploy" in c for c in fake_server.commands)  # per-user backup folder


def test_copy_follows_an_ssh_config_alias_and_its_proxyjump(cli, cert_dir, fake_server, tmp_path, capsys):
    ssh_config = tmp_path / "ssh_config"
    ssh_config.write_text(
        "Host bastion\n  HostName 203.0.113.9\n  Port 40222\n  User jumpuser\n"
        "Host app-1\n  HostName 10.128.0.7\n  Port 142\n  User deploy\n  ProxyJump bastion\n",
        encoding="utf-8",
    )
    rc = cli.main([
        "copy", "--host", "app-1", "--ssh-config", str(ssh_config), "--check-cmd", "true",
        "--file", f"{cert_dir / f'main_{DOMAIN}.crt'}:/home/deploy/site.crt", "--no-color",
    ])
    assert rc == 0, capsys.readouterr().out
    assert any("ssl-auto-backups-deploy" in c for c in fake_server.commands)  # user came from the alias


def test_copy_with_a_check_that_fails_exits_nonzero_and_restores(cli, cert_dir, fake_server, capsys):
    fake_server.write("/srv/ssl/site.crt", b"OLD")
    fake_server.script_results["nginx -t"] = (1, "", "bad")
    rc = cli.main([
        "copy", "--host", "deploy@10.0.0.5", "--check-cmd", "nginx -t",
        "--file", f"{cert_dir / f'main_{DOMAIN}.crt'}:/srv/ssl/site.crt", "--no-color",
    ])
    assert rc == 1 and "Copy failed" in capsys.readouterr().out
    assert fake_server.read("/srv/ssl/site.crt") == b"OLD"


def test_copy_dry_run_says_would_copy_and_touches_nothing(cli, cert_dir, fake_server, capsys):
    rc = cli.main([
        "copy", "--host", "deploy@10.0.0.5", "--dry-run",
        "--file", f"{cert_dir / f'main_{DOMAIN}.crt'}:/srv/ssl/site.crt", "--no-color",
    ])
    out = capsys.readouterr().out
    assert rc == 0 and "would copy" in out and "dry run" in out
    assert fake_server.files() == [] and fake_server.commands == []


def test_copy_argument_errors_are_clear(cli, cert_dir, capsys):
    spec = f"{cert_dir / f'main_{DOMAIN}.crt'}:/srv/x.crt"
    assert cli.main(["copy", "--file", spec, "--no-color"]) == 1  # neither --server nor --host
    assert cli.main(["copy", "--host", "h", "--server", "s", "--file", spec, "--no-color"]) == 1  # both
    assert cli.main(["copy", "--server", "s", "--user", "u", "--file", spec, "--no-color"]) == 1
    assert "exactly one" in capsys.readouterr().out
