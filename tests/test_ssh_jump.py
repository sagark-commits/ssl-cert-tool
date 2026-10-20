# Author: Sagar K | 2026 | MIT licence
"""Jump hosts: real tunnelling through in-process SSH servers, and ssh-config resolution."""
from __future__ import annotations

import textwrap

import paramiko
import pytest

from ssh_servers import SSHServer
from ssl_cert_tool.platform import Terminal
from ssl_deploy.deployer import SSLDeployer
from ssl_deploy.ssh import (
    HostKeyVerificationError,
    RemoteHost,
    connect_chain,
    describe_route,
    fingerprint_sha256,
    hop_from_ssh_config,
    load_ssh_config,
    parse_hop_spec,
    resolve_hops,
)


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    """Never read the developer's real ~/.ssh/known_hosts."""
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)
    for name in list(__import__("os").environ):
        if name.startswith("SSH_PASSWORD"):
            monkeypatch.delenv(name)


@pytest.fixture
def pair():
    jump = SSHServer(users={"jumper": "jump-pw"})
    target = SSHServer(users={"tester": "target-pw"})
    target.exec_handler = lambda chan, cmd: (chan.send(b"target-reached"), chan.send_exit_status(0), chan.close())
    yield jump, target
    jump.close()
    target.close()


def hops_for(jump, target):
    jump_hop = {"name": "jump", "host": "127.0.0.1", "port": jump.port, "user": "jumper"}
    target_hop = {"name": "app", "host": "127.0.0.1", "port": target.port, "user": "tester"}
    return [jump_hop], target_hop


def chain(pair, tmp_path, **kwargs):
    jump, target = pair
    hops, target_hop = hops_for(jump, target)
    kwargs.setdefault("policy", "accept-new")
    return connect_chain(hops, target_hop, known_hosts_path=tmp_path / "kh", timeout=15, **kwargs)


# ---------------------------------------------------------------------------
# Real tunnelling
# ---------------------------------------------------------------------------

def test_commands_reach_the_target_through_the_jump_host(pair, tmp_path):
    jump, target = pair
    client = chain(pair, tmp_path, target_password="target-pw", password_for=lambda hop: "jump-pw")
    host = RemoteHost(client)
    try:
        code, out, _ = host.run("anything", timeout=15)
    finally:
        host.close()
    assert (code, out) == (0, "target-reached")  # the answer came from the *target*
    assert jump.forwarded == [("127.0.0.1", target.port)]  # ...and travelled through the jump host


def test_the_targets_password_is_never_offered_to_the_jump_host(pair, tmp_path):
    jump, _ = pair
    chain(pair, tmp_path, target_password="target-pw", password_for=lambda hop: "jump-pw").close()
    tried_on_jump = [password for _user, password in jump.attempts]
    assert "jump-pw" in tried_on_jump and "target-pw" not in tried_on_jump


def test_each_hop_gets_its_own_password_from_the_environment(pair, tmp_path, monkeypatch):
    monkeypatch.setenv("SSH_PASSWORD_JUMP", "jump-pw")
    chain(pair, tmp_path, target_password="target-pw").close()  # no prompt callback needed


def test_the_prompt_is_only_used_after_keys_and_agent_are_refused(pair, tmp_path):
    asked = []

    def prompt(hop):
        asked.append(hop["name"])
        return {"jump": "jump-pw", "app": "target-pw"}[hop["name"]]

    chain(pair, tmp_path, password_for=prompt).close()
    assert asked == ["jump", "app"]  # one prompt per host, in route order


def test_a_wrong_jump_password_fails_cleanly(pair, tmp_path):
    with pytest.raises(paramiko.AuthenticationException):
        chain(pair, tmp_path, target_password="target-pw", password_for=lambda hop: "nope")


def test_a_wrong_target_password_fails_after_the_jump(pair, tmp_path):
    with pytest.raises(paramiko.AuthenticationException):
        chain(pair, tmp_path, target_password="wrong", password_for=lambda hop: "jump-pw")


def test_a_jump_host_that_forbids_forwarding_blocks_the_route(tmp_path):
    jump = SSHServer(users={"jumper": "jump-pw"}, allow_forwarding=False)
    target = SSHServer(users={"tester": "target-pw"})
    try:
        with pytest.raises(Exception):
            chain((jump, target), tmp_path, target_password="target-pw", password_for=lambda hop: "jump-pw")
    finally:
        jump.close()
        target.close()


# ---------------------------------------------------------------------------
# Host keys are verified on every hop
# ---------------------------------------------------------------------------

def test_an_untrusted_jump_host_is_refused_before_anything_else(pair, tmp_path):
    jump, _ = pair
    with pytest.raises(HostKeyVerificationError) as exc:
        chain(pair, tmp_path, policy="strict", target_password="target-pw", password_for=lambda hop: "jump-pw")
    assert fingerprint_sha256(jump.host_key) in str(exc.value)
    assert jump.attempts == []  # no password was sent to an unverified host


def test_accept_new_trusts_all_hops_and_a_changed_target_key_is_refused(pair, tmp_path):
    jump, target = pair
    kwargs = dict(target_password="target-pw", password_for=lambda hop: "jump-pw")
    chain(pair, tmp_path, **kwargs).close()
    known = (tmp_path / "kh").read_text()
    assert f"[127.0.0.1]:{jump.port}" in known and f"[127.0.0.1]:{target.port}" in known
    chain(pair, tmp_path, policy="strict", **kwargs).close()  # both trusted now

    target.rotate_key()
    with pytest.raises(paramiko.BadHostKeyException):
        chain(pair, tmp_path, policy="strict", **kwargs)


def test_a_target_pin_is_checked_even_behind_a_jump_host(pair, tmp_path):
    jump, target = pair
    jump_hop, target_hop = hops_for(jump, target)
    target_hop["host_key_sha256"] = "SHA256:" + "A" * 43
    with pytest.raises(HostKeyVerificationError, match="mismatch"):
        connect_chain(jump_hop, target_hop, policy="accept-new", known_hosts_path=tmp_path / "kh",
                      target_password="target-pw", password_for=lambda hop: "jump-pw", timeout=15)


# ---------------------------------------------------------------------------
# The deployer end to end
# ---------------------------------------------------------------------------

def test_deployer_connects_through_proxy_jump_from_the_config(pair, tmp_path):
    jump, target = pair
    cfg = {
        "servers": {
            "jump": {"host": "127.0.0.1", "port": jump.port, "user": "jumper", "password": "jump-pw"},
            "app": {"host": "127.0.0.1", "port": target.port, "user": "tester", "password": "target-pw",
                    "proxy_jump": "jump"},
        },
        "services": {},
    }
    term = Terminal()
    term.disable()
    deployer = SSLDeployer("<ad-hoc>", terminal=term, host_key_policy="accept-new",
                           known_hosts_path=tmp_path / "kh", config=cfg)
    assert deployer.load_config()
    remote = deployer.connect_server("app")
    assert remote is not None
    try:
        assert remote.run("x", timeout=15)[1] == "target-reached"
    finally:
        deployer.close_connections()
    assert jump.forwarded  # the route really went through the jump host


def test_deployer_reports_which_hop_failed(pair, tmp_path, capsys):
    jump, target = pair
    cfg = {
        "servers": {
            "jump": {"host": "127.0.0.1", "port": jump.port, "user": "jumper", "password": "WRONG"},
            "app": {"host": "127.0.0.1", "port": target.port, "user": "tester", "password": "target-pw",
                    "proxy_jump": "jump"},
        },
        "services": {},
    }
    deployer = SSLDeployer("<ad-hoc>", terminal=Terminal(), host_key_policy="accept-new",
                           known_hosts_path=tmp_path / "kh", config=cfg)
    deployer.load_config()
    assert deployer.connect_server("app") is None
    out = capsys.readouterr().out
    assert "route:" in out and f"jumper@127.0.0.1:{jump.port}" in out  # the route is shown in the error


# ---------------------------------------------------------------------------
# ~/.ssh/config resolution (pure, no network)
# ---------------------------------------------------------------------------

SSH_CONFIG = textwrap.dedent(
    """
    Host jump-host
      HostName control.example.com
      Port 40222
      User jumpuser

    Host edge-nginx
      HostName 203.0.113.9
      Port 142
      User deploy
      ProxyJump jump-host

    Host app-1
      HostName 10.128.0.7
      Port 142
      User deploy
      ProxyJump edge-nginx

    Host loopy-a
      HostName a.example
      ProxyJump loopy-b
    Host loopy-b
      HostName b.example
      ProxyJump loopy-a

    Host viacmd
      HostName c.example
      ProxyCommand ssh -W %h:%p somewhere

    Host lab-*
      User labuser
    """
)


@pytest.fixture
def ssh_cfg(tmp_path):
    path = tmp_path / "ssh_config"
    path.write_text(SSH_CONFIG, encoding="utf-8")
    return load_ssh_config(path)


def test_an_alias_chain_resolves_in_connect_order(ssh_cfg):
    servers = {"app": {"ssh_alias": "app-1"}}
    target, hops = resolve_hops("app", servers["app"], servers, ssh_cfg, {})
    assert [h["name"] for h in hops] == ["jump-host", "edge-nginx"]
    assert describe_route(hops, target) == (
        "jumpuser@control.example.com:40222 -> deploy@203.0.113.9:142 -> deploy@10.128.0.7:142"
    )


def test_explicit_settings_beat_the_alias_and_alias_beats_defaults(ssh_cfg):
    servers = {"app": {"ssh_alias": "app-1", "user": "root", "port": 2200}}
    target, _ = resolve_hops("app", servers["app"], servers, ssh_cfg, {"user": "dflt", "port": 22})
    assert (target["user"], target["port"]) == ("root", 2200)  # explicit wins
    servers = {"app": {"ssh_alias": "app-1"}}
    target, _ = resolve_hops("app", servers["app"], servers, ssh_cfg, {"user": "dflt", "port": 22})
    assert (target["user"], target["port"]) == ("deploy", 142)  # alias beats defaults
    servers = {"app": {"host": "h"}}
    target, _ = resolve_hops("app", servers["app"], servers, ssh_cfg, {"user": "dflt"})
    assert (target["user"], target["port"]) == ("dflt", 22)  # defaults fill the rest


def test_proxy_jump_can_name_config_servers_aliases_or_user_host_port(ssh_cfg):
    servers = {
        "jump": {"host": "j.example", "user": "ops"},
        "app": {"host": "a.example", "proxy_jump": "jump"},
        "app2": {"host": "a2.example", "proxy_jump": ["jump", "edge-nginx"]},
        "app3": {"host": "a3.example", "proxy_jump": "bob@bastion.example:2222"},
        "app4": {"host": "a4.example", "proxy_jump": "none"},
    }
    _, hops = resolve_hops("app", servers["app"], servers, ssh_cfg, {})
    assert [h["host"] for h in hops] == ["j.example"]
    _, hops = resolve_hops("app2", servers["app2"], servers, ssh_cfg, {})
    assert [h["host"] for h in hops] == ["j.example", "203.0.113.9"]
    _, hops = resolve_hops("app3", servers["app3"], servers, ssh_cfg, {})
    assert [(h["user"], h["host"], h["port"]) for h in hops] == [("bob", "bastion.example", 2222)]
    _, hops = resolve_hops("app4", servers["app4"], servers, ssh_cfg, {})
    assert hops == []


def test_loops_unknown_aliases_and_proxycommand_are_rejected_clearly(ssh_cfg):
    with pytest.raises(ValueError, match="loop"):
        resolve_hops("x", {"ssh_alias": "loopy-a"}, {}, ssh_cfg, {})
    with pytest.raises(ValueError, match="not found in ~/.ssh/config"):
        resolve_hops("x", {"ssh_alias": "nope"}, {}, ssh_cfg, {})
    with pytest.raises(ValueError, match="ProxyCommand"):
        resolve_hops("x", {"ssh_alias": "viacmd"}, {}, ssh_cfg, {})
    with pytest.raises(ValueError, match="no host"):
        resolve_hops("x", {"user": "u"}, {}, ssh_cfg, {})


def test_wildcard_host_blocks_count_as_defined(ssh_cfg):
    hop = hop_from_ssh_config("lab-7", ssh_cfg)
    assert hop is not None and hop["user"] == "labuser"
    assert hop_from_ssh_config("unrelated", ssh_cfg) is None


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("host", {"host": "host"}),
        ("user@host", {"host": "host", "user": "user"}),
        ("user@host:2222", {"host": "host", "user": "user", "port": 2222}),
        ("[::1]:22", {"host": "::1", "port": 22}),
    ],
)
def test_host_specs(spec, expected):
    parsed = parse_hop_spec(spec)
    assert {k: v for k, v in parsed.items() if k != "name"} == expected


@pytest.mark.parametrize("bad", ["nope@@", "a b", "user@", "@host", "host:99999", "host:0", "ho$t", "a;b", ""])
def test_malformed_host_specs_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_hop_spec(bad)


def test_missing_ssh_config_is_not_an_error(tmp_path):
    assert load_ssh_config(tmp_path / "does-not-exist") is None
    with pytest.raises(ValueError, match="not found in ~/.ssh/config"):
        resolve_hops("x", {"ssh_alias": "a"}, {}, None, {})
