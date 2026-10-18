"""Host-key verification and the command runner, against a real in-process SSH server."""
from __future__ import annotations

import socket
import threading

import paramiko
import pytest

from conftest import posix_only
from ssl_deploy.ssh import (
    HostKeyVerificationError,
    PinnedKeyPolicy,
    RemoteHost,
    connect_ssh,
    fingerprint_sha256,
    normalize_fingerprint,
    shell_quote,
    validate_remote_path,
)


class _Interface(paramiko.ServerInterface):
    def __init__(self, exec_handler):
        self.exec_handler = exec_handler

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = (username, password) == ("tester", "pw")
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        threading.Thread(target=self.exec_handler, args=(channel, command), daemon=True).start()
        return True


class SSHServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.host_key = paramiko.ECDSAKey.generate()
        self.exec_handler = lambda chan, cmd: (chan.send_exit_status(0), chan.close())
        self._transports = []
        self._stop = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Interface(self.exec_handler))
            except Exception:
                pass

    def rotate_key(self):
        self.host_key = paramiko.ECDSAKey.generate()

    def cfg(self, **extra):
        return {"host": "127.0.0.1", "port": self.port, "user": "tester", **extra}

    def close(self):
        self._stop = True
        self.sock.close()
        for t in self._transports:
            t.close()


@pytest.fixture
def server(monkeypatch):
    # Hermetic: never read the developer's real ~/.ssh/known_hosts.
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)
    srv = SSHServer()
    yield srv
    srv.close()


def connect(server, known_hosts, policy="strict", **extra):
    return connect_ssh(
        server.cfg(**extra), policy=policy, known_hosts_path=known_hosts, password="pw", timeout=10
    )


def test_unknown_host_is_refused_by_default_with_fingerprint_in_message(server, tmp_path):
    with pytest.raises(HostKeyVerificationError) as exc:
        connect(server, tmp_path / "kh")
    message = str(exc.value)
    assert fingerprint_sha256(server.host_key) in message
    assert "--accept-new-hostkeys" in message
    assert not (tmp_path / "kh").exists()  # nothing was trusted behind our back


def test_accept_new_trusts_and_remembers_the_host(server, tmp_path):
    kh = tmp_path / "kh"
    notices = []
    client = connect_ssh(
        server.cfg(), policy="accept-new", known_hosts_path=kh, password="pw", timeout=10,
        notice=notices.append,
    )
    client.close()
    assert kh.is_file() and f"[127.0.0.1]:{server.port}" in kh.read_text()
    assert notices and fingerprint_sha256(server.host_key) in notices[0]
    # ...and from now on the strict default is happy.
    connect(server, kh).close()


@posix_only
def test_known_hosts_file_is_private(server, tmp_path):
    kh = tmp_path / "dir" / "kh"
    connect(server, kh, policy="accept-new").close()
    assert (kh.stat().st_mode & 0o777) == 0o600


def test_changed_host_key_is_always_fatal_even_with_accept_new(server, tmp_path):
    kh = tmp_path / "kh"
    connect(server, kh, policy="accept-new").close()
    server.rotate_key()
    with pytest.raises(paramiko.BadHostKeyException):
        connect(server, kh, policy="accept-new")


def test_pinned_fingerprint_allows_only_that_key(server, tmp_path):
    kh = tmp_path / "kh"
    good = fingerprint_sha256(server.host_key)
    connect(server, kh, host_key_sha256=good).close()
    assert not kh.exists()  # pinning does not write known_hosts
    with pytest.raises(HostKeyVerificationError, match="mismatch"):
        connect(server, kh, host_key_sha256="SHA256:" + "A" * 43)


def test_wrong_password_fails_and_does_not_leak_connection(server, tmp_path):
    with pytest.raises(paramiko.AuthenticationException):
        connect_ssh(
            server.cfg(), policy="accept-new", known_hosts_path=tmp_path / "kh",
            password="nope", timeout=10,
        )


def test_large_stdout_and_stderr_do_not_deadlock_the_runner(server, tmp_path):
    def handler(chan, command):
        chan.sendall(b"o" * 3_000_000)
        chan.sendall_stderr(b"e" * 2_000_000)
        chan.send_exit_status(7)
        chan.close()

    server.exec_handler = handler
    host = RemoteHost(connect(server, tmp_path / "kh", policy="accept-new"))
    try:
        code, out, err = host.run("anything", timeout=30)
    finally:
        host.close()
    assert (code, len(out), len(err)) == (7, 3_000_000, 2_000_000)


def test_idle_command_times_out_instead_of_hanging(server, tmp_path):
    release = threading.Event()

    def handler(chan, command):
        release.wait(10)  # never answers within the idle timeout
        try:
            chan.close()
        except Exception:
            pass

    server.exec_handler = handler
    host = RemoteHost(connect(server, tmp_path / "kh", policy="accept-new"))
    try:
        with pytest.raises(TimeoutError):
            host.run("sleep", timeout=1)
    finally:
        release.set()
        host.close()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_fingerprint_formats_are_normalised():
    assert normalize_fingerprint("SHA256:abc==") == "SHA256:abc"
    assert normalize_fingerprint("  abc ") == "SHA256:abc"


def test_pinned_policy_rejects_mismatch():
    class Key:
        def asbytes(self):
            return b"key-bytes"

        def get_name(self):
            return "ssh-ed25519"

    policy = PinnedKeyPolicy(fingerprint_sha256(Key()))
    policy.missing_host_key(None, "h", Key())  # matches: no exception
    with pytest.raises(HostKeyVerificationError):
        PinnedKeyPolicy("SHA256:other").missing_host_key(None, "h", Key())


@pytest.mark.parametrize(
    "value, expected",
    [("plain", "plain"), ("a b", "'a b'"), ("x; rm -rf /", "'x; rm -rf /'"), ("it's", "'it'\"'\"'s'")],
)
def test_shell_quote(value, expected):
    assert shell_quote(value) == expected


@pytest.mark.parametrize("bad", ["", "relative", "~/x", "/", "//", "/a\x00b", "/a\nb", None, 5])
def test_validate_remote_path_rejects(bad):
    with pytest.raises(ValueError):
        validate_remote_path(bad)


def test_validate_remote_path_accepts_normal_absolute_paths():
    assert validate_remote_path("/etc/ssl/x.crt") == "/etc/ssl/x.crt"
