# Author: Sagar K | 2026 | MIT licence
"""In-process SSH servers for tests: password auth, exec handlers, and direct-tcpip forwarding
(so one server can act as a jump host for another)."""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

import paramiko


class _Interface(paramiko.ServerInterface):
    def __init__(self, owner: "SSHServer") -> None:
        self.owner = owner

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.owner.attempts.append((username, password))
        ok = self.owner.users.get(username) == password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    # paramiko sends the "exec accepted" reply only after this method returns. A handler that wrote
    # output and closed the channel first made the client see "Channel closed" instead of success,
    # which a real server never does; give the reply a head start so the order is always right.
    REPLY_HEAD_START = 0.15

    def check_channel_exec_request(self, channel, command):
        def run() -> None:
            time.sleep(self.REPLY_HEAD_START)
            self.owner.exec_handler(channel, command)

        threading.Thread(target=run, daemon=True).start()
        return True

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if not self.owner.allow_forwarding:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.owner.forwarded.append(tuple(destination))
        self.owner.pending[chanid] = tuple(destination)
        return paramiko.OPEN_SUCCEEDED


def _pump(source, sink) -> None:
    try:
        while True:
            data = source.recv(32768)
            if not data:
                break
            sink.sendall(data)
    except Exception:
        pass
    finally:
        for end in (source, sink):
            try:
                end.close()
            except Exception:
                pass


class SSHServer:
    def __init__(self, users: Optional[Dict[str, str]] = None, allow_forwarding: bool = True) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.host_key = paramiko.ECDSAKey.generate()
        self.users = users if users is not None else {"tester": "pw"}
        self.allow_forwarding = allow_forwarding
        self.exec_handler: Callable = lambda chan, cmd: (chan.send_exit_status(0), chan.close())
        self.attempts: List[Tuple[str, str]] = []
        self.forwarded: List[Tuple[str, int]] = []
        self.pending: Dict[int, Tuple[str, int]] = {}
        self._transports: List[paramiko.Transport] = []
        self._stop = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Interface(self))
            except Exception:
                continue
            threading.Thread(target=self._serve_channels, args=(transport,), daemon=True).start()

    def _serve_channels(self, transport: paramiko.Transport) -> None:
        """Bridge accepted direct-tcpip channels to their destination (what a jump host does)."""
        while transport.is_active() and not self._stop:
            chan = transport.accept(1)
            if chan is None:
                continue
            destination = self.pending.pop(chan.get_id(), None)
            if destination is None:
                continue
            try:
                upstream = socket.create_connection(destination, timeout=10)
            except OSError:
                chan.close()
                continue
            threading.Thread(target=_pump, args=(chan, upstream), daemon=True).start()
            threading.Thread(target=_pump, args=(upstream, chan), daemon=True).start()

    def rotate_key(self) -> None:
        self.host_key = paramiko.ECDSAKey.generate()

    def cfg(self, **extra):
        user = next(iter(self.users), "tester")
        return {"host": "127.0.0.1", "port": self.port, "user": user, **extra}

    def close(self) -> None:
        self._stop = True
        self.sock.close()
        for transport in self._transports:
            try:
                transport.close()
            except Exception:
                pass
