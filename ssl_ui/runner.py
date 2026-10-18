"""Run services on a worker thread; everything the UI needs crosses a queue back to the Tk thread.

The worker never touches a widget. It posts events ("log", "password", "done"); the Tk thread
drains them every few milliseconds. A password prompt blocks the *worker* (not the window)
until the dialog on the Tk thread returns.
"""
from __future__ import annotations

import contextlib
import queue
import threading
import traceback
from typing import Any, Callable, Dict, Optional

from ssl_cert_tool.platform import Terminal

LogSink = Callable[[str, str], None]


class GuiTerminal(Terminal):
    """A Terminal that writes to the activity log instead of stdout."""

    def __init__(self, sink: LogSink) -> None:
        self.sink = sink
        self.enabled = False
        self.RED = self.GREEN = self.YELLOW = self.BLUE = self.CYAN = self.BOLD = self.RESET = ""

    def disable(self) -> None:  # colour is not a thing here
        pass

    def step(self, current: int, total: int, message: str) -> None:
        self.sink("step", f"[{current}/{total}] {message}")

    def success(self, message: str) -> None:
        self.sink("success", message)

    def warn(self, message: str) -> None:
        self.sink("warn", message)

    def error(self, message: str) -> None:
        self.sink("error", message)

    def info(self, message: str) -> None:
        self.sink("info", message)

    def detail(self, message: str, indent: int = 6) -> None:
        text = str(message)
        if text.startswith("[ok]"):
            level = "success"
        elif text.startswith("[FAIL]"):
            level = "error"
        elif text.startswith("[WARN]"):
            level = "warn"
        elif text.startswith("[DRY-RUN]"):
            level = "cmd"
        else:
            level = "detail"
        self.sink(level, text)


class StreamToLog:
    """File-like object that turns print() output from library code into log lines."""

    def __init__(self, sink: LogSink) -> None:
        self.sink = sink
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line.strip():
                lowered = line.lower()
                level = "warn" if "[warn]" in lowered else "error" if lowered.startswith("error") else "info"
                self.sink(level, line.rstrip())
        return len(text)

    def flush(self) -> None:
        if self._buffer.strip():
            self.sink("info", self._buffer.rstrip())
        self._buffer = ""


class TaskContext:
    """What a running task is given: a terminal, a logger, and a password prompt."""

    def __init__(self, runner: "TaskRunner") -> None:
        self._runner = runner
        self.term = GuiTerminal(self.log)

    def log(self, level: str, message: str) -> None:
        self._runner.events.put(("log", level, str(message)))

    def ask_password(self, hop: Dict[str, Any]) -> Optional[str]:
        """Blocks this worker until the user answers the dialog (or cancels -> None)."""
        holder: Dict[str, Any] = {"event": threading.Event(), "value": None}
        self._runner.events.put(("password", dict(hop), holder))
        holder["event"].wait()
        return holder["value"]


class TaskRunner:
    POLL_MS = 40

    def __init__(
        self,
        scheduler: Any,
        *,
        on_log: LogSink,
        on_state: Callable[[bool, str], None],
        ask_password_ui: Callable[[Dict[str, Any]], Optional[str]],
    ) -> None:
        self._scheduler = scheduler
        self.on_log, self.on_state, self.ask_password_ui = on_log, on_state, ask_password_ui
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.busy = False
        self._started = False
        self._stopped = False

    def start(self) -> None:
        if not self._started:
            self._started = True
            self._scheduler.after(self.POLL_MS, self._tick)

    def stop(self) -> None:
        """Stop polling (the window is going away); a running task is left to finish on its own."""
        self._stopped = True

    def run(
        self,
        label: str,
        func: Callable[[TaskContext], Any],
        on_done: Callable[[Any, Optional[BaseException]], None],
    ) -> bool:
        """Start `func` on a worker thread. False if another task is still running."""
        if self.busy:
            return False
        self.busy = True
        self.on_state(True, label)
        ctx = TaskContext(self)

        def work() -> None:
            result, error = None, None
            try:
                with contextlib.redirect_stdout(StreamToLog(ctx.log)):
                    result = func(ctx)
            except BaseException as exc:  # reported on the Tk thread
                error = exc
                if not _is_expected(exc):
                    ctx.log("detail", traceback.format_exc())
            self.events.put(("done", result, error, on_done))

        threading.Thread(target=work, daemon=True, name=f"task-{label}").start()
        return True

    def pump(self) -> None:
        """Handle every pending event (called by the Tk timer; tests call it directly)."""
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                return
            self._handle(event)

    def _tick(self) -> None:
        if self._stopped:
            return
        self.pump()
        self._scheduler.after(self.POLL_MS, self._tick)

    def _handle(self, event: tuple) -> None:
        kind = event[0]
        if kind == "log":
            self.on_log(event[1], event[2])
        elif kind == "password":
            _kind, hop, holder = event
            try:
                holder["value"] = self.ask_password_ui(hop)
            except Exception:
                holder["value"] = None
            finally:
                holder["event"].set()
        elif kind == "done":
            _kind, result, error, on_done = event
            self.busy = False
            self.on_state(False, "")
            try:
                on_done(result, error)
            except Exception as exc:  # never let a UI bug kill the pump
                self.on_log("error", f"Internal error while showing the result: {exc}")


def _is_expected(exc: BaseException) -> bool:
    from ssl_ui.services import UiError

    return isinstance(exc, UiError)
