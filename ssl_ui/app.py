# Author: Sagar K | 2026 | MIT licence
"""The Studio window: sidebar, header, pages, and the activity log dock."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ssl_cert_tool import __version__ as TOOL_VERSION
from ssl_ui import REPO_URL, __author__ as AUTHOR, __license__ as LICENCE, __version__ as UI_VERSION
from ssl_ui.render import mix, render_gradient_bar, render_round
from ssl_ui.runner import TaskRunner
from ssl_ui.services import UiError
from ssl_ui.state import UiState
from ssl_ui.theme import Theme, enable_dpi_awareness
from ssl_ui.widgets import AboutDialog, Button, LogView, PasswordDialog, Pill, Shimmer, apply_dark_titlebar

NAV: List[Tuple[str, str, str]] = [
    ("home", "⌂", "Home"),
    ("certs", "◈", "Certificates"),
    ("deploy", "⇪", "Deploy"),
    ("copy", "⇄", "Copy to server"),
    ("rollback", "↺", "Rollback"),
    ("keystore", "⚿", "Keystores"),
]


class NavItem(tk.Frame):
    def __init__(self, parent: tk.Misc, theme: Theme, icon: str, text: str, command: Callable[[], None]) -> None:
        p = theme.p
        super().__init__(parent, bg=p.sidebar, cursor="hand2")
        self.theme = theme
        self.bar = tk.Frame(self, bg=p.sidebar, width=3)
        self.bar.pack(side="left", fill="y")
        self.icon = tk.Label(self, text=icon, bg=p.sidebar, fg=p.muted, font=theme.f_icon, width=2, cursor="hand2")
        self.icon.pack(side="left", padx=(12, 4), pady=9)
        self.label = tk.Label(self, text=text, bg=p.sidebar, fg=p.muted, font=theme.f_body, anchor="w", cursor="hand2")
        self.label.pack(side="left", fill="x", expand=True)
        self.active = False
        for widget in (self, self.icon, self.label, self.bar):
            widget.bind("<Button-1>", lambda _e: command())
            widget.bind("<Enter>", lambda _e: self._paint(True))
            widget.bind("<Leave>", lambda _e: self._paint(False))

    def set_active(self, active: bool) -> None:
        self.active = active
        self._paint(False)

    def _paint(self, hover: bool) -> None:
        p = self.theme.p
        bg = mix(p.sidebar, p.accent, 0.20) if self.active else (mix(p.sidebar, p.surface2, 0.8) if hover else p.sidebar)
        fg = p.text if (self.active or hover) else p.muted
        for widget in (self, self.icon, self.label):
            widget.configure(bg=bg)
        self.icon.configure(fg=p.accent2 if self.active else fg)
        self.label.configure(fg=fg, font=self.theme.f_bold if self.active else self.theme.f_body)
        self.bar.configure(bg=p.accent2 if self.active else bg)


class StudioApp:
    def __init__(
        self,
        root: tk.Tk,
        *,
        configs_dir: Optional[Path] = None,
        state: Optional[UiState] = None,
        ssl_config: Optional[Path] = None,
        known_hosts: Optional[Path] = None,
        ssh_config: Optional[Path] = None,
    ) -> None:
        self.root = root
        self.theme = Theme(root)
        self.p = self.theme.p
        self.state = state or UiState(None)
        self.configs_dir = Path(configs_dir) if configs_dir else None
        self.ssh_config = Path(ssh_config) if ssh_config else None
        self.known_hosts = Path(known_hosts) if known_hosts else None
        self.pages: Dict[str, Any] = {}
        self.current: Optional[str] = None
        self.nav_items: Dict[str, NavItem] = {}
        self._page_classes = self._load_page_classes()
        self._build_window()
        self.runner = TaskRunner(root, on_log=self.log, on_state=self._on_state, ask_password_ui=self._ask_password)
        self.runner.start()

    # -- construction ---------------------------------------------------------------
    @staticmethod
    def _load_page_classes() -> Dict[str, type]:
        from ssl_ui.pages import PAGES

        return dict(PAGES)

    def _build_window(self) -> None:
        p, theme, root = self.p, self.theme, self.root
        root.title("SSL Certificate Studio")
        screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
        width, height = min(1280, screen_w - 80), min(840, screen_h - 100)
        root.geometry(f"{width}x{height}+{max(0, (screen_w - width) // 2)}+{max(0, (screen_h - height) // 3)}")
        root.minsize(min(1040, width), min(660, height))
        apply_dark_titlebar(root)
        self._icon = render_round(root, 64, 64, 16, p.accent, p.accent2, p.bg)
        root.iconphoto(True, self._icon)

        sidebar = tk.Frame(root, bg=p.sidebar, width=232)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(root, bg=p.border, width=1).pack(side="left", fill="y")

        brand = tk.Frame(sidebar, bg=p.sidebar)
        brand.pack(fill="x", padx=18, pady=(22, 20))
        logo = tk.Label(brand, text="⚿", bg=mix(p.sidebar, p.accent, 0.35), fg=p.accent2, font=theme.f_icon_big, width=2)
        logo.pack(side="left")
        names = tk.Frame(brand, bg=p.sidebar)
        names.pack(side="left", padx=(12, 0))
        tk.Label(names, text="Cert Studio", bg=p.sidebar, fg=p.text, font=theme.f_h3, anchor="w").pack(fill="x")
        tk.Label(names, text="SSL certificate toolkit", bg=p.sidebar, fg=p.faint, font=theme.f_tiny, anchor="w").pack(fill="x")

        for key, icon, text in NAV:
            item = NavItem(sidebar, theme, icon, text, lambda key=key: self.navigate(key))
            item.pack(fill="x", pady=1)
            self.nav_items[key] = item

        footer = tk.Frame(sidebar, bg=p.sidebar)
        footer.pack(side="bottom", fill="x", padx=18, pady=16)
        Pill(footer, theme, "host keys: strict", "success", dot=True, bg=p.sidebar, font=theme.f_tiny, pady=1).pack(anchor="w")
        tk.Label(footer, text=f"studio {UI_VERSION}", bg=p.sidebar, fg=p.faint, font=theme.f_tiny).pack(anchor="w", pady=(8, 0))
        self.credit_label = tk.Label(footer, text=f"by {AUTHOR}  ·  About", bg=p.sidebar, fg=p.faint, font=theme.f_tiny, cursor="hand2")
        self.credit_label.pack(anchor="w", pady=(2, 0))
        self.credit_label.bind("<Button-1>", lambda _e: self._about())
        self.credit_label.bind("<Enter>", lambda _e: self.credit_label.configure(fg=p.accent2))
        self.credit_label.bind("<Leave>", lambda _e: self.credit_label.configure(fg=p.faint))
        root.bind("<F1>", lambda _e: self._about())

        main = tk.Frame(root, bg=p.bg)
        main.pack(side="left", fill="both", expand=True)

        header = tk.Frame(main, bg=p.bg)
        header.pack(fill="x", padx=28, pady=(20, 8))
        titles = tk.Frame(header, bg=p.bg)
        titles.pack(side="left", fill="x", expand=True)
        self.title_label = tk.Label(titles, text="", bg=p.bg, fg=p.text, font=theme.f_h1, anchor="w")
        self.title_label.pack(fill="x")
        self.subtitle_label = tk.Label(titles, text="", bg=p.bg, fg=p.muted, font=theme.f_body, anchor="w")
        self.subtitle_label.pack(fill="x")
        status = tk.Frame(header, bg=p.bg)
        status.pack(side="right", anchor="n")
        self.status_pill = Pill(status, theme, "Ready", "success", dot=True, bg=p.bg, padx=12, pady=3)
        self.status_pill.pack(anchor="e")
        self.shimmer = Shimmer(status, theme, width=150)
        self.shimmer.pack(anchor="e", pady=(8, 0))

        line = tk.Canvas(main, height=3, bg=p.bg, highlightthickness=0, bd=0)
        line.pack(fill="x", padx=28)
        self._line_image = render_gradient_bar(root, 2400, 3, p.accent, p.accent2, p.success)
        line.create_image(0, 0, image=self._line_image, anchor="nw")

        self.dock = tk.Frame(main, bg=p.bg)
        self.dock.pack(side="bottom", fill="x", padx=28, pady=(8, 18))
        bar = tk.Frame(self.dock, bg=p.bg)
        bar.pack(fill="x", pady=(0, 6))
        tk.Label(bar, text="Activity", bg=p.bg, fg=p.muted, font=theme.f_bold).pack(side="left")
        self.toggle_btn = Button(bar, theme, "Hide", self._toggle_log, kind="quiet", padx=10, pady=3, font=theme.f_tiny)
        self.toggle_btn.pack(side="right")
        Button(bar, theme, "Copy", self._copy_log, kind="quiet", padx=10, pady=3, font=theme.f_tiny).pack(side="right", padx=(0, 6))
        Button(bar, theme, "Clear", lambda: self.logview.clear(), kind="quiet", padx=10, pady=3, font=theme.f_tiny).pack(side="right", padx=(0, 6))
        self.log_holder = tk.Frame(self.dock, bg=p.bg, height=130)
        self.log_holder.pack_propagate(False)
        self.logview = LogView(self.log_holder, theme)
        self.logview.pack(fill="both", expand=True)
        self._log_visible = False          # opens by itself on the first message
        self._log_hidden_by_user = False
        self.toggle_btn.set_text("Show")

        self.content = tk.Frame(main, bg=p.bg)
        self.content.pack(fill="both", expand=True, pady=(4, 0))
        for index, (key, _icon, _text) in enumerate(NAV[:9], start=1):
            root.bind(f"<Control-Key-{index}>", lambda _e, key=key: self.navigate(key))

    # -- navigation -------------------------------------------------------------------
    def page(self, key: str):
        if key not in self.pages:
            self.pages[key] = self._page_classes[key](self.content, self)
        return self.pages[key]

    def navigate(self, key: str):
        if key not in self._page_classes:
            return None
        if self.current:
            self.pages[self.current].pack_forget()
        page = self.page(key)
        page.pack(fill="both", expand=True)
        self.current = key
        for name, item in self.nav_items.items():
            item.set_active(name == key)
        self.title_label.configure(text=page.title)
        self.subtitle_label.configure(text=page.subtitle)
        page.on_show()
        return page

    # -- activity log / status ---------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        self.logview.write(level, message)
        if not self._log_visible and (level == "error" or not self._log_hidden_by_user):
            self._show_log(True)

    def _show_log(self, visible: bool) -> None:
        if visible:
            self.log_holder.pack(fill="x")
            self.toggle_btn.set_text("Hide")
        else:
            self.log_holder.pack_forget()
            self.toggle_btn.set_text("Show")
        self._log_visible = visible

    def _toggle_log(self) -> None:
        self._log_hidden_by_user = self._log_visible  # hiding is a choice; showing resets it
        self._show_log(not self._log_visible)

    def _copy_log(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.logview.contents())
        self.log("detail", "Activity copied to the clipboard.")

    def _on_state(self, busy: bool, label: str) -> None:
        if busy:
            self.status_pill.set(f"{label}…", "info")
            self.shimmer.start()
        else:
            self.status_pill.set("Ready", "success")
            self.shimmer.stop()

    def run_task(self, label: str, func: Callable[[Any], Any], on_done: Callable[[Any, Optional[BaseException]], None], *,
                 quiet: bool = False) -> bool:
        """Run `func(ctx)` on the worker; `on_done(result, error)` runs on the UI thread."""
        if self.runner.busy:
            self.log("warn", "Another task is still running — please wait for it to finish.")
            return False
        if not quiet:
            self.log("step", f"{label}…")

        def finished(result: Any, error: Optional[BaseException]) -> None:
            if error is not None:
                if isinstance(error, UiError):
                    self.log("error", str(error))
                else:
                    self.log("error", f"Unexpected error: {error}")
            on_done(result, error)

        return self.runner.run(label, func, finished)

    # -- dialogs ----------------------------------------------------------------------
    def _about(self) -> None:
        AboutDialog(self.root, self.theme, version=UI_VERSION, tool_version=TOOL_VERSION, author=AUTHOR, licence=LICENCE,
                    url=REPO_URL).show()

    def _ask_password(self, hop: Dict[str, Any]) -> Optional[str]:
        who = f"{hop.get('user', 'root')}@{hop.get('host')}:{hop.get('port', 22)}"
        return PasswordDialog(self.root, self.theme, who, "It will be used for this connection only.").show()


def launch(argv: Optional[List[str]] = None) -> int:
    """Create the window and run the Tk main loop."""
    import argparse

    from ssl_cert_tool.paths import configs_dir
    from ssl_ui.state import default_state_path

    parser = argparse.ArgumentParser(prog="ssl-gui2", description="SSL Certificate Studio")
    parser.add_argument("--page", default="home", choices=[k for k, _i, _t in NAV])
    parser.add_argument("--screenshot", metavar="PNG", help="save a screenshot of the window and exit (development)")
    parser.add_argument("--no-state", action="store_true", help="do not read or write remembered settings")
    args = parser.parse_args(argv)

    enable_dpi_awareness()
    root = tk.Tk()
    app = StudioApp(root, configs_dir=configs_dir(), state=UiState(None if args.no_state else default_state_path()))
    app.navigate(args.page)
    if args.screenshot:
        from ssl_ui.devtools import capture_window

        root.after(1200, lambda: (capture_window(root, args.screenshot), root.destroy()))
    root.mainloop()
    return 0
