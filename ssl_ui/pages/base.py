"""Base class shared by every screen."""
from __future__ import annotations

import tkinter as tk
from typing import Any, Tuple

from ssl_ui.widgets import Scrollable


class Page(tk.Frame):
    key = ""
    title = ""
    subtitle = ""

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        super().__init__(parent, bg=app.theme.p.bg)
        self.app = app
        self.theme = app.theme
        self.p = app.theme.p
        # The action bar stays visible at the bottom while the page content scrolls.
        self._footer_line = tk.Frame(self, bg=self.p.border, height=1)
        self.footer = tk.Frame(self, bg=self.p.bg)
        self._scroller = Scrollable(self, self.theme)
        self._scroller.pack(fill="both", expand=True)
        self.root_frame = tk.Frame(self._scroller.inner, bg=self.p.bg)
        self.root_frame.pack(fill="both", expand=True, padx=28, pady=22)
        self.build()
        if self.footer.winfo_children():
            self._scroller.pack_forget()
            self._footer_line.pack(side="bottom", fill="x", padx=28)
            self.footer.pack(side="bottom", fill="x", padx=28, pady=10)
            self._scroller.pack(fill="both", expand=True)

    # -- to override -------------------------------------------------------------
    def build(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def on_show(self) -> None:
        """Called every time the page becomes visible."""

    # -- helpers -----------------------------------------------------------------
    def columns(self, left_min: int = 400, right_min: int = 420, ratio: Tuple[int, int] = (5, 6)) -> Tuple[tk.Frame, tk.Frame]:
        """A two-column layout; returns (left, right) frames."""
        grid = tk.Frame(self.root_frame, bg=self.p.bg)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=ratio[0], minsize=left_min, uniform="cols")
        grid.columnconfigure(1, weight=ratio[1], minsize=right_min, uniform="cols")
        left = tk.Frame(grid, bg=self.p.bg)
        right = tk.Frame(grid, bg=self.p.bg)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        return left, right

    def stack(self, parent: tk.Misc, widget: tk.Widget, pady: Tuple[int, int] = (0, 14)) -> tk.Widget:
        widget.pack(fill="x", pady=pady)
        return widget
