"""Palette, fonts and ttk styling for SSL Certificate Studio."""
from __future__ import annotations

import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk
from typing import Iterable, Optional

from ssl_ui.render import mix


@dataclass(frozen=True)
class Palette:
    bg: str = "#0a0f1f"          # window
    sidebar: str = "#0c1226"
    surface: str = "#121a2f"     # cards
    surface2: str = "#18223d"    # hover / raised
    field: str = "#0d1426"       # inputs
    border: str = "#243050"
    border_hi: str = "#35477a"
    text: str = "#e8edff"
    muted: str = "#8f9bbd"
    faint: str = "#5d6a8c"
    accent: str = "#6f6df7"      # indigo
    accent2: str = "#22d3ee"     # cyan
    success: str = "#34d399"
    warn: str = "#fbbf24"
    danger: str = "#f87171"
    info: str = "#60a5fa"


def _first_available(wanted: Iterable[str], families: set, default: str) -> str:
    for name in wanted:
        if name in families:
            return name
    return default


class Theme:
    """Everything visual, created once per root window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.p = Palette()
        families = set(tkfont.families(root))
        ui = _first_available(
            ["Segoe UI Variable Display", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "Cantarell", "DejaVu Sans"],
            families, "TkDefaultFont",
        )
        mono = _first_available(
            ["Cascadia Mono", "Cascadia Code", "Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Courier New"],
            families, "TkFixedFont",
        )
        symbols = _first_available(["Segoe UI Symbol", "Apple Symbols", "DejaVu Sans"], families, ui)
        self.ui_family, self.mono_family, self.symbol_family = ui, mono, symbols
        self.f_body = tkfont.Font(root=root, family=ui, size=10)
        self.f_bold = tkfont.Font(root=root, family=ui, size=10, weight="bold")
        self.f_small = tkfont.Font(root=root, family=ui, size=9)
        self.f_tiny = tkfont.Font(root=root, family=ui, size=8)
        self.f_h1 = tkfont.Font(root=root, family=ui, size=20, weight="bold")
        self.f_h2 = tkfont.Font(root=root, family=ui, size=13, weight="bold")
        self.f_h3 = tkfont.Font(root=root, family=ui, size=11, weight="bold")
        self.f_mono = tkfont.Font(root=root, family=mono, size=10)
        self.f_mono_small = tkfont.Font(root=root, family=mono, size=9)
        self.f_icon = tkfont.Font(root=root, family=symbols, size=14)
        self.f_icon_big = tkfont.Font(root=root, family=symbols, size=22)
        self._style(root)

    # -- colour helpers ----------------------------------------------------------
    def tint(self, color: str, amount: float = 0.16, onto: Optional[str] = None) -> str:
        """`color` faded into the surface: the background of a status pill."""
        return mix(onto or self.p.surface, color, amount)

    def kind_color(self, kind: str) -> str:
        p = self.p
        return {
            "success": p.success, "ok": p.success, "good": p.success,
            "warn": p.warn, "warning": p.warn,
            "danger": p.danger, "error": p.danger, "bad": p.danger,
            "info": p.info, "accent": p.accent, "muted": p.muted,
        }.get(kind, p.muted)

    # -- ttk ---------------------------------------------------------------------
    def _style(self, root: tk.Tk) -> None:
        p = self.p
        root.configure(bg=p.bg)
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=p.surface, foreground=p.text, font=self.f_body, borderwidth=0)

        style.configure("Treeview", background=p.surface, fieldbackground=p.surface, foreground=p.text,
                        rowheight=int(self.f_body.metrics("linespace") * 1.9), borderwidth=0, relief="flat", font=self.f_body)
        style.configure("Treeview.Heading", background=p.surface2, foreground=p.muted, font=self.f_small,
                        relief="flat", borderwidth=0, padding=(10, 6))
        style.map("Treeview", background=[("selected", mix(p.surface, p.accent, 0.35))], foreground=[("selected", p.text)])
        style.map("Treeview.Heading", background=[("active", p.surface2)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background=p.border, troughcolor=p.bg, bordercolor=p.bg,
                            lightcolor=p.border, darkcolor=p.border, arrowcolor=p.muted, relief="flat", gripcount=0,
                            arrowsize=12, width=10)
            style.map(f"{orient}.TScrollbar", background=[("active", p.border_hi), ("pressed", p.accent)])

        style.configure("TCombobox", fieldbackground=p.field, background=p.surface2, foreground=p.text,
                        arrowcolor=p.muted, bordercolor=p.border, lightcolor=p.border, darkcolor=p.border,
                        padding=6, selectbackground=p.field, selectforeground=p.text)
        style.map("TCombobox", fieldbackground=[("readonly", p.field)], bordercolor=[("focus", p.accent)],
                  foreground=[("readonly", p.text)], selectbackground=[("readonly", p.field)],
                  selectforeground=[("readonly", p.text)])
        root.option_add("*TCombobox*Listbox.background", p.surface2)
        root.option_add("*TCombobox*Listbox.foreground", p.text)
        root.option_add("*TCombobox*Listbox.selectBackground", p.accent)
        root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        root.option_add("*TCombobox*Listbox.font", self.f_body)


def enable_dpi_awareness() -> None:
    """Crisp text on high-DPI Windows screens (must run before the first window)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
