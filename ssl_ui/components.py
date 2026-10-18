"""Composite widgets shared by the pages."""
from __future__ import annotations

import tkinter as tk
from typing import Callable, List, Optional, Sequence

from ssl_ui.render import mix
from ssl_ui.services import CertCard, Outcome
from ssl_ui.theme import Theme
from ssl_ui.widgets import Pill, autowrap

STATUS = {
    "success": ("OK", "success"),
    "failed": ("FAILED", "danger"),
    "rolled_back": ("RESTORED", "warn"),
    "skipped": ("SKIPPED", "muted"),
    "pending": ("PENDING", "muted"),
}


def expiry_pill(days, expired: bool) -> tuple:
    if days is None:
        return "expiry unknown", "muted"
    if expired:
        return "EXPIRED", "danger"
    if days < 14:
        return f"{days} days left", "danger"
    if days < 45:
        return f"{days} days left", "warn"
    return f"{days} days left", "success"


class EmptyState(tk.Frame):
    def __init__(self, parent: tk.Misc, theme: Theme, icon: str, title: str, text: str, bg: Optional[str] = None) -> None:
        p = theme.p
        bg = bg or parent.cget("bg")
        super().__init__(parent, bg=bg)
        tk.Label(self, text=icon, bg=bg, fg=p.faint, font=theme.f_icon_big).pack(pady=(26, 6))
        tk.Label(self, text=title, bg=bg, fg=p.muted, font=theme.f_h3).pack()
        tk.Label(self, text=text, bg=bg, fg=p.faint, font=theme.f_small, wraplength=420, justify="center").pack(pady=(4, 26))


class Tile(tk.Frame):
    """A big clickable card (the Home screen's actions)."""

    def __init__(self, parent: tk.Misc, theme: Theme, icon: str, title: str, text: str, command: Callable[[], None], *,
                 accent: Optional[str] = None) -> None:
        p = theme.p
        self.theme = theme
        self._base, self._hover = p.surface, mix(p.surface, p.accent, 0.12)
        super().__init__(parent, bg=self._base, highlightthickness=1, highlightbackground=p.border, cursor="hand2")
        accent = accent or p.accent
        self._accent = accent
        inner = tk.Frame(self, bg=self._base)
        inner.pack(fill="both", expand=True, padx=18, pady=16)
        self._widgets: List[tk.Widget] = [self, inner]
        icon_label = tk.Label(inner, text=icon, bg=self._base, fg=accent, font=theme.f_icon_big, anchor="w")
        icon_label.pack(fill="x")
        title_label = tk.Label(inner, text=title, bg=self._base, fg=p.text, font=theme.f_h3, anchor="w")
        title_label.pack(fill="x", pady=(8, 2))
        text_label = tk.Label(inner, text=text, bg=self._base, fg=p.muted, font=theme.f_small, anchor="w", justify="left", wraplength=250)
        text_label.pack(fill="x")
        self._widgets += [icon_label, title_label, text_label]
        for widget in self._widgets:
            widget.bind("<Enter>", lambda _e: self._paint(True))
            widget.bind("<Leave>", lambda _e: self._paint(False))
            widget.bind("<Button-1>", lambda _e: command())

    def _paint(self, hover: bool) -> None:
        color = self._hover if hover else self._base
        for widget in self._widgets:
            widget.configure(bg=color)
        self.configure(highlightbackground=self._accent if hover else self.theme.p.border)


class RouteTimeline(tk.Frame):
    """The hops a connection will take: 'laptop -> jump -> target'."""

    def __init__(self, parent: tk.Misc, theme: Theme) -> None:
        super().__init__(parent, bg=parent.cget("bg"))
        self.theme = theme

    def set(self, hops: Sequence[str], error: Optional[str] = None) -> None:
        p = self.theme.p
        bg = self.master.cget("bg")
        for child in self.winfo_children():
            child.destroy()
        if error:
            Pill(self, self.theme, error, "danger", bg=bg).pack(anchor="w")
            return
        if not hops:
            tk.Label(self, text="Pick a host to see the route.", bg=bg, fg=p.faint, font=self.theme.f_small).pack(anchor="w")
            return
        row = tk.Frame(self, bg=bg)
        row.pack(anchor="w", fill="x")
        tk.Label(row, text="●", bg=bg, fg=p.faint, font=self.theme.f_small).pack(side="left")
        tk.Label(row, text="this computer", bg=bg, fg=p.faint, font=self.theme.f_small).pack(side="left", padx=(8, 0))
        for index, hop in enumerate(hops):
            last = index == len(hops) - 1
            tk.Label(self, text="│", bg=bg, fg=p.border_hi, font=self.theme.f_small).pack(anchor="w", padx=(1, 0))
            line = tk.Frame(self, bg=bg)
            line.pack(anchor="w", fill="x")
            color = p.success if last else p.accent2
            tk.Label(line, text="◆" if last else "●", bg=bg, fg=color, font=self.theme.f_small).pack(side="left")
            tk.Label(line, text=hop, bg=bg, fg=p.text, font=self.theme.f_mono_small).pack(side="left", padx=(8, 8))
            Pill(line, self.theme, "target" if last else "jump host", "success" if last else "info", bg=bg, font=self.theme.f_tiny, pady=1).pack(side="left")


class ResultList(tk.Frame):
    """A banner plus one line per result (deploy / copy / rollback)."""

    def __init__(self, parent: tk.Misc, theme: Theme) -> None:
        super().__init__(parent, bg=parent.cget("bg"))
        self.theme = theme

    def clear(self) -> None:
        for child in self.winfo_children():
            child.destroy()

    def show(self, outcome: Outcome, *, dry_run: bool = False) -> None:
        p = self.theme.p
        bg = self.master.cget("bg")
        self.clear()
        banner = tk.Frame(self, bg=bg)
        banner.pack(fill="x", pady=(0, 8))
        if outcome.ok:
            Pill(banner, self.theme, "PREVIEW OK — nothing was changed" if dry_run else "COMPLETED", "info" if dry_run else "success",
                 dot=True, bg=bg, font=self.theme.f_bold, padx=14, pady=4).pack(side="left")
        else:
            Pill(banner, self.theme, "FAILED", "danger", dot=True, bg=bg, font=self.theme.f_bold, padx=14, pady=4).pack(side="left")
        if outcome.aborted:
            reason = tk.Label(self, text=outcome.aborted, bg=bg, fg=p.danger, font=self.theme.f_small, anchor="w", justify="left", wraplength=320)
            reason.pack(fill="x", pady=(0, 6))
            autowrap(reason, self)
        for row in outcome.rows:
            line = tk.Frame(self, bg=bg)
            line.pack(fill="x", pady=2)
            text, kind = STATUS.get(row.status, (row.status.upper(), "muted"))
            Pill(line, self.theme, text, kind, bg=bg, font=self.theme.f_tiny, pady=1).pack(side="left", anchor="n")
            label = f"{row.server} \u00b7 {row.item}" if row.server not in ("*", "") else row.item
            col = tk.Frame(line, bg=bg)
            col.pack(side="left", fill="x", expand=True, padx=(10, 0))
            head = tk.Label(col, text=label, bg=bg, fg=p.text, font=self.theme.f_bold, anchor="w", justify="left", wraplength=320)
            head.pack(fill="x")
            autowrap(head, col)
            message = row.message
            if message.endswith(row.item) and " -> " in message:
                message = "from " + message.split(" -> ")[0]
            if message:
                detail = tk.Label(col, text=message, bg=bg, fg=p.muted, font=self.theme.f_small, anchor="w", justify="left", wraplength=320)
                detail.pack(fill="x")
                autowrap(detail, col)
        if outcome.hint:
            tip = tk.Label(self, text=outcome.hint, bg=bg, fg=p.faint, font=self.theme.f_small, anchor="w", justify="left", wraplength=320)
            tip.pack(fill="x", pady=(8, 0))
            autowrap(tip, self)


class CertRow(tk.Frame):
    """One certificate in the chain: role, name, issuer, expiry, where it came from."""

    ROLE_KIND = {"LEAF": "accent", "INTERMEDIATE": "info", "ROOT": "muted", "CERT": "muted"}

    def __init__(self, parent: tk.Misc, theme: Theme, card: CertCard) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=p.surface2, highlightthickness=1, highlightbackground=p.border)
        inner = tk.Frame(self, bg=p.surface2)
        inner.pack(fill="x", padx=14, pady=10)
        top = tk.Frame(inner, bg=p.surface2)
        top.pack(fill="x")
        text, kind = expiry_pill(card.days_left, card.expired)
        Pill(top, theme, text, kind, bg=p.surface2, dot=True, font=theme.f_tiny, pady=1).pack(side="right")  # packed first: never squeezed
        Pill(top, theme, card.role, self.ROLE_KIND.get(card.role, "muted"), bg=p.surface2, font=theme.f_tiny, pady=1).pack(side="left")
        name = tk.Label(top, text=card.cn, bg=p.surface2, fg=p.text, font=theme.f_bold, anchor="w", justify="left", wraplength=240)
        name.pack(side="left", padx=(10, 6), fill="x", expand=True)
        tk.Label(inner, text=f"issued by {card.issuer}", bg=p.surface2, fg=p.muted, font=theme.f_small, anchor="w").pack(fill="x", pady=(3, 0))
        detail = f"expires {card.not_after}   ·   {card.key_info}   ·   from {card.source}"
        tk.Label(inner, text=detail, bg=p.surface2, fg=p.faint, font=theme.f_tiny, anchor="w").pack(fill="x")
        if card.names and card.role == "LEAF":
            covers = tk.Label(inner, text="covers  " + ",  ".join(card.names), bg=p.surface2, fg=p.faint, font=theme.f_tiny, anchor="w",
                              justify="left", wraplength=300)
            covers.pack(fill="x", pady=(2, 0))
            autowrap(covers, inner)


class KeyValue(tk.Frame):
    """A label/value row (the Home screen's environment card)."""

    def __init__(self, parent: tk.Misc, theme: Theme, label: str, value: str, kind: str = "muted", pill: Optional[str] = None) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg)
        tk.Label(self, text=label, bg=bg, fg=p.muted, font=theme.f_small, anchor="w", width=16).pack(side="left")
        if pill:
            Pill(self, theme, pill, kind, bg=bg, dot=True, font=theme.f_tiny, pady=1).pack(side="left", padx=(0, 8))
        tk.Label(self, text=value, bg=bg, fg=p.text, font=theme.f_small, anchor="w", justify="left", wraplength=360).pack(side="left", fill="x")
