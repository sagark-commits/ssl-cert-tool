"""Keystores: open a .jks or .p12 and see what's inside (no Java needed)."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Optional

from ssl_ui import services
from ssl_ui.components import EmptyState, expiry_pill
from ssl_ui.pages.base import Page
from ssl_ui.widgets import Button, Card, Field, PathField, Pill, autowrap


class KeystorePage(Page):
    key = "keystore"
    title = "Keystores"
    subtitle = "Open a .jks or .p12 and see the alias, chain and expiry — no Java needed."

    def build(self) -> None:
        p, theme = self.p, self.theme
        self.path_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        left, right = self.columns(left_min=420, right_min=460, ratio=(4, 6))
        card = Card(left, theme, "Open a keystore", "JKS and PKCS#12 are both supported.", accent=p.info)
        card.pack(fill="x")
        PathField(card.body, theme, "Keystore file", self.path_var, mode="file",
                  filetypes=[("Keystores", "*.jks *.p12 *.pfx"), ("All files", "*.*")]).pack(fill="x", pady=(0, 8))
        password = Field(card.body, theme, "Password", self.pass_var, show="•")
        password.pack(fill="x", pady=(0, 14))
        password.entry.bind("<Return>", lambda _e: self.open())
        self.open_btn = Button(card.body, theme, "Open keystore", self.open, icon="⚿", padx=24, pady=9)
        self.open_btn.pack(anchor="w")
        self.info_card = Card(right, theme, "Contents", None, accent=p.accent)
        self.info_card.pack(fill="x")
        self.info_body = tk.Frame(self.info_card.body, bg=p.surface)
        self.info_body.pack(fill="x")
        self._empty()

    def _clear(self) -> None:
        for child in self.info_body.winfo_children():
            child.destroy()

    def _empty(self) -> None:
        self._clear()
        EmptyState(self.info_body, self.theme, "⚿", "No keystore open", "Choose a .jks or .p12 and enter its password.", bg=self.p.surface).pack(fill="x")

    def open(self) -> None:
        path, password = self.path_var.get().strip(), self.pass_var.get()
        if not path:
            self.app.log("error", "Choose a keystore file first.")
            return
        self.open_btn.set_enabled(False)

        def done(view: Optional[services.KeystoreView], error: Optional[BaseException]) -> None:
            self.open_btn.set_enabled(True)
            self._clear()
            if error is not None or view is None:
                Pill(self.info_body, self.theme, str(error), "danger", bg=self.p.surface).pack(anchor="w")
                return
            self._show(view)

        self.app.run_task("Opening keystore", lambda ctx: services.keystore_info(Path(path), password), done, quiet=True)

    def _show(self, view: services.KeystoreView) -> None:
        p, theme = self.p, self.theme
        head = tk.Frame(self.info_body, bg=p.surface)
        head.pack(fill="x", pady=(0, 10))
        text, kind = expiry_pill(view.days_left, view.expired)
        Pill(head, theme, text, kind, dot=True, bg=p.surface, font=theme.f_bold, padx=12, pady=3).pack(side="left")
        Pill(head, theme, view.key_type, "info", bg=p.surface).pack(side="left", padx=8)
        for label, value in (("Alias", view.alias), ("Domain", view.domain), ("Issued by", view.issuer), ("Expires", view.expires), ("File", view.path)):
            line = tk.Frame(self.info_body, bg=p.surface)
            line.pack(fill="x", pady=2)
            tk.Label(line, text=label, bg=p.surface, fg=p.muted, font=theme.f_small, width=11, anchor="w").pack(side="left")
            shown = tk.Label(line, text=value, bg=p.surface, fg=p.text, font=theme.f_mono_small if label == "File" else theme.f_body, anchor="w",
                             justify="left", wraplength=300)
            shown.pack(side="left", fill="x", expand=True)
            autowrap(shown, line, margin=100)
        tk.Label(self.info_body, text="CHAIN", bg=p.surface, fg=p.faint, font=theme.f_tiny, anchor="w").pack(fill="x", pady=(14, 4))
        for index, (cn, role) in enumerate(view.chain):
            line = tk.Frame(self.info_body, bg=p.surface)
            line.pack(fill="x", pady=2)
            Pill(line, theme, (role or "cert").upper(), "accent" if role == "leaf" else "muted", bg=p.surface, font=theme.f_tiny, pady=1).pack(side="left")
            tk.Label(line, text=cn, bg=p.surface, fg=p.text, font=theme.f_body).pack(side="left", padx=10)
