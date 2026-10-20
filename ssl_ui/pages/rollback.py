# Author: Sagar K | 2026 | MIT licence
"""Rollback: put the previous files back from the last backup."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Optional

from ssl_ui import services
from ssl_ui.components import ResultList
from ssl_ui.pages.base import Page
from ssl_ui.widgets import Button, Card, Combo, ConfirmDialog, Field, PathField, Toggle


class RollbackPage(Page):
    key = "rollback"
    title = "Rollback"
    subtitle = "Something wrong after a deploy? Restore the files from the last backup."

    def build(self) -> None:
        p, theme, state = self.p, self.theme, self.app.state
        self.config_var = tk.StringVar(value=state.get("config") or "")
        self.server_var = tk.StringVar(value="(all servers)")
        self.snapshot_var = tk.StringVar()
        self.dry = tk.BooleanVar(value=True)
        self.restart = tk.BooleanVar(value=False)
        self.trust = tk.BooleanVar(value=False)
        left, right = self.columns(left_min=420, right_min=460, ratio=(5, 6))

        what = Card(left, theme, "What to restore", "Uses the same config you deployed with.", accent=p.warn)
        what.pack(fill="x", pady=(0, 14))
        PathField(what.body, theme, "Deployment config (.yaml)", self.config_var, mode="file",
                  filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*.*")], on_change=lambda _v: self._servers()).pack(fill="x", pady=(0, 8))
        self.server_combo = Combo(what.body, theme, "Only this server (optional)", ["(all servers)"], self.server_var, readonly=True)
        self.server_combo.pack(fill="x", pady=(0, 8))
        Field(what.body, theme, "Specific backup (optional)", self.snapshot_var, hint="Leave empty for the newest. Format: 20261017_232251").pack(fill="x")

        safety = Card(left, theme, "Safety", None, accent=p.danger)
        safety.pack(fill="x", pady=(0, 14))
        Toggle(safety.body, theme, "Dry run — preview only", self.dry, hint="Shows what would be restored without touching the server.",
               command=lambda _v: self._restyle()).pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Reload services afterwards", self.restart, hint="Restored files only take effect once the service reloads.").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Trust new SSH host keys", self.trust, hint="First connection only.").pack(fill="x", pady=4)
        self.run_btn = Button(self.footer, theme, "Preview rollback", self.run, icon="\u21ba", padx=28, pady=9)
        self.run_btn.pack(side="left")
        self.mode_note = tk.Label(self.footer, text="Dry run is on: nothing will be restored.", bg=p.bg, fg=p.faint, font=theme.f_small)
        self.mode_note.pack(side="left", padx=14)

        how = Card(right, theme, "How rollback works", None, accent=p.accent)
        how.pack(fill="x", pady=(0, 14))
        for text in (
            "Every deploy copies each file it replaces into a private backup folder on the server before writing anything.",
            "Rollback copies those files back — keeping their owner and permissions — and can reload the services.",
            "A file that did not exist before the deploy is removed again.",
        ):
            tk.Label(how.body, text="•  " + text, bg=p.surface, fg=p.muted, font=theme.f_small, anchor="w", justify="left", wraplength=480).pack(fill="x", pady=3)
        self.result_card = Card(right, theme, "Result", None, accent=p.success)
        self.result = ResultList(self.result_card.body, theme)
        self.result.pack(fill="x")

    def on_show(self) -> None:
        if not self.config_var.get() and self.app.state.get("config"):
            self.config_var.set(self.app.state.get("config"))
        self._servers()

    def _servers(self) -> None:
        path = self.config_var.get().strip()
        try:
            plan = services.load_plan(Path(path), self.app.ssh_config) if path else None
        except services.UiError:
            plan = None
        self.server_combo.set_values(["(all servers)"] + ([s.name for s in plan.servers] if plan else []))

    def _restyle(self) -> None:
        if self.dry.get():
            self.run_btn.set_text("Preview rollback", "\u21ba", kind="primary")
            self.mode_note.configure(text="Dry run is on: nothing will be restored.", fg=self.p.faint)
        else:
            self.run_btn.set_text("Roll back now", "\u21ba", kind="danger")
            self.mode_note.configure(text="Live: the files from the backup will be put back.", fg=self.p.warn)

    def run(self) -> None:
        config = self.config_var.get().strip()
        if not config:
            self.app.log("error", "Choose the deployment config first.")
            return
        server = self.server_var.get()
        options = dict(server=None if server == "(all servers)" else server, timestamp=self.snapshot_var.get().strip() or None,
                       restart=self.restart.get(), dry_run=self.dry.get(), trust_new_hosts=self.trust.get())
        if not options["dry_run"]:
            if not ConfirmDialog(self.app.root, self.theme, "Restore the previous files?",
                                 "The files from the chosen backup replace what is on the server now.", confirm="Roll back now",
                                 kind="danger", lines=[server, "backup: " + (options["timestamp"] or "newest")]).show():
                return
        self.result_card.pack_forget()
        self.run_btn.set_enabled(False)

        def job(ctx):
            return services.run_rollback(Path(config), terminal=ctx.term, password_prompt=ctx.ask_password,
                                         known_hosts=self.app.known_hosts, ssh_config=self.app.ssh_config, **options)

        def done(outcome, error):
            self.run_btn.set_enabled(True)
            if outcome is not None:
                self.result_card.pack(fill="x")
                self.result.show(outcome, dry_run=options["dry_run"])
                self.app.log("success" if outcome.ok else "error", "Rollback finished." if outcome.ok else "Rollback failed.")

        self.app.run_task("Previewing rollback" if options["dry_run"] else "Rolling back", job, done)
