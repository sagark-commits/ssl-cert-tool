# Author: Sagar K | 2026 | MIT licence
"""Deploy: roll a certificate folder out to the servers in a config, preview first."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Optional

from ssl_ui import services
from ssl_ui.components import EmptyState, ResultList, RouteTimeline
from ssl_ui.pages.base import Page
from ssl_ui.widgets import Button, Card, Combo, ConfirmDialog, PathField, Pill, Toggle, autowrap


class DeployPage(Page):
    key = "deploy"
    title = "Deploy"
    subtitle = "Roll certificates out to your servers — preview first, every file backed up."

    PICK = "Pick a saved config\u2026"

    def build(self) -> None:
        p, theme, state = self.p, self.theme, self.app.state
        self.config_var = tk.StringVar(value=state.get("config") or "")
        self.certdir_var = tk.StringVar(value=state.get("cert_dir") or "")
        self.quick_var = tk.StringVar(value=self.PICK)
        self.server_var = tk.StringVar(value="(all servers)")
        self.dry = tk.BooleanVar(value=True)
        self.trust = tk.BooleanVar(value=False)
        self.skip_verify = tk.BooleanVar(value=False)
        self.auto_rollback = tk.BooleanVar(value=True)
        self.no_restart = tk.BooleanVar(value=False)
        self.preflight = tk.BooleanVar(value=False)
        self.plan: Optional[services.PlanView] = None
        self._plan_job: Optional[str] = None
        self._last_state_dir = self.certdir_var.get()
        left, right = self.columns(left_min=420, right_min=460, ratio=(5, 6))

        what = Card(left, theme, "What to deploy", "A config says which servers and services; the folder holds the generated files.", accent=p.accent)
        what.pack(fill="x", pady=(0, 14))
        self.quick = Combo(what.body, theme, "Saved configs", [], self.quick_var, readonly=True, on_change=self._quick_pick)
        self.quick.pack(fill="x", pady=(0, 8))
        PathField(what.body, theme, "Deployment config (.yaml)", self.config_var, mode="file",
                  filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*.*")], on_change=lambda _v: self._schedule_plan()).pack(fill="x", pady=(0, 8))
        PathField(what.body, theme, "Certificate folder", self.certdir_var, mode="dir",
                  hint="Usually the folder Generate just created.").pack(fill="x")
        self.server_combo = Combo(what.body, theme, "Only this server (optional)", ["(all servers)"], self.server_var, readonly=True)
        self.server_combo.pack(fill="x", pady=(8, 0))

        safety = Card(left, theme, "Safety", "Defaults are the cautious choice.", accent=p.warn)
        safety.pack(fill="x", pady=(0, 14))
        Toggle(safety.body, theme, "Dry run — preview only", self.dry, hint="Shows exactly what would happen. Nothing is changed.",
               command=lambda _v: self._restyle()).pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Trust new SSH host keys", self.trust, hint="First connection only. A changed key is always refused.").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Restore files if a check fails", self.auto_rollback, hint="A failing hook stops the restart and puts the old files back.").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Don't restart services", self.no_restart, hint="Upload only; restart them yourself later.").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Pre-flight status check", self.preflight, hint="Reads each server's service status first (can be slow).").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Skip certificate checks", self.skip_verify, hint="Not recommended: deploys even if the key doesn't match.").pack(fill="x", pady=4)

        self.run_btn = Button(self.footer, theme, "Preview deployment", self.run, icon="\u21ea", padx=28, pady=9)
        self.run_btn.pack(side="left")
        tk.Label(self.footer, text="Dry run is on: nothing will be changed.", bg=p.bg, fg=p.faint, font=theme.f_small).pack(side="left", padx=14)
        self.mode_note = self.footer.winfo_children()[-1]

        self.plan_card = Card(right, theme, "Plan", "Servers and services in this config.", accent=p.accent2)
        self.plan_card.pack(fill="x", pady=(0, 14))
        self.plan_body = tk.Frame(self.plan_card.body, bg=p.surface)
        self.plan_body.pack(fill="x")
        self.result_card = Card(right, theme, "Result", None, accent=p.success)
        self.result = ResultList(self.result_card.body, theme)
        self.result.pack(fill="x")
        self._show_plan_empty()

    # -- navigation hooks -------------------------------------------------------------------
    def on_show(self) -> None:
        names = self.app.state.get("configs_seen", [])
        env_configs = services.env_status(self.app.configs_dir, self.app.ssh_config).configs
        self.quick.set_values(env_configs or names)
        state_dir = self.app.state.get("cert_dir") or ""
        if state_dir and state_dir != self._last_state_dir:
            self._last_state_dir = state_dir
            self.certdir_var.set(state_dir)
        if self.config_var.get() and self.plan is None:
            self._schedule_plan(50)

    def _quick_pick(self, name: str) -> None:
        if name and name != self.PICK and self.app.configs_dir:
            self.config_var.set(str(Path(self.app.configs_dir) / name))

    # -- plan ---------------------------------------------------------------------------------
    def _schedule_plan(self, delay: int = 350) -> None:
        if self._plan_job:
            self.after_cancel(self._plan_job)
        self._plan_job = self.after(delay, self.reload_plan)

    def _clear(self, frame: tk.Frame) -> None:
        for child in frame.winfo_children():
            child.destroy()

    def _show_plan_empty(self, message: Optional[str] = None) -> None:
        self._clear(self.plan_body)
        if message:
            Pill(self.plan_body, self.theme, message, "danger", bg=self.p.surface).pack(anchor="w")
        else:
            EmptyState(self.plan_body, self.theme, "⇪", "Pick a config to see the plan",
                       "You'll see every server, how it will be reached (including jump hosts) and which files go where.",
                       bg=self.p.surface).pack(fill="x")

    def reload_plan(self) -> None:
        self._plan_job = None
        path = self.config_var.get().strip()
        self.plan = None
        if not path:
            self._show_plan_empty()
            return
        try:
            self.plan = services.load_plan(Path(path), self.app.ssh_config)
        except services.UiError as exc:
            self._show_plan_empty(str(exc))
            return
        self.app.state.set("config", path)
        p, theme = self.p, self.theme
        self._clear(self.plan_body)
        head = tk.Frame(self.plan_body, bg=p.surface)
        head.pack(fill="x", pady=(0, 8))
        Pill(head, theme, self.plan.domain, "accent", bg=p.surface).pack(side="left")
        Pill(head, theme, f"{len(self.plan.servers)} server(s)", "muted", bg=p.surface).pack(side="left", padx=8)
        self.server_combo.set_values(["(all servers)"] + [s.name for s in self.plan.servers])
        for server in self.plan.servers:
            box = tk.Frame(self.plan_body, bg=p.surface2, highlightthickness=1, highlightbackground=p.border)
            box.pack(fill="x", pady=5)
            inner = tk.Frame(box, bg=p.surface2)
            inner.pack(fill="x", padx=14, pady=10)
            top = tk.Frame(inner, bg=p.surface2)
            top.pack(fill="x")
            tk.Label(top, text=server.name, bg=p.surface2, fg=p.text, font=theme.f_bold).pack(side="left")
            Pill(top, theme, f"{len(server.services)} service(s)", "muted", bg=p.surface2, font=theme.f_tiny, pady=1).pack(side="right")
            if server.error:
                Pill(inner, theme, server.error, "danger", bg=p.surface2, font=theme.f_tiny).pack(anchor="w", pady=(6, 0))
            else:
                RouteTimelineInline(inner, theme, server.route, p.surface2).pack(fill="x", pady=(6, 4))
            for name, kind, where in server.services:
                line = tk.Frame(inner, bg=p.surface2)
                line.pack(fill="x", pady=2)
                head = tk.Frame(line, bg=p.surface2)
                head.pack(fill="x")
                Pill(head, theme, kind, "info", bg=p.surface2, font=theme.f_tiny, pady=0).pack(side="left")
                tk.Label(head, text=name, bg=p.surface2, fg=p.text, font=theme.f_small).pack(side="left", padx=(8, 0))
                path = tk.Label(line, text=where, bg=p.surface2, fg=p.faint, font=theme.f_mono_small, anchor="w", justify="left", wraplength=300)
                path.pack(fill="x", padx=(2, 0))
                autowrap(path, line)

    # -- run ---------------------------------------------------------------------------------------
    def _restyle(self) -> None:
        if self.dry.get():
            self.run_btn.set_text("Preview deployment", "\u21ea", kind="primary")
            self.mode_note.configure(text="Dry run is on: nothing will be changed.", fg=self.p.faint)
        else:
            self.run_btn.set_text("Deploy now", "\u21ea", kind="danger")
            self.mode_note.configure(text="Live: files will be uploaded and services may restart.", fg=self.p.warn)

    def run(self) -> None:
        config, certdir = self.config_var.get().strip(), self.certdir_var.get().strip()
        if not config or not certdir:
            self.app.log("error", "Choose a deployment config and a certificate folder first.")
            return
        server = self.server_var.get()
        options = services.DeployOptions(
            dry_run=self.dry.get(), trust_new_hosts=self.trust.get(), skip_verify=self.skip_verify.get(),
            auto_rollback=self.auto_rollback.get(), no_restart=self.no_restart.get(), preflight=self.preflight.get(),
            server=None if server == "(all servers)" else server,
        )
        if not options.dry_run:
            scope = [s for s in (self.plan.servers if self.plan else []) if not options.server or s.name == options.server]
            lines = [f"{s.name}  →  {len(s.services)} service(s)" for s in scope] or ["(servers from the config)"]
            if not ConfirmDialog(self.app.root, self.theme, "Deploy to your servers?",
                                 "This uploads the files and may restart services. Every file it replaces is backed up first, "
                                 "and you can roll back from the Rollback screen.", confirm="Deploy now", kind="danger", lines=lines).show():
                return
        self.result_card.pack_forget()
        self.run_btn.set_enabled(False)

        def job(ctx):
            return services.run_deploy(Path(config), Path(certdir), options, terminal=ctx.term, password_prompt=ctx.ask_password,
                                       known_hosts=self.app.known_hosts, ssh_config=self.app.ssh_config)

        def done(outcome, error):
            self.run_btn.set_enabled(True)
            if outcome is not None:
                self.result_card.pack(fill="x")
                self.result.show(outcome, dry_run=options.dry_run)
                self.app.state.set("cert_dir", certdir)
                self.app.log("success" if outcome.ok else "error",
                             "Preview finished." if outcome.ok and options.dry_run else "Deployment finished." if outcome.ok else "Deployment finished with errors.")

        self.app.run_task("Previewing" if options.dry_run else "Deploying", job, done)


class RouteTimelineInline(tk.Frame):
    """A one-line route: user@host -> user@host (compact version for the plan)."""

    def __init__(self, parent: tk.Misc, theme, hops, bg: str) -> None:
        super().__init__(parent, bg=bg)
        p = theme.p
        for index, hop in enumerate(hops):
            if index:
                tk.Label(self, text="➜", bg=bg, fg=p.faint, font=theme.f_small).pack(side="left", padx=6)
            last = index == len(hops) - 1
            tk.Label(self, text=hop, bg=bg, fg=p.success if last else p.accent2, font=theme.f_mono_small).pack(side="left")
