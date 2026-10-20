# Author: Sagar K | 2026 | MIT licence
"""Copy to server: scp-style push, through jump hosts if needed."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Dict, List, Optional

from ssl_deploy.deployer import CopyItem
from ssl_ui import services
from ssl_ui.components import EmptyState, ResultList, RouteTimeline
from ssl_ui.pages.base import Page
from ssl_ui.widgets import Button, Card, Combo, ConfirmDialog, Dialog, Field, PathField, Pill, Toggle


class CopyItemDialog(Dialog):
    """Add or edit one file: where it comes from, where it goes, and (optionally) its mode."""

    def __init__(self, parent: tk.Misc, theme, item: Optional[Dict[str, str]] = None) -> None:
        super().__init__(parent, theme, "Add file", width=520)
        p = theme.p
        tk.Label(self.body, text="File to copy", bg=p.surface, fg=p.text, font=theme.f_h2, anchor="w").pack(fill="x", pady=(0, 10))
        self.src = tk.StringVar(value=(item or {}).get("src", ""))
        self.dest = tk.StringVar(value=(item or {}).get("dest", ""))
        self.mode = tk.StringVar(value=(item or {}).get("mode", ""))
        PathField(self.body, theme, "On this computer", self.src, mode="file").pack(fill="x", pady=(0, 8))
        self.dest_field = Field(self.body, theme, "On the server (absolute path)", self.dest, hint="e.g. /etc/nginx/ssl/site.crt — the SSH user must be able to write there")
        self.dest_field.pack(fill="x", pady=(0, 8))
        Field(self.body, theme, "Permissions (optional)", self.mode, hint="Octal, e.g. 644 or 600. Empty = 600 for keys, 644 otherwise.", width=10).pack(fill="x")
        row = tk.Frame(self.body, bg=p.surface)
        row.pack(fill="x", pady=(16, 0))
        Button(row, theme, "Save", self._save, padx=22).pack(side="right")
        Button(row, theme, "Cancel", lambda: self.finish(None), kind="ghost", padx=18).pack(side="right", padx=(0, 10))

    def _save(self) -> None:
        src, dest, mode = self.src.get().strip(), self.dest.get().strip(), self.mode.get().strip()
        if not src:
            return
        if dest and not dest.startswith("/"):
            self.dest_field.set_error("Must start with /")
            return
        if mode and (not mode.isdigit() or any(c not in "01234567" for c in mode) or len(mode) not in (3, 4)):
            self.dest_field.set_error("Permissions must be octal like 644")
            return
        self.finish({"src": src, "dest": dest, "mode": mode})


class CopyPage(Page):
    key = "copy"
    title = "Copy to server"
    subtitle = "Send files over SSH — verified, atomic, backed up, and restored if anything fails."

    def build(self) -> None:
        p, theme, state = self.p, self.theme, self.app.state
        self.host_var = tk.StringVar(value=state.get("copy_host") or "")
        self.via_var = tk.StringVar(value=state.get("copy_via") or "")
        self.user_var = tk.StringVar(value=state.get("copy_user") or "")
        self.check_var = tk.StringVar()
        self.reload_var = tk.StringVar()
        self.backup_var = tk.StringVar()
        self.dry = tk.BooleanVar(value=True)
        self.trust = tk.BooleanVar(value=False)
        self.skip_verify = tk.BooleanVar(value=False)
        self.items: List[Dict[str, str]] = []
        self._route_job: Optional[str] = None
        left, right = self.columns(left_min=420, right_min=460, ratio=(5, 6))

        target = Card(left, theme, "Target", "An alias from your ~/.ssh/config (jump hosts are followed), or user@host:port.", accent=p.accent)
        target.pack(fill="x", pady=(0, 14))
        self.host_combo = Combo(target.body, theme, "Host", services.ssh_aliases(self.app.ssh_config), self.host_var)
        self.host_combo.pack(fill="x", pady=(0, 8))
        row = tk.Frame(target.body, bg=p.surface)
        row.pack(fill="x")
        row.columnconfigure((0, 1), weight=1, uniform="v")
        Field(row, theme, "Via jump host(s) (optional)", self.via_var, hint="Aliases or user@host, comma separated").grid(row=0, column=0, sticky="new", padx=(0, 6))
        Field(row, theme, "SSH user (optional)", self.user_var, hint="Overrides the alias").grid(row=0, column=1, sticky="new", padx=(6, 0))
        tk.Label(target.body, text="ROUTE", bg=p.surface, fg=p.faint, font=theme.f_tiny, anchor="w").pack(fill="x", pady=(14, 4))
        self.route = RouteTimeline(target.body, theme)
        self.route.pack(fill="x")
        for var in (self.host_var, self.via_var, self.user_var):
            var.trace_add("write", lambda *_a: self._schedule_route())

        safety = Card(left, theme, "Checks & safety", "Run a check on the server; if it fails, everything copied is restored.", accent=p.warn)
        safety.pack(fill="x", pady=(0, 14))
        Field(safety.body, theme, "After copying, check with (optional)", self.check_var, hint="e.g. nginx -t   or   httpd -t").pack(fill="x", pady=(0, 8))
        Field(safety.body, theme, "Then reload with (optional)", self.reload_var, hint="e.g. systemctl reload nginx").pack(fill="x", pady=(0, 10))
        Toggle(safety.body, theme, "Dry run — preview only", self.dry, hint="Resolves the route and lists what would be copied; connects to nothing.",
               command=lambda _v: self._restyle()).pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Trust new SSH host keys", self.trust, hint="First connection only. A changed key is always refused.").pack(fill="x", pady=4)
        Toggle(safety.body, theme, "Skip certificate checks", self.skip_verify, hint="Not recommended.").pack(fill="x", pady=4)

        files = Card(right, theme, "Files", "Double-click a row to edit it.", accent=p.accent2)
        files.pack(fill="x", pady=(0, 14))
        bar = tk.Frame(files.body, bg=p.surface)
        bar.pack(fill="x", pady=(0, 8))
        Button(bar, theme, "Add file", self.add_item, kind="ghost", icon="+", padx=14, pady=5, font=theme.f_small).pack(side="left")
        Button(bar, theme, "Edit", self.edit_item, kind="quiet", padx=12, pady=5, font=theme.f_small).pack(side="left", padx=6)
        Button(bar, theme, "Remove", self.remove_item, kind="quiet", padx=12, pady=5, font=theme.f_small).pack(side="left")
        self.tree = ttk.Treeview(files.body, columns=("src", "dest", "mode"), show="headings", height=5, selectmode="browse")
        for column, text, width in (("src", "File", 170), ("dest", "On the server", 230), ("mode", "Mode", 56)):
            self.tree.heading(column, text=text, anchor="w")
            self.tree.column(column, width=width, anchor="w", stretch=column == "dest", minwidth=50)
        self.tree.pack(fill="x")
        self.tree.bind("<Double-1>", lambda _e: self.edit_item())
        self.tree.tag_configure("missing", foreground=p.warn)
        self.empty = EmptyState(files.body, theme, "⇄", "No files yet", "Add the certificate and key you want on the server.", bg=p.surface)

        self.run_btn = Button(self.footer, theme, "Preview copy", self.run, icon="\u21c4", padx=28, pady=9)
        self.run_btn.pack(side="left")
        self.mode_note = tk.Label(self.footer, text="Dry run is on: connects to nothing.", bg=p.bg, fg=p.faint, font=theme.f_small)
        self.mode_note.pack(side="left", padx=14)
        self.result_card = Card(right, theme, "Result", None, accent=p.success)
        self.result = ResultList(self.result_card.body, theme)
        self.result.pack(fill="x")
        self._refresh_tree()
        self._schedule_route(50)

    def on_show(self) -> None:
        self.host_combo.set_values(services.ssh_aliases(self.app.ssh_config))

    # -- route ----------------------------------------------------------------------------------
    def _schedule_route(self, delay: int = 300) -> None:
        if self._route_job:
            self.after_cancel(self._route_job)
        self._route_job = self.after(delay, self._update_route)

    def _update_route(self) -> None:
        self._route_job = None
        host = self.host_var.get().strip()
        if not host:
            self.route.set([], None)
            return
        view = services.preview_route(host, self.via_var.get(), self.user_var.get(), self.app.ssh_config)
        self.route.set(view.hops, view.error)
        if not view.error:
            for key, var in (("copy_host", self.host_var), ("copy_via", self.via_var), ("copy_user", self.user_var)):
                self.app.state.set(key, var.get())

    # -- files ------------------------------------------------------------------------------------
    def _refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.items):
            dest = item["dest"] or "⟵ set the path on the server"
            self.tree.insert("", "end", iid=str(index), values=(Path(item["src"]).name, dest, item["mode"] or "auto"),
                             tags=("missing",) if not item["dest"] else ())
        self.tree.configure(height=max(3, min(8, len(self.items) or 3)))
        if self.items:
            self.empty.pack_forget()
        else:
            self.empty.pack(fill="x")

    def add_generated(self, folder: Path, domain: str) -> None:
        """Called by the Certificates screen: pre-fill the certificate and key it just generated."""
        for name in (f"main_{domain}.crt", f"{domain}.key"):
            path = Path(folder) / name
            if path.is_file() and not any(i["src"] == str(path) for i in self.items):
                self.items.append({"src": str(path), "dest": "", "mode": ""})
        self._refresh_tree()

    def add_item(self) -> None:
        item = CopyItemDialog(self.app.root, self.theme).show()
        if item:
            self.items.append(item)
            self._refresh_tree()

    def _selected(self) -> Optional[int]:
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def edit_item(self) -> None:
        index = self._selected()
        if index is None:
            return
        item = CopyItemDialog(self.app.root, self.theme, self.items[index]).show()
        if item:
            self.items[index] = item
            self._refresh_tree()

    def remove_item(self) -> None:
        index = self._selected()
        if index is not None:
            del self.items[index]
            self._refresh_tree()

    # -- run -----------------------------------------------------------------------------------------
    def _restyle(self) -> None:
        if self.dry.get():
            self.run_btn.set_text("Preview copy", "\u21c4", kind="primary")
            self.mode_note.configure(text="Dry run is on: connects to nothing.", fg=self.p.faint)
        else:
            self.run_btn.set_text("Copy now", "\u21c4", kind="danger")
            self.mode_note.configure(text="Live: files will be sent to the server.", fg=self.p.warn)

    def run(self) -> None:
        if not self.items:
            self.app.log("error", "Add at least one file first.")
            return
        missing = [Path(i["src"]).name for i in self.items if not i["dest"]]
        if missing:
            self.app.log("error", f"Set the path on the server for: {', '.join(missing)}")
            return
        copy_items = [CopyItem(Path(i["src"]), i["dest"], int(i["mode"], 8) if i["mode"] else None) for i in self.items]
        host, via, user = self.host_var.get(), self.via_var.get(), self.user_var.get()
        options = dict(check_cmd=self.check_var.get().strip(), reload_cmd=self.reload_var.get().strip(), dry_run=self.dry.get(),
                       skip_verify=self.skip_verify.get(), trust_new_hosts=self.trust.get(), backup_dir=self.backup_var.get().strip() or None)
        dry = options["dry_run"]
        if not dry:
            view = services.preview_route(host, via, user, self.app.ssh_config)
            lines = [" ➜ ".join(view.hops) or host] + [f"{Path(i['src']).name} → {i['dest']}" for i in self.items]
            if not ConfirmDialog(self.app.root, self.theme, "Copy these files?", "The old version of each file is backed up first, "
                                 "and everything is restored if a step fails.", confirm="Copy now", kind="danger", lines=lines).show():
                return
        self.result_card.pack_forget()
        self.run_btn.set_enabled(False)

        def job(ctx):
            return services.run_copy(copy_items, terminal=ctx.term, host=host, via=via, user=user, password_prompt=ctx.ask_password,
                                     known_hosts=self.app.known_hosts, ssh_config=self.app.ssh_config, **options)

        def done(outcome, error):
            self.run_btn.set_enabled(True)
            if outcome is not None:
                self.result_card.pack(fill="x")
                self.result.show(outcome, dry_run=dry)
                self.app.log("success" if outcome.ok else "error", "Copy finished." if outcome.ok else "Copy failed.")

        self.app.run_task("Previewing copy" if dry else "Copying", job, done)
