"""Certificates: inspect a bundle, check the key, generate the deployment files."""
from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import List, Optional

from ssl_ui import services
from ssl_ui.components import CertRow, EmptyState
from ssl_ui.pages.base import Page
from ssl_ui.widgets import Button, Card, Disclosure, Field, PathField, Pill, autowrap

# (suffix test, what the file is for) - first match wins
PURPOSE = [
    (lambda n: n.endswith(".jks"), "Java keystore (Tomcat, Ameyo)"),
    (lambda n: n.endswith((".p12", ".pfx")), "PKCS#12 keystore"),
    (lambda n: n.endswith(".key"), "Private key — keep it secret"),
    (lambda n: n.startswith("main_") and n.endswith(".crt"), "Server certificate"),
    (lambda n: n.startswith("asterisk") and n.endswith(".pem"), "Asterisk: key + chain"),
    (lambda n: n.startswith("asterisk") and n.endswith(".crt"), "Asterisk chain"),
    (lambda n: n in ("chain.crt", "crm-ca.crt") or n.endswith(".ca-bundle"), "CA chain (Apache, Nginx)"),
    (lambda n: n.startswith(("intermediate_", "root_")), "CA certificate"),
    (lambda n: n.endswith(".pem"), "Full chain PEM"),
]


def describe_file(name: str) -> str:
    lowered = name.lower()
    for test, text in PURPOSE:
        if test(lowered):
            return text
    return ""


def human_size(size: int) -> str:
    return f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB"


def open_folder(path: Path) -> None:
    try:
        if sys.platform == "win32":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError:
        pass


class CertsPage(Page):
    key = "certs"
    title = "Certificates"
    subtitle = "Inspect what the CA sent, then generate every format your servers need."

    def build(self) -> None:
        p, theme, state = self.p, self.theme, self.app.state
        self.sources: List[Path] = [Path(s) for s in state.get("sources", []) if Path(s).exists()]
        self.key_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.domain_var = tk.StringVar()
        self.out_var = tk.StringVar(value=state.get("output_dir") or str(Path.cwd() / "output"))
        self.store_var = tk.StringVar(value="changeit")
        self.alias_var = tk.StringVar(value="ameyo-server")
        self._inspect_job: Optional[str] = None
        self.last_inspect: Optional[services.InspectView] = None
        self.last_generated: Optional[services.GenerateView] = None
        left, right = self.columns(left_min=420, right_min=460)

        # ---- 1. sources -------------------------------------------------------------
        src = Card(left, theme, "1 · Source files", "Certificates, a zip, an email, a .p7b — whatever the CA sent. Add several.", accent=p.accent)
        src.pack(fill="x", pady=(0, 14))
        box = tk.Frame(src.body, bg=p.surface)
        box.pack(fill="x")
        self.listbox = tk.Listbox(box, height=4, bg=p.field, fg=p.text, selectbackground=p.accent, selectforeground="#ffffff",
                                  relief="flat", bd=0, highlightthickness=1, highlightbackground=p.border, highlightcolor=p.accent,
                                  activestyle="none", font=theme.f_body, exportselection=False)
        self.listbox.pack(fill="x", ipady=4)
        buttons = tk.Frame(src.body, bg=p.surface)
        buttons.pack(fill="x", pady=(8, 12))
        Button(buttons, theme, "Add files", self.add_files, kind="ghost", icon="+", padx=14, pady=5, font=theme.f_small).pack(side="left")
        Button(buttons, theme, "Add folder", self.add_folder, kind="ghost", icon="+", padx=14, pady=5, font=theme.f_small).pack(side="left", padx=6)
        Button(buttons, theme, "Remove", self.remove_selected, kind="quiet", padx=12, pady=5, font=theme.f_small).pack(side="left")
        Button(buttons, theme, "Clear", self.clear_sources, kind="quiet", padx=12, pady=5, font=theme.f_small).pack(side="left", padx=6)
        PathField(src.body, theme, "Private key (only if it isn't inside the files above)", self.key_var, mode="file",
                  filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")], on_change=lambda _v: self._schedule_inspect()).pack(fill="x", pady=(0, 8))
        more = Disclosure(src.body, theme, "More options")
        more.pack(fill="x")
        row = tk.Frame(more.body, bg=p.surface)
        row.pack(fill="x")
        row.columnconfigure((0, 1), weight=1, uniform="a")
        Field(row, theme, "Key passphrase", self.pass_var, show="\u2022", hint="Only if the key is encrypted").grid(row=0, column=0, sticky="new", padx=(0, 6))
        Field(row, theme, "Domain", self.domain_var, hint="Empty = detect it").grid(row=0, column=1, sticky="new", padx=(6, 0))
        for var in (self.pass_var, self.domain_var):
            var.trace_add("write", lambda *_a: self._schedule_inspect())

        # ---- 2. generate -------------------------------------------------------------
        gen = Card(left, theme, "2 · Create deployment files", "JKS, PKCS#12, PEM, chain and Asterisk files, ready to deploy.", accent=p.accent2)
        gen.pack(fill="x")
        PathField(gen.body, theme, "Output folder", self.out_var, mode="dir").pack(fill="x", pady=(0, 8))
        row2 = tk.Frame(gen.body, bg=p.surface)
        row2.pack(fill="x")
        row2.columnconfigure((0, 1), weight=1, uniform="b")
        pw_box = tk.Frame(row2, bg=p.surface)
        pw_box.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        Field(pw_box, theme, "Keystore password", self.store_var, show="•").pack(fill="x")
        self.default_pw_pill = Pill(pw_box, theme, "default \u2014 testing only", "warn", bg=p.surface, font=theme.f_tiny, pady=1)
        Field(row2, theme, "Alias", self.alias_var).grid(row=0, column=1, sticky="new", padx=(6, 0))
        self.store_var.trace_add("write", lambda *_a: self._pw_hint())
        self._pw_hint()
        env = services.env_status(self.app.configs_dir, self.app.ssh_config)
        how = f"Java keytool will build the .jks ({Path(env.keytool).name})" if env.keytool else "No Java needed — the built-in writer builds the .jks"
        how_label = tk.Label(gen.body, text="\u2139  " + how, bg=p.surface, fg=p.muted, font=theme.f_small, anchor="w", justify="left", wraplength=360)
        how_label.pack(fill="x", pady=(10, 12))
        autowrap(how_label, gen.body)
        self.generate_btn = Button(self.footer, theme, "Generate files", self.generate, icon="\u25c8", padx=28, pady=9)
        self.generate_btn.pack(side="left")
        tk.Label(self.footer, text="Creates the files in the output folder (step 2).", bg=p.bg, fg=p.faint, font=theme.f_small).pack(side="left", padx=14)

        # ---- results ---------------------------------------------------------------------
        self.chain_card = Card(right, theme, "Certificate chain", "Updates as you add files.", accent=p.accent)
        self.chain_card.pack(fill="x", pady=(0, 14))
        self.chain_body = tk.Frame(self.chain_card.body, bg=p.surface)
        self.chain_body.pack(fill="x")
        self.gen_card = Card(right, theme, "Generated files", None, accent=p.success)
        self.gen_body = tk.Frame(self.gen_card.body, bg=p.surface)
        self.gen_body.pack(fill="x")
        self._refresh_list()
        self._show_empty()

    # -- inputs ---------------------------------------------------------------------------
    def _pw_hint(self) -> None:
        if self.store_var.get() == "changeit":
            self.default_pw_pill.pack(anchor="w", pady=(4, 0))
        else:
            self.default_pw_pill.pack_forget()

    def _refresh_list(self) -> None:
        self.listbox.delete(0, "end")
        for path in self.sources:
            self.listbox.insert("end", f"  {path.name or path}")
        self.listbox.configure(height=max(3, min(6, len(self.sources))))
        self.app.state.set("sources", [str(s) for s in self.sources])

    def add_files(self) -> None:
        chosen = filedialog.askopenfilenames(title="Add certificate files", filetypes=[("Certificate files", "*.crt *.cer *.pem *.p7b *.p7c *.p12 *.pfx *.eml *.zip *.7z *.docx *.txt *.key"), ("All files", "*.*")])
        self._add([Path(c) for c in chosen])

    def add_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Add a folder of certificate files")
        if chosen:
            self._add([Path(chosen)])

    def _add(self, paths: List[Path]) -> None:
        for path in paths:
            if path not in self.sources:
                self.sources.append(path)
        self._refresh_list()
        self._schedule_inspect(delay=50)

    def remove_selected(self) -> None:
        for index in reversed(self.listbox.curselection()):
            del self.sources[index]
        self._refresh_list()
        self._schedule_inspect(delay=50)

    def clear_sources(self) -> None:
        self.sources.clear()
        self._refresh_list()
        self._schedule_inspect(delay=50)

    # -- inspect -----------------------------------------------------------------------------
    def _schedule_inspect(self, delay: int = 450) -> None:
        if self._inspect_job:
            self.after_cancel(self._inspect_job)
        self._inspect_job = self.after(delay, self.run_inspect)

    def run_inspect(self) -> None:
        self._inspect_job = None
        if not self.sources:
            self._show_empty()
            return
        if self.app.runner.busy:
            self._schedule_inspect(500)
            return
        sources, key = list(self.sources), (Path(self.key_var.get()) if self.key_var.get().strip() else None)
        password, domain = self.pass_var.get(), self.domain_var.get().strip()
        self.app.run_task("Inspecting", lambda ctx: services.inspect_paths(sources, key, password, domain), self._inspected, quiet=True)

    def _clear(self, frame: tk.Frame) -> None:
        for child in frame.winfo_children():
            child.destroy()

    def _show_empty(self) -> None:
        self._clear(self.chain_body)
        EmptyState(self.chain_body, self.theme, "◈", "Nothing to inspect yet", "Add the files you received — the chain, expiry dates and "
                   "key match appear here automatically.", bg=self.p.surface).pack(fill="x")

    def _inspected(self, view: Optional[services.InspectView], error: Optional[BaseException]) -> None:
        p, theme = self.p, self.theme
        self._clear(self.chain_body)
        if error is not None:
            Pill(self.chain_body, theme, str(error), "danger", bg=p.surface).pack(anchor="w")
            return
        assert view is not None
        self.last_inspect = view
        head = tk.Frame(self.chain_body, bg=p.surface)
        head.pack(fill="x", pady=(0, 10))
        Pill(head, theme, f"{len(view.certs)} certificate(s)", "info", bg=p.surface).pack(side="left")
        Pill(head, theme, f"{view.files_scanned} file(s) scanned", "muted", bg=p.surface).pack(side="left", padx=8)
        if view.certs:
            for card in view.certs:
                CertRow(self.chain_body, theme, card).pack(fill="x", pady=4)
        else:
            tk.Label(self.chain_body, text="No certificates were found in these files.", bg=p.surface, fg=p.warn, font=theme.f_body).pack(anchor="w")
        keys = tk.Frame(self.chain_body, bg=p.surface)
        keys.pack(fill="x", pady=(10, 0))
        if view.keys:
            for name, match in view.keys:
                line = tk.Frame(keys, bg=p.surface)
                line.pack(fill="x", pady=2)
                if match is None:
                    Pill(line, theme, "KEY", "muted", bg=p.surface, font=theme.f_tiny, pady=1).pack(side="left")
                else:
                    Pill(line, theme, "KEY MATCHES" if match else "DOES NOT MATCH", "success" if match else "danger", dot=True, bg=p.surface,
                         font=theme.f_tiny, pady=1).pack(side="left")
                tk.Label(line, text=name, bg=p.surface, fg=p.muted, font=theme.f_mono_small).pack(side="left", padx=10)
        else:
            Pill(keys, theme, "NO PRIVATE KEY FOUND — choose it in step 1", "warn", dot=True, bg=p.surface, font=theme.f_tiny, pady=1).pack(anchor="w")
        for note in dict.fromkeys(view.notes):
            hint = tk.Label(self.chain_body, text="\u2192  " + note, bg=p.surface, fg=p.muted, font=theme.f_small, anchor="w", justify="left", wraplength=320)
            hint.pack(fill="x", pady=(8, 0))
            autowrap(hint, self.chain_body)

    # -- generate ------------------------------------------------------------------------------
    def generate(self) -> None:
        if not self.sources:
            self.app.log("error", "Add the certificate files first.")
            return
        sources = list(self.sources)
        key = Path(self.key_var.get()) if self.key_var.get().strip() else None
        args = dict(key_path=key, key_password=self.pass_var.get(), domain=self.domain_var.get().strip() or None)
        out, store, alias = Path(self.out_var.get().strip() or "output"), self.store_var.get(), self.alias_var.get().strip()
        self.generate_btn.set_enabled(False)

        def job(ctx):
            ctx.log("detail", f"output folder: {out}")
            return services.generate_artifacts(sources, out, store, alias, **args)

        def done(view, error):
            self.generate_btn.set_enabled(True)
            if error is None and view is not None:
                self._generated(view)
                self.app.state.set("output_dir", str(out))
                self.app.state.set("cert_dir", str(view.output_dir))
                self.app.log("success", f"Created {len(view.files)} files in {view.output_dir}")
                for warning in view.warnings:
                    self.app.log("warn", warning)

        self.app.run_task("Generating files", job, done)

    def _generated(self, view: services.GenerateView) -> None:
        p, theme = self.p, self.theme
        self.last_generated = view
        self._clear(self.gen_body)
        self.gen_card.pack(fill="x")
        head = tk.Frame(self.gen_body, bg=p.surface)
        head.pack(fill="x", pady=(0, 8))
        Pill(head, theme, f"{len(view.files)} files created", "success", dot=True, bg=p.surface, font=theme.f_bold, padx=12, pady=3).pack(side="left")
        if view.jks:
            Pill(head, theme, "JKS by Java keytool" if view.jks == "keytool" else "JKS by built-in writer", "info", bg=p.surface).pack(side="left", padx=8)
        Pill(head, theme, f"expires {view.expires}", "muted", bg=p.surface).pack(side="left")
        where = tk.Label(self.gen_body, text=str(view.output_dir), bg=p.surface, fg=p.faint, font=theme.f_mono_small, anchor="w", wraplength=320,
                         justify="left")
        where.pack(fill="x", pady=(0, 6))
        autowrap(where, self.gen_body)
        for name, size in view.files:
            line = tk.Frame(self.gen_body, bg=p.surface)
            line.pack(fill="x", pady=1)
            # size and purpose are packed first so a long file name can never squeeze them out
            tk.Label(line, text=human_size(size), bg=p.surface, fg=p.faint, font=theme.f_tiny).pack(side="right")
            purpose = describe_file(name)
            if purpose:
                tk.Label(line, text=purpose, bg=p.surface, fg=p.muted, font=theme.f_tiny).pack(side="right", padx=12)
            tk.Label(line, text=name, bg=p.surface, fg=p.text, font=theme.f_mono_small, anchor="w").pack(side="left")
        for warning in view.warnings:
            caution = tk.Label(self.gen_body, text="\u26a0  " + warning, bg=p.surface, fg=p.warn, font=theme.f_small, anchor="w", justify="left", wraplength=320)
            caution.pack(fill="x", pady=(8, 0))
            autowrap(caution, self.gen_body)
        actions = tk.Frame(self.gen_body, bg=p.surface)
        actions.pack(fill="x", pady=(14, 0))
        Button(actions, self.theme, "Open folder", lambda: open_folder(view.output_dir), kind="ghost", padx=16, pady=6, font=theme.f_small).pack(side="left")
        Button(actions, self.theme, "Deploy these", lambda: self.app.navigate("deploy"), kind="success", icon="⇪", padx=16, pady=6,
               font=theme.f_small).pack(side="left", padx=8)
        Button(actions, self.theme, "Copy to a server", lambda: self._to_copy(view), kind="primary", icon="⇄", padx=16, pady=6,
               font=theme.f_small).pack(side="left")

    def _to_copy(self, view: services.GenerateView) -> None:
        page = self.app.page("copy")
        page.add_generated(view.output_dir, view.domain)
        self.app.navigate("copy")
