"""Home: what you can do, and what this machine is set up for."""
from __future__ import annotations

import tkinter as tk

from ssl_ui import services
from ssl_ui.components import KeyValue, Tile
from ssl_ui.pages.base import Page
from ssl_ui.render import render_gradient_bar
from ssl_ui.widgets import Card


class HomePage(Page):
    key = "home"
    title = "Home"
    subtitle = "Certificates, deployed with confidence."

    def build(self) -> None:
        p, theme = self.p, self.theme
        hero = tk.Frame(self.root_frame, bg=p.bg)
        hero.pack(fill="x", pady=(0, 18))
        tk.Label(hero, text="Parse it. Build it. Ship it — safely.", bg=p.bg, fg=p.text, font=theme.f_h1, anchor="w").pack(fill="x")
        tk.Label(hero, text="Take whatever the CA sent, build every format your servers need, and push it out "
                            "verified, backed up and reversible.", bg=p.bg, fg=p.muted, font=theme.f_body, anchor="w",
                 justify="left", wraplength=760).pack(fill="x", pady=(4, 0))

        tiles = tk.Frame(self.root_frame, bg=p.bg)
        tiles.pack(fill="x")
        items = [
            ("◈", "Certificates", "Inspect a bundle, check the key matches, and generate JKS, PEM, PKCS#12 and Asterisk files.", "certs", p.accent),
            ("⇪", "Deploy", "Roll certificates out to your servers from a config. Preview first; every file is backed up.", "deploy", p.success),
            ("⇄", "Copy to a server", "scp-style copy with checksums and automatic restore — through jump hosts too.", "copy", p.accent2),
            ("↺", "Rollback", "Put the previous files back from the last backup, and reload the services.", "rollback", p.warn),
            ("⚿", "Keystores", "Open a .jks or .p12 and see the alias, chain and expiry. No Java needed.", "keystore", p.info),
        ]
        for column in range(3):
            tiles.columnconfigure(column, weight=1, uniform="tile")
        for index, (icon, title, text, page, accent) in enumerate(items):
            tile = Tile(tiles, theme, icon, title, text, lambda page=page: self.app.navigate(page), accent=accent)
            tile.grid(row=index // 3, column=index % 3, sticky="nsew", padx=6, pady=6)

        self.env_card = Card(tiles, theme, "Your setup", "What this computer can do right now.", accent=p.accent2, padding=14)
        self.env_card.grid(row=1, column=2, sticky="nsew", padx=6, pady=6)
        self.env_rows = tk.Frame(self.env_card.body, bg=p.surface)
        self.env_rows.pack(fill="x")

    def on_show(self) -> None:
        env = services.env_status(self.app.configs_dir, self.app.ssh_config)
        for child in self.env_rows.winfo_children():
            child.destroy()
        rows = [
            ("Java", "keytool found" if env.keytool else "built-in JKS writer", "success" if env.keytool else "info",
             "ok" if env.keytool else "not needed"),
            ("SSH hosts", f"{len(env.ssh_aliases)} alias(es)" if env.ssh_config else "no ~/.ssh/config",
             "success" if env.ssh_aliases else "muted", "ready" if env.ssh_aliases else "none"),
            ("Trusted keys", f"{env.trusted_hosts} on file", "success" if env.trusted_hosts else "warn", "strict"),
            ("Configs", f"{len(env.configs)} saved" if env.configs else "none yet", "success" if env.configs else "muted", None),
            ("Version", f"{env.version} · Py {env.python}", "muted", None),
        ]
        for label, value, kind, pill in rows:
            KeyValue(self.env_rows, self.theme, label, value, kind, pill).pack(fill="x", pady=3)
