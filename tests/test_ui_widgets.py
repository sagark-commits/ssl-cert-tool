# Author: Sagar K | 2026 | MIT licence
"""The Studio window, driven for real: widgets, dialogs, pages, and full flows.

These use a real Tk root. Without a display (e.g. headless Linux CI) they are skipped;
run them under `xvfb-run` there.
"""
from __future__ import annotations

import gc
import time
import tkinter as tk
from pathlib import Path

import pytest

from conftest import DOMAIN
from fake_remote import FakeRemote
from ssl_deploy.deployer import SSLDeployer
from ssl_ui import render, services
from ssl_ui.app import NAV, StudioApp
from ssl_ui.components import STATUS, expiry_pill
from ssl_ui.pages.certs import describe_file, human_size
from ssl_ui.state import UiState
from ssl_ui.theme import Theme
from ssl_ui.widgets import (Button, ConfirmDialog, Dialog, Disclosure, Field, LogView, PasswordDialog, Pill, Toggle)


@pytest.fixture(scope="module")
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available for Tk")
    # A withdrawn root never lays its children out (every widget reports 1x1), so keep it mapped
    # but invisible: geometry-dependent behaviour such as click-inside checks then works.
    try:
        root.attributes("-alpha", 0.0)
    except tk.TclError:
        pass
    root.geometry("1280x900+0+0")
    root.update()
    yield root
    root.destroy()


@pytest.fixture(autouse=True)
def headless_dialogs(monkeypatch):
    """Keep modal dialogs off the user's screen.

    A real Dialog maps a window, grabs the keyboard and waits for a person. On a desktop that pops
    windows up in front of whoever is working (and swallows their typing), and a generated key event
    never arrives without real focus, so the test would hang. Here every dialog stays unmapped, never
    takes focus, and fails the test if it is still waiting after a few seconds.
    """
    expired = []
    real_init, real_show = Dialog.__init__, Dialog.show

    def init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        self.withdraw()

    def show(self):
        def give_up():
            expired.append(type(self).__name__)
            self.finish(None)

        self.after(4000, give_up)
        return real_show(self)

    monkeypatch.setattr(Dialog, "__init__", init)
    monkeypatch.setattr(Dialog, "show", show)
    monkeypatch.setattr(Dialog, "deiconify", lambda self: None)
    monkeypatch.setattr(Dialog, "grab_set", lambda self: None)
    monkeypatch.setattr(Dialog, "focus_force", lambda self: None)
    yield
    assert not expired, f"dialog(s) were still waiting for input: {expired}"


@pytest.fixture
def theme(tk_root):
    return Theme(tk_root)


def _release_tk_garbage(root):
    """Finalise dead Tk objects (images, variables) here, on the main thread.

    These tests drive the window with update() rather than mainloop(). A Tk object finalised on the
    worker thread then stalls for about a second while Tkinter waits for a main loop that is not
    running, so leftovers from earlier tests would make later ones crawl and time out. The shipped
    app is unaffected: its main thread is always inside mainloop().
    """
    root.update()
    gc.collect()


@pytest.fixture
def app(tk_root, tmp_path):
    for child in tk_root.winfo_children():
        child.destroy()
    _release_tk_garbage(tk_root)
    window = StudioApp(tk_root, configs_dir=tmp_path / "configs", state=UiState(tmp_path / "state.json"),
                       ssh_config=tmp_path / "no-ssh-config", known_hosts=tmp_path / "kh")
    tk_root.update()
    yield window
    window.runner.stop()
    try:
        window.shimmer.stop()
    except tk.TclError:
        pass
    for child in tk_root.winfo_children():
        child.destroy()
    del window
    _release_tk_garbage(tk_root)


def pump(app, until=None, timeout=15.0):
    """Run the Tk event loop and the task runner until `until()` is true (or the task finishes)."""
    end = time.time() + timeout
    while time.time() < end:
        app.root.update()
        app.runner.pump()
        if (until() if until else not app.runner.busy):
            break
        time.sleep(0.01)
    app.root.update()
    app.runner.pump()
    app.root.update()


def texts(widget):
    """Every text string shown inside a widget tree."""
    found = []
    for child in widget.winfo_children():
        try:
            value = child.cget("text")
            if value:
                found.append(str(value))
        except tk.TclError:
            pass
        found.extend(texts(child))
    return found


# ---------------------------------------------------------------------------
# Rendering and small helpers (no window needed)
# ---------------------------------------------------------------------------

def test_colour_mixing_and_status_tables():
    assert render.mix("#000000", "#ffffff", 0.5) == "#808080"
    assert render.mix("#102030", "#102030", 0.7) == "#102030"
    assert STATUS["failed"][1] == "danger" and STATUS["success"][0] == "OK"


@pytest.mark.parametrize("days, expired, expected", [
    (400, False, ("400 days left", "success")), (30, False, ("30 days left", "warn")),
    (5, False, ("5 days left", "danger")), (-3, True, ("EXPIRED", "danger")), (None, False, ("expiry unknown", "muted")),
])
def test_expiry_pill_thresholds(days, expired, expected):
    assert expiry_pill(days, expired) == expected


def test_file_purpose_labels_and_sizes():
    assert "Java keystore" in describe_file("example.com.jks")
    assert "Private key" in describe_file("example.com.key")
    assert "Asterisk" in describe_file("asterisk.pem")
    assert describe_file("mystery.bin") == ""
    assert human_size(512) == "512 B" and human_size(2048) == "2.0 KB"


def test_rounded_gradient_image_has_clear_corners_and_a_filled_centre(tk_root):
    image = render.render_round(tk_root, 80, 30, 12, "#ff0000", "#0000ff", "#000000")
    assert (image.width(), image.height()) == (80, 30)
    assert image.get(0, 0) == (0, 0, 0)           # corner is the background colour
    left, right = image.get(10, 15), image.get(70, 15)
    assert left[0] > left[2] and right[2] > right[0]  # gradient runs red -> blue
    assert render.render_round(tk_root, 80, 30, 12, "#ff0000", "#0000ff", "#000000") is image  # cached


def test_state_remembers_paths_but_refuses_secrets(tmp_path):
    state = UiState(tmp_path / "s.json")
    state.set("config", Path("/x/y.yaml"))
    assert UiState(tmp_path / "s.json").get("config") == str(Path("/x/y.yaml"))
    for key in ("password", "key_passphrase", "api_token"):
        with pytest.raises(ValueError, match="never saved"):
            state.set(key, "hunter2")
    assert "hunter2" not in (tmp_path / "s.json").read_text()
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert UiState(tmp_path / "bad.json").data == {}  # a damaged file is ignored, not fatal


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

def test_button_fires_on_release_inside_and_not_when_disabled(tk_root, theme):
    fired = []
    button = Button(tk_root, theme, "Go", lambda: fired.append(1))
    button.pack()
    tk_root.update()
    button.event_generate("<ButtonPress-1>", x=3, y=3)
    button.event_generate("<ButtonRelease-1>", x=3, y=3)
    assert fired == [1]
    button.event_generate("<ButtonPress-1>", x=3, y=3)
    button.event_generate("<ButtonRelease-1>", x=-50, y=-50)  # released outside: cancelled
    assert fired == [1]
    button.set_enabled(False)
    button.event_generate("<ButtonPress-1>", x=3, y=3)
    button.event_generate("<ButtonRelease-1>", x=3, y=3)
    assert fired == [1]
    button.set_enabled(True)
    button.set_text("Deploy now", "\u21ea", kind="danger")
    assert "Deploy now" in button.cget("text") and button.kind == "danger"
    button.destroy()


def test_toggle_switches_variable_and_calls_back(tk_root, theme):
    seen = []
    toggle = Toggle(tk_root, theme, "Dry run", command=seen.append)
    toggle.pack()
    tk_root.update()
    assert toggle.variable.get() is False
    toggle._toggle()
    assert toggle.variable.get() is True and seen == [True]
    toggle.variable.set(False)  # programmatic changes animate to the right place too
    for _ in range(20):
        tk_root.update()
        time.sleep(0.01)
    assert toggle._pos == 0.0
    toggle.destroy()


def test_pill_updates_and_log_view_levels(tk_root, theme):
    pill = Pill(tk_root, theme, "OK", "success")
    pill.set("FAILED", "danger")
    assert "FAILED" in pill.cget("text")
    log = LogView(tk_root, theme)
    log.write("success", "all good")
    log.write("error", "line one\nline two")
    log.write("nonsense-level", "falls back to info")
    contents = log.contents()
    assert "all good" in contents and "line two" in contents and "falls back to info" in contents
    assert log.text.tag_ranges("error") and log.text.tag_ranges("success")
    log.clear()
    assert log.contents().strip() == ""


def test_field_error_state_and_disclosure(tk_root, theme):
    field = Field(tk_root, theme, "Name", hint="a hint")
    field.set_error("bad value")
    assert field.entry.cget("highlightbackground") == theme.p.danger
    field.set_error(None)
    assert field.entry.cget("highlightbackground") == theme.p.border
    fold = Disclosure(tk_root, theme, "More options")
    fold.pack()
    assert not fold.body.winfo_manager()
    fold.toggle()
    assert fold.body.winfo_manager() and "More options" in fold.header.cget("text")


def test_password_dialog_returns_what_was_typed_and_supports_cancel(tk_root, theme):
    dialog = PasswordDialog(tk_root, theme, "deploy@10.0.0.1:142")
    echoed = []

    def type_and_submit():
        echoed.append(dialog.entry.cget("show"))  # the window closes after show(), so read it now
        dialog.var.set("s3cret")
        dialog.finish(dialog.var.get())  # what the Connect button and the Return key both do

    tk_root.after(80, type_and_submit)
    assert dialog.show() == "s3cret"
    assert echoed == ["\u2022"]  # never echoed in clear
    dialog2 = PasswordDialog(tk_root, theme, "u@h")
    tk_root.after(80, lambda: dialog2.finish(None))
    assert dialog2.show() is None


def test_confirm_dialog_returns_the_choice(tk_root, theme):
    yes = ConfirmDialog(tk_root, theme, "Deploy?", "Sure?", confirm="Deploy now", kind="danger", lines=["web -> 2 services"])
    tk_root.after(80, lambda: yes.finish(True))
    assert yes.show() is True
    no = ConfirmDialog(tk_root, theme, "Deploy?", "Sure?")
    tk_root.after(80, lambda: no.finish(False))
    assert no.show() is False


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------

def test_every_page_opens_and_shows_its_title(app):
    for key, _icon, label in NAV:
        page = app.navigate(key)
        app.root.update()
        assert page is not None and app.current == key
        assert app.title_label.cget("text") == page.title and page.title
        assert app.nav_items[key].active
        assert sum(1 for item in app.nav_items.values() if item.active) == 1
    assert app.navigate("no-such-page") is None


def test_home_reports_the_environment(app):
    app.navigate("home")
    shown = " ".join(texts(app.page("home")))
    assert "Your setup" in shown and "Version" in shown and "Java" in shown


def test_log_dock_opens_itself_on_first_activity_and_respects_a_manual_hide(app):
    assert not app._log_visible
    app.log("info", "first message")
    assert app._log_visible
    app._toggle_log()                      # the user hides it...
    app.log("detail", "quiet message")
    assert not app._log_visible            # ...and routine messages do not reopen it
    app.log("error", "something broke")
    assert app._log_visible                # but an error always does


def test_a_second_task_is_refused_with_a_message(app):
    import threading

    gate = threading.Event()
    assert app.run_task("long", lambda ctx: gate.wait(5), lambda r, e: None)
    assert app.run_task("another", lambda ctx: None, lambda r, e: None) is False
    assert "Another task is still running" in app.logview.contents()
    assert "long" in app.status_pill.cget("text")
    gate.set()
    pump(app)
    assert app.status_pill.cget("text").startswith("\u25cf Ready")


def test_password_prompt_in_a_running_task_reaches_the_dialog_and_back(app, monkeypatch):
    shown = []
    monkeypatch.setattr(PasswordDialog, "show", lambda self: shown.append(self) or "typed")
    result = []
    app.run_task("ask", lambda ctx: ctx.ask_password({"user": "u", "host": "10.1.1.1", "port": 22}), lambda r, e: result.append(r))
    pump(app, until=lambda: result)
    assert result == ["typed"] and len(shown) == 1


# ---------------------------------------------------------------------------
# Full flows through the real pages, services and worker thread
# ---------------------------------------------------------------------------

def test_certificates_flow_inspect_then_generate(app, cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    page = app.navigate("certs")
    page.sources = [cert_dir]
    page._refresh_list()
    page.run_inspect()
    pump(app)
    shown = " ".join(texts(page.chain_body))
    assert DOMAIN in shown and "LEAF" in shown and "KEY MATCHES" in shown and "days left" in shown

    page.out_var.set(str(tmp_path / "generated"))
    page.store_var.set("longenough1")
    page.generate()
    pump(app)
    created = " ".join(texts(page.gen_body))
    assert "files created" in created and f"{DOMAIN}.jks" in created and "built-in writer" in created
    assert (tmp_path / "generated" / DOMAIN / f"{DOMAIN}.jks").is_file()
    assert app.state.get("cert_dir") == str(tmp_path / "generated" / DOMAIN)
    assert page.generate_btn._enabled  # the button is usable again


def test_certificates_page_explains_a_failure_instead_of_crashing(app, tmp_path):
    page = app.navigate("certs")
    page.sources = [tmp_path / "does-not-exist"]
    page.run_inspect()
    pump(app)
    assert "Not found" in " ".join(texts(page.chain_body))
    page.sources = []
    page.generate()
    assert "Add the certificate files first" in app.logview.contents()


def test_generated_files_can_be_sent_to_the_copy_page(app, cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    certs = app.navigate("certs")
    certs.sources = [cert_dir]
    certs.out_var.set(str(tmp_path / "out"))
    certs.store_var.set("longenough1")
    certs.generate()
    pump(app)
    certs._to_copy(certs.last_generated)
    assert app.current == "copy"
    names = [Path(i["src"]).name for i in app.page("copy").items]
    assert names == [f"main_{DOMAIN}.crt", f"{DOMAIN}.key"]
    assert all(i["dest"] == "" for i in app.page("copy").items)  # the user still chooses where they go


def _deploy_config(tmp_path, cert_dir):
    cfg = tmp_path / "deploy.yaml"
    cfg.write_text(
        f"domain: {DOMAIN}\nbackup_dir: /var/b\nservers:\n  web:\n    host: 10.0.0.1\n    services: [c]\n"
        "services:\n  c:\n    type: custom\n    file_mappings:\n      certificate: /srv/a.crt\n      private_key: /srv/a.key\n",
        encoding="utf-8",
    )
    return cfg


def test_deploy_page_shows_the_plan_previews_and_only_deploys_after_confirmation(app, cert_dir, tmp_path, monkeypatch):
    remote = FakeRemote(tmp_path / "remote")
    monkeypatch.setattr(SSLDeployer, "connect_server", lambda self, name, force=False: remote)
    page = app.navigate("deploy")
    page.config_var.set(str(_deploy_config(tmp_path, cert_dir)))
    page.certdir_var.set(str(cert_dir))
    page.reload_plan()
    plan = " ".join(texts(page.plan_body))
    assert "web" in plan and "custom" in plan and "/srv/a.crt" in plan and "root@10.0.0.1:22" in plan

    page.run()  # dry run is the default
    pump(app)
    assert "PREVIEW OK" in " ".join(texts(page.result)) and remote.files() == []

    page.dry.set(False)
    page._restyle()
    assert "Deploy now" in page.run_btn.cget("text") and page.run_btn.kind == "danger"
    monkeypatch.setattr("ssl_ui.pages.deploy.ConfirmDialog", type("No", (), {"__init__": lambda self, *a, **k: None, "show": lambda self: False}))
    page.run()
    pump(app)
    assert remote.files() == []  # cancelled at the confirmation: nothing happened

    monkeypatch.setattr("ssl_ui.pages.deploy.ConfirmDialog", type("Yes", (), {"__init__": lambda self, *a, **k: None, "show": lambda self: True}))
    page.run()
    pump(app)
    assert remote.exists("/srv/a.crt") and "COMPLETED" in " ".join(texts(page.result))


def test_deploy_page_reports_a_broken_config(app, tmp_path):
    page = app.navigate("deploy")
    page.config_var.set(str(tmp_path / "missing.yaml"))
    page.reload_plan()
    assert "not found" in " ".join(texts(page.plan_body)).lower()
    page.config_var.set("")
    page.certdir_var.set("")
    page.run()
    assert "Choose a deployment config" in app.logview.contents()


def test_copy_page_route_preview_files_and_a_dry_run(app, cert_dir, tmp_path, monkeypatch):
    cfg = tmp_path / "ssh_config"
    cfg.write_text("Host bastion\n  HostName 203.0.113.9\n  Port 40222\n  User jumpuser\n"
                   "Host app-1\n  HostName 10.128.0.7\n  Port 142\n  User deploy\n  ProxyJump bastion\n", encoding="utf-8")
    app.ssh_config = cfg
    page = app.navigate("copy")
    page.host_var.set("app-1")
    page._update_route()
    route = " ".join(texts(page.route))
    assert "jumpuser@203.0.113.9:40222" in route and "deploy@10.128.0.7:142" in route and "jump host" in route and "target" in route
    page.host_var.set("nope@@")
    page._update_route()
    assert "cannot understand" in " ".join(texts(page.route))

    page.host_var.set("app-1")
    page.items = [{"src": str(cert_dir / f"main_{DOMAIN}.crt"), "dest": "", "mode": ""}]
    page._refresh_tree()
    page.run()
    assert "Set the path on the server" in app.logview.contents()  # incomplete rows are refused with a reason

    page.items[0]["dest"] = "/srv/ssl/site.crt"
    remote = FakeRemote(tmp_path / "remote")
    monkeypatch.setattr(SSLDeployer, "connect_server", lambda self, name, force=False: remote)
    page.run()  # dry run
    pump(app)
    assert "PREVIEW OK" in " ".join(texts(page.result)) and remote.files() == []


def test_copy_page_live_copy_after_confirmation(app, cert_dir, tmp_path, monkeypatch):
    remote = FakeRemote(tmp_path / "remote")
    monkeypatch.setattr(SSLDeployer, "connect_server", lambda self, name, force=False: remote)
    monkeypatch.setattr("ssl_ui.pages.copy.ConfirmDialog", type("Yes", (), {"__init__": lambda self, *a, **k: None, "show": lambda self: True}))
    page = app.navigate("copy")
    page.host_var.set("deploy@10.0.0.5:2222")
    page.items = [{"src": str(cert_dir / f"main_{DOMAIN}.crt"), "dest": "/srv/ssl/site.crt", "mode": "644"},
                  {"src": str(cert_dir / f"{DOMAIN}.key"), "dest": "/srv/ssl/site.key", "mode": ""}]
    page.dry.set(False)
    page.run()
    pump(app)
    assert remote.exists("/srv/ssl/site.crt") and remote.exists("/srv/ssl/site.key")
    assert "COMPLETED" in " ".join(texts(page.result))


def test_copy_item_dialog_validates_before_accepting(app, tmp_path):
    from ssl_ui.pages.copy import CopyItemDialog

    dialog = CopyItemDialog(app.root, app.theme)
    dialog.src.set("a.crt")
    dialog.dest.set("relative/path")
    dialog._save()
    assert dialog.result is None and dialog.dest_field.entry.cget("highlightbackground") == app.theme.p.danger
    dialog.dest.set("/srv/ssl/a.crt")
    dialog.mode.set("999")
    dialog._save()
    assert dialog.result is None
    dialog.mode.set("640")
    app.root.after(50, dialog._save)
    assert dialog.show() == {"src": "a.crt", "dest": "/srv/ssl/a.crt", "mode": "640"}


def test_rollback_page_dry_run_and_server_list(app, cert_dir, tmp_path):
    page = app.navigate("rollback")
    page.config_var.set(str(_deploy_config(tmp_path, cert_dir)))
    page._servers()
    assert "web" in page.server_combo.box.cget("values")
    page.run()
    pump(app)
    assert "PREVIEW OK" in " ".join(texts(page.result))
    page.config_var.set("")
    page.run()
    assert "Choose the deployment config" in app.logview.contents()


def test_keystore_page_opens_a_real_keystore_and_explains_a_wrong_password(app, cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    view = services.generate_artifacts([cert_dir], tmp_path / "ks", "longenough1", "app-key")
    page = app.navigate("keystore")
    page.path_var.set(str(view.output_dir / f"{DOMAIN}.jks"))
    page.pass_var.set("longenough1")
    page.open()
    pump(app)
    shown = " ".join(texts(page.info_body))
    assert "app-key" in shown and DOMAIN in shown and "days left" in shown and "LEAF" in shown

    page.pass_var.set("wrong")
    page.open()
    pump(app)
    assert "Invalid password" in " ".join(texts(page.info_body))


def test_no_password_is_ever_written_to_the_saved_state(app, cert_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_AUTO_BUILTIN_JKS", "1")
    page = app.navigate("certs")
    page.sources = [cert_dir]
    page.out_var.set(str(tmp_path / "o"))
    page.store_var.set("S3cretKeystorePw")
    page.pass_var.set("KeyPassphrase1")
    page.generate()
    pump(app)
    saved = (tmp_path / "state.json").read_text(encoding="utf-8")
    assert "S3cretKeystorePw" not in saved and "KeyPassphrase1" not in saved
    assert "S3cretKeystorePw" not in app.logview.contents()


def test_sidebar_credit_opens_the_about_box_with_the_author_and_licence(app, monkeypatch):
    from ssl_ui.widgets import AboutDialog

    assert "Sagar K" in app.credit_label.cget("text")
    opened = []
    monkeypatch.setattr(app, "_about", lambda: opened.append("about"))
    app.credit_label.event_generate("<Button-1>")
    assert opened == ["about"]

    dialog = AboutDialog(app.root, app.theme, version="9.9", tool_version="8.8", author="Sagar K", licence="MIT",
                         url="https://example.com/source")
    shown = " ".join(texts(dialog))
    assert "Created by Sagar K" in shown and "MIT licence" in shown and "Studio 9.9" in shown and "https://example.com/source" in shown
    monkeypatch.setattr("ssl_ui.widgets.webbrowser.open", lambda url: opened.append(url))
    dialog.open_source()
    assert opened[-1] == "https://example.com/source"
    dialog.destroy()
