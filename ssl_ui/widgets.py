# Author: Sagar K | 2026 | MIT licence
"""Widget kit for SSL Certificate Studio: buttons, cards, pills, toggles, fields, log, dialogs."""
from __future__ import annotations

import sys
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, ttk
from typing import Callable, List, Optional, Sequence, Tuple

from ssl_ui.render import mix, render_glow, render_round
from ssl_ui.theme import Theme

FileTypes = Sequence[Tuple[str, str]]


def autowrap(label: tk.Label, container: tk.Misc, margin: int = 0) -> tk.Label:
    """Keep `label` wrapped to the width of `container` (so text never runs off a card)."""

    def fit(event: tk.Event) -> None:
        label.configure(wraplength=max(120, event.width - margin))

    container.bind("<Configure>", fit, add="+")
    return label


def apply_dark_titlebar(window: tk.Misc) -> None:
    """Dark title bar on Windows 10/11 (silently does nothing elsewhere)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (Win11 / older Win10 builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------

class Button(tk.Label):
    """Rounded button with a gradient, hover and pressed states."""

    def __init__(self, parent: tk.Misc, theme: Theme, text: str, command: Optional[Callable[[], None]] = None, *,
                 kind: str = "primary", icon: Optional[str] = None, padx: int = 18, pady: int = 8, min_width: int = 0,
                 font=None) -> None:
        p = theme.p
        self.theme, self.command, self.kind = theme, command, kind
        self._enabled = True
        self._font = font or theme.f_bold
        self._padx, self._pady, self._min_width = padx, pady, min_width
        self._bg = parent.cget("bg")
        self._master_ref = parent
        self._label = f"{icon}  {text}" if icon else text
        self._states = self._build_images()
        super().__init__(parent, text=self._label, image=self._states["normal"], compound="center", font=self._font,
                         fg=self._fg(), bg=self._bg, bd=0, padx=0, pady=0, cursor="hand2", takefocus=1)
        self.bind("<Enter>", lambda _e: self._set("hover"))
        self.bind("<Leave>", lambda _e: self._set("normal"))
        self.bind("<ButtonPress-1>", lambda _e: self._set("pressed"))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Return>", lambda _e: self._fire())
        self.bind("<space>", lambda _e: self._fire())

    # -- looks ---------------------------------------------------------------
    def _palette(self, state: str):
        p = self.theme.p
        base = {
            "primary": (p.accent, p.accent2, None),
            "success": (mix(p.success, "#000000", 0.25), p.success, None),
            "danger": (mix(p.danger, "#000000", 0.15), p.danger, None),
            "ghost": (p.surface2, p.surface2, p.border_hi),
            "quiet": (p.surface, p.surface, p.border),
        }[self.kind]
        c1, c2, border = base
        if state == "hover":
            lift = 0.16 if self.kind in ("primary", "success", "danger") else 0.35
            target = "#ffffff" if self.kind in ("primary", "success", "danger") else p.accent
            c1, c2 = mix(c1, target, lift), mix(c2, target, lift)
            border = mix(border, p.accent, 0.6) if border else None
        elif state == "pressed":
            c1, c2 = mix(c1, "#000000", 0.18), mix(c2, "#000000", 0.18)
        elif state == "disabled":
            c1 = c2 = mix(p.surface2, p.bg, 0.4)
            border = p.border if border else None
        return c1, c2, border

    def _build_images(self):
        height = self._font.metrics("linespace") + 2 * self._pady
        width = max(self._min_width, self._font.measure(self._label) + 2 * self._padx)
        radius = min(10, height / 2)
        out = {}
        for state in ("normal", "hover", "pressed", "disabled"):
            c1, c2, border = self._palette(state)
            out[state] = render_round(self._master_ref, width, height, radius, c1, c2, self._bg, border=border)
        return out

    def _fg(self) -> str:
        p = self.theme.p
        if not self._enabled:
            return p.faint
        return "#ffffff" if self.kind in ("primary", "success", "danger") else p.text

    def _set(self, state: str) -> None:
        if not self._enabled:
            return
        self.configure(image=self._states[state])

    # -- behaviour -------------------------------------------------------------
    def _release(self, event) -> None:
        if not self._enabled:
            return
        inside = 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height()
        self._set("hover" if inside else "normal")
        if inside:
            self._fire()

    def _fire(self) -> None:
        if self._enabled and self.command:
            self.command()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.configure(image=self._states["normal" if enabled else "disabled"], fg=self._fg(),
                       cursor="hand2" if enabled else "arrow")

    def set_text(self, text: str, icon: Optional[str] = None, kind: Optional[str] = None) -> None:
        """Change the label (and optionally the style: primary / success / danger / ghost)."""
        if kind:
            self.kind = kind
        self._label = f"{icon}  {text}" if icon else text
        self._states = self._build_images()
        self.configure(text=self._label, image=self._states["normal" if self._enabled else "disabled"], fg=self._fg())


class Pill(tk.Label):
    """A small rounded status chip (OK / FAIL / 12 days left ...)."""

    def __init__(self, parent: tk.Misc, theme: Theme, text: str, kind: str = "muted", *, dot: bool = False,
                 font=None, padx: int = 10, pady: int = 2, bg: Optional[str] = None) -> None:
        self.theme = theme
        self._font = font or theme.f_small
        self._padx, self._pady, self._dot = padx, pady, dot
        self._bg = bg or parent.cget("bg")
        self._master_ref = parent
        super().__init__(parent, bd=0, padx=0, pady=0, bg=self._bg, compound="center", font=self._font)
        self.set(text, kind)

    def set(self, text: str, kind: str) -> None:
        color = self.theme.kind_color(kind)
        label = ("● " if self._dot else "") + text
        height = self._font.metrics("linespace") + 2 * self._pady
        width = self._font.measure(label) + 2 * self._padx
        fill = mix(self._bg, color, 0.16)
        image = render_round(self._master_ref, width, height, height / 2, fill, fill, self._bg, border=mix(self._bg, color, 0.45))
        self.configure(text=label, image=image, fg=color)
        self._image = image


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

class Card(tk.Frame):
    """A bordered surface. Put content in `.body`."""

    def __init__(self, parent: tk.Misc, theme: Theme, title: Optional[str] = None, subtitle: Optional[str] = None, *,
                 padding: int = 16, accent: Optional[str] = None, bg: Optional[str] = None) -> None:
        p = theme.p
        self.theme = theme
        fill = bg or p.surface
        super().__init__(parent, bg=fill, highlightthickness=1, highlightbackground=p.border, highlightcolor=p.border)
        if accent:
            tk.Frame(self, bg=accent, height=2).pack(fill="x")
        self.body = tk.Frame(self, bg=fill)
        self.body.pack(fill="both", expand=True, padx=padding, pady=padding)
        if title:
            tk.Label(self.body, text=title, bg=fill, fg=p.text, font=theme.f_h3, anchor="w").pack(fill="x")
        if subtitle:
            sub = tk.Label(self.body, text=subtitle, bg=fill, fg=p.muted, font=theme.f_small, anchor="w", justify="left", wraplength=360)
            sub.pack(fill="x", pady=(2, 0))
            autowrap(sub, self.body)
        if title or subtitle:
            tk.Frame(self.body, bg=fill, height=10).pack()


class Divider(tk.Frame):
    def __init__(self, parent: tk.Misc, theme: Theme, vertical: bool = False) -> None:
        super().__init__(parent, bg=theme.p.border, **({"width": 1} if vertical else {"height": 1}))


class Scrollable(tk.Frame):
    """A vertically scrolling container for long pages."""

    def __init__(self, parent: tk.Misc, theme: Theme, bg: Optional[str] = None) -> None:
        bg = bg or theme.p.bg
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._window, width=e.width))
        self.canvas.bind("<Enter>", lambda _e: self._bind_wheel(True))
        self.canvas.bind("<Leave>", lambda _e: self._bind_wheel(False))

    def _bind_wheel(self, on: bool) -> None:
        if on:
            self.canvas.bind_all("<MouseWheel>", self._wheel)
        else:
            self.canvas.unbind_all("<MouseWheel>")

    def _wheel(self, event) -> None:
        if self.inner.winfo_height() > self.canvas.winfo_height():
            self.canvas.yview_scroll(int(-event.delta / 120), "units")


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def make_entry(parent: tk.Misc, theme: Theme, variable: Optional[tk.StringVar] = None, *, show: str = "", width: int = 30,
               font=None) -> tk.Entry:
    p = theme.p
    return tk.Entry(parent, textvariable=variable, show=show, width=width, font=font or theme.f_body, bg=p.field, fg=p.text,
                    insertbackground=p.accent2, relief="flat", bd=0, highlightthickness=1, highlightbackground=p.border,
                    highlightcolor=p.accent, disabledbackground=p.field, disabledforeground=p.faint,
                    selectbackground=p.accent, selectforeground="#ffffff")


class Field(tk.Frame):
    """Label above an input, with an optional hint underneath."""

    def __init__(self, parent: tk.Misc, theme: Theme, label: str, variable: Optional[tk.StringVar] = None, *,
                 show: str = "", hint: Optional[str] = None, width: int = 30) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg)
        self.theme = theme
        self.variable = variable if variable is not None else tk.StringVar()
        self._label = tk.Label(self, text=label, bg=bg, fg=p.muted, font=theme.f_small, anchor="w")
        self._label.pack(fill="x")
        self.entry = make_entry(self, theme, self.variable, show=show, width=width)
        self.entry.pack(fill="x", ipady=6, pady=(3, 0))
        self._hint = None
        if hint:
            self._hint = tk.Label(self, text=hint, bg=bg, fg=p.faint, font=theme.f_tiny, anchor="w", justify="left", wraplength=300)
            self._hint.pack(fill="x", pady=(2, 0))
            autowrap(self._hint, self)

    def set_error(self, message: Optional[str]) -> None:
        p = self.theme.p
        self.entry.configure(highlightbackground=p.danger if message else p.border)
        if self._hint is not None:
            self._hint.configure(text=message or self._hint.cget("text"), fg=p.danger if message else p.faint)


class PathField(Field):
    """A text field with a Browse button (file, folder, or several files)."""

    def __init__(self, parent: tk.Misc, theme: Theme, label: str, variable: Optional[tk.StringVar] = None, *,
                 mode: str = "file", filetypes: Optional[FileTypes] = None, hint: Optional[str] = None,
                 on_change: Optional[Callable[[str], None]] = None, initialdir: Optional[str] = None) -> None:
        super().__init__(parent, theme, label, variable, hint=hint)
        self.mode, self.filetypes, self.on_change, self.initialdir = mode, filetypes, on_change, initialdir
        self.entry.pack_forget()
        row = tk.Frame(self, bg=parent.cget("bg"))
        row.pack(fill="x", pady=(3, 0), after=self._label)
        self.entry = make_entry(row, theme, self.variable)
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)
        Button(row, theme, "Browse", self._browse, kind="ghost", padx=14, pady=5, font=theme.f_small).pack(side="left", padx=(8, 0))
        if on_change:
            self.variable.trace_add("write", lambda *_a: on_change(self.variable.get()))

    def _browse(self) -> None:
        start = self.initialdir or None
        if self.mode == "dir":
            chosen = filedialog.askdirectory(initialdir=start)
        else:
            chosen = filedialog.askopenfilename(filetypes=list(self.filetypes or [("All files", "*.*")]), initialdir=start)
        if chosen:
            self.variable.set(chosen)


class Disclosure(tk.Frame):
    """A collapsible section ("More options"). Put content in `.body`."""

    def __init__(self, parent: tk.Misc, theme: Theme, title: str, expanded: bool = False) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg)
        self.theme, self.title, self.expanded = theme, title, expanded
        self.header = tk.Label(self, text="", bg=bg, fg=p.accent2, font=theme.f_small, anchor="w", cursor="hand2")
        self.header.pack(fill="x")
        self.header.bind("<Button-1>", lambda _e: self.toggle())
        self.body = tk.Frame(self, bg=bg)
        self._paint()

    def _paint(self) -> None:
        self.header.configure(text=("\u25be  " if self.expanded else "\u25b8  ") + self.title)
        if self.expanded:
            self.body.pack(fill="x", pady=(8, 0))
        else:
            self.body.pack_forget()

    def toggle(self) -> None:
        self.expanded = not self.expanded
        self._paint()


class Toggle(tk.Frame):
    """An on/off switch with a label (bound to a BooleanVar)."""

    W, H = 40, 22

    def __init__(self, parent: tk.Misc, theme: Theme, text: str, variable: Optional[tk.BooleanVar] = None, *,
                 hint: Optional[str] = None, command: Optional[Callable[[bool], None]] = None) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg, cursor="hand2")
        self.theme, self.command = theme, command
        self.variable = variable if variable is not None else tk.BooleanVar(value=False)
        self._pos = 1.0 if self.variable.get() else 0.0
        self.canvas = tk.Canvas(self, width=self.W, height=self.H, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.canvas.pack(side="left", padx=(0, 10))
        text_box = tk.Frame(self, bg=bg)
        text_box.pack(side="left", fill="x", expand=True)
        self._title = tk.Label(text_box, text=text, bg=bg, fg=p.text, font=theme.f_body, anchor="w", cursor="hand2")
        self._title.pack(fill="x")
        if hint:
            note = tk.Label(text_box, text=hint, bg=bg, fg=p.faint, font=theme.f_tiny, anchor="w", justify="left", wraplength=300,
                            cursor="hand2")
            note.pack(fill="x")
            autowrap(note, text_box)
            note.bind("<Button-1>", self._toggle)
        for widget in (self, self.canvas, self._title, text_box):
            widget.bind("<Button-1>", self._toggle)
        self.variable.trace_add("write", lambda *_a: self._animate_to(1.0 if self.variable.get() else 0.0))
        self._draw()

    def _draw(self) -> None:
        p = self.theme.p
        c = self.canvas
        c.delete("all")
        track = mix(p.border_hi, p.accent, self._pos)
        h, w = self.H, self.W
        c.create_oval(0, 0, h, h, fill=track, outline=track)
        c.create_oval(w - h, 0, w, h, fill=track, outline=track)
        c.create_rectangle(h / 2, 0, w - h / 2, h, fill=track, outline=track)
        x = 3 + (w - h) * self._pos
        c.create_oval(x, 3, x + h - 6, h - 3, fill="#ffffff", outline="#ffffff")

    def _animate_to(self, target: float, steps: int = 6) -> None:
        start = self._pos

        def step(i: int = 1) -> None:
            self._pos = start + (target - start) * i / steps
            self._draw()
            if i < steps:
                self.after(14, step, i + 1)

        step()

    def _toggle(self, _event=None) -> None:
        self.variable.set(not self.variable.get())
        if self.command:
            self.command(self.variable.get())


class Combo(tk.Frame):
    """Label + dark combobox (editable so any value can be typed)."""

    def __init__(self, parent: tk.Misc, theme: Theme, label: str, values: Sequence[str], variable: Optional[tk.StringVar] = None, *,
                 hint: Optional[str] = None, readonly: bool = False, on_change: Optional[Callable[[str], None]] = None) -> None:
        p = theme.p
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg)
        self.variable = variable if variable is not None else tk.StringVar()
        tk.Label(self, text=label, bg=bg, fg=p.muted, font=theme.f_small, anchor="w").pack(fill="x")
        self.box = ttk.Combobox(self, textvariable=self.variable, values=list(values), state="readonly" if readonly else "normal",
                                font=theme.f_body)
        self.box.pack(fill="x", pady=(3, 0), ipady=3)
        if hint:
            note = tk.Label(self, text=hint, bg=bg, fg=p.faint, font=theme.f_tiny, anchor="w", justify="left", wraplength=300)
            note.pack(fill="x", pady=(2, 0))
            autowrap(note, self)
        if on_change:
            self.variable.trace_add("write", lambda *_a: on_change(self.variable.get()))
            self.box.bind("<<ComboboxSelected>>", lambda _e: on_change(self.variable.get()))

    def set_values(self, values: Sequence[str]) -> None:
        self.box.configure(values=list(values))


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

class Shimmer(tk.Canvas):
    """An indeterminate progress bar: a soft highlight sweeping along a thin track."""

    def __init__(self, parent: tk.Misc, theme: Theme, width: int = 160, height: int = 4) -> None:
        bg = parent.cget("bg")
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0)
        self.theme = theme
        self._width, self._height = width, height
        self._running = False
        self._x = -80.0
        track = theme.p.border
        self.create_rectangle(0, 0, width, height, fill=track, outline=track, tags="track")
        self._glow = render_glow(self, 90, height, theme.p.accent2, track)
        self._item = self.create_image(-90, 0, image=self._glow, anchor="nw", state="hidden")

    def start(self) -> None:
        if not self._running:
            self._running = True
            self.itemconfigure(self._item, state="normal")
            self._tick()

    def stop(self) -> None:
        self._running = False
        self.itemconfigure(self._item, state="hidden")

    def _tick(self) -> None:
        if not self._running:
            return
        self._x += 7
        if self._x > self._width:
            self._x = -90
        self.coords(self._item, self._x, 0)
        self.after(16, self._tick)


class LogView(tk.Frame):
    """A coloured, read-only console for task output."""

    LEVELS = ("info", "step", "success", "warn", "error", "detail", "cmd")

    def __init__(self, parent: tk.Misc, theme: Theme) -> None:
        p = theme.p
        super().__init__(parent, bg=p.field, highlightthickness=1, highlightbackground=p.border)
        self.theme = theme
        self.text = tk.Text(self, bg=p.field, fg=p.text, font=theme.f_mono_small, wrap="word", relief="flat", bd=0,
                            padx=12, pady=8, highlightthickness=0, insertbackground=p.accent2, state="disabled",
                            selectbackground=p.accent, spacing1=1, spacing3=1, cursor="arrow")
        bar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.tag_configure("time", foreground=p.faint)
        self.text.tag_configure("info", foreground=p.text)
        self.text.tag_configure("step", foreground=p.accent2, font=theme.f_mono_small)
        self.text.tag_configure("success", foreground=p.success)
        self.text.tag_configure("warn", foreground=p.warn)
        self.text.tag_configure("error", foreground=p.danger)
        self.text.tag_configure("detail", foreground=p.muted)
        self.text.tag_configure("cmd", foreground=p.accent)

    def write(self, level: str, message: str) -> None:
        level = level if level in self.LEVELS else "info"
        stamp = time.strftime("%H:%M:%S")
        self.text.configure(state="normal")
        for line in str(message).splitlines() or [""]:
            self.text.insert("end", f"{stamp}  ", "time")
            self.text.insert("end", line + "\n", level)
        self.text.configure(state="disabled")
        self.text.see("end")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def contents(self) -> str:
        return self.text.get("1.0", "end")


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------

class Dialog(tk.Toplevel):
    """A modal, dark, centred dialog. Subclasses fill `.body` and call `finish(value)`."""

    def __init__(self, parent: tk.Misc, theme: Theme, title: str, *, width: int = 440) -> None:
        super().__init__(parent)
        self.theme = theme
        self.result = None
        self.title(title)
        self.configure(bg=theme.p.bg)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        outer = tk.Frame(self, bg=theme.p.surface, highlightthickness=1, highlightbackground=theme.p.border_hi)
        outer.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Frame(outer, bg=theme.p.accent, height=2).pack(fill="x")
        self.body = tk.Frame(outer, bg=theme.p.surface, width=width)
        self.body.pack(fill="both", expand=True, padx=22, pady=20)
        self.protocol("WM_DELETE_WINDOW", lambda: self.finish(None))
        self.bind("<Escape>", lambda _e: self.finish(None))

    def finish(self, value) -> None:
        self.result = value
        self.grab_release()
        self.destroy()

    def show(self):
        self.update_idletasks()
        parent = self.master.winfo_toplevel()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        apply_dark_titlebar(self)
        self.deiconify()
        self.grab_set()
        self.focus_force()
        self.wait_window(self)
        return self.result


class PasswordDialog(Dialog):
    """Hidden-input prompt for an SSH password (one per host that refuses your keys)."""

    def __init__(self, parent: tk.Misc, theme: Theme, who: str, detail: str = "") -> None:
        super().__init__(parent, theme, "Password required")
        p = theme.p
        tk.Label(self.body, text="⚿  Password required", bg=p.surface, fg=p.text, font=theme.f_h2, anchor="w").pack(fill="x")
        tk.Label(self.body, text=f"{who} did not accept your keys or agent.\n{detail}".strip(), bg=p.surface, fg=p.muted,
                 font=theme.f_small, anchor="w", justify="left", wraplength=400).pack(fill="x", pady=(4, 12))
        self.var = tk.StringVar()
        self.entry = make_entry(self.body, theme, self.var, show="•", width=36)
        self.entry.pack(fill="x", ipady=7)
        self.entry.bind("<Return>", lambda _e: self.finish(self.var.get()))
        tk.Label(self.body, text="Used for this connection only. It is never saved.", bg=p.surface, fg=p.faint,
                 font=theme.f_tiny, anchor="w").pack(fill="x", pady=(6, 14))
        row = tk.Frame(self.body, bg=p.surface)
        row.pack(fill="x")
        Button(row, theme, "Connect", lambda: self.finish(self.var.get()), padx=22).pack(side="right")
        Button(row, theme, "Cancel", lambda: self.finish(None), kind="ghost", padx=18).pack(side="right", padx=(0, 10))

    def show(self):
        self.after(60, self.entry.focus_set)
        return super().show()


class ConfirmDialog(Dialog):
    def __init__(self, parent: tk.Misc, theme: Theme, title: str, message: str, *, confirm: str = "Continue",
                 kind: str = "primary", lines: Optional[List[str]] = None) -> None:
        super().__init__(parent, theme, title)
        p = theme.p
        tk.Label(self.body, text=title, bg=p.surface, fg=p.text, font=theme.f_h2, anchor="w").pack(fill="x")
        tk.Label(self.body, text=message, bg=p.surface, fg=p.muted, font=theme.f_body, anchor="w", justify="left",
                 wraplength=420).pack(fill="x", pady=(6, 10))
        if lines:
            box = tk.Frame(self.body, bg=p.field, highlightthickness=1, highlightbackground=p.border)
            box.pack(fill="x", pady=(0, 14))
            for line in lines:
                tk.Label(box, text=line, bg=p.field, fg=p.text, font=theme.f_mono_small, anchor="w", justify="left",
                         wraplength=400, padx=10, pady=2).pack(fill="x")
        row = tk.Frame(self.body, bg=p.surface)
        row.pack(fill="x")
        Button(row, theme, confirm, lambda: self.finish(True), kind=kind, padx=22).pack(side="right")
        Button(row, theme, "Cancel", lambda: self.finish(False), kind="ghost", padx=18).pack(side="right", padx=(0, 10))


class AboutDialog(Dialog):
    """Who made the Studio, which version this is, and where the source lives."""

    def __init__(self, parent: tk.Misc, theme: Theme, *, version: str, tool_version: str, author: str, licence: str, url: str) -> None:
        super().__init__(parent, theme, "About SSL Certificate Studio")
        p = theme.p
        self.url = url
        tk.Label(self.body, text="⚿  SSL Certificate Studio", bg=p.surface, fg=p.text, font=theme.f_h2, anchor="w").pack(fill="x")
        tk.Label(self.body, text=f"Studio {version}  ·  tool {tool_version}", bg=p.surface, fg=p.muted, font=theme.f_small,
                 anchor="w").pack(fill="x", pady=(4, 14))
        tk.Label(self.body, text=f"Created by {author}", bg=p.surface, fg=p.text, font=theme.f_bold, anchor="w").pack(fill="x")
        tk.Label(self.body, text=f"{licence} licence  ·  see the LICENSE file", bg=p.surface, fg=p.muted, font=theme.f_small,
                 anchor="w").pack(fill="x", pady=(2, 0))
        tk.Label(self.body, text=url, bg=p.surface, fg=p.accent2, font=theme.f_mono_small, anchor="w").pack(fill="x", pady=(12, 16))
        row = tk.Frame(self.body, bg=p.surface)
        row.pack(fill="x")
        Button(row, theme, "Close", lambda: self.finish(None), padx=22).pack(side="right")
        Button(row, theme, "Open on GitHub", self.open_source, kind="ghost", padx=18).pack(side="right", padx=(0, 10))

    def open_source(self) -> None:
        try:
            webbrowser.open(self.url)
        except Exception:  # no browser available: the address is shown in the dialog anyway
            pass
