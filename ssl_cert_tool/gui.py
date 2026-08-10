"""Desktop GUI for SSL certificate deployment automation."""
from __future__ import annotations

import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from .core import (
    KEYTOOL_DEFAULT,
    BuildResult,
    build_outputs,
    cert_cn,
    cert_issuer_cn,
    classify_certs,
    collect_input_files,
    get_cert_summary,
    infer_domain,
    load_certs_from_eml,
    load_certs_from_text,
    load_private_key,
    parse_all_inputs,
    public_numbers_match,
    validate_key_cert,
    ParsedCert,
)

CERT_EXTENSIONS = (
    ".crt", ".cer", ".pem", ".p7b", ".p7c", ".p12", ".pfx", ".der", 
    ".ca-bundle", ".bundle", ".eml", ".txt"
)

TOOLTIPS = {
    "cert_files": "Add certificate files (.crt, .pem, .p7b, .eml, .txt, etc.) or folders containing certificates",
    "key_file": "Private key file (.key or .pem) - required for JKS/P12 generation",
    "domain": "Domain name for output files. Auto-detected from leaf cert CN if empty",
    "store_pass": "Password for JKS and P12 keystore files",
    "alias": "Alias name for the key entry in the keystore",
    "output_dir": "Directory where output files will be created",
    "keytool": "Path to Java keytool.exe. Required for JKS creation",
    "p12_password": "Password for PKCS12 (.p12/.pfx) input files if encrypted",
    "paste_cert": "Paste PEM certificate text directly from clipboard",
    "paste_text": "Manually enter or paste PEM certificate text",
}


class ToolTip:
    """Simple tooltip implementation."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tip_window:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("Segoe UI", 9), padx=6, pady=4)
        label.pack()

    def hide(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


def enable_windows_drag_drop(widget: tk.Misc, callback) -> None:
    """Enable file drag-and-drop on Windows without extra dependencies."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import WINFUNCTYPE, c_long, c_uint, c_void_p

        shell32 = ctypes.windll.shell32
        user32 = ctypes.windll.user32
        WM_DROPFILES = 0x0233
        GWL_WNDPROC = -4

        hwnd = widget.winfo_id()
        shell32.DragAcceptFiles(hwnd, True)

        old_wndproc = user32.GetWindowLongPtrW(hwnd, GWL_WNDPROC)

        @WINFUNCTYPE(c_long, c_void_p, c_uint, c_void_p, c_void_p)
        def wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_DROPFILES:
                count = shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                files = []
                buf = ctypes.create_unicode_buffer(1024)
                for i in range(count):
                    shell32.DragQueryFileW(wparam, i, buf, 1024)
                    files.append(buf.value)
                shell32.DragFinish(wparam)
                widget.after(0, lambda f=files: callback(f))
                return 0
            return user32.CallWindowProcW(old_wndproc, hwnd, msg, wparam, lparam)

        widget._dnd_wnd_proc = wnd_proc
        user32.SetWindowLongPtrW(hwnd, GWL_WNDPROC, wnd_proc)
    except Exception:
        pass


class PasteDialog(tk.Toplevel):
    """Dialog for pasting certificate text."""
    def __init__(self, parent, title="Paste Certificate"):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x450")
        self.result = None
        self.transient(parent)
        self.grab_set()

        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="Paste PEM certificate text below:").pack(anchor=tk.W)
        ttk.Label(main, text="(Supports multiple certificates, e.g., full chain)", 
                  foreground="gray").pack(anchor=tk.W)

        self.text = scrolledtext.ScrolledText(main, height=18, wrap=tk.WORD)
        self.text.pack(fill=tk.BOTH, expand=True, pady=(6, 10))

        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Paste from Clipboard", 
                   command=self._paste_clipboard).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_frame, text="Clear", command=self._clear).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="OK", command=self._on_ok).pack(side=tk.RIGHT, padx=(0, 6))

        self.text.focus_set()
        self.bind("<Escape>", lambda e: self.destroy())

    def _paste_clipboard(self):
        try:
            text = self.clipboard_get()
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", text)
        except tk.TclError:
            messagebox.showwarning("Clipboard Empty", "No text in clipboard.", parent=self)

    def _clear(self):
        self.text.delete("1.0", tk.END)

    def _on_ok(self):
        self.result = self.text.get("1.0", tk.END).strip()
        self.destroy()


class CertPreviewDialog(tk.Toplevel):
    """Dialog showing certificate preview before generation."""
    def __init__(self, parent, certs: list[ParsedCert], leaf, intermediates, root):
        super().__init__(parent)
        self.title("Certificate Preview")
        self.geometry("750x500")
        self.transient(parent)
        self.grab_set()

        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text=f"Detected {len(certs)} certificate(s)", 
                  font=("Segoe UI", 11, "bold")).pack(anchor=tk.W)

        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(6, 10))

        cols = ("type", "cn", "issuer", "valid_until")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=12)
        self.tree.heading("type", text="Type")
        self.tree.heading("cn", text="Common Name")
        self.tree.heading("issuer", text="Issuer CN")
        self.tree.heading("valid_until", text="Valid Until")
        self.tree.column("type", width=100)
        self.tree.column("cn", width=220)
        self.tree.column("issuer", width=200)
        self.tree.column("valid_until", width=180)

        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        if leaf:
            summary = get_cert_summary(leaf.cert)
            self.tree.insert("", tk.END, values=(
                "LEAF (Server)", 
                summary["cn"], 
                summary["issuer_cn"],
                summary["not_after"]
            ), tags=("leaf",))

        for pc in intermediates:
            summary = get_cert_summary(pc.cert)
            self.tree.insert("", tk.END, values=(
                "Intermediate CA", 
                summary["cn"], 
                summary["issuer_cn"],
                summary["not_after"]
            ), tags=("intermediate",))

        if root:
            summary = get_cert_summary(root.cert)
            self.tree.insert("", tk.END, values=(
                "Root CA", 
                summary["cn"], 
                summary["issuer_cn"],
                summary["not_after"]
            ), tags=("root",))

        self.tree.tag_configure("leaf", background="#e6ffe6")
        self.tree.tag_configure("intermediate", background="#fff0e6")
        self.tree.tag_configure("root", background="#e6e6ff")

        legend = ttk.Frame(main)
        legend.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(legend, text="Legend:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(legend, text="  Leaf  ", background="#e6ffe6", relief=tk.GROOVE).pack(side=tk.LEFT, padx=2)
        tk.Label(legend, text="  Intermediate  ", background="#fff0e6", relief=tk.GROOVE).pack(side=tk.LEFT, padx=2)
        tk.Label(legend, text="  Root  ", background="#e6e6ff", relief=tk.GROOVE).pack(side=tk.LEFT, padx=2)

        ttk.Button(main, text="Close", command=self.destroy).pack()

        self.bind("<Escape>", lambda e: self.destroy())


class SSLCertToolApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("SSL Cert Tool - Ameyo/CRM Deployment")
        self.root.geometry("1100x850")
        self.root.minsize(950, 700)

        self.cert_paths: list[Path] = []
        self.pasted_certs: list[ParsedCert] = []
        self._busy = False
        self._last_result: BuildResult | None = None
        self._parsed_certs: list[ParsedCert] = []
        self._parsed_keys: list = []

        self.key_path = tk.StringVar()
        self.domain = tk.StringVar()
        self.store_pass = tk.StringVar(value="changeit")
        self.alias = tk.StringVar(value="ameyo-server")
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "output"))
        self.keytool_path = tk.StringVar(value=str(KEYTOOL_DEFAULT))
        self.p12_password = tk.StringVar()

        self.match_status = tk.StringVar(value="—")
        self.leaf_cn = tk.StringVar(value="—")
        self.intermediate_info = tk.StringVar(value="—")
        self.root_info = tk.StringVar(value="—")
        self.valid_from = tk.StringVar(value="—")
        self.valid_until = tk.StringVar(value="—")
        self.status_text = tk.StringVar(value="Ready. Add certificate files to begin.")

        self._build_ui()
        enable_windows_drag_drop(self.root, self._on_drop_files)

    def _build_ui(self) -> None:
        style = ttk.Style()
        if sys.platform == "win32":
            style.theme_use("vista")

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(main, text="Input", padding=8)
        input_frame.pack(fill=tk.X, pady=(0, 8))

        cert_row = ttk.Frame(input_frame)
        cert_row.pack(fill=tk.X, pady=2)
        lbl = ttk.Label(cert_row, text="Certificate files:", width=18)
        lbl.pack(side=tk.LEFT)
        ToolTip(lbl, TOOLTIPS["cert_files"])

        self.cert_listbox = tk.Listbox(cert_row, height=4, selectmode=tk.EXTENDED)
        self.cert_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        cert_btns = ttk.Frame(cert_row)
        cert_btns.pack(side=tk.RIGHT)
        btn = ttk.Button(cert_btns, text="Add Files...", command=self._browse_certs)
        btn.pack(fill=tk.X, pady=1)
        btn = ttk.Button(cert_btns, text="Add Folder...", command=self._browse_folder)
        btn.pack(fill=tk.X, pady=1)
        btn = ttk.Button(cert_btns, text="Paste Cert...", command=self._paste_cert_dialog)
        btn.pack(fill=tk.X, pady=1)
        ToolTip(btn, TOOLTIPS["paste_text"])
        btn = ttk.Button(cert_btns, text="Quick Paste", command=self._quick_paste_clipboard)
        btn.pack(fill=tk.X, pady=1)
        ToolTip(btn, TOOLTIPS["paste_cert"])
        btn = ttk.Button(cert_btns, text="Remove", command=self._remove_selected_certs)
        btn.pack(fill=tk.X, pady=1)

        ttk.Label(input_frame, text="Drag and drop files/folders onto this window. "
                  "Supports: .crt, .pem, .p7b, .p12, .eml (GlobalSign emails), .txt",
                  foreground="gray").pack(anchor=tk.W)

        self._add_field(input_frame, "Private key:", self.key_path, self._browse_key, 
                        optional=True, tooltip=TOOLTIPS["key_file"])
        self._add_field(input_frame, "Domain name:", self.domain, 
                        optional=True, tooltip=TOOLTIPS["domain"])

        row = ttk.Frame(input_frame)
        row.pack(fill=tk.X, pady=2)
        lbl = ttk.Label(row, text="P12 password (optional):", width=18)
        lbl.pack(side=tk.LEFT)
        ToolTip(lbl, TOOLTIPS["p12_password"])
        entry = ttk.Entry(row, textvariable=self.p12_password, show="*")
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self._add_field(input_frame, "Keystore password:", self.store_pass, show="*",
                        tooltip=TOOLTIPS["store_pass"])
        self._add_field(input_frame, "Alias:", self.alias, tooltip=TOOLTIPS["alias"])
        self._add_field(input_frame, "Output directory:", self.output_dir, self._browse_output,
                        tooltip=TOOLTIPS["output_dir"])
        self._add_field(input_frame, "Keytool path:", self.keytool_path, self._browse_keytool,
                        tooltip=TOOLTIPS["keytool"])

        action_frame = ttk.Frame(main)
        action_frame.pack(fill=tk.X, pady=(0, 8))
        
        self.preview_btn = ttk.Button(action_frame, text="Preview Certs", command=self._on_preview)
        self.preview_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self.preview_btn, "Parse inputs and preview detected certificates")
        
        self.validate_btn = ttk.Button(action_frame, text="Validate", command=self._on_validate)
        self.validate_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self.validate_btn, "Validate that private key matches the leaf certificate")
        
        self.generate_btn = ttk.Button(action_frame, text="Generate", command=self._on_generate)
        self.generate_btn.pack(side=tk.LEFT, padx=(0, 6))
        ToolTip(self.generate_btn, "Generate all output files (PEM, JKS, P12, etc.)")
        
        ttk.Button(action_frame, text="Clear", command=self._on_clear).pack(side=tk.LEFT)
        
        self.progress = ttk.Progressbar(action_frame, mode="indeterminate", length=180)
        self.progress.pack(side=tk.RIGHT)

        results = ttk.LabelFrame(main, text="Results", padding=8)
        results.pack(fill=tk.BOTH, expand=True)

        summary = ttk.Frame(results)
        summary.pack(fill=tk.X, pady=(0, 6))
        self._summary_row(summary, "Leaf CN:", self.leaf_cn, 0)
        self._summary_row(summary, "Intermediate:", self.intermediate_info, 1)
        self._summary_row(summary, "Root:", self.root_info, 2)
        self._summary_row(summary, "Valid from:", self.valid_from, 3)
        self._summary_row(summary, "Valid until:", self.valid_until, 4)
        
        match_row = ttk.Frame(summary)
        match_row.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=2)
        ttk.Label(match_row, text="Key/Cert match:", width=18).pack(side=tk.LEFT)
        self.match_label = ttk.Label(match_row, textvariable=self.match_status, 
                                     font=("Segoe UI", 10, "bold"))
        self.match_label.pack(side=tk.LEFT)

        notebook = ttk.Notebook(results)
        notebook.pack(fill=tk.BOTH, expand=True)

        md5_frame = ttk.Frame(notebook, padding=4)
        notebook.add(md5_frame, text="MD5 Checksums")
        md5_cols = ("file", "md5")
        self.md5_tree = ttk.Treeview(md5_frame, columns=md5_cols, show="headings", height=8)
        self.md5_tree.heading("file", text="File")
        self.md5_tree.heading("md5", text="MD5")
        self.md5_tree.column("file", width=360)
        self.md5_tree.column("md5", width=280)
        md5_scroll = ttk.Scrollbar(md5_frame, orient=tk.VERTICAL, command=self.md5_tree.yview)
        self.md5_tree.configure(yscrollcommand=md5_scroll.set)
        self.md5_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        md5_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        files_frame = ttk.Frame(notebook, padding=4)
        notebook.add(files_frame, text="Created Files")
        files_cols = ("file", "size", "status")
        self.files_tree = ttk.Treeview(files_frame, columns=files_cols, show="headings", height=8)
        self.files_tree.heading("file", text="File")
        self.files_tree.heading("size", text="Size (bytes)")
        self.files_tree.heading("status", text="Status")
        self.files_tree.column("file", width=350)
        self.files_tree.column("size", width=100, anchor=tk.E)
        self.files_tree.column("status", width=100)
        files_scroll = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=files_scroll.set)
        self.files_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        files_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        log_frame = ttk.Frame(notebook, padding=4)
        notebook.add(log_frame, text="Log")
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        status_bar = ttk.Label(main, textvariable=self.status_text, relief=tk.SUNKEN, 
                               anchor=tk.W, padding=4)
        status_bar.pack(fill=tk.X, pady=(6, 0))

    def _add_field(self, parent, label, var, browse_cmd=None, optional=False, show=None, 
                   tooltip=None) -> None:
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        lbl_text = label + (" (optional)" if optional else "")
        lbl = ttk.Label(row, text=lbl_text, width=18)
        lbl.pack(side=tk.LEFT)
        if tooltip:
            ToolTip(lbl, tooltip)
        entry = ttk.Entry(row, textvariable=var, show=show)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        if browse_cmd:
            ttk.Button(row, text="Browse...", command=browse_cmd).pack(side=tk.RIGHT)

    def _summary_row(self, parent, label, var, row) -> None:
        ttk.Label(parent, text=label, width=18).grid(row=row, column=0, sticky=tk.W, pady=1)
        ttk.Label(parent, textvariable=var, wraplength=700).grid(row=row, column=1, sticky=tk.W, pady=1)

    def _log(self, message: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _clear_log(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _refresh_cert_listbox(self) -> None:
        self.cert_listbox.delete(0, tk.END)
        for p in self.cert_paths:
            self.cert_listbox.insert(tk.END, str(p))
        if self.pasted_certs:
            self.cert_listbox.insert(tk.END, f"[Pasted: {len(self.pasted_certs)} cert(s)]")

    def _add_paths(self, paths: list[str]) -> None:
        added = 0
        for raw in paths:
            path = Path(raw)
            if path.is_dir():
                for f in collect_input_files([path]):
                    if f not in self.cert_paths:
                        self.cert_paths.append(f)
                        added += 1
            elif path.is_file():
                if path not in self.cert_paths:
                    self.cert_paths.append(path)
                    added += 1
        self._refresh_cert_listbox()
        if added:
            self._log(f"Added {added} file(s).")
            self.status_text.set(f"{len(self.cert_paths)} certificate file(s) loaded.")

    def _on_drop_files(self, files: list[str]) -> None:
        self._add_paths(files)

    def _browse_certs(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select certificate files",
            filetypes=[
                ("All Certificate Types", "*.crt *.cer *.pem *.p7b *.p7c *.p12 *.pfx *.der *.ca-bundle *.eml *.txt"),
                ("Certificate files", "*.crt *.cer *.pem *.der"),
                ("PKCS7 bundles", "*.p7b *.p7c"),
                ("PKCS12 keystores", "*.p12 *.pfx"),
                ("CA bundles", "*.ca-bundle *.bundle"),
                ("Email files (GlobalSign)", "*.eml"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if paths:
            self._add_paths(list(paths))

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder containing certificates")
        if path:
            self._add_paths([path])

    def _browse_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Select private key",
            filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")],
        )
        if path:
            self.key_path.set(path)

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.output_dir.set(path)

    def _browse_keytool(self) -> None:
        path = filedialog.askopenfilename(
            title="Select keytool executable",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.keytool_path.set(path)

    def _paste_cert_dialog(self) -> None:
        dialog = PasteDialog(self.root)
        self.root.wait_window(dialog)
        if dialog.result:
            certs = load_certs_from_text(dialog.result, "pasted_text")
            if certs:
                self.pasted_certs.extend(certs)
                self._refresh_cert_listbox()
                self._log(f"Parsed {len(certs)} certificate(s) from pasted text.")
                self.status_text.set(f"Added {len(certs)} pasted certificate(s).")
            else:
                messagebox.showwarning("No Certificates", 
                    "No valid PEM certificates found in the pasted text.", parent=self.root)

    def _quick_paste_clipboard(self) -> None:
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Clipboard Empty", "No text in clipboard.", parent=self.root)
            return
        certs = load_certs_from_text(text, "clipboard")
        if certs:
            self.pasted_certs.extend(certs)
            self._refresh_cert_listbox()
            self._log(f"Parsed {len(certs)} certificate(s) from clipboard.")
            self.status_text.set(f"Added {len(certs)} certificate(s) from clipboard.")
        else:
            messagebox.showwarning("No Certificates", 
                "No valid PEM certificates found in clipboard.", parent=self.root)

    def _remove_selected_certs(self) -> None:
        selected = list(self.cert_listbox.curselection())
        if not selected:
            return
        for idx in reversed(selected):
            if idx < len(self.cert_paths):
                del self.cert_paths[idx]
            else:
                self.pasted_certs.clear()
        self._refresh_cert_listbox()

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.preview_btn.configure(state=state)
        self.validate_btn.configure(state=state)
        self.generate_btn.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _parse_inputs(self):
        if not self.cert_paths and not self.pasted_certs:
            raise ValueError("Add at least one certificate file, folder, or paste certificate text.")
        
        all_certs = list(self.pasted_certs)
        keys = []
        
        if self.cert_paths:
            files = collect_input_files(self.cert_paths)
            if files:
                self._log(f"Processing {len(files)} input file(s)...")
                p12_pwd = self.p12_password.get().strip() or None
                parsed_certs, parsed_keys = parse_all_inputs(files, p12_pwd)
                all_certs.extend(parsed_certs)
                keys.extend(parsed_keys)
                self._log(f"Parsed {len(parsed_certs)} certificate(s), {len(parsed_keys)} private key(s) from files.")
        
        if self.pasted_certs:
            self._log(f"Including {len(self.pasted_certs)} pasted certificate(s).")
        
        if not all_certs:
            raise ValueError("No certificates found in the inputs.")
        
        self._parsed_certs = all_certs
        self._parsed_keys = keys
        
        private_key = None
        key_file = self.key_path.get().strip()
        if key_file:
            key_path = Path(key_file)
            if not key_path.is_file():
                raise ValueError(f"Private key not found: {key_path}")
            private_key = load_private_key(key_path.read_bytes())
            self._log(f"Loaded private key from {key_path.name}")
        elif keys:
            private_key = keys[0][1]
            self._log(f"Using private key from {keys[0][0].name}")
        
        domain_hint = self.domain.get().strip() or None
        leaf, intermediates, root = classify_certs(all_certs, domain_hint)
        
        if leaf is None:
            raise ValueError("Could not identify leaf/server certificate.")
        
        if not domain_hint and leaf:
            cn = cert_cn(leaf.cert)
            if cn:
                auto_domain = cn.lstrip("*.")
                self.domain.set(auto_domain)
                self._log(f"Auto-detected domain from CN: {auto_domain}")
        
        return all_certs, keys, private_key, leaf, intermediates, root, domain_hint

    def _update_classification(self, leaf, intermediates, root) -> None:
        self.leaf_cn.set(cert_cn(leaf.cert) or "(unknown)")
        if intermediates:
            names = ", ".join(cert_cn(pc.cert) or pc.source.name for pc in intermediates)
            self.intermediate_info.set(names)
        else:
            self.intermediate_info.set("not found")
        if root:
            self.root_info.set(cert_cn(root.cert) or root.source.name)
        else:
            self.root_info.set("not found")

    def _update_validation_display(self, validation: dict) -> None:
        self.valid_from.set(validation.get("not_before", "—"))
        self.valid_until.set(validation.get("not_after", "—"))
        match = validation.get("key_cert_match")
        if match is True:
            self.match_status.set("PASS")
            self.match_label.configure(foreground="green")
        elif match is False:
            self.match_status.set("FAIL")
            self.match_label.configure(foreground="red")
        else:
            self.match_status.set("—")
            self.match_label.configure(foreground="black")

    def _update_md5_tree(self, md5_map: dict[str, str]) -> None:
        for item in self.md5_tree.get_children():
            self.md5_tree.delete(item)
        for name in sorted(md5_map):
            self.md5_tree.insert("", tk.END, values=(name, md5_map[name]))

    def _update_files_tree(self, files: list[Path], warnings: list[str] = None) -> None:
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        warning_files = set()
        if warnings:
            for w in warnings:
                if "JKS" in w:
                    warning_files.add(".jks")
        for f in sorted(files):
            try:
                size = f.stat().st_size
                status = "OK"
            except OSError:
                size = 0
                status = "Error"
            if any(f.suffix == ext for ext in warning_files):
                status = "Warning"
            self.files_tree.insert("", tk.END, values=(str(f), f"{size:,}", status))

    def _on_preview(self) -> None:
        self._clear_log()
        self._log("Parsing inputs for preview...")
        try:
            all_certs, keys, private_key, leaf, intermediates, root, _ = self._parse_inputs()
            self._update_classification(leaf, intermediates, root)
            CertPreviewDialog(self.root, all_certs, leaf, intermediates, root)
            self.status_text.set(f"Preview: {len(all_certs)} cert(s) - Leaf: {cert_cn(leaf.cert)}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc), parent=self.root)
            self._log(f"ERROR: {exc}")
            self.status_text.set("Preview failed.")

    def _run_validate(self) -> None:
        try:
            _, _, private_key, leaf, intermediates, root, _ = self._parse_inputs()
            self.root.after(0, lambda: self._update_classification(leaf, intermediates, root))
            if private_key is None:
                self.root.after(0, lambda: messagebox.showwarning(
                    "Private Key Missing",
                    "No private key found. Browse for a .key/.pem file before validating key/cert match.",
                    parent=self.root
                ))
                from .core import cert_fingerprint_md5
                v = {
                    "not_before": str(leaf.cert.not_valid_before_utc),
                    "not_after": str(leaf.cert.not_valid_after_utc),
                    "key_cert_match": None,
                    "cert_fingerprint_md5": cert_fingerprint_md5(leaf.cert),
                }
                self.root.after(0, lambda: self._update_validation_display(v))
                self.root.after(0, lambda: self._update_md5_tree({"cert_md5": v["cert_fingerprint_md5"]}))
                self.root.after(0, lambda: self.status_text.set(
                    "Certificates classified. Private key required for match check."))
                return
            v = validate_key_cert(private_key, leaf)
            self.root.after(0, lambda: self._update_validation_display(v))
            md5_map = {
                "cert_fingerprint": v["cert_fingerprint_md5"],
                "key_md5": v["key_md5"],
                "cert_der_md5": v["cert_md5"],
            }
            self.root.after(0, lambda: self._update_md5_tree(md5_map))
            status = "Validation PASS" if v["key_cert_match"] else "Validation FAIL - key does not match certificate"
            self.root.after(0, lambda: self._log(status))
            self.root.after(0, lambda: self.status_text.set(status))
            if not v["key_cert_match"]:
                self.root.after(0, lambda: messagebox.showerror(
                    "Validation Failed", "Private key does NOT match the leaf certificate.",
                    parent=self.root))
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc), parent=self.root))
            self.root.after(0, lambda: self._log(f"ERROR: {exc}"))
            self.root.after(0, lambda: self.status_text.set("Validation failed."))
        finally:
            self.root.after(0, lambda: self._set_busy(False))

    def _run_generate(self) -> None:
        try:
            _, _, private_key, leaf, intermediates, root, domain_hint = self._parse_inputs()
            if private_key is None:
                raise ValueError("Private key is required. Browse for a .key or .pem file.")
            if not public_numbers_match(private_key, leaf.cert):
                v = validate_key_cert(private_key, leaf)
                self.root.after(0, lambda: self._update_validation_display(v))
                raise ValueError("Private key does not match the leaf certificate.")
            domain = infer_domain(leaf, domain_hint or self.domain.get().strip())
            out_base = Path(self.output_dir.get().strip() or "output")
            output_dir = out_base / domain
            store_pass = self.store_pass.get() or "changeit"
            alias = self.alias.get() or "ameyo-server"
            keytool = Path(self.keytool_path.get().strip()) if self.keytool_path.get().strip() else KEYTOOL_DEFAULT
            self.root.after(0, lambda: self._log(f"Generating files -> {output_dir}"))
            self.root.after(0, lambda: self._log(f"Using keytool: {keytool}"))
            result = build_outputs(
                domain=domain,
                output_dir=output_dir,
                leaf=leaf,
                intermediates=intermediates,
                root=root,
                private_key=private_key,
                store_pass=store_pass,
                alias=alias,
                keytool=keytool,
            )
            self._last_result = result
            self.root.after(0, lambda: self._update_classification(leaf, intermediates, root))
            self.root.after(0, lambda: self._update_validation_display(result.validation))
            self.root.after(0, lambda: self._update_md5_tree(result.validation.get("output_md5", {})))
            self.root.after(0, lambda: self._update_files_tree(result.files, result.warnings))
            for w in result.warnings:
                self.root.after(0, lambda msg=w: self._log(f"WARNING: {msg}"))
            self.root.after(0, lambda: self._log(f"Created {len(result.files)} file(s) in {output_dir}"))
            self.root.after(0, lambda: self.status_text.set(
                f"Done. {len(result.files)} files created in {output_dir}"))
            self.root.after(0, lambda: messagebox.showinfo(
                "Success", f"Generated {len(result.files)} files in:\n{output_dir}",
                parent=self.root))
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Error", str(exc), parent=self.root))
            self.root.after(0, lambda: self._log(f"ERROR: {exc}"))
            self.root.after(0, lambda: self.status_text.set("Generation failed."))
        finally:
            self.root.after(0, lambda: self._set_busy(False))

    def _start_task(self, target) -> None:
        if self._busy:
            return
        self._set_busy(True)
        threading.Thread(target=target, daemon=True).start()

    def _on_validate(self) -> None:
        self._clear_log()
        self._log("Starting validation...")
        self._start_task(self._run_validate)

    def _on_generate(self) -> None:
        self._clear_log()
        self._log("Starting generation...")
        self._start_task(self._run_generate)

    def _on_clear(self) -> None:
        self.cert_paths.clear()
        self.pasted_certs.clear()
        self._parsed_certs.clear()
        self._parsed_keys.clear()
        self._refresh_cert_listbox()
        self.key_path.set("")
        self.domain.set("")
        self.p12_password.set("")
        self.store_pass.set("changeit")
        self.alias.set("ameyo-server")
        self.output_dir.set(str(Path.cwd() / "output"))
        self.leaf_cn.set("—")
        self.intermediate_info.set("—")
        self.root_info.set("—")
        self.valid_from.set("—")
        self.valid_until.set("—")
        self.match_status.set("—")
        self.match_label.configure(foreground="black")
        self._update_md5_tree({})
        self._update_files_tree([])
        self._clear_log()
        self.status_text.set("Cleared. Ready.")
        self._last_result = None

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    app = SSLCertToolApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())