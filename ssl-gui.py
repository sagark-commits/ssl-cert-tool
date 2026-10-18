"""SSL Certificate Tool - Tkinter GUI"""
from __future__ import annotations

import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from typing import Callable

# Support running from source and as a frozen PyInstaller app
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _meipass = str(sys._MEIPASS)
    if _meipass not in sys.path:
        sys.path.insert(0, _meipass)

try:
    from ssl_cert_tool.core import (
        KEYTOOL_DEFAULT,
        build_outputs,
        classify_certs,
        collect_input_files,
        format_inspect_report,
        infer_domain,
        inspect_inputs,
        load_private_key,
        parse_all_inputs,
        public_numbers_match,
        cert_cn,
        read_jks_info,
        format_jks_info,
    )
    CORE_AVAILABLE = True
except ImportError as e:
    CORE_AVAILABLE = False
    IMPORT_ERROR = str(e)

try:
    from ssl_deploy.deployer import SSLDeployer, load_deploy_config
    DEPLOY_AVAILABLE = True
except ImportError:
    DEPLOY_AVAILABLE = False


class ToolTip:
    """Simple tooltip implementation."""
    def __init__(self, widget: tk.Widget, text: str):
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


class SSLCertToolGUI:
    """Main GUI application."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SSL Certificate Tool")
        self.root.geometry("900x700")
        self.root.minsize(750, 550)
        
        self.cert_paths: list[Path] = []
        self.key_path = tk.StringVar()
        self.domain = tk.StringVar()
        self.store_pass = tk.StringVar(value="changeit")
        self.alias = tk.StringVar(value="ameyo-server")
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "output"))
        self.keytool_path = tk.StringVar(value=str(KEYTOOL_DEFAULT) if CORE_AVAILABLE else "keytool")
        self.p12_password = tk.StringVar()
        
        self.deploy_config_path = tk.StringVar()
        self.deploy_cert_dir = tk.StringVar()
        self.dry_run = tk.BooleanVar(value=False)
        self.trust_new_hosts = tk.BooleanVar(value=False)
        
        self._build_ui()
    
    def _build_ui(self):
        style = ttk.Style()
        if sys.platform == "win32":
            style.theme_use("vista")
        
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        
        self.generate_tab = ttk.Frame(notebook, padding=10)
        self.inspect_tab = ttk.Frame(notebook, padding=10)
        self.deploy_tab = ttk.Frame(notebook, padding=10)
        
        notebook.add(self.generate_tab, text=" Generate ")
        notebook.add(self.inspect_tab, text=" Inspect ")
        notebook.add(self.deploy_tab, text=" Deploy ")
        
        self._build_generate_tab()
        self._build_inspect_tab()
        self._build_deploy_tab()
        
        results_frame = ttk.LabelFrame(main, text="Results", padding=8)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame, height=12, wrap=tk.WORD,
            font=("Consolas", 9), state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=4)
        status_bar.pack(fill=tk.X, pady=(8, 0))
    
    def _build_generate_tab(self):
        frame = self.generate_tab
        
        cert_frame = ttk.LabelFrame(frame, text="Certificate Files", padding=8)
        cert_frame.pack(fill=tk.X, pady=(0, 8))
        
        self.cert_listbox = tk.Listbox(cert_frame, height=4, selectmode=tk.EXTENDED)
        self.cert_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        
        cert_btns = ttk.Frame(cert_frame)
        cert_btns.pack(side=tk.RIGHT, fill=tk.Y)
        btn = ttk.Button(cert_btns, text="Add Files...", command=self._browse_certs)
        btn.pack(fill=tk.X, pady=1)
        ToolTip(btn, "Add certificate files (.crt, .pem, .p7b, .p12, .eml, etc.)")
        btn = ttk.Button(cert_btns, text="Add Folder...", command=self._browse_folder)
        btn.pack(fill=tk.X, pady=1)
        ToolTip(btn, "Add a folder containing certificate files")
        ttk.Button(cert_btns, text="Remove", command=self._remove_selected_certs).pack(fill=tk.X, pady=1)
        ttk.Button(cert_btns, text="Clear", command=self._clear_certs).pack(fill=tk.X, pady=1)
        
        self._add_field(frame, "Private Key:", self.key_path, self._browse_key,
                       tooltip="Private key file (.key or .pem) - required for JKS/P12 generation")
        self._add_field(frame, "Domain:", self.domain,
                       tooltip="Domain name (auto-detected from cert CN if empty)")
        
        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="P12 Password:", width=18).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.p12_password, show="*", width=20).pack(side=tk.LEFT, padx=(0, 10))
        ToolTip(row, "Password for encrypted PKCS12 input files (optional)")
        
        self._add_field(frame, "Keystore Password:", self.store_pass,
                       tooltip="Password for output JKS/P12 keystores")
        self._add_field(frame, "Key Alias:", self.alias,
                       tooltip="Alias name for the key entry in keystore")
        self._add_field(frame, "Output Directory:", self.output_dir, self._browse_output,
                       tooltip="Directory where output files will be created")
        self._add_field(frame, "Keytool Path:", self.keytool_path, self._browse_keytool,
                       tooltip="Optional. Path to Java keytool; if it is not found, a built-in JKS writer is used")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Preview Certs", command=self._on_preview).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Validate Key/Cert", command=self._on_validate).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Generate All", command=self._on_generate).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear Results", command=self._clear_results).pack(side=tk.RIGHT)
    
    def _build_inspect_tab(self):
        frame = self.inspect_tab
        
        input_frame = ttk.LabelFrame(frame, text="Files to Inspect", padding=8)
        input_frame.pack(fill=tk.X, pady=(0, 8))
        
        self.inspect_listbox = tk.Listbox(input_frame, height=4, selectmode=tk.EXTENDED)
        self.inspect_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        
        btns = ttk.Frame(input_frame)
        btns.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(btns, text="Add Files...", command=self._browse_inspect_files).pack(fill=tk.X, pady=1)
        ttk.Button(btns, text="Add Folder...", command=self._browse_inspect_folder).pack(fill=tk.X, pady=1)
        ttk.Button(btns, text="Remove", command=self._remove_inspect_files).pack(fill=tk.X, pady=1)
        ttk.Button(btns, text="Clear", command=self._clear_inspect_files).pack(fill=tk.X, pady=1)
        
        self.inspect_paths: list[Path] = []
        
        jks_frame = ttk.LabelFrame(frame, text="JKS Inspection (Optional)", padding=8)
        jks_frame.pack(fill=tk.X, pady=(0, 8))
        
        self.jks_path = tk.StringVar()
        self.jks_password = tk.StringVar(value="changeit")
        
        self._add_field(jks_frame, "JKS File:", self.jks_path, self._browse_jks,
                       tooltip="Path to existing JKS keystore to inspect")
        self._add_field(jks_frame, "JKS Password:", self.jks_password,
                       tooltip="Password for the JKS keystore")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Inspect Files", command=self._on_inspect).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Inspect JKS", command=self._on_inspect_jks).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear Results", command=self._clear_results).pack(side=tk.RIGHT)
    
    def _build_deploy_tab(self):
        frame = self.deploy_tab
        
        if not DEPLOY_AVAILABLE:
            ttk.Label(frame, text="Deployment requires: pip install pyyaml paramiko",
                     font=("Segoe UI", 10)).pack(pady=20)
            return
        
        config_frame = ttk.LabelFrame(frame, text="Deployment Configuration", padding=8)
        config_frame.pack(fill=tk.X, pady=(0, 8))
        
        self._add_field(config_frame, "Config File:", self.deploy_config_path, self._browse_deploy_config,
                       tooltip="YAML configuration file for deployment (deploy-config.yaml)")
        self._add_field(config_frame, "Certificate Dir:", self.deploy_cert_dir, self._browse_deploy_certs,
                       tooltip="Directory containing generated SSL files")
        
        opts_frame = ttk.Frame(config_frame)
        opts_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Checkbutton(opts_frame, text="Dry Run (no changes)", variable=self.dry_run).pack(side=tk.LEFT)
        ttk.Checkbutton(
            opts_frame,
            text="Trust new SSH host keys (first connection only)",
            variable=self.trust_new_hosts,
        ).pack(side=tk.LEFT, padx=(12, 0))
        ToolTip(opts_frame, "Preview what would be deployed without making changes")
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Validate Config", command=self._on_validate_deploy).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Deploy", command=self._on_deploy).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear Results", command=self._clear_results).pack(side=tk.RIGHT)
    
    def _add_field(self, parent, label: str, var: tk.StringVar, browse_cmd: Callable = None,
                  tooltip: str = None):
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        lbl = ttk.Label(row, text=label, width=18)
        lbl.pack(side=tk.LEFT)
        entry = ttk.Entry(row, textvariable=var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        if browse_cmd:
            ttk.Button(row, text="Browse...", command=browse_cmd).pack(side=tk.RIGHT)
        if tooltip:
            ToolTip(lbl, tooltip)
            ToolTip(entry, tooltip)
    
    def _browse_certs(self):
        files = filedialog.askopenfilenames(
            title="Select certificate files",
            filetypes=[
                ("All Cert Types", "*.crt *.cer *.pem *.p7b *.p7c *.p12 *.pfx *.der *.ca-bundle *.eml *.txt"),
                ("Certificate files", "*.crt *.cer *.pem *.der"),
                ("PKCS7 bundles", "*.p7b *.p7c"),
                ("PKCS12 keystores", "*.p12 *.pfx"),
                ("Email files", "*.eml"),
                ("All files", "*.*"),
            ],
        )
        self._add_paths(files)
    
    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder containing certificates")
        if path:
            self._add_paths([path])
    
    def _add_paths(self, paths):
        for p in paths:
            path = Path(p)
            if path not in self.cert_paths:
                self.cert_paths.append(path)
                self.cert_listbox.insert(tk.END, str(path))
    
    def _remove_selected_certs(self):
        selected = list(self.cert_listbox.curselection())
        for idx in reversed(selected):
            self.cert_listbox.delete(idx)
            if idx < len(self.cert_paths):
                del self.cert_paths[idx]
    
    def _clear_certs(self):
        self.cert_paths.clear()
        self.cert_listbox.delete(0, tk.END)
    
    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select private key",
            filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")],
        )
        if path:
            self.key_path.set(path)
    
    def _browse_output(self):
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.output_dir.set(path)
    
    def _browse_keytool(self):
        path = filedialog.askopenfilename(
            title="Select keytool executable",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.keytool_path.set(path)
    
    def _browse_inspect_files(self):
        files = filedialog.askopenfilenames(
            title="Select files to inspect",
            filetypes=[
                ("All Cert Types", "*.crt *.cer *.pem *.p7b *.p7c *.p12 *.pfx *.der *.eml *.txt *.jks"),
                ("All files", "*.*"),
            ],
        )
        for f in files:
            path = Path(f)
            if path not in self.inspect_paths:
                self.inspect_paths.append(path)
                self.inspect_listbox.insert(tk.END, str(path))
    
    def _browse_inspect_folder(self):
        path = filedialog.askdirectory(title="Select folder to inspect")
        if path:
            p = Path(path)
            if p not in self.inspect_paths:
                self.inspect_paths.append(p)
                self.inspect_listbox.insert(tk.END, str(p))
    
    def _remove_inspect_files(self):
        selected = list(self.inspect_listbox.curselection())
        for idx in reversed(selected):
            self.inspect_listbox.delete(idx)
            if idx < len(self.inspect_paths):
                del self.inspect_paths[idx]
    
    def _clear_inspect_files(self):
        self.inspect_paths.clear()
        self.inspect_listbox.delete(0, tk.END)
    
    def _browse_jks(self):
        path = filedialog.askopenfilename(
            title="Select JKS keystore",
            filetypes=[("JKS files", "*.jks"), ("All files", "*.*")],
        )
        if path:
            self.jks_path.set(path)
    
    def _browse_deploy_config(self):
        path = filedialog.askopenfilename(
            title="Select deployment config",
            filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")],
        )
        if path:
            self.deploy_config_path.set(path)
    
    def _browse_deploy_certs(self):
        path = filedialog.askdirectory(title="Select certificate directory")
        if path:
            self.deploy_cert_dir.set(path)
    
    def _log(self, message: str):
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.results_text.configure(state=tk.DISABLED)
    
    def _clear_results(self):
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.configure(state=tk.DISABLED)
    
    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()
    
    def _run_task(self, task: Callable, desc: str):
        if not CORE_AVAILABLE:
            messagebox.showerror("Error", f"Core module not available: {IMPORT_ERROR}")
            return
        
        def wrapper():
            self._set_status(f"{desc}...")
            try:
                task()
                self._set_status("Done")
            except Exception as e:
                self._log(f"\nERROR: {e}")
                self._set_status("Error")
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=wrapper, daemon=True).start()
    
    def _on_preview(self):
        if not self.cert_paths:
            messagebox.showwarning("Warning", "Add certificate files first.")
            return
        self._run_task(self._do_preview, "Parsing certificates")
    
    def _do_preview(self):
        self._clear_results()
        files = collect_input_files(self.cert_paths)
        self._log(f"Found {len(files)} input file(s)")
        
        p12_pwd = self.p12_password.get().strip() or None
        all_certs, keys = parse_all_inputs(files, p12_pwd)
        self._log(f"Parsed {len(all_certs)} certificate(s), {len(keys)} private key(s)\n")
        
        domain_hint = self.domain.get().strip() or None
        leaf, intermediates, root = classify_certs(all_certs, domain_hint)
        
        self._log("=== Certificate Classification ===")
        if leaf:
            self._log(f"  Leaf CN      : {cert_cn(leaf.cert)}")
            self._log(f"  Valid until  : {leaf.cert.not_valid_after_utc}")
        else:
            self._log("  Leaf: NOT FOUND")
        
        if intermediates:
            self._log(f"  Intermediates: {len(intermediates)}")
            for pc in intermediates:
                self._log(f"    - {cert_cn(pc.cert) or pc.source.name}")
        
        if root:
            self._log(f"  Root CA      : {cert_cn(root.cert)}")
        else:
            self._log("  Root: not found (may be embedded)")
        
        if keys:
            self._log(f"\n  Private keys found: {len(keys)}")
            for kp, _ in keys:
                self._log(f"    - {kp.name}")
    
    def _on_validate(self):
        if not self.cert_paths:
            messagebox.showwarning("Warning", "Add certificate files first.")
            return
        if not self.key_path.get().strip():
            messagebox.showwarning("Warning", "Select a private key file.")
            return
        self._run_task(self._do_validate, "Validating")
    
    def _do_validate(self):
        self._clear_results()
        key_file = Path(self.key_path.get().strip())
        if not key_file.is_file():
            raise ValueError(f"Key file not found: {key_file}")
        
        private_key = load_private_key(key_file.read_bytes())
        
        files = collect_input_files(self.cert_paths)
        p12_pwd = self.p12_password.get().strip() or None
        all_certs, _ = parse_all_inputs(files, p12_pwd)
        
        if not all_certs:
            raise ValueError("No certificates found in inputs.")
        
        domain_hint = self.domain.get().strip() or None
        leaf, _, _ = classify_certs(all_certs, domain_hint)
        
        if not leaf:
            raise ValueError("Could not identify leaf certificate.")
        
        match = public_numbers_match(private_key, leaf.cert)
        
        self._log("=== Key/Certificate Validation ===")
        self._log(f"  Key file  : {key_file.name}")
        self._log(f"  Leaf CN   : {cert_cn(leaf.cert)}")
        self._log(f"  Valid     : {leaf.cert.not_valid_before_utc} -> {leaf.cert.not_valid_after_utc}")
        self._log(f"  Match     : {'PASS' if match else 'FAIL'}")
        
        if not match:
            self._log("\n  WARNING: Private key does NOT match the leaf certificate!")
    
    def _on_generate(self):
        if not self.cert_paths:
            messagebox.showwarning("Warning", "Add certificate files first.")
            return
        if not self.key_path.get().strip():
            messagebox.showwarning("Warning", "Select a private key file.")
            return
        self._run_task(self._do_generate, "Generating files")
    
    def _do_generate(self):
        self._clear_results()
        key_file = Path(self.key_path.get().strip())
        if not key_file.is_file():
            raise ValueError(f"Key file not found: {key_file}")
        
        private_key = load_private_key(key_file.read_bytes())
        
        files = collect_input_files(self.cert_paths)
        self._log(f"Processing {len(files)} input file(s)...")
        
        p12_pwd = self.p12_password.get().strip() or None
        all_certs, _ = parse_all_inputs(files, p12_pwd)
        
        if not all_certs:
            raise ValueError("No certificates found in inputs.")
        
        domain_hint = self.domain.get().strip() or None
        leaf, intermediates, root = classify_certs(all_certs, domain_hint)
        
        if not leaf:
            raise ValueError("Could not identify leaf certificate.")
        
        if not public_numbers_match(private_key, leaf.cert):
            raise ValueError("Private key does NOT match the leaf certificate!")
        
        domain = infer_domain(leaf, domain_hint)
        out_dir = Path(self.output_dir.get().strip()) / domain
        
        self._log(f"Building outputs -> {out_dir}")
        
        keytool = Path(self.keytool_path.get().strip()) if self.keytool_path.get().strip() else KEYTOOL_DEFAULT
        
        result = build_outputs(
            domain=domain,
            output_dir=out_dir,
            leaf=leaf,
            intermediates=intermediates,
            root=root,
            private_key=private_key,
            store_pass=self.store_pass.get() or "changeit",
            alias=self.alias.get() or "ameyo-server",
            keytool=keytool,
        )
        
        self._log("\n=== Generation Complete ===")
        self._log(f"  Domain: {result.domain}")
        self._log(f"  Output: {result.output_dir}")
        self._log(f"\n  Created {len(result.files)} file(s):")
        for f in sorted(result.files):
            self._log(f"    - {f.name} ({f.stat().st_size:,} bytes)")
        
        if result.warnings:
            self._log("\n  Warnings:")
            for w in result.warnings:
                self._log(f"    - {w}")
        
        v = result.validation
        self._log(f"\n  Validation:")
        self._log(f"    Key/Cert match: {'PASS' if v.get('key_cert_match') else 'FAIL'}")
        self._log(f"    Cert fingerprint: {v.get('cert_fingerprint_md5', 'N/A')}")
    
    def _on_inspect(self):
        if not self.inspect_paths:
            messagebox.showwarning("Warning", "Add files to inspect first.")
            return
        self._run_task(self._do_inspect, "Inspecting")
    
    def _do_inspect(self):
        self._clear_results()
        result = inspect_inputs(self.inspect_paths)
        report = format_inspect_report(result)
        self._log(report)
    
    def _on_inspect_jks(self):
        jks = self.jks_path.get().strip()
        if not jks:
            messagebox.showwarning("Warning", "Select a JKS file first.")
            return
        self._run_task(self._do_inspect_jks, "Inspecting JKS")
    
    def _do_inspect_jks(self):
        self._clear_results()
        jks_file = Path(self.jks_path.get().strip())
        password = self.jks_password.get() or "changeit"
        
        info = read_jks_info(jks_file, password)
        report = format_jks_info(info)
        self._log(report)
    
    def _on_validate_deploy(self):
        if not DEPLOY_AVAILABLE:
            messagebox.showwarning("Warning", "Deployment requires: pip install pyyaml paramiko")
            return
        config_path = self.deploy_config_path.get().strip()
        if not config_path:
            messagebox.showwarning("Warning", "Select a deployment config file.")
            return
        self._run_task(self._do_validate_deploy, "Validating config")
    
    def _do_validate_deploy(self):
        self._clear_results()
        config_path = Path(self.deploy_config_path.get().strip())
        
        if not config_path.is_file():
            raise ValueError(f"Config file not found: {config_path}")
        
        config = load_deploy_config(config_path)
        
        self._log("=== Deployment Config ===")
        self._log(f"  Config: {config_path.name}")
        self._log(f"  Domain: {config.get('domain', '(not set)')}")
        
        servers = config.get("servers", {})
        self._log(f"\n  Servers ({len(servers)}):")
        for name, srv in servers.items():
            self._log(f"    - {name}: {srv.get('host', '?')}:{srv.get('port', 22)}")
            for svc in srv.get("services", []):
                self._log(f"        -> {svc}")
        
        services = config.get("services", {})
        self._log(f"\n  Services ({len(services)}):")
        for name, svc in services.items():
            self._log(f"    - {name} ({svc.get('type', 'custom')})")
    
    def _on_deploy(self):
        if not DEPLOY_AVAILABLE:
            messagebox.showwarning("Warning", "Deployment requires: pip install pyyaml paramiko")
            return
        config_path = self.deploy_config_path.get().strip()
        cert_dir = self.deploy_cert_dir.get().strip()
        if not config_path:
            messagebox.showwarning("Warning", "Select a deployment config file.")
            return
        if not cert_dir:
            messagebox.showwarning("Warning", "Select a certificate directory.")
            return
        
        if not self.dry_run.get():
            if not messagebox.askyesno("Confirm", "Deploy certificates to servers?\n\nThis will upload files and may restart services."):
                return
        
        self._run_task(self._do_deploy, "Deploying")
    
    def _do_deploy(self):
        self._clear_results()
        config_path = Path(self.deploy_config_path.get().strip())
        cert_dir = Path(self.deploy_cert_dir.get().strip())
        
        deployer = SSLDeployer(
            config_path=config_path,
            cert_path=cert_dir,
            dry_run=self.dry_run.get(),
            verbose=True,
            # Unknown servers are refused unless the operator explicitly opts in;
            # a CHANGED host key is always refused.
            host_key_policy="accept-new" if self.trust_new_hosts.get() else None,
        )
        
        if not deployer.load_config():
            raise ValueError("Failed to load deployment config")
        
        if not deployer.validate_config():
            raise ValueError("Invalid deployment config")
        
        mode = "[DRY RUN] " if self.dry_run.get() else ""
        self._log(f"{mode}=== Starting Deployment ===")
        self._log(f"  Config: {config_path.name}")
        self._log(f"  Certs:  {cert_dir}")
        
        results = deployer.deploy_all()
        
        self._log(f"\n=== Deployment Results ===")
        for r in results:
            status = "OK" if r.status.value == "success" else r.status.value.upper()
            self._log(f"  [{status}] {r.server}/{r.service}: {r.message}")
        
        success = sum(1 for r in results if r.status.value == "success")
        failed = len(results) - success
        self._log(f"\n  Summary: {success} succeeded, {failed} failed")
        if any("Untrusted host key" in r.message for r in results):
            self._log(
                "\n  Hint: verify the server's fingerprint, then tick "
                "'Trust new SSH host keys' and deploy again."
            )
    
    def run(self):
        self.root.mainloop()


def main():
    app = SSLCertToolGUI()
    app.run()


if __name__ == "__main__":
    main()