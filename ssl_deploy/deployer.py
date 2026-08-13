"""Cross-platform SSL deployment orchestrator (paramiko-based)."""
from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ssl_cert_tool.platform import Terminal, expand_user, normalize_path

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


class ServiceType(Enum):
    JKS = "jks"
    APACHE = "apache"
    ASTERISK = "asterisk"
    NGINX = "nginx"
    CUSTOM = "custom"


class DeploymentStatus(Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class DeploymentResult:
    server: str
    service: str
    status: DeploymentStatus
    message: str = ""
    backup_path: str = ""
    details: Dict = field(default_factory=dict)


def normalize_deploy_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Merge top-level keystore defaults; normalize field aliases."""
    cfg = dict(config)
    keystore = cfg.get("keystore") or {}
    store_pass = keystore.get("password") or keystore.get("keystore_pass")
    alias = keystore.get("alias")

    services = cfg.get("services") or {}
    normalized_services: Dict[str, Any] = {}
    for name, svc in services.items():
        entry = dict(svc)
        if entry.get("type") == "jks":
            entry.setdefault("keystore_path", entry.pop("remote_path", None))
            if store_pass and "keystore_pass" not in entry:
                entry["keystore_pass"] = store_pass
            if alias and "alias" not in entry:
                entry["alias"] = alias
        entry.setdefault("restart_cmd", entry.pop("restart", None))
        normalized_services[name] = entry
    cfg["services"] = normalized_services

    servers = cfg.get("servers") or {}
    normalized_servers: Dict[str, Any] = {}
    for name, srv in servers.items():
        entry = dict(srv)
        entry.setdefault("key_file", entry.pop("ssh_key", None))
        password = entry.pop("ssh_password", None)
        if password:
            entry["password"] = password
        normalized_servers[name] = entry
    cfg["servers"] = normalized_servers
    return cfg


def load_deploy_config(config_path: Path) -> Dict[str, Any]:
    if not HAS_YAML:
        raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
    text = config_path.read_text(encoding="utf-8")
    config = yaml.safe_load(text) or {}
    return normalize_deploy_config(config)


class SSLDeployer:
    BACKUP_DIR = "/tmp/ssl-deploy-backups"

    def __init__(
        self,
        config_path: str | Path,
        cert_path: str | Path | None = None,
        *,
        dry_run: bool = False,
        verbose: bool = False,
        no_restart: bool = False,
        parallel: bool = False,
        terminal: Terminal | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.cert_path = Path(cert_path) if cert_path else None
        self.dry_run = dry_run
        self.verbose = verbose
        self.no_restart = no_restart
        self.parallel = parallel
        self.term = terminal or Terminal()
        self.config: Dict[str, Any] = {}
        self.results: List[DeploymentResult] = []
        self.ssh_connections: Dict[str, Any] = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            format="%(levelname)s: %(message)s",
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> bool:
        try:
            self.config = load_deploy_config(self.config_path)
            return True
        except Exception as exc:
            self.term.error(f"Failed to load config: {exc}")
            return False

    def validate_config(self) -> bool:
        """Validate configuration with graceful handling of missing sections."""
        servers = self.config.get("servers")
        services = self.config.get("services")
        
        if not servers:
            self.term.warn("No servers defined in config - deploy will be skipped")
            return True
        
        if not services:
            self.term.warn("No services defined in config - deploy will have no effect")
            return True
        
        # Warn about undefined services referenced by servers
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                self.term.warn(f"Server '{server_name}' has invalid config, skipping")
                continue
            for svc_name in server_cfg.get("services", []):
                if svc_name not in services:
                    self.term.warn(f"Server '{server_name}' references undefined service '{svc_name}'")
        
        return True

    def validate_cert_files(self) -> Dict[str, Path]:
        if not self.cert_path or not self.cert_path.exists():
            self.term.error(f"Certificate path not found: {self.cert_path}")
            return {}

        cert_files: Dict[str, Path] = {}
        domain = self.config.get("domain", "")
        patterns = {
            "private_key": [f"{domain}.key", "private.key", "*.key"],
            "certificate": [f"main_{domain}.crt", f"{domain}.crt", "certificate.crt", "*.crt"],
            "chain": [f"intermediate_{domain}.crt", "chain.crt", "crm-ca.crt", f"{domain}.ca-bundle", "ca-bundle.crt"],
            "fullchain": [f"{domain}.pem", "fullchain.pem", "*.pem"],
            "jks": [f"{domain}.jks", "keystore.jks", "*.jks"],
            "p12": ["keystore.p12", f"{domain}.p12", "*.p12"],
            "asterisk_key": ["asterisk.key", f"asterisk_{domain}.key"],
            "asterisk_crt": [f"asterisk_{domain}.crt", "asterisk.crt"],
            "asterisk_pem": [f"asterisk_{domain}.pem", "asterisk.pem"],
            "ca_crt": ["crm-ca.crt", "ca.crt", "root*.crt"],
        }

        for cert_type, file_patterns in patterns.items():
            for pattern in file_patterns:
                if "*" in pattern:
                    matches = list(self.cert_path.glob(pattern))
                    if matches:
                        cert_files[cert_type] = matches[0]
                        break
                else:
                    file_path = self.cert_path / pattern
                    if file_path.exists():
                        cert_files[cert_type] = file_path
                        break
        return cert_files

    def _ssh_password(self, server_config: Dict[str, Any]) -> str | None:
        return server_config.get("password") or os.environ.get("SSH_PASSWORD")

    def connect_server(self, server_name: str) -> Any | None:
        if not HAS_PARAMIKO and not self.dry_run:
            self.term.error("paramiko not installed. Run: pip install paramiko")
            return None
        if not HAS_PARAMIKO and self.dry_run:
            return None
        if server_name in self.ssh_connections:
            return self.ssh_connections[server_name]

        server_config = self.config["servers"].get(server_name)
        if not server_config:
            self.term.error(f"Server '{server_name}' not found in config")
            return None

        host = server_config.get("host")
        user = server_config.get("user", "root")
        port = server_config.get("port", 22)
        key_file = server_config.get("key_file")
        password = self._ssh_password(server_config)

        if self.dry_run:
            self.term.detail(f"[DRY-RUN] Would connect to {user}@{host}:{port}")
            return None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs: Dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": user,
                "timeout": 30,
                "allow_agent": True,
                "look_for_keys": True,
            }
            if key_file:
                connect_kwargs["key_filename"] = str(expand_user(key_file))
            if password:
                connect_kwargs["password"] = password
            client.connect(**connect_kwargs)
            self.ssh_connections[server_name] = client
            return client
        except Exception as exc:
            self.term.error(f"Failed to connect to {host}: {exc}")
            return None

    def execute_remote(
        self, ssh: Any, command: str, *, check_error: bool = True
    ) -> Tuple[int, str, str]:
        if self.dry_run:
            self.term.detail(f"[DRY-RUN] Would execute: {command}")
            return 0, "", ""
        try:
            _stdin, stdout, stderr = ssh.exec_command(command, timeout=120)
            exit_code = stdout.channel.recv_exit_status()
            stdout_str = stdout.read().decode("utf-8", errors="replace")
            stderr_str = stderr.read().decode("utf-8", errors="replace")
            if check_error and exit_code != 0:
                self.logger.warning("Command failed (%s): %s", exit_code, stderr_str)
            return exit_code, stdout_str, stderr_str
        except Exception as exc:
            self.logger.error("Command execution failed: %s", exc)
            return -1, "", str(exc)

    def upload_file(
        self, ssh: Any, local_path: Path, remote_path: str, mode: int = 0o644
    ) -> bool:
        if self.dry_run:
            self.term.detail(f"[DRY-RUN] Would upload {local_path.name} -> {remote_path}")
            return True
        try:
            sftp = ssh.open_sftp()
            remote_dir = os.path.dirname(remote_path)
            self.execute_remote(ssh, f"mkdir -p {remote_dir}", check_error=False)
            sftp.put(str(local_path), remote_path)
            sftp.chmod(remote_path, mode)
            sftp.close()
            return True
        except Exception as exc:
            self.logger.error("Upload failed: %s", exc)
            return False

    def backup_remote_file(
        self, ssh: Any, remote_path: str, server_name: str
    ) -> Optional[str]:
        backup_dir = f"{self.BACKUP_DIR}/{server_name}/{self.timestamp}"
        backup_path = f"{backup_dir}/{os.path.basename(remote_path)}"
        if self.dry_run:
            self.term.detail(f"[DRY-RUN] Would backup {remote_path} -> {backup_path}")
            return backup_path
        exit_code, _, _ = self.execute_remote(
            ssh,
            f"test -f {remote_path} && mkdir -p {backup_dir} && cp -p {remote_path} {backup_path}",
            check_error=False,
        )
        return backup_path if exit_code == 0 else None

    def deploy_jks(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
    ) -> DeploymentResult:
        keystore_path = service_config.get("keystore_path")
        keystore_pass = service_config.get("keystore_pass", "changeit")
        alias = service_config.get("alias", "server")
        if "jks" not in cert_files:
            return DeploymentResult(
                server_name, service_name, DeploymentStatus.FAILED, "JKS file not found"
            )
        backup_path = self.backup_remote_file(ssh, keystore_path, server_name)
        if not self.upload_file(ssh, cert_files["jks"], keystore_path, mode=0o600):
            return DeploymentResult(
                server_name,
                service_name,
                DeploymentStatus.FAILED,
                "Failed to upload JKS",
                backup_path or "",
            )
        if not self.dry_run and ssh:
            self.execute_remote(
                ssh,
                f"keytool -list -keystore {keystore_path} -storepass {keystore_pass} -alias {alias} 2>/dev/null | head -5",
                check_error=False,
            )
        return DeploymentResult(
            server_name,
            service_name,
            DeploymentStatus.SUCCESS,
            f"JKS -> {keystore_path}",
            backup_path or "",
        )

    def _resolve_apache_paths(self, service_config: Dict) -> Tuple[str, str, str]:
        domain = self.config.get("domain", "server")
        ssl_dir = service_config.get("ssl_dir")
        cert_path = service_config.get("cert_path", "/etc/pki/tls/certs/")
        key_path = service_config.get("key_path", "/etc/pki/tls/private/")
        cert_file = service_config.get("cert_file", f"{domain}.crt")
        key_file = service_config.get("key_file", f"{domain}.key")
        chain_file = service_config.get("chain_file", "chain.crt")
        if ssl_dir:
            base = ssl_dir.rstrip("/")
            return f"{base}/{cert_file}", f"{base}/{key_file}", f"{base}/{chain_file}"
        return (
            f"{cert_path.rstrip('/')}/{cert_file}",
            f"{key_path.rstrip('/')}/{key_file}",
            f"{cert_path.rstrip('/')}/{chain_file}",
        )

    def deploy_apache(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
    ) -> DeploymentResult:
        cert_remote, key_remote, chain_remote = self._resolve_apache_paths(service_config)
        for req in ("certificate", "private_key"):
            if req not in cert_files:
                return DeploymentResult(
                    server_name,
                    service_name,
                    DeploymentStatus.FAILED,
                    f"Missing {req}",
                )
        self.backup_remote_file(ssh, cert_remote, server_name)
        self.backup_remote_file(ssh, key_remote, server_name)
        if not self.upload_file(ssh, cert_files["certificate"], cert_remote):
            return DeploymentResult(
                server_name, service_name, DeploymentStatus.FAILED, "Cert upload failed"
            )
        if not self.upload_file(ssh, cert_files["private_key"], key_remote, mode=0o600):
            return DeploymentResult(
                server_name, service_name, DeploymentStatus.FAILED, "Key upload failed"
            )
        chain_file = cert_files.get("chain") or cert_files.get("ca_crt")
        if chain_file:
            self.backup_remote_file(ssh, chain_remote, server_name)
            self.upload_file(ssh, chain_file, chain_remote)
        deploy_dir = os.path.dirname(cert_remote)
        return DeploymentResult(
            server_name,
            service_name,
            DeploymentStatus.SUCCESS,
            f"Apache -> {deploy_dir}/",
        )

    def deploy_asterisk(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
    ) -> DeploymentResult:
        cert_dir = service_config.get("cert_dir", "/etc/asterisk/keys/")
        mappings = {
            "asterisk_key": ("asterisk.key", 0o600),
            "asterisk_crt": ("asterisk.crt", 0o644),
            "asterisk_pem": ("asterisk.pem", 0o600),
        }
        fallbacks = {
            "asterisk_key": "private_key",
            "asterisk_crt": "certificate",
            "asterisk_pem": "fullchain",
        }
        uploaded: list[str] = []
        for file_type, (filename, mode) in mappings.items():
            source = cert_files.get(file_type) or cert_files.get(fallbacks[file_type], "")
            if source:
                remote_path = f"{cert_dir.rstrip('/')}/{filename}"
                self.backup_remote_file(ssh, remote_path, server_name)
                if self.upload_file(ssh, source, remote_path, mode=mode):
                    uploaded.append(filename)
        if not uploaded:
            return DeploymentResult(
                server_name,
                service_name,
                DeploymentStatus.FAILED,
                "No Asterisk files found",
            )
        return DeploymentResult(
            server_name,
            service_name,
            DeploymentStatus.SUCCESS,
            f"Asterisk: {', '.join(uploaded)}",
        )

    def deploy_nginx(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
    ) -> DeploymentResult:
        cert_path = service_config.get("cert_path", "/etc/nginx/ssl/")
        domain = self.config.get("domain", "server")
        if "certificate" not in cert_files or "private_key" not in cert_files:
            return DeploymentResult(
                server_name, service_name, DeploymentStatus.FAILED, "Missing cert/key"
            )
        cert_remote = f"{cert_path.rstrip('/')}/{domain}.crt"
        key_remote = f"{cert_path.rstrip('/')}/{domain}.key"
        self.backup_remote_file(ssh, cert_remote, server_name)
        self.backup_remote_file(ssh, key_remote, server_name)
        self.upload_file(ssh, cert_files["certificate"], cert_remote)
        self.upload_file(ssh, cert_files["private_key"], key_remote, mode=0o600)
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"Nginx -> {cert_path}"
        )

    def deploy_custom(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
    ) -> DeploymentResult:
        file_mappings = service_config.get("file_mappings", {})
        if not file_mappings:
            return DeploymentResult(
                server_name,
                service_name,
                DeploymentStatus.FAILED,
                "No file_mappings for custom service",
            )
        uploaded: list[str] = []
        for source_type, remote_path in file_mappings.items():
            if source_type in cert_files:
                mode = 0o600 if "key" in source_type.lower() else 0o644
                self.backup_remote_file(ssh, remote_path, server_name)
                if self.upload_file(ssh, cert_files[source_type], remote_path, mode=mode):
                    uploaded.append(remote_path)
        status = DeploymentStatus.SUCCESS if uploaded else DeploymentStatus.FAILED
        return DeploymentResult(
            server_name,
            service_name,
            status,
            f"Deployed {len(uploaded)} file(s)" if uploaded else "No files deployed",
        )

    def restart_service(self, ssh: Any, service_config: Dict) -> bool:
        restart_cmd = service_config.get("restart_cmd")
        if not restart_cmd:
            return True
        if self.no_restart:
            return True
        if self.dry_run:
            self.term.detail(f"[DRY-RUN] Would restart: {restart_cmd}")
            return True
        exit_code, _, stderr = self.execute_remote(ssh, restart_cmd)
        return exit_code == 0 or not stderr

    def deploy_service(
        self, server_name: str, service_name: str, cert_files: Dict[str, Path]
    ) -> DeploymentResult:
        service_config = self.config["services"].get(service_name)
        if not service_config:
            return DeploymentResult(
                server_name,
                service_name,
                DeploymentStatus.FAILED,
                f"Service '{service_name}' not in config",
            )
        service_type = ServiceType(service_config.get("type", "custom"))
        ssh = self.connect_server(server_name)
        if not ssh and not self.dry_run:
            return DeploymentResult(
                server_name,
                service_name,
                DeploymentStatus.FAILED,
                "SSH connection failed",
            )
        handlers = {
            ServiceType.JKS: self.deploy_jks,
            ServiceType.APACHE: self.deploy_apache,
            ServiceType.ASTERISK: self.deploy_asterisk,
            ServiceType.NGINX: self.deploy_nginx,
            ServiceType.CUSTOM: self.deploy_custom,
        }
        result = handlers.get(service_type, self.deploy_custom)(
            ssh, server_name, service_name, service_config, cert_files
        )
        if result.status == DeploymentStatus.SUCCESS:
            self.restart_service(ssh, service_config)
        return result

    def deploy_server(
        self,
        server_name: str,
        cert_files: Dict[str, Path],
        service_filter: str | None = None,
    ) -> List[DeploymentResult]:
        server_config = self.config["servers"].get(server_name)
        if not server_config:
            return []
        results: list[DeploymentResult] = []
        for service_name in server_config.get("services", []):
            if service_filter and service_name != service_filter:
                continue
            result = self.deploy_service(server_name, service_name, cert_files)
            results.append(result)
            self.results.append(result)
        return results

    def deploy_all(
        self,
        server_filter: str | None = None,
        service_filter: str | None = None,
    ) -> List[DeploymentResult]:
        cert_files = self.validate_cert_files()
        if not cert_files and not self.dry_run:
            self.term.error("No certificate files found")
            return []

        servers = self.config.get("servers") or {}
        if not servers:
            self.term.warn("No servers defined - nothing to deploy")
            return []

        server_names = [
            name
            for name in servers
            if not server_filter or name == server_filter
        ]

        if self.parallel and len(server_names) > 1:
            with ThreadPoolExecutor(max_workers=len(server_names)) as pool:
                futures = {
                    pool.submit(self.deploy_server, name, cert_files, service_filter): name
                    for name in server_names
                }
                for future in as_completed(futures):
                    future.result()
        else:
            for server_name in server_names:
                self.deploy_server(server_name, cert_files, service_filter)

        self.close_connections()
        return self.results

    def close_connections(self) -> None:
        for ssh in self.ssh_connections.values():
            try:
                ssh.close()
            except Exception:
                pass
        self.ssh_connections.clear()

    def format_server_summary(self, server_name: str) -> str:
        server_results = [r for r in self.results if r.server == server_name]
        if not server_results:
            return ""
        host = self.config["servers"].get(server_name, {}).get("host", server_name)
        parts: list[str] = []
        for result in server_results:
            mark = "OK" if result.status == DeploymentStatus.SUCCESS else "FAIL"
            parts.append(f"{result.service} {mark}")
        return f"      {host}: {', '.join(parts)}"


def resolve_default_config(script_dir: Path) -> Path | None:
    """Search for default config in standard locations."""
    search_paths = [
        script_dir / "deploy-config.yaml",
        script_dir / "deploy-config.yml",
        script_dir / "configs" / "default.yaml",
        script_dir / "configs" / "default.yml",
        script_dir / "config.yaml",
        script_dir.parent / "ssl-deploy" / "config.yaml",
    ]
    for candidate in search_paths:
        if candidate.is_file():
            return candidate
    return None
