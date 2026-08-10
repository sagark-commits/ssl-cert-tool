# ssl-auto   Universal SSL Certificate Tool

Generate deployment-ready certificates from ANY customer input format and deploy them to ANY server configuration via SSH. Cross-platform: **Windows, macOS, Linux**.

## Features

- **Universal input handling**   Parse certificates from emails (.eml), archives (.zip, .7z), documents (.docx), PKCS7 (.p7b), PKCS12 (.p12), PEM, DER, and more
- **Any domain**   Auto-detects domain from certificate CN
- **Any server setup**   Configure via YAML for any combination of servers and services
- **Multiple service types**   JKS (Java/Tomcat), Apache, Nginx, Asterisk, or custom
- **One command**   Generate artifacts + validate + deploy in a single run
- **Dry-run mode**   Preview all changes before deployment
- **Cross-platform**   Works identically on Windows, macOS, and Linux

## Quick Start

### Windows

```bat
setup.bat
python ssl-auto.py run --input "customer_certs/" --key "domain.key" --config deploy-config.yaml
```

### macOS / Linux

```bash
chmod +x setup.sh ssl-auto
./setup.sh
./ssl-auto run --input customer_certs/ --key domain.key --config deploy-config.yaml
```

## Commands

| Command | Description |
|---------|-------------|
| `run` | Full pipeline: parse �! generate �! validate �! deploy |
| `generate` | Generate artifacts only |
| `deploy` | Deploy existing artifacts |
| `inspect` | Inspect inputs without generating files |
| `init` | Create a new configuration file |
| `configs` | List available configurations |
| `validate` | Validate a configuration file |
| `plan` | Show deployment plan without changes |

### Examples

```bash
# Generate + deploy (full automation)
python ssl-auto.py run --input certs/ --key domain.key --config myconfig.yaml

# Generate only, no deploy
python ssl-auto.py run --input certs/ --key domain.key --no-deploy

# Dry run (preview changes)
python ssl-auto.py run --input certs/ --key domain.key --config myconfig.yaml --dry-run

# Deploy existing certs to one server
python ssl-auto.py deploy --certs output/example.com/ --config myconfig.yaml --server web_server

# Create a new config
python ssl-auto.py init --name mycompany --domain example.com

# Validate config
python ssl-auto.py validate --config myconfig.yaml

# Show deployment plan
python ssl-auto.py plan --config myconfig.yaml --certs output/example.com/
```

## Configuration

Create a YAML config file for each environment. See `configs/template.yaml` for documentation.

**Minimal example:**

```yaml
domain: ""  # Auto-detect from certificate

keystore:
  password: "changeit"
  alias: "server-cert"

servers:
  web_server:
    host: "192.168.1.10"
    user: "root"
    services: [tomcat]

services:
  tomcat:
    type: jks
    remote_path: /opt/tomcat/conf/keystore.jks
    restart: "systemctl restart tomcat"
```

### Service Types

| Type | Use for | Key fields |
|------|---------|------------|
| `jks` | Tomcat, Java apps | `remote_path`, `restart` |
| `apache` | Apache httpd | `ssl_dir`, `cert_file`, `key_file`, `chain_file` |
| `nginx` | Nginx | `cert_path`, `restart` |
| `asterisk` | Asterisk VoIP | `cert_dir`, `restart` |
| `custom` | Any service | `file_mappings` |

### SSH Authentication

- **SSH key**: Set `ssh_key: ~/.ssh/id_rsa` per server (recommended)
- **Password**: Set `SSH_PASSWORD` env var or `ssh_password` in config
- **ssh-agent**: Supported on macOS/Linux

## Options

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would happen without making changes |
| `--no-deploy` | Generate only (with `run`) |
| `--no-restart` | Deploy files but skip service restarts |
| `--server NAME` | Deploy to one server only |
| `--service NAME` | Deploy one service only |
| `--parallel` | Deploy to multiple servers in parallel |
| `--no-color` | Disable colored output |

## Generated Output

For domain `example.com`, generates in `output/example.com/`:

| File | Purpose |
|------|---------|
| `example.com.jks` | Java keystore |
| `main_example.com.crt` | Leaf certificate |
| `intermediate_example.com.crt` | CA chain |
| `example.com.key` | Private key |
| `example.com.pem` | Full chain PEM |
| `chain.crt` | Apache CA bundle |
| `asterisk_example.com.crt` | Asterisk cert chain (certs only) |
| `asterisk_example.com.pem` / `asterisk.pem` | Ameyo Asterisk combined PEM (key + leaf + intermediate + root) |
| `keystore.p12` | PKCS12 keystore |

## Supported Input Formats

`.crt`, `.cer`, `.pem`, `.p7b`, `.p7c`, `.p12`, `.pfx`, `.eml`, `.docx`, `.txt`, `.zip`, `.7z`, `.ca-bundle`, `.der`, base64-only files, combined key+cert files, folders.

## Requirements

- Python 3.8+
- Java JDK (for `.jks` generation via `keytool`)
- SSH access to target servers (for deploy)

Run `python setup.py` to install Python dependencies and verify tools.

## Directory Structure

```
ssl-cert-tool/
%%% ssl-auto.py              # Main entry point
%%% ssl-auto.bat             # Windows launcher
%%% ssl-auto / ssl-auto.command  # Unix launchers
%%% configs/                 # Configuration files
%   %%% template.yaml        # Blank template with docs
%   %%% example-simple.yaml  # Single server example
%   %%% example-multiserver.yaml
%%% deploy-config.yaml       # Active/default config
%%% ssl_cert_tool/           # Certificate generation
%   %%% core.py
%   %%% platform.py
%%% ssl_deploy/              # SSH deployment
%   %%% deployer.py
%%% setup.py / setup.bat / setup.sh
%%% QUICK_START.md
%%% USER_GUIDE.md
%%% requirements.txt
```

## Documentation

- [QUICK_START.md](QUICK_START.md)   5-step setup guide
- [USER_GUIDE.md](USER_GUIDE.md)   Full documentation
- `configs/template.yaml`   Configuration reference

## License

MIT
