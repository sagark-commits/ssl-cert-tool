# SSL Certificate Tool — Quick Start

Five steps to generate and deploy SSL certificates for any domain.

---

## 1. Setup (one-time)

**Windows:**
```bat
cd path\to\ssl-cert-tool
setup.bat
```

**macOS / Linux:**
```bash
cd path/to/ssl-cert-tool
chmod +x setup.sh
./setup.sh
```

---

## 2. Create a config for your environment

```bash
python ssl-auto.py init --name mycompany --domain example.com
```

Edit `configs/mycompany.yaml` to add your servers and services.

**Minimal example:**
```yaml
domain: ""  # Auto-detect from cert

keystore:
  password: "changeit"  # Change this!
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

---

## 3. Inspect customer certs (optional)

```bash
python ssl-auto.py inspect --input "path/to/customer/certs" --key "path/to/private.key"
```

---

## 4. Generate + deploy (one command)

```bash
python ssl-auto.py run \
  --config mycompany \
  --input "path/to/customer/certs" \
  --key "path/to/private.key"
```

---

## 5. Or step-by-step

```bash
# Generate only
python ssl-auto.py run --input certs/ --key private.key --no-deploy

# Deploy separately  
python ssl-auto.py deploy --certs output/example.com/ --config mycompany
```

---

## Options

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview changes without modifying servers |
| `--no-deploy` | Generate artifacts only |
| `--no-restart` | Deploy files but skip service restarts |
| `--server NAME` | Deploy to one server only |

---

## Helper commands

```bash
# List available configs
python ssl-auto.py configs

# Validate a config
python ssl-auto.py validate --config mycompany

# Show deployment plan
python ssl-auto.py plan --config mycompany --certs output/example.com/

# Undo the last deploy
python ssl-auto.py rollback --config mycompany
```

---

**Output folder:** `output/<domain>/`

**Full guide:** see [USER_GUIDE.md](USER_GUIDE.md)

**Example configs:** see `configs/` directory
