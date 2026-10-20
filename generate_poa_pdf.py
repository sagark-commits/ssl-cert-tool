# Author: Sagar K | 2026 | MIT licence
from datetime import date
from pathlib import Path
import yaml
from fpdf import FPDF

BASE = Path(r"C:\Users\sagar.k\Downloads\ssl-cert-tool")
OUT = BASE / "ASNB_SSL_Deployment_POA.pdf"
cfg = yaml.safe_load((BASE / "configs" / "asnb.yaml").read_text(encoding="utf-8"))
domain = cfg.get("domain", "example.com")
ks_pass = cfg.get("keystore", {}).get("password", "<see config>")
ks_alias = cfg.get("keystore", {}).get("alias", "server-cert")

class P(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

pdf = P()
pdf.alias_nb_pages()
pdf.set_auto_page_break(True, 20)

def title(t, size=14):
    pdf.set_font("Helvetica", "B", size)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(0, 10, t, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

def body(t):
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, t)
    pdf.ln(2)

def code(t):
    pdf.set_font("Courier", "", 8)
    pdf.set_fill_color(245, 245, 245)
    for line in t.splitlines():
        pdf.cell(0, 4.5, "  " + line, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

def checklist(items):
    pdf.set_font("Helvetica", "", 10)
    for i in items:
        pdf.cell(0, 6, f"  [ ]  {i}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

# Cover
pdf.add_page()
pdf.ln(25)
pdf.set_font("Helvetica", "B", 24)
pdf.cell(0, 12, "SSL Certificate Deployment", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "B", 18)
pdf.cell(0, 12, "Plan of Action (POA)", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(10)
pdf.set_font("Helvetica", "", 12)
pdf.cell(0, 8, "ASNB Production Environment", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 8, f"Date: {date.today().strftime('%d %B %Y')}", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 8, f"Domain: {domain}", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(15)
body("This POA covers certificate generation and deployment for ASNB using Method A (Python automation) and Method B (Bash script). Includes pre-checks, deployment steps, verification, rollback, and sign-off.")

# Section 1
pdf.add_page()
title("1. Document Control")
body(f"Domain: {domain}\nKeystore Alias: {ks_alias}\nKeystore Password: (configured in configs/asnb.yaml)\nServers: asnb-app-db (AppServer, Reports, CRM), asnb-cs (Asterisk)")
title("2. Pre-Requisites", 12)
checklist([
    "GlobalSign EML certificate email received",
    "Private key file available (must match certificate)",
    "SSH access: dacx@asnb-app-db, root@asnb-cs",
    "Maintenance window approved",
    "Backup of existing certificates taken",
    "configs/asnb.yaml and deploy.conf reviewed",
])

# Method A
pdf.add_page()
title("3. Method A - Python Automation (Recommended)")
body("Location: ssl-cert-tool folder on Windows laptop")
title("Step A1: Setup (one-time)", 11)
code("cd ssl-cert-tool\nsetup.bat")
title("Step A2: Inspect customer cert", 11)
code(f'python ssl-auto.py inspect --input "ASNB CERT" --key "ASNB CERT/{domain}.key"')
body("Expected: Key/Cert match PASS, CN matches domain, expiry ~2027-01-16")
title("Step A3: Generate deployment files", 11)
code(f'python ssl-auto.py generate --input "ASNB CERT" --key "{domain}.key" --alias "{ks_alias}" --password "<from config>" -o output/{domain}')
title("Step A4: Validate and plan", 11)
code("python ssl-auto.py validate --config asnb\npython ssl-auto.py plan --config asnb --certs output/" + domain)
title("Step A5: Dry-run deploy", 11)
code("python ssl-auto.py deploy --config asnb --certs output/" + domain + " --dry-run")
title("Step A6: Production deploy", 11)
code("python ssl-auto.py deploy --config asnb --certs output/" + domain)
body("Deploy order: Asterisk (asnb-cs) -> CRM -> AppServer/Reports (asnb-app-db)")
title("Step A7: Full automation (one command)", 11)
code(f'python ssl-auto.py run --config asnb --input "ASNB CERT" --key "{domain}.key" --alias "{ks_alias}"')

# Method B
pdf.add_page()
title("4. Method B - Bash Script (No Python on Server)")
body("Generate certs on Windows (Method A Steps A1-A3), then deploy from Linux jump host.")
title("Step B1: Copy certs to jump host", 11)
code("scp -r output/" + domain + "/ user@jump-host:/tmp/certs/")
title("Step B2: Dry-run", 11)
code("./deploy.sh --certs /tmp/certs/" + domain + " --config deploy.conf --dry-run")
title("Step B3: Deploy", 11)
code("./deploy.sh --certs /tmp/certs/" + domain + " --config deploy.conf")
title("Step B4: Per-server deploy (optional)", 11)
code("./deploy.sh --certs /tmp/certs/" + domain + " --config deploy.conf --server ASNB_CS\n./deploy.sh --certs /tmp/certs/" + domain + " --config deploy.conf --server ASNB_APP_DB")

# Paths & Verification
pdf.add_page()
title("5. Deployment Paths")
rows = [
    ("asnbcc.jks", "/dacx/ssl2025/asnbcc.jks", "AppServer, Reports"),
    ("crm.crt", "/dacx/ssl2025/crm.crt", "CRM"),
    (f"{domain}.key", "/dacx/ssl2025/", "CRM"),
    ("chain.crt", "/dacx/ssl2025/chain.crt", "CRM"),
    ("asterisk.crt/key/pem", "/dacx/var/ameyo/.../asterisk/keys/", "Asterisk"),
]
pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(0, 51, 102)
pdf.set_text_color(255, 255, 255)
for h, w in [("File", 55), ("Remote Path", 70), ("Service", 65)]:
    pdf.cell(w, 7, h, 1, 0, "L", True)
pdf.ln()
pdf.set_text_color(0, 0, 0)
pdf.set_font("Helvetica", "", 9)
for i, r in enumerate(rows):
    if i % 2: pdf.set_fill_color(240, 240, 240)
    else: pdf.set_fill_color(255, 255, 255)
    for val, w in zip(r, [55, 70, 65]):
        pdf.cell(w, 6, val, 1, 0, "L", True)
    pdf.ln()

title("6. Post-Deploy Verification", 12)
code("keytool -list -keystore /dacx/ssl2025/asnbcc.jks -storepass <password> -alias " + ks_alias + "\nopenssl x509 -in /dacx/ssl2025/crm.crt -noout -subject -dates\nopenssl x509 -in .../asterisk/keys/asterisk.crt -noout -subject -dates")
checklist(["JKS opens with configured password", "New expiry date confirmed", "AppServer HTTPS OK", "Reports HTTPS OK", "CRM HTTPS OK", "Asterisk TLS OK", "Stakeholder sign-off"])

title("7. Rollback", 12)
code("python ssl-auto.py deploy --config asnb --rollback --server asnb_app_db\n./deploy.sh --config deploy.conf --rollback --server ASNB_APP_DB")
body("Tool creates automatic backups before overwriting files.")

title("8. Important Notes", 12)
body("- Tool copies certificate files only; does NOT edit tomcat.conf or httpd.conf\n- Always dry-run before production deploy\n- AppServer and Reports share same JKS file\n- GUI option: double-click ssl-gui.bat\n- Credentials stored in configs/asnb.yaml - do not share externally")

# Sign-off
pdf.add_page()
title("9. Sign-Off")
pdf.set_font("Helvetica", "B", 10)
for h, w in [("Role", 45), ("Name", 60), ("Signature / Date", 85)]:
    pdf.cell(w, 8, h, 1)
pdf.ln()
pdf.set_font("Helvetica", "", 10)
for role in ["Performed By", "Reviewed By", "Approved By", "Date Completed"]:
    pdf.cell(45, 10, role, 1)
    pdf.cell(60, 10, "", 1)
    pdf.cell(85, 10, "", 1)
    pdf.ln()

pdf.output(str(OUT))
print("Created:", OUT)