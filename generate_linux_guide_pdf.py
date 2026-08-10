"""Generate Linux script-only SSL generate guide PDF."""
from datetime import date
from pathlib import Path
from fpdf import FPDF

BASE = Path(__file__).resolve().parent
OUT = BASE / "SSL_Certificate_Tool_Linux_Generate_Guide.pdf"


class P(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "SSL Certificate Tool - Linux Generate Guide", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


pdf = P(format="A4")
pdf.alias_nb_pages()
pdf.set_auto_page_break(True, 18)
pdf.set_left_margin(18)
pdf.set_right_margin(18)


def rx():
    pdf.set_x(pdf.l_margin)


def h1(t):
    rx()
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(0, 51, 102)
    pdf.multi_cell(0, 9, t)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def h2(t):
    rx()
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 70, 120)
    pdf.multi_cell(0, 7, t)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def body(t):
    rx()
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, t)
    pdf.ln(2)


def bullets(items):
    pdf.set_font("Helvetica", "", 10)
    for i in items:
        rx()
        pdf.multi_cell(0, 5, f"- {i}")
    pdf.ln(2)


def code(t):
    pdf.set_font("Courier", "", 8)
    pdf.set_fill_color(242, 242, 242)
    for line in t.splitlines() or [""]:
        rx()
        pdf.cell(pdf.epw, 4.5, "  " + line[:100], fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


# Cover
pdf.add_page()
pdf.ln(28)
pdf.set_font("Helvetica", "B", 20)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 10, "SSL Certificate Tool", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "B", 14)
pdf.cell(0, 9, "Generate on Linux Server (Script Only)", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(6)
pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(0, 0, 0)
pdf.cell(0, 7, f"Date: {date.today().strftime('%d %B %Y')}", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(12)
body(
    "Use this guide when Windows/Mac GUI packages are not available. "
    "Generate Ameyo-ready SSL files (PEM, P12, JKS, Asterisk, ca-bundle) directly on a Linux server."
)

pdf.add_page()
h1("1. Why no Mac ZIP on Windows?")
body(
    "Mac applications must be built on a Mac computer. Running build-windows.bat only creates "
    "SSLCertTool-Windows.zip. To create Mac ZIP, on a Mac run: ./build-mac.sh"
)
h2("Package matrix")
bullets([
    "Windows ZIP: build-windows.bat on Windows",
    "Linux Source ZIP: pack-linux-source.bat on Windows (uses python3 on server)",
    "Linux Binary ZIP: ./build-linux.sh on Linux",
    "Mac ZIP: ./build-mac.sh on Mac only",
])

h1("2. Copy Linux source package to server")
code(
    "scp SSLCertTool-Linux-Source.zip dacx@server:/dacx/\n"
    "ssh dacx@server\n"
    "cd /dacx\n"
    "unzip SSLCertTool-Linux-Source.zip -d SSLCertTool\n"
    "cd SSLCertTool\n"
    "chmod +x generate-on-linux.sh"
)

h1("3. One-time setup")
code(
    "# RHEL/CentOS\n"
    "sudo yum install -y python3 python3-pip\n"
    "# Ubuntu/Debian\n"
    "sudo apt install -y python3 python3-pip\n\n"
    "python3 -m pip install --user -r requirements.txt\n"
    "# Offline: cd offline && ./install-offline.sh"
)

h1("4. Generate certificates")
h2("4.1 Interactive")
code("./generate-on-linux.sh")
h2("4.2 One command")
code(
    "./generate-on-linux.sh \\\n"
    "  --input /dacx/SSL2026/customer.eml \\\n"
    "  --key /dacx/SSL2026/domain.key \\\n"
    "  --password 'YOUR_KEYSTORE_PASSWORD' \\\n"
    "  --alias ameyo-server \\\n"
    "  -o /dacx/SSL2026/out"
)
h2("4.3 Using ssl-auto.py directly")
code(
    "python3 ssl-auto.py generate \\\n"
    "  --input /dacx/SSL2026/customer.eml \\\n"
    "  --key /dacx/SSL2026/domain.key \\\n"
    "  --password 'YOUR_KEYSTORE_PASSWORD' \\\n"
    "  --alias ameyo-server \\\n"
    "  -o /dacx/SSL2026/out"
)
body("Password must match connector.https.keystorePass on Tomcat. Alias is usually ameyo-server.")

pdf.add_page()
h1("5. Output files")
bullets([
    "main_<domain>.crt - CRM/Apache leaf (often rename to crm.crt)",
    "<domain>.key - private key",
    "chain.crt / crm-ca.crt - Apache chain",
    "<domain>.ca-bundle - legacy ca-bundle (intermediate + root)",
    "<domain>.pem - full chain (certs only)",
    "asterisk.pem - KEY first + certs (required for Ameyo WSS)",
    "asterisk_<domain>.crt - Asterisk cert chain",
    "<domain>.jks - Tomcat JKS (needs Java keytool)",
    "keystore.p12 - PKCS12",
])

h1("6. Verify")
code(
    "openssl x509 -noout -modulus -in out/*/main_*.crt | openssl md5\n"
    "openssl rsa  -noout -modulus -in out/*/*.key | openssl md5\n"
    "grep -E 'BEGIN PRIVATE KEY|BEGIN CERTIFICATE' out/*/asterisk.pem | head\n"
    "keytool -list -keystore out/*/*.jks -storepass 'PASS' -alias ameyo-server"
)

h1("7. Deploy (examples)")
code(
    "# Backup\n"
    "cp /dacx/ssl2025/app.jks /dacx/ssl2025/app.jks.bak.$(date +%Y%m%d)\n\n"
    "# Tomcat JKS (path = connector.https.keystoreFile)\n"
    "cp out/<domain>/<domain>.jks /dacx/ssl2025/app.jks\n\n"
    "# CRM\n"
    "cp out/<domain>/main_<domain>.crt /dacx/ssl2025/crm.crt\n"
    "cp out/<domain>/<domain>.key /dacx/ssl2025/<domain>.key\n"
    "cp out/<domain>/chain.crt /dacx/ssl2025/chain.crt\n\n"
    "# Asterisk\n"
    "KEYS=/dacx/var/ameyo/dacxdata/asterisks/13/etc/asterisk/keys\n"
    "cp out/<domain>/asterisk.pem $KEYS/asterisk.pem\n"
    "cp out/<domain>/<domain>.key $KEYS/asterisk.key\n"
    "chmod 600 $KEYS/asterisk.key $KEYS/asterisk.pem\n"
    "# then restart AppServer / httpd / asterisk"
)

h1("8. JKS import on Linux (if needed)")
code(
    "keytool -importkeystore \\\n"
    "  -srckeystore /dacx/SSL2026/keystore.p12 \\\n"
    "  -srcstoretype PKCS12 \\\n"
    "  -srcstorepass 'PASS' \\\n"
    "  -destkeystore /dacx/ssl2025/app.jks \\\n"
    "  -deststoretype JKS \\\n"
    "  -deststorepass 'PASS' \\\n"
    "  -srcalias ameyo-server \\\n"
    "  -destalias ameyo-server \\\n"
    "  -noprompt"
)
body(
    "Do NOT import into .../cacerts for Tomcat HTTPS. Copy/import into the path from "
    "connector.https.keystoreFile. Default cacerts password is changeit (unrelated)."
)

h1("9. Checklist")
pdf.set_font("Helvetica", "", 10)
for item in [
    "Unzip Linux source package on server",
    "Install python3 + pip requirements",
    "Have customer cert + matching private key",
    "Generate with correct keystore password/alias",
    "Confirm Key/Cert match and asterisk.pem KEY-first",
    "Backup old server certs",
    "Copy to Tomcat/CRM/Asterisk paths",
    "Restart and verify HTTPS + WSS 8089",
]:
    rx()
    pdf.cell(0, 6, f"[ ]  {item}", new_x="LMARGIN", new_y="NEXT")

pdf.output(str(OUT))
print("Wrote", OUT)