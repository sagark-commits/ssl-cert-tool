# Author: Sagar K | 2026 | MIT licence
"""Generate SSL Certificate Tool User Guide PDF (Windows/Mac all-in-one)."""
from datetime import date
from pathlib import Path

from fpdf import FPDF

BASE = Path(__file__).resolve().parent
OUT = BASE / "SSL_Certificate_Tool_User_Guide.pdf"
DIST = BASE / "dist" / "SSLCertTool-Windows"


class GuidePDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, "SSL Certificate Tool - User Guide", align="L", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")
        self.set_text_color(0, 0, 0)


pdf = GuidePDF(format="A4")
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=18)
pdf.set_left_margin(18)
pdf.set_right_margin(18)
pdf.set_top_margin(18)


def reset_x():
    pdf.set_x(pdf.l_margin)


def h1(text):
    reset_x()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(0, 51, 102)
    pdf.multi_cell(0, 10, text)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def h2(text):
    reset_x()
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 70, 120)
    pdf.multi_cell(0, 8, text)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def body(text):
    reset_x()
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, text)
    pdf.ln(2)


def bullet(items):
    pdf.set_font("Helvetica", "", 10)
    for item in items:
        reset_x()
        pdf.multi_cell(0, 5, f"- {item}")
    pdf.ln(2)


def code(text):
    pdf.set_font("Courier", "", 8)
    pdf.set_fill_color(242, 242, 242)
    for line in text.splitlines() or [""]:
        reset_x()
        pdf.cell(pdf.epw, 4.5, "  " + line[:100], fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


def table(rows, col_w):
    reset_x()
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(220, 230, 240)
    for i, cell in enumerate(rows[0]):
        pdf.cell(col_w[i], 6, cell, border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for row in rows[1:]:
        reset_x()
        for i, cell in enumerate(row):
            pdf.cell(col_w[i], 6, str(cell)[:48], border=1)
        pdf.ln()
    pdf.ln(3)
    reset_x()


# Cover
pdf.add_page()
pdf.ln(30)
pdf.set_font("Helvetica", "B", 22)
pdf.set_text_color(0, 51, 102)
pdf.cell(0, 12, "SSL Certificate Tool", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("Helvetica", "B", 16)
pdf.cell(0, 10, "User Guide", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(6)
pdf.set_font("Helvetica", "", 12)
pdf.set_text_color(0, 0, 0)
pdf.cell(0, 8, "Windows & macOS All-in-One Package", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 8, f"Date: {date.today().strftime('%d %B %Y')}", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(18)
body(
    "This guide explains how to install and use the SSL Certificate Tool without installing "
    "Python. Use it to convert customer certificates into Ameyo-ready files (JKS, P12, PEM, "
    "Asterisk, ca-bundle) and optionally deploy them over SSH."
)

# 1
pdf.add_page()
h1("1. Install (No Python Required)")
h2("1.1 Windows")
bullet([
    "Unzip SSLCertTool-Windows.zip to any folder (example: Desktop\\SSLCertTool-Windows).",
    "Keep the whole folder together. Do not move only the .exe file.",
    "Double-click: Start SSL Certificate Tool.bat (or SSLCertTool.exe).",
    "Optional CLI: Start CLI Wizard.bat or ssl-auto.exe --wizard",
])
h2("1.2 macOS")
bullet([
    "Unzip SSLCertTool-Mac.zip.",
    "First launch: right-click Start SSL Certificate Tool.command -> Open -> Open.",
    "Later: double-click the same shortcut or SSLCertTool.app.",
    "If blocked: System Settings -> Privacy & Security -> Allow Anyway.",
    "Optional fix: xattr -dr com.apple.quarantine SSLCertTool-Mac",
])
h2("1.3 Package contents")
table([
    ["File / Folder", "Purpose"],
    ["SSLCertTool.exe / SSLCertTool", "Desktop GUI"],
    ["ssl-auto.exe / ssl-auto", "Command-line tool"],
    ["configs/", "YAML deploy configs (editable)"],
    ["output/", "Generated certificate files"],
    ["INSTALL.txt / README.txt", "Quick reference"],
], col_w=[90, 90])

# 2
h1("2. What You Need Before Starting")
bullet([
    "Customer certificate (EML email, ZIP, CRT/PEM, folder, etc.).",
    "Matching private key (.key) for that certificate.",
    "Keystore password and alias used on the server (for JKS/P12).",
    "Optional: server paths / YAML config for SSH deploy.",
])
body("Supported inputs: .crt .cer .pem .p7b .p12 .pfx .ca-bundle .eml .txt .docx .zip .7z and folders.")

# 3
pdf.add_page()
h1("3. How to Use the GUI (Recommended)")
h2("3.1 Generate certificates")
bullet([
    "Open SSLCertTool.",
    "Go to the Generate tab.",
    "Add Certificate Files (EML / folder / CRT / ZIP).",
    "Select Private Key (.key).",
    "Set Keystore Password (must match Tomcat keystorePass).",
    "Set Key Alias (usually ameyo-server).",
    "Choose Output Directory.",
    "Click Generate.",
    "Confirm Key/Cert match: PASS.",
])
h2("3.2 Important password rule")
body(
    "If the server uses connector.https.keystorePass=YOUR_PASSWORD, generate JKS/P12 with that "
    "same password. Do not leave changeit unless the server also uses changeit."
)
h2("3.3 Inspect / Deploy tabs")
bullet([
    "Inspect: check leaf CN, expiry, chain, and key match before deploy.",
    "Deploy: uses configs/*.yaml to copy files over SSH (always dry-run first).",
])

# 4
h1("4. How to Use the CLI")
h2("4.1 Interactive wizard")
code("ssl-auto --wizard")
h2("4.2 Generate")
code(
    "ssl-auto generate --input \"customer_folder_or.eml\" --key \"domain.key\" "
    "--alias ameyo-server --password \"YOUR_STORE_PASS\" -o output"
)
h2("4.3 Inspect")
code("ssl-auto inspect --input \"customer_folder_or.eml\"")
h2("4.4 Deploy")
code(
    "ssl-auto plan --config mycustomer\n"
    "ssl-auto deploy --certs output/domain/ --config mycustomer --dry-run\n"
    "ssl-auto deploy --certs output/domain/ --config mycustomer"
)
h2("4.5 Config helpers")
code(
    "ssl-auto init --name mycustomer --domain example.com\n"
    "ssl-auto configs\n"
    "ssl-auto validate --config mycustomer"
)

# 5
pdf.add_page()
h1("5. Generated Files (What Goes Where)")
table([
    ["Generated file", "Typical use"],
    ["main_{domain}.crt", "CRM / Apache leaf (often crm.crt)"],
    ["{domain}.key", "Private key"],
    ["chain.crt / crm-ca.crt", "Apache chain (usually intermediate)"],
    ["{domain}.ca-bundle", "Legacy Ameyo ca-bundle (int + root)"],
    ["{domain}.pem", "Full cert chain (certs only)"],
    ["asterisk.pem", "Asterisk WSS: KEY first + certs"],
    ["asterisk_{domain}.crt", "Asterisk cert chain"],
    ["{domain}.jks", "Tomcat / AppServer keystore"],
    ["keystore.p12", "PKCS12 keystore"],
], col_w=[70, 110])
h2("5.1 Asterisk PEM order (critical)")
body(
    "asterisk.pem must start with the private key, then leaf, then intermediate, then root "
    "(if present). If http.conf uses tlscertfile=asterisk.pem with no tlsprivatekey, a "
    "certs-only PEM will prevent port 8089 / WebRTC from starting."
)
code(
    "Correct order inside asterisk.pem:\n"
    "  1) BEGIN PRIVATE KEY / RSA PRIVATE KEY\n"
    "  2) BEGIN CERTIFICATE  (leaf)\n"
    "  3) BEGIN CERTIFICATE  (intermediate)\n"
    "  4) BEGIN CERTIFICATE  (root, optional)"
)

# 6
h1("6. Typical Ameyo Deploy Mapping")
table([
    ["Service", "Copy to (example)"],
    ["AppServer / Reports JKS", "/dacx/ssl2025/<name>.jks"],
    ["CRM cert", "/dacx/ssl2025/crm.crt"],
    ["CRM key", "/dacx/ssl2025/<domain>.key"],
    ["CRM chain / ca-bundle", "/dacx/ssl2025/chain.crt or *.ca-bundle"],
    ["Asterisk", ".../asterisk/keys/asterisk.pem (+ .crt/.key)"],
], col_w=[70, 110])
body(
    "Always backup old files first. After copy: verify key matches cert, restart services "
    "(Tomcat/AppServer, Apache/CRM, Asterisk). Confirm HTTPS and WSS (8089) are listening."
)

# 7
pdf.add_page()
h1("7. Verification Commands (on server)")
h2("7.1 Key matches certificate")
code(
    "openssl x509 -noout -modulus -in crm.crt | openssl md5\n"
    "openssl rsa  -noout -modulus -in domain.key | openssl md5\n"
    "# Both MD5 values must be identical"
)
h2("7.2 Certificate dates")
code("openssl x509 -in crm.crt -noout -subject -dates")
h2("7.3 JKS alias and password")
code("keytool -list -v -keystore app.jks -storepass YOUR_PASS -alias ameyo-server")
h2("7.4 Asterisk WSS port")
code(
    "ss -tlnp | grep 8089\n"
    "echo | openssl s_client -connect HOST:8089 2>&1 | head -20"
)
h2("7.5 Asterisk PEM structure")
code('grep -E "BEGIN PRIVATE KEY|BEGIN CERTIFICATE" asterisk.pem')

# 8
h1("8. Troubleshooting")
table([
    ["Problem", "Fix"],
    ["App won't open (Mac)", "Right-click Open / allow in Privacy"],
    ["Key/Cert match FAIL", "Wrong key; use matching private key"],
    ["Tomcat SSL fails", "JKS password must equal keystorePass"],
    ["WebRTC / 8089 down", "asterisk.pem KEY-first; restart Asterisk"],
    ["Must open IP:8089 first", "Cert CN != IP; use domain in WSS URL"],
    ["No .jks created", "Install Java keytool or use keystore.p12"],
    ["ca-bundle too short", "Use {domain}.ca-bundle (int+root)"],
], col_w=[55, 125])

# 9
h1("9. Building the Package (IT / Maintainers)")
body("End users do not build. Maintainers build on each OS, then share the ZIP.")
code(
    "Windows build machine:\n"
    "  cd ssl-cert-tool\n"
    "  build-windows.bat\n"
    "  -> dist\\SSLCertTool-Windows.zip\n\n"
    "Mac build machine:\n"
    "  cd ssl-cert-tool\n"
    "  chmod +x build-mac.sh && ./build-mac.sh\n"
    "  -> dist/SSLCertTool-Mac.zip"
)
body(
    "A Mac binary must be built on a Mac. Java is optional for end users unless they need "
    "JKS generation (P12/PEM work without Java)."
)

# 10
h1("10. Quick Checklist")
pdf.set_font("Helvetica", "", 10)
for item in [
    "Unzip package; launch GUI or CLI wizard",
    "Load customer cert + matching private key",
    "Set keystore password/alias to match server",
    "Generate; confirm Key/Cert match PASS",
    "Check asterisk.pem starts with PRIVATE KEY",
    "Backup old server certs",
    "Deploy/copy files using correct names",
    "Verify modulus match + dates + ports 443/8089",
    "Restart AppServer / CRM / Asterisk as needed",
    "Test HTTPS and WebRTC troubleshooter",
]:
    reset_x()
    pdf.cell(0, 6, f"[ ]  {item}", new_x="LMARGIN", new_y="NEXT")
pdf.ln(6)
body("For support, keep the full package folder and the output/ directory from the generation run.")

pdf.output(str(OUT))
print(f"Wrote: {OUT}")
if DIST.is_dir():
    dest = DIST / "SSL_Certificate_Tool_User_Guide.pdf"
    dest.write_bytes(OUT.read_bytes())
    print(f"Copied: {dest}")
# refresh zip if present
zip_path = BASE / "dist" / "SSLCertTool-Windows.zip"
if zip_path.exists() and DIST.is_dir():
    import zipfile
    # re-zip folder
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in DIST.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(DIST))
    print(f"Updated zip: {zip_path}")