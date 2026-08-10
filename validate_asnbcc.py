import hashlib, glob, shutil, subprocess, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
DOMAIN = "asnbcc.tmone.com.my"
EXPECTED_EXPIRY = "2027-01-16"
KEYSTORE_PASSWORDS = ["23w1LLch4", "changeit"]
KEYSTORE_ALIAS = "ameyo-server"
CERT_DIR = Path(r"C:\Users\sagar.k\Downloads\ssl-cert-tool\output\asnbcc.tmone.com.my")
ALT_DIR = Path(r"C:\Users\sagar.k\Downloads\output\asnbcc.tmone.com.my")
def md5_file(path):
    d = hashlib.md5()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(8192), b""): d.update(c)
    return d.hexdigest()
def md5_cert_der(der): return hashlib.md5(der).hexdigest()
def load_private_key(path): return serialization.load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())
def load_certs_from_file(path):
    data = path.read_text(encoding="utf-8", errors="replace"); certs = []
    for block in data.split("-----BEGIN CERTIFICATE-----"):
        if "-----END CERTIFICATE-----" not in block: continue
        pem = "-----BEGIN CERTIFICATE-----" + block.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
        try: certs.append(x509.load_pem_x509_certificate(pem.encode(), default_backend()))
        except Exception: pass
    if not certs:
        try: certs.append(x509.load_pem_x509_certificate(path.read_bytes(), default_backend()))
        except Exception: pass
    return certs
def cert_cn(cert):
    try: return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception: return ""
def keys_match(pk, cert):
    pub, pp = cert.public_key(), pk.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and isinstance(pp, rsa.RSAPublicKey): return pub.public_numbers() == pp.public_numbers()
    if isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pp, ec.EllipticCurvePublicKey): return pub.public_numbers() == pp.public_numbers()
    return False
def issuer_matches_subject(i, s): return i.subject == s.issuer
def key_size(k):
    if isinstance(k, rsa.RSAPrivateKey): return k.key_size
    if isinstance(k, ec.EllipticCurvePrivateKey): return k.curve.key_size
    return None
def find_keytool():
    f = shutil.which("keytool")
    if f: return f
    for p in glob.glob(r"C:\Program Files\Java\*\bin\keytool.exe"): return p
    for p in glob.glob(r"C:\Program Files\Eclipse Adoptium\*\bin\keytool.exe"): return p
    return None
def check_keystore_jks(path, passwords):
    kt = find_keytool()
    if not kt: return False, "keytool not found"
    for pw in passwords:
        r = subprocess.run([kt, "-list", "-v", "-keystore", str(path), "-storepass", pw], capture_output=True, text=True)
        if r.returncode == 0:
            ha, hk = KEYSTORE_ALIAS in r.stdout, "PrivateKeyEntry" in r.stdout
            return ha and hk, "Opened with %r alias=%s key=%s" % (pw, ha, hk)
    return False, "Cannot open JKS"
def check_keystore_p12(path, passwords):
    for pw in passwords:
        try:
            with open(path, "rb") as f: serialization.pkcs12.load_key_and_certificates(f.read(), pw.encode(), backend=default_backend())
            return True, "Opened PKCS12 with %r" % pw
        except Exception: pass
    return False, "Cannot open P12"
def validate_chain_order(certs):
    if not certs: return False, "no certs"
    ok, msgs = True, []
    if cert_cn(certs[0]) != DOMAIN: ok = False; msgs.append("bad leaf CN")
    for i in range(len(certs)-1):
        if not issuer_matches_subject(certs[i+1], certs[i]): ok = False; msgs.append("broken link %d" % i)
    if ok: msgs.append("order OK: " + " -> ".join(cert_cn(c) for c in certs))
    return ok, "; ".join(msgs)
def extract_first_key_pem(text):
    for m in ("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"):
        t = "-----" + m + "-----"
        if t in text:
            s = text.index(t); e = text.index("-----END", s); e = text.index("-----", e+5)+5; return text[s:e]
    return ""
print("=== SSL Certificate Validation Report ===")
print("Domain:", DOMAIN); print()
cert_dir = CERT_DIR if CERT_DIR.exists() else ALT_DIR
if not cert_dir.exists(): print("[FAIL] No cert dir"); sys.exit(1)
files = sorted([f for f in cert_dir.iterdir() if f.is_file()])
file_md5s = {f.name: md5_file(f) for f in files}
key_path = cert_dir / (DOMAIN + ".key")
main_crt = cert_dir / ("main_" + DOMAIN + ".crt")
inter_crt = cert_dir / ("intermediate_" + DOMAIN + ".crt")
pem_path = cert_dir / (DOMAIN + ".pem")
chain_crt = cert_dir / "chain.crt"
crm_ca = cert_dir / "crm-ca.crt"
asterisk_crt = cert_dir / ("asterisk_" + DOMAIN + ".crt")
asterisk_pem = cert_dir / ("asterisk_" + DOMAIN + ".pem")
asterisk_pem_deploy = cert_dir / "asterisk.pem"
jks_path = cert_dir / (DOMAIN + ".jks")
p12_path = cert_dir / "keystore.p12"
results = {}
priv_key = load_private_key(key_path); ks = key_size(priv_key); key_md5 = md5_file(key_path)
results["Private Key"] = (ks in (2048,4096), "PEM OK, %s-bit, MD5=%s" % (ks, key_md5))
leaf_cert = load_certs_from_file(main_crt)[0]
leaf_fp = md5_cert_der(leaf_cert.public_bytes(serialization.Encoding.DER))
nb = leaf_cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
na = leaf_cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
leaf_ok = cert_cn(leaf_cert) == DOMAIN and leaf_cert.not_valid_after_utc.date().isoformat() == EXPECTED_EXPIRY
results["Leaf Certificate"] = (leaf_ok, "CN=%s, MD5 fp=%s, %s to %s" % (cert_cn(leaf_cert), leaf_fp, nb, na))
match_ok = keys_match(priv_key, leaf_cert)
results["Key-Cert Match"] = (match_ok, "Public key matches private key" if match_ok else "MISMATCH")
inter_cert = load_certs_from_file(inter_crt)[0]
links = issuer_matches_subject(inter_cert, leaf_cert)
results["Intermediate CA"] = (links, "CN=%s, MD5 fp=%s, links=%s" % (cert_cn(inter_cert), md5_cert_der(inter_cert.public_bytes(serialization.Encoding.DER)), links))
chain_ok, chain_msg = validate_chain_order(load_certs_from_file(chain_crt))
results["Certificate Chain"] = (chain_ok, chain_msg)
pem_certs = load_certs_from_file(pem_path); pem_ok, pem_msg = validate_chain_order(pem_certs)
if pem_certs and md5_cert_der(pem_certs[0].public_bytes(serialization.Encoding.DER)) != leaf_fp: pem_ok=False; pem_msg+="; PEM leaf differs"
results["PEM Full Chain"] = (pem_ok, pem_msg)
jks_ok, jks_msg = check_keystore_jks(jks_path, KEYSTORE_PASSWORDS) if jks_path.exists() else (False,"missing")
results["JKS Keystore (password 23w1LLch4)"] = (jks_ok, jks_msg)
p12_ok, p12_msg = check_keystore_p12(p12_path, KEYSTORE_PASSWORDS) if p12_path.exists() else (False,"missing")
if p12_ok:
    with open(p12_path,"rb") as f: _,c,_=serialization.pkcs12.load_key_and_certificates(f.read(), b"23w1LLch4", backend=default_backend())
    if c and keys_match(priv_key,c): p12_msg += "; p12 key matches domain.key"
    elif c: p12_ok=False; p12_msg += "; p12 key MISMATCH"
results["P12 Keystore"] = (p12_ok, p12_msg)
asterisk_ok=True; ast_msgs=[]
ast_certs=load_certs_from_file(asterisk_crt)
if ast_certs and md5_cert_der(ast_certs[0].public_bytes(serialization.Encoding.DER))!=leaf_fp: asterisk_ok=False; ast_msgs.append("asterisk.crt leaf differs")
else: ast_msgs.append("asterisk.crt leaf matches main")
pem_text=asterisk_pem.read_text(encoding="utf-8", errors="replace")
has_key="BEGIN PRIVATE KEY" in pem_text or "BEGIN RSA PRIVATE KEY" in pem_text
cert_count=pem_text.count("BEGIN CERTIFICATE")
key_pos=min([pem_text.find(m) for m in ("BEGIN PRIVATE KEY","BEGIN RSA PRIVATE KEY") if m in pem_text] or [-1])
cert_pos=pem_text.find("BEGIN CERTIFICATE")
key_first=has_key and key_pos>=0 and cert_pos>=0 and key_pos<cert_pos
ast_msgs.append("asterisk.pem key=%s certs=%d key_first=%s" % (has_key,cert_count,key_first))
if not has_key: asterisk_ok=False
if not key_first: asterisk_ok=False; ast_msgs.append("key must come before certs (Ameyo format)")
if asterisk_pem_deploy.exists():
    if md5_file(asterisk_pem_deploy)!=md5_file(asterisk_pem): asterisk_ok=False; ast_msgs.append("asterisk.pem differs from asterisk_%s.pem" % DOMAIN)
    else: ast_msgs.append("asterisk.pem deploy copy OK")
else: ast_msgs.append("asterisk.pem deploy copy missing")
kb=extract_first_key_pem(pem_text)
if kb:
    ak=serialization.load_pem_private_key(kb.encode(),None,default_backend())
    if keys_match(ak,leaf_cert): ast_msgs.append("asterisk.pem key matches domain.key")
    else: asterisk_ok=False; ast_msgs.append("asterisk.pem key MISMATCH")
results["Asterisk Files"] = (asterisk_ok, "; ".join(ast_msgs))
crm_certs=load_certs_from_file(crm_ca); chain_certs=load_certs_from_file(chain_crt)
crm_ok=len(crm_certs)==len(chain_certs)
if crm_ok:
    for a,b in zip(crm_certs,chain_certs):
        if md5_cert_der(a.public_bytes(serialization.Encoding.DER))!=md5_cert_der(b.public_bytes(serialization.Encoding.DER)): crm_ok=False; break
co_ok, co_msg = validate_chain_order(crm_certs); crm_ok = crm_ok and co_ok
results["CRM chain.crt"] = (crm_ok, ("crm-ca identical; " if crm_ok else "") + co_msg)
all_pass=True
for name,(ok,msg) in results.items():
    if not ok: all_pass=False
    print("[%s] %s" % ("PASS" if ok else "FAIL", name)); print("         "+msg)
print(); print("MD5 Checksums:")
for n,m in sorted(file_md5s.items()): print("  %s -> %s" % (n,m))
print(); print("Expiry:"); print("  Not Before:", nb); print("  Not After:", na)
print("  Leaf cert MD5 fingerprint:", leaf_fp); print("  Private key file MD5:", key_md5)
print(); print("Source:", cert_dir); print("Alt path exists:", ALT_DIR.exists()); print()
print("Ready for deployment:", "YES" if all_pass else "NO")
if not all_pass:
    print(); print("Failures / fixes needed:")
    for name,(ok,msg) in results.items():
        if not ok: print("  - %s: %s" % (name,msg))
sys.exit(0 if all_pass else 1)
