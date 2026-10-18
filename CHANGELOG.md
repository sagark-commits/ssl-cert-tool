# Changelog

## 2.1.0

Security hardening, safer deploys, and a test suite. Upgrading note: servers must now be
trusted before the tool will deploy to them (see "Host keys" in the README).

### Security
- **SSH host keys are verified.** Unknown servers are refused (the fingerprint is printed);
  `--accept-new-hostkeys` trusts-on-first-use, `host_key_sha256` pins a key. A changed key is
  always refused. Previously every host key was accepted automatically (`AutoAddPolicy`).
- **No more shell injection through paths.** Every remote path/argument is shell-quoted,
  destinations must be absolute, and rollback no longer builds a shell script from the
  snapshot name (snapshot names are validated and the restore runs over SFTP + quoted `cp`/`mv`).
- **Passwords stay off command lines.** `keytool` receives the keystore password through the
  environment (`-storepass:env`), the remote keystore check sends it on stdin, and the tool
  masks known passwords in its output. New `--password-env`, `--password-file`,
  `${env:VAR}` in configs, `--key-password` / `SSL_KEY_PASSWORD`.
- **Private material is owner-only.** Generated `.key`, `keystore.p12`, `asterisk.pem` and the
  JKS are `0600` (created that way, not chmod-ed afterwards); the output folder is `0700`.
  Keys are never deployed group/world-readable, and a file containing a private key is never
  picked up as a public certificate/chain.
- **Backups are trustworthy.** The backup directory must be owned by the SSH user (it is
  created `0700`); previously a pre-created `/tmp/ssl-deploy-backups` owned by another local
  user could read the backed-up keys or feed rollback files of its choosing.
- **Untrusted archives.** `.zip`/`.7z` input rejects path traversal, symlinks and archive bombs;
  one bad file no longer aborts a folder scan. Catalogue values spliced into hook scripts are
  escaped/validated.
- `scp` subprocess in `check-old --remote` replaced by the same verified SFTP connection.
- Dependency floors raised to `cryptography>=44.0.1` and `paramiko>=3.4.0` (known CVEs).

### Safer deploys
- **Pre-deploy verification** (key matches cert, validity window, domain coverage, chain
  contains the issuer). Failure stops the deploy; `--skip-verify` overrides.
- **Atomic uploads**: `0600` temp file -> size + SHA-256 check -> rename, preserving owner and
  following symlinked destinations.
- **A failed service is undone**, and a failed backup now blocks the overwrite (it used to be
  ignored).
- **Failing hooks stop the restart** and restore the files. Previously `jks_verify`,
  `keypair_check` etc. only printed a warning and the services were restarted anyway.
- JKS services are opened on the server with the configured password/alias before restart.
- Optional `verify_tls` live check after restart; restart failures are reported as failures.
- `rollback --restart` actually applies the restored files.
- Correct exit codes: a deploy that found no certificates, or aborted, no longer reports
  "Deployment Complete" / exit 0. Pre-flight connection failures stop the run.
- Command output is drained while running (no deadlock on large output); idle timeout instead
  of a per-read timeout.

### Fixed
- **Customer configs were being shipped inside the Windows/Mac/Linux packages** (the whole `configs/`
  folder, including real hostnames and passwords, was bundled into the exe and copied next to it).
  Builds now include only `template.yaml` and the example configs.
- **Certificates inside `.zip`/`.7z` inputs were silently dropped** (keys survived, so a bundle
  of cert + key reported "No certificates found").
- Key/certificate matching now works for Ed25519/Ed448/DSA (was RSA/EC only), and generation
  no longer fails for those key types.
- **Private-key passphrase handling.** A passphrase supplied for an *unencrypted* key (for example via
  `SSL_KEY_PASSWORD`) is ignored instead of raising a misleading "passphrase-protected" error, and a wrong passphrase is
  always reported as wrong: decrypting with a wrong passphrase occasionally yields valid-looking padding (about 1 in 256),
  and the resulting parse error used to be reported as "supply --key-password".
- Encrypted private keys give an actionable message (and are supported with `--key-password`)
  instead of a traceback.
- When the inputs hold several private keys, the one matching the certificate is used.
- The documented top-level `ssh:` defaults block is now applied to servers.
- nginx `cert_file` / `key_file` options are honoured (and `fullchain` can be used).
- Asterisk's combined PEM no longer falls back to a chain-only file (which would break WSS).
- An existing JKS is no longer deleted before the new one is successfully built.
- Documentation encoding damage (BOM, broken arrows/dashes/tree) repaired.

### Added
- **Built-in JKS reader/writer (`ssl_cert_tool/jks.py`): no JDK required.** `keytool` is still
  preferred when installed; without it the tool builds the `.jks` itself, reads it straight back,
  and says so. `check-old`, `compare`, `--from-old` and the password validation step also work
  without Java. Verified against real `keytool`-generated keystores (reader opens them; the writer's
  output is byte-identical to Java's in every fixed field) and against the independent `pyjks`
  library in both directions. Only RSA/EC keys are written (JKS limitation). Set
  `SSL_AUTO_BUILTIN_JKS=1` to force the built-in writer.
- Build scripts now bundle `catalogues/` (Ameyo profiles work inside the exe), build into a
  versioned folder instead of deleting the previous release, smoke-test the built exe, and write
  `SHA256SUMS.txt`.
- `tests/` (pytest): key matching, hostile archives, `keytool` handling, the deployer against a
  fake remote host, and host-key verification against a real in-process SSH server.
- `pyproject.toml`, `requirements-dev.txt`, GitHub Actions workflow (tests on Linux/macOS/Windows,
  `pip-audit`).

### Added: SSL Certificate Studio (new GUI, preview)
- **`python ssl-gui2.py`** opens a redesigned dark-theme GUI with six pages: Home, Certificates (inspect a pile of
  files, see the chain and whether the key matches, then generate), Deploy, Copy to server, Rollback and Keystores.
  It is the same engine as the CLI (`ssl_ui/services.py` calls the real core and deployer), so results are identical.
  Tkinter only: no new dependency and no local web server.
- Safe by default: **dry run is on**, a live deploy/copy/rollback asks for confirmation first, work runs on a background
  thread so the window never freezes, and SSH passwords are asked for in a hidden dialog per `user@host` (used once, never
  saved). Only folders and file paths are remembered (`~/.ssl-auto/studio.json`); the state file refuses any key that looks
  like a password, token or secret.
- The Copy page shows the jump-host route (laptop -> bastion -> ... -> target) as you type, and "Deploy these" / "Copy to a
  server" carry freshly generated files straight into the next step.
- The classic `ssl-gui.py` is **unchanged**, and the Windows/macOS/Linux builds still ship the classic GUI until the Studio
  is promoted.
- `tests/test_ui_widgets.py` drives the real window (every page, full inspect/generate/deploy/copy/rollback/keystore flows,
  dialogs, widgets). The tests are skipped when there is no display (use `xvfb-run` on a headless Linux box), never show a
  window or take keyboard focus, and fail instead of hanging if a dialog waits for input.

### Added after testing on a real Linux VM (UAT)
- **Jump hosts.** Servers behind bastions work like `ssh -J`: `proxy_jump:` in the config (server names, ssh-config
  aliases or `user@host:port`, one or several hops) or `ssh_alias:` to reuse `~/.ssh/config` (its `ProxyJump` chain is
  followed). Every hop is host-key verified; each hop has its own password and the target's is never sent to a jump host.
- **`copy` command** (scp-like): verified, atomic, backed up and reversible, with `--check-cmd` (restores everything if
  it fails) and `--reload-cmd`; works ad hoc (`--host`) or from a config (`--server`).
- **`--ask-ssh-password`**: hidden prompt, once per `user@host`, only after keys/agent were refused. Nothing is put in
  the environment.
- A slow `ameyoctl status` is a pre-flight *warning* ("service states unknown") instead of blocking the deploy.
- Backup snapshots are safe from two deploys in the same second: the first backup of a path is never overwritten.
- Explicit file modes: group access (e.g. `640`) is honoured for private keys; world access is still refused.
- Verified end to end on a Rocky Linux 8 VM: 29 scratch-directory checks, then a real deploy of a wildcard certificate to
  two Apache vhosts (owner `dacx` preserved, `httpd -t` gate, graceful reload, live TLS check) and a rollback drill.

### Also fixed while verifying the builds
- `plan` printed the keystore password from hook/restart commands; it is now masked.
- File destinations that are actually directories (e.g. a blank `ca_bundle_legacy` producing `/dacx/ssl/`)
  are rejected by `validate` and by deploy with a clear message instead of failing mid-upload.
- Validation no longer echoes the first characters of the keystore password.
- `SHA256SUMS.txt` uses LF line endings so `sha256sum -c` works everywhere.

### Known limitations
- Ameyo catalogue hooks (`cacerts_import`, `jks_verify`) still embed the keystore password in
  the remote command line.
- Checks that depend on POSIX file modes, symlinks and the remote `[ -O dir ]` ownership test
  run on Linux/macOS CI; they are skipped on Windows.
