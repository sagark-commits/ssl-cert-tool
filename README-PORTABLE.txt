SSL Certificate Tool - Portable Packages
=======================================

AVAILABLE PACKAGES
------------------
Windows:  SSLCertTool-Windows.zip          (build-windows.bat)
Linux:    SSLCertTool-Linux-Source.zip     (pack-linux-source.bat)
Mac:      SSLCertTool-Mac-Source.zip       (pack-mac-source.bat) READY TO RUN ON MAC


MAC - NO MAC BUILD PC NEEDED
----------------------------
Use: dist\SSLCertTool-Mac-Source.zip

On the Mac:
  1. Install Python 3 from https://www.python.org/downloads/macos/ (once)
  2. Unzip SSLCertTool-Mac-Source.zip
  3. Right-click "Start SSL Certificate Tool.command" -> Open -> Open
  4. First run auto-installs deps into .venv and opens GUI

CLI: generate-on-mac.command
Details: INSTALL-MAC-SOURCE.txt inside the zip

Note: A true no-Python .app still needs ./build-mac.sh ON a Mac.


WINDOWS USE
-----------
1. Unzip SSLCertTool-Windows.zip
2. Double-click Start SSL Certificate Tool.bat


LINUX USE
---------
1. Copy SSLCertTool-Linux-Source.zip to server
2. unzip; chmod +x generate-on-linux.sh
3. python3 -m pip install --user -r requirements.txt
4. ./generate-on-linux.sh


NOTES
-----
- Keep whole folder together
- P12/PEM/CRT: no Java needed
- JKS: needs Java keytool on PATH