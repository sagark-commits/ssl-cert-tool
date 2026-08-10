"""Bootstrap script to write ssl_cert_tool package with correct UTF-8 encoding."""
from pathlib import Path

BASE = Path(__file__).parent / "ssl_cert_tool"
BASE.mkdir(parents=True, exist_ok=True)

MODULES = {
    "__init__.py": '''"""SSL certificate deployment automation for Ameyo/CRM environments."""

__version__ = "1.0.0"
''',
    "__main__.py": '''from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
''',
}

# Will be populated below via exec of remaining modules from heredoc in shell
for name, content in MODULES.items():
    (BASE / name).write_text(content, encoding="utf-8", newline="\n")

print("Base files written")
