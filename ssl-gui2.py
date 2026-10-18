#!/usr/bin/env python3
"""SSL Certificate Studio - the next-generation GUI (the classic ssl-gui.py is unchanged).

    python ssl-gui2.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    sys.path.insert(0, str(sys._MEIPASS))
elif str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ssl_ui.app import launch  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(launch())
