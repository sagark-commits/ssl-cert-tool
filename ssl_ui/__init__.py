# Author: Sagar K | 2026 | MIT licence
"""SSL Certificate Studio - the next-generation GUI (Tkinter, no extra dependencies).

Layers, bottom to top:
  render.py   procedural anti-aliased rounded/gradient images (pure Python, no Pillow)
  theme.py    palette, fonts, ttk styling
  widgets.py  buttons, cards, pills, toggles, log view, dialogs
  services.py plain functions that call the real core/deployer and return plain data (unit-tested)
  runner.py   runs services on a worker thread; UI events cross back through a queue
  pages/      one module per screen
  app.py      window, sidebar, header, log dock
"""

__version__ = "0.1.0"
__author__ = "Sagar K"
__license__ = "MIT"
REPO_URL = "https://github.com/sagark-commits/ssl-cert-tool"
