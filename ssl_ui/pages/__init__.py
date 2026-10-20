# Author: Sagar K | 2026 | MIT licence
"""The Studio's screens. PAGES maps a navigation key to its Page class."""
from __future__ import annotations

from ssl_ui.pages.certs import CertsPage
from ssl_ui.pages.copy import CopyPage
from ssl_ui.pages.deploy import DeployPage
from ssl_ui.pages.home import HomePage
from ssl_ui.pages.keystore import KeystorePage
from ssl_ui.pages.rollback import RollbackPage

PAGES = {
    "home": HomePage,
    "certs": CertsPage,
    "deploy": DeployPage,
    "copy": CopyPage,
    "rollback": RollbackPage,
    "keystore": KeystorePage,
}
