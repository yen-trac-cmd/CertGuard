# my_addon.py
import logging
import os

LOGGER_NAME = "mitmproxy.addons.my_addon"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)

# File handler that includes the logger name in the format
logfile = os.path.join(os.getcwd(), "my_addon.log")
handler = logging.FileHandler(logfile)
formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
handler.setFormatter(formatter)

# Avoid duplicate handlers when mitmproxy reloads addons
if not any(
    isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == handler.baseFilename
    for h in logger.handlers
):
    logger.addHandler(handler)

class MyAddon:
    def request(self, flow):
        # high-level message that will be written to my_addon.log
        logger.info("intercepted request to %s", flow.request.pretty_host)

addons = [MyAddon()]
