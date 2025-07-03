"""Default logger for FastAPI-UI-Auth package."""

import logging
import sys

CUSTOM_LOGGER = logging.getLogger(__name__)
CUSTOM_LOGGER.setLevel(logging.DEBUG)
CONSOLE_HANDLER = logging.StreamHandler(sys.stdout)
CONSOLE_FORMATTER = logging.Formatter(
    fmt="%(levelname)-9s %(message)s",
)
CONSOLE_HANDLER.setFormatter(fmt=CONSOLE_FORMATTER)
CUSTOM_LOGGER.addHandler(hdlr=CONSOLE_HANDLER)
