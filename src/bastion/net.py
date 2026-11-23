"""HTTP helpers shared by Bastion's API clients."""

import logging

# httpx2 and httpcore2 log request URLs. Some URLs carry secrets (the Telegram bot token is part
# of every Bot API path) or private data (Gmail search queries), so these loggers are held at
# WARNING whatever the application's logging configuration says.
REQUEST_LOGGERS = ("httpx2", "httpcore2")


def quiet_request_logs() -> None:
    for name in REQUEST_LOGGERS:
        logger = logging.getLogger(name)
        if logger.level < logging.WARNING:
            logger.setLevel(logging.WARNING)
