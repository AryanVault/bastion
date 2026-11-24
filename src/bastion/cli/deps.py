"""External resources the CLI depends on. Tests replace these functions.

Callers must use ``deps.secret_store()`` (module attribute access), never
``from bastion.cli.deps import secret_store``, so that replacements take effect.
"""

import webbrowser

import httpx2

from bastion.config import bastion_home
from bastion.google.api import google_client
from bastion.llm.types import LLMProvider
from bastion.security.sealed_store import store_from_environment
from bastion.security.vault import SecretStore
from bastion.telegram.api import BotApi, TelegramApi


def secret_store() -> SecretStore:
    """The OS keyring, or the sealed file store on servers (``BASTION_SECRET_STORE=file``)."""
    return store_from_environment(bastion_home())


def provider_override() -> LLMProvider | None:
    return None


def bot_api(token: str) -> TelegramApi:
    return BotApi(token)


def google_http() -> httpx2.AsyncClient:
    return google_client()


def open_browser(url: str) -> bool:
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False
