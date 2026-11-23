"""External resources the CLI depends on. Tests replace these functions.

Callers must use ``deps.secret_store()`` (module attribute access), never
``from bastion.cli.deps import secret_store``, so that replacements take effect.
"""

from bastion.llm.types import LLMProvider
from bastion.security.vault import KeyringStore, SecretStore
from bastion.telegram.api import BotApi, TelegramApi


def secret_store() -> SecretStore:
    return KeyringStore()


def provider_override() -> LLMProvider | None:
    return None


def bot_api(token: str) -> TelegramApi:
    return BotApi(token)
