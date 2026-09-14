from typing import TypeVar

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.methods import TelegramMethod
from aiogram.types import InlineKeyboardMarkup
from sqlalchemy import select

from app.db import Database
from app.models import UiEmojiSetting

# One semantic assignment is used everywhere the same fallback emoji occurs.
# Labels describe the most common user-facing contexts shown in the editor.
CATALOG: dict[str, tuple[str, str]] = {
    "lock": ("🔐", "T-Secret, защищённый секрет"),
    "plus": ("➕", "Создать секрет"),
    "inbox": ("📥", "Запросить или получить"),
    "dice": ("🎲", "Генератор"),
    "folder": ("📂", "Мои секреты"),
    "shield": ("🛡", "Защита"),
    "info": ("ℹ️", "О сервисе"),
    "help": ("❓", "Помощь"),
    "settings": ("⚙️", "Настройки"),
    "outbox": ("📨", "Активные секреты"),
    "history": ("🕘", "История"),
    "panic": ("🚨", "Экстренное удаление"),
    "hourglass": ("⏳", "Срок действия"),
    "clock": ("⏰", "Доступность"),
    "eye": ("👁", "Просмотры, показать"),
    "fire": ("🔥", "Уничтожить"),
    "success": ("✅", "Включено, подтверждение"),
    "disabled": ("❌", "Отключено, отмена"),
    "digits": ("🔢", "PIN"),
    "keyboard": ("⌨️", "Ввести вручную"),
    "telegram_id": ("🆔", "Telegram ID"),
    "person": ("👤", "Получатель"),
    "explode": ("💥", "После открытия"),
    "bell": ("🔔", "Уведомления"),
    "id": ("🪪", "Проверка ID"),
    "fast": ("⚡", "Сразу, быстро"),
    "people": ("👥", "Любой пользователь"),
    "first": ("🥇", "Первый открывший"),
    "target": ("🎯", "Конкретный пользователь"),
    "back": ("⬅️", "Назад"),
    "file": ("📎", "Файл"),
    "note": ("📝", "Текст"),
    "key": ("🔑", "Пароль"),
    "coin": ("🪙", "API Token"),
    "dna": ("🧬", "UUID"),
    "share": ("📤", "Поделиться"),
    "copy": ("📋", "Получить ссылку"),
    "relay": ("🔁", "Передать дальше"),
    "refresh": ("🔄", "Создать новый"),
    "chat": ("💬", "Открыть в личке"),
    "warning": ("⚠️", "Предупреждение"),
    "denied": ("⛔", "Доступ запрещён"),
    "limited": ("🚫", "Ограничение"),
    "online": ("🟢", "Активен"),
    "expired": ("⌛", "Истёк"),
    "previous": ("◀️", "Предыдущая страница"),
    "next": ("▶️", "Следующая страница"),
    "clear": ("🧹", "Убрать настройку"),
    "radio_off": ("○", "Не выбран"),
    "radio_on": ("●", "Выбран"),
}

_custom: dict[str, str] = {}


def custom_id(slot: str) -> str | None:
    return _custom.get(slot)


def set_custom_id(slot: str, emoji_id: str | None) -> None:
    if emoji_id:
        _custom[slot] = emoji_id
    else:
        _custom.pop(slot, None)


async def load_ui_emojis(db: Database) -> None:
    async with db.sessions() as session:
        rows = (await session.scalars(select(UiEmojiSetting))).all()
    _custom.clear()
    _custom.update({row.slot: row.custom_emoji_id for row in rows if row.slot in CATALOG})


def render_text(value: str) -> str:
    for slot, (fallback, _) in CATALOG.items():
        emoji_id = _custom.get(slot)
        if emoji_id and fallback in value:
            value = value.replace(fallback, f'<tg-emoji emoji-id="{emoji_id}">{fallback}</tg-emoji>')
    return value


def render_markup(markup: InlineKeyboardMarkup | None) -> InlineKeyboardMarkup | None:
    if markup is None:
        return None
    for row in markup.inline_keyboard:
        for button in row:
            for slot, (fallback, _) in CATALOG.items():
                emoji_id = _custom.get(slot)
                if emoji_id and button.text.startswith(fallback):
                    remaining_text = button.text[len(fallback):].lstrip()
                    # Telegram requires non-empty button text even when a custom
                    # emoji icon is present. Keep the Unicode fallback for
                    # icon-only controls such as pagination arrows.
                    if remaining_text:
                        button.text = remaining_text
                        button.icon_custom_emoji_id = emoji_id
                    break
    return markup


T = TypeVar("T")


class UiBot(Bot):
    async def __call__(
        self, method: TelegramMethod[T], request_timeout: int | None = None
    ) -> T:
        # All messages sent by this bot pass here, including Message.answer and
        # edit_text shortcuts, so no user-facing screen can be missed.
        fallback_updates: dict[str, object] = {}
        original_markup = getattr(method, "reply_markup", None)
        if isinstance(original_markup, InlineKeyboardMarkup):
            fallback_updates["reply_markup"] = original_markup.model_copy(deep=True)
        fallback_method = method.model_copy(deep=False, update=fallback_updates)
        text = getattr(method, "text", None)
        if isinstance(text, str):
            method.text = render_text(text)  # type: ignore[attr-defined]
        caption = getattr(method, "caption", None)
        if isinstance(caption, str):
            method.caption = render_text(caption)  # type: ignore[attr-defined]
        markup = getattr(method, "reply_markup", None)
        if isinstance(markup, InlineKeyboardMarkup):
            method.reply_markup = render_markup(markup)  # type: ignore[attr-defined]
        try:
            return await super().__call__(method, request_timeout=request_timeout)
        except TelegramBadRequest as exc:
            # A bot/account may temporarily be ineligible to use a particular
            # custom emoji. Never let cosmetic configuration break the UI.
            message = str(exc).lower()
            if ("emoji" not in message and "parse entities" not in message
                    and "button text must be non-empty" not in message):
                raise
            return await super().__call__(fallback_method, request_timeout=request_timeout)
