from urllib.parse import urlencode

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder


def main_menu(is_admin: bool = False) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="➕ Создать секрет", callback_data="create", style="success")
    b.button(text="📥 Запросить", callback_data="request:create", style="primary")
    b.button(text="🎲 Генератор", callback_data="type:generator", style="primary")
    b.button(text="📂 Мои секреты", callback_data="my:secrets", style="primary")
    b.button(text="🚨 УДАЛИТЬ ВСЕ СЕКРЕТЫ", callback_data="panic:quick", style="danger")
    b.button(text="••• Ещё", callback_data="more")
    if is_admin:
        b.button(text="🛡 Админка", callback_data="admin:home")
    b.adjust(1, 2, 1, 1, 1, 1)
    return b.as_markup()


def my_secrets_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📨 Активные", callback_data="active:0"),
         InlineKeyboardButton(text="🕘 История", callback_data="history:0")],
        [InlineKeyboardButton(text="🚨 Экстренное удаление", callback_data="panic")],
        [InlineKeyboardButton(text="⬅️ На главную", callback_data="menu")],
    ])


def more_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🛡 О сервисе и безопасности", callback_data="about")],
        [InlineKeyboardButton(text="❓ Как пользоваться", callback_data="help")],
        [InlineKeyboardButton(text="⬅️ На главную", callback_data="menu")],
    ])


def ttl_menu(selected: int | None = 86400) -> InlineKeyboardMarkup:
    values = [("5 мин", 300), ("30 мин", 1800), ("1 час", 3600), ("6 часов", 21600),
              ("24 часа", 86400), ("3 дня", 259200), ("7 дней", 604800), ("До открытия", 0)]
    b = InlineKeyboardBuilder()
    for label, seconds in values:
        b.button(text=label, callback_data=f"ttl:{seconds}",
                 style="success" if selected == seconds else None)
    b.button(text="Дальше →", callback_data="ttl:continue", style="primary")
    b.button(text="⬅️ Назад", callback_data="nav:create")
    b.adjust(2, 2, 2, 2, 1, 1)
    return b.as_markup()


def content_type_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📝 Текст", callback_data="type:text"), InlineKeyboardButton(text="📎 Файл", callback_data="type:file")],
        [InlineKeyboardButton(text="🎲 Генератор", callback_data="type:generator", style="primary")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="menu")],
    ])


def views_menu(selected: int | None = 1) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    for label, count in (("1 раз", 1), ("2 раза", 2), ("3 раза", 3), ("5 раз", 5)):
        b.button(text=label, callback_data=f"views:{count}",
                 style="success" if selected == count else None)
    b.button(text="Дальше →", callback_data="views:continue", style="primary")
    b.button(text="⬅️ Назад", callback_data="nav:ttl")
    b.adjust(2, 2, 1, 1)
    return b.as_markup()


def protection_menu(data: dict) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="🔢 PIN-код", callback_data="protect:pin",
             style="success" if data.get("pin_hash") else None)
    b.button(text="👤 Получатель", callback_data="protect:recipient",
             style="success" if data.get("recipient_mode", "any") != "any" else None)
    b.button(text="⚙️ Дополнительно", callback_data="protect:advanced")
    b.button(text="Создать секрет", callback_data="protect:continue", style="success")
    b.button(text="⬅️ Назад", callback_data="nav:views")
    b.adjust(1, 1, 1, 1, 1)
    return b.as_markup()


def protection_advanced_menu(data: dict) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="💥 Самоуничтожение", callback_data="protect:destroy_timer",
             style="success" if data.get("destroy_after_open_seconds", 3600) == 3600 else None)
    b.button(text="🔔 Уведомления", callback_data="protect:notifications")
    b.button(text="🪪 Проверка ID", callback_data="protect:confirm",
             style="success" if data.get("require_identity_confirmation") else None)
    b.button(text="⬅️ К защите", callback_data="protect:back")
    b.adjust(1, 1, 1, 1)
    return b.as_markup()


def destroy_timer_menu(selected: int | None = 3600) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    for label, seconds in (("Сразу по лимиту", 0), ("Через 1 минуту", 60),
                           ("Через 5 минут", 300), ("Через 1 час", 3600)):
        b.button(text=label, callback_data=f"destroy_timer:{seconds}",
                 style="success" if selected == seconds else None)
    b.button(text="⬅️ Назад", callback_data="protect:back")
    b.adjust(1, 1, 1, 1, 1)
    return b.as_markup()


def generator_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Пароль", callback_data="gen:password"), InlineKeyboardButton(text="🔢 PIN", callback_data="gen:pin")],
        [InlineKeyboardButton(text="🪙 API Token", callback_data="gen:token"), InlineKeyboardButton(text="🧬 UUID", callback_data="gen:uuid")],
        [InlineKeyboardButton(text="🔐 Secret Key", callback_data="gen:key")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="nav:create")],
    ])


def password_length_menu(options: dict | None = None) -> InlineKeyboardMarkup:
    options = options or {"gen_upper": True, "gen_lower": True, "gen_digits": True, "gen_symbols": True}
    b = InlineKeyboardBuilder()
    for size in (16, 24, 32, 48, 64):
        b.button(text=str(size), callback_data=f"gen_password:{size}")
    for label, field in (("A-Z", "gen_upper"), ("a-z", "gen_lower"), ("0-9", "gen_digits"), ("Символы", "gen_symbols")):
        b.button(text=label, callback_data=f"genopt:{field}",
                 style="success" if options.get(field, True) else None)
    b.button(text="⬅️ Назад", callback_data="type:generator")
    b.adjust(3, 2, 2, 2, 1)
    return b.as_markup()


def generated_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👁 Показать", callback_data="generated:show")],
        [InlineKeyboardButton(text="🔐 Передать как секрет", callback_data="generated:transfer")],
        [InlineKeyboardButton(text="🔄 Новый такой же", callback_data="generated:new")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="type:generator")],
    ])


def request_created_menu(token: str, username: str, request_id: str) -> InlineKeyboardMarkup:
    link = f"https://t.me/{username}?start=rq_{token}"
    share_url = "https://t.me/share/url?" + urlencode({"url": link, "text": "📥 Запрос защищённой информации через T-Secret."})
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📤 Поделиться запросом", url=share_url)],
        [InlineKeyboardButton(text="🔥 Отменить", callback_data=f"request:cancel:{request_id}")],
        [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="menu")],
    ])


def pin_choice_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🎲 Сгенерировать PIN", callback_data="pin:generate")],
        [InlineKeyboardButton(text="⌨️ Ввести свой", callback_data="pin:custom")],
        [InlineKeyboardButton(text="🧹 Убрать PIN", callback_data="pin:remove")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="protect:back")],
    ])


def recipient_menu(mode: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Любой", callback_data="recipient:any", style="success" if mode == "any" else None)],
        [InlineKeyboardButton(text="Конкретный пользователь", callback_data="recipient:specific", style="success" if mode == "specific" else None)],
        [InlineKeyboardButton(text="Первый открывший", callback_data="recipient:first", style="success" if mode == "first" else None)],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="protect:back")],
    ])


def recipient_input_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🆔 Ввести Telegram ID", callback_data="recipient:enter_id")],
        [InlineKeyboardButton(text="📨 Переслать сообщение", callback_data="recipient:forward")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="protect:recipient")],
    ])


def notifications_menu(data: dict) -> InlineKeyboardMarkup:
    fields = (("Открытие секрета", "notify_open"), ("Ошибочный PIN", "notify_wrong_pin"),
              ("Чужой пользователь", "notify_wrong_user"), ("Истечение", "notify_expiry"),
              ("Уничтожение", "notify_destroy"))
    b = InlineKeyboardBuilder()
    for label, field in fields:
        b.button(text=label, callback_data=f"notify:{field}",
                 style="success" if data.get(field) else None)
    b.button(text="⬅️ Назад", callback_data="protect:back")
    b.adjust(1)
    return b.as_markup()


def identity_confirmation(secret_id: str, telegram_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Это я", callback_data=f"confirm:{secret_id}")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu")],
    ])


def created_menu(token: str, username: str, secret_id: str) -> InlineKeyboardMarkup:
    link = f"https://t.me/{username}?start=s_{token}"
    share_url = "https://t.me/share/url?" + urlencode({"url": link, "text": "🔐 Вам передан секрет через T-Secret."})
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📤 Поделиться", url=share_url, style="success")],
        [InlineKeyboardButton(text="📋 Получить ссылку", callback_data=f"link:{secret_id}", style="primary")],
        [InlineKeyboardButton(text="🔥 Уничтожить", callback_data=f"destroy:{secret_id}", style="danger")],
        [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="menu")],
    ])


def reveal_menu(secret_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👁 Открыть секрет", callback_data=f"reveal:{secret_id}", style="success")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu", style="danger")],
    ])


def file_reveal_menu(secret_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📥 Получить файл", callback_data=f"reveal:{secret_id}", style="success")],
        [InlineKeyboardButton(text="❌ Отмена", callback_data="menu", style="danger")],
    ])


def delete_message_menu(secret_id: str | None = None) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text="🔥 Удалить сейчас", callback_data="delete_message", style="danger")]]
    if secret_id:
        rows.append([InlineKeyboardButton(text="🔁 Передать дальше", callback_data=f"relay:{secret_id}", style="primary")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def back_menu(callback_data: str = "menu", text: str = "⬅️ Назад") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=text, callback_data=callback_data)]])
