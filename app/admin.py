import html
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from aiogram import Bot, F, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from redis.asyncio import Redis
from sqlalchemy import func, select

from app.audit import write_audit
from app.config import Settings
from app.db import Database
from app.models import (
    AuditEvent,
    ContentType,
    DestroyReason,
    Secret,
    SecretRequest,
    SecretStatus,
    UiEmojiSetting,
    User,
    UserStatus,
)
from app.states import AdminEmoji, AdminUserSearch
from app.text import dt
from app.ui_emoji import CATALOG, custom_id, set_custom_id


def admin_menu():
    b = InlineKeyboardBuilder()
    for label, data in (("👥 Пользователи", "admin:users"), ("📊 Статистика", "admin:stats"),
                        ("🔐 Секреты", "admin:secrets"), ("🚫 Ограничения", "admin:restrictions"),
                        ("⚙️ Система", "admin:system"), ("📜 Audit", "admin:audit"),
                        ("🎨 Эмодзи UI", "admin:emoji")):
        b.button(text=label, callback_data=data)
    b.button(text="⬅️ Главное меню", callback_data="menu")
    b.adjust(2, 2, 2, 1, 1)
    return b.as_markup()


def back_admin():
    b = InlineKeyboardBuilder(); b.button(text="⬅️ Admin", callback_data="admin:home")
    return b.as_markup()


USER_SORTS = {
    "activity": "По активности",
    "new": "Сначала новые",
    "telegram": "По Telegram ID",
}

AUDIT_LABELS = {
    "secret_created": "🆕 Секрет создан",
    "secret_access_attempt": "🔎 Попытка доступа",
    "secret_opened": "👁 Секрет открыт",
    "secret_destroyed": "🔥 Секрет уничтожен",
    "secret_expired": "⌛ Секрет истёк",
    "secret_pin_failed": "🔢 Ошибка PIN",
    "secret_claimed": "👤 Получатель закреплён",
    "secret_request_created": "📥 Запрос создан",
    "file_uploaded": "📎 Файл загружен",
    "panic_delete": "🚨 Массовое удаление",
    "admin_action": "🛡 Действие администратора",
}


def audit_event_label(event_type: str) -> str:
    return AUDIT_LABELS.get(event_type, f"📌 {event_type.replace('_', ' ')}")


def audit_list_markup(rows: list[AuditEvent], page: int, total_pages: int, owner_id: int | None = None):
    owner_value = owner_id or 0
    b = InlineKeyboardBuilder()
    for row in rows:
        created_msk = row.created_at.astimezone(ZoneInfo("Europe/Moscow"))
        code = row.secret_public_code or "без ID"
        b.button(
            text=f"{created_msk:%d.%m %H:%M} · {audit_event_label(row.event_type)} · {code}",
            callback_data=f"admin:audit:event:{row.id}:{page}:{owner_value}",
        )
    b.button(text="◀️", callback_data=f"admin:audit:page:{max(0, page - 1)}:{owner_value}")
    b.button(text=f"{page + 1} / {total_pages}", callback_data="admin:audit:page-number")
    b.button(text="▶️", callback_data=f"admin:audit:page:{min(total_pages - 1, page + 1)}:{owner_value}")
    if owner_id is None:
        b.button(text="⬅️ Admin", callback_data="admin:home")
    else:
        b.button(text="⬅️ К пользователю", callback_data=f"admin:user:{owner_id}")
    b.adjust(*([1] * len(rows)), 3, 1)
    return b.as_markup()


def users_list_markup(users: list[User], page: int, total_pages: int, sort_key: str):
    b = InlineKeyboardBuilder()
    b.button(text="🔎 Поиск", callback_data="admin:users:search", style="primary")
    b.button(text=f"↕️ {USER_SORTS[sort_key]}", callback_data=f"admin:users:sort:{sort_key}")
    for user in users:
        b.button(text=f"#{user.id} · {user.telegram_id}", callback_data=f"admin:user:{user.telegram_id}")
    b.button(text="◀️", callback_data=f"admin:users:{sort_key}:{max(0, page - 1)}")
    b.button(text=f"{page + 1} / {total_pages}", callback_data="admin:users:page")
    b.button(text="▶️", callback_data=f"admin:users:{sort_key}:{min(total_pages - 1, page + 1)}")
    b.button(text="⬅️ Admin", callback_data="admin:home")
    b.adjust(2, *([1] * len(users)), 3, 1)
    return b.as_markup()


def users_sort_markup(sort_key: str):
    b = InlineKeyboardBuilder()
    for key, label in USER_SORTS.items():
        b.button(text=label, callback_data=f"admin:users:{key}:0",
                 style="success" if key == sort_key else None)
    b.button(text="⬅️ К пользователям", callback_data=f"admin:users:{sort_key}:0")
    b.adjust(1)
    return b.as_markup()


def admin_user_markup(telegram_id: int):
    b = InlineKeyboardBuilder()
    for label, action in (("🚫 Ban", "ban"), ("⏳ Ban 24h", "temp"), ("👁 Read-only", "readonly"),
                          ("🔐 Creation off", "creation"), ("📎 Files off", "files"),
                          ("🐢 Rate limited", "rate"), ("✅ Снять ограничения", "clear")):
        b.button(text=label, callback_data=f"admin:restrict:{action}:{telegram_id}")
    b.button(text="🕘 Audit", callback_data=f"admin:useraudit:{telegram_id}")
    b.button(text="⬅️ Назад", callback_data="admin:users:activity:0")
    b.adjust(2)
    return b.as_markup()


def build_admin_router(settings: Settings, db: Database, redis: Redis) -> Router:
    router = Router(name="admin")

    def allowed(user_id: int) -> bool:
        return user_id in settings.admin_id_set

    async def emoji_page(event: CallbackQuery, page: int = 0) -> None:
        entries = list(CATALOG.items())
        page_size = 8
        max_page = max(0, (len(entries) - 1) // page_size)
        page = min(max(page, 0), max_page)
        chunk = entries[page * page_size:(page + 1) * page_size]
        b = InlineKeyboardBuilder()
        b.button(text="🚀 Заполнить пропуски", callback_data="admin:emoji:wizard:missing")
        b.button(text="🔄 Пройти все заново", callback_data="admin:emoji:wizard:all")
        for slot, (fallback, label) in chunk:
            mark = "✅" if custom_id(slot) else "▫️"
            b.button(text=f"{fallback} {label} {mark}", callback_data=f"admin:emoji:slot:{slot}:{page}")
        if page > 0:
            b.button(text="◀️", callback_data=f"admin:emoji:{page - 1}")
        if page < max_page:
            b.button(text="▶️", callback_data=f"admin:emoji:{page + 1}")
        b.button(text="⬅️ Admin", callback_data="admin:home")
        b.adjust(2, *([1] * len(chunk)), 2, 1)
        await event.message.edit_text(  # type: ignore[union-attr]
            f"🎨 <b>Premium-эмодзи интерфейса</b>\n\n"
            f"Страница {page + 1}/{max_page + 1}\n"
            "Нажмите на элемент, затем пришлите один premium-эмодзи. "
            "Назначение применяется ко всем пользовательским текстам и кнопкам с этим знаком.",
            reply_markup=b.as_markup(),
        )
        await event.answer()

    def wizard_markup():
        b = InlineKeyboardBuilder()
        b.button(text="⏭ Пропустить", callback_data="admin:emoji:wizard:skip")
        b.button(text="⏹ Завершить", callback_data="admin:emoji:wizard:stop")
        b.adjust(2)
        return b.as_markup()

    async def show_wizard(bot: Bot, chat_id: int, message_id: int,
                          sequence: list[str], position: int) -> None:
        if position >= len(sequence):
            b = InlineKeyboardBuilder()
            b.button(text="🎨 Открыть каталог", callback_data="admin:emoji:0")
            b.button(text="⬅️ Admin", callback_data="admin:home")
            b.adjust(1)
            await bot.edit_message_text(
                "✅ <b>Настройка завершена</b>\n\nВсе выбранные позиции пройдены. Изменения уже применяются.",
                chat_id=chat_id, message_id=message_id, reply_markup=b.as_markup(),
            )
            return
        slot = sequence[position]
        fallback, label = CATALOG[slot]
        current = "✅ уже назначен" if custom_id(slot) else "▫️ не назначен"
        await bot.edit_message_text(
            f"🚀 <b>Быстрая настройка эмодзи</b>\n\n"
            f"Шаг <b>{position + 1}/{len(sequence)}</b>\n\n"
            f"{fallback} — <b>{label}</b>\nСтатус: {current}\n\n"
            "Пришлите один premium-эмодзи — бот сразу переключится на следующий.",
            chat_id=chat_id, message_id=message_id, reply_markup=wizard_markup(),
        )

    async def dashboard_text(bot: Bot) -> str:
        now_msk = datetime.now(ZoneInfo("Europe/Moscow"))
        today = now_msk.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
        async with db.sessions() as session:
            users = await session.scalar(select(func.count()).select_from(User)) or 0
            active_today = await session.scalar(select(func.count()).select_from(User).where(User.last_seen_at >= today)) or 0
            created = await session.scalar(select(func.count()).select_from(Secret)) or 0
            destroyed = await session.scalar(select(func.count()).select_from(Secret).where(Secret.status != SecretStatus.ACTIVE)) or 0
            active = await session.scalar(select(func.count()).select_from(Secret).where(Secret.status == SecretStatus.ACTIVE)) or 0
            db_ok = bool(await session.scalar(select(1)))
        redis_ok = bool(await redis.ping())
        worker_ok = bool(await redis.get("worker:heartbeat"))
        try:
            await bot.get_me(); telegram_ok = True
        except Exception:  # noqa: BLE001 - health status must survive any Telegram transport failure
            telegram_ok = False
        dot = lambda value: "🟢" if value else "🔴"
        return ("🛡 <b>T-Secret Admin</b>\n\n"
                f"👥 Пользователей: {users:,}\n🟢 Сегодня активны: {active_today:,}\n"
                f"🔐 Создано секретов: {created:,}\n🔥 Уничтожено: {destroyed:,}\n📨 Активно сейчас: {active:,}\n\n"
                f"💾 Database: {dot(db_ok)}\n🧠 Redis: {dot(redis_ok)}\n"
                f"🤖 Telegram API: {dot(telegram_ok)}\n⚙️ Worker: {dot(worker_ok)}")

    @router.callback_query(F.data == "admin:home")
    async def admin_home(event: CallbackQuery, bot: Bot, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            await event.answer("Недоступно", show_alert=True); return
        await state.clear()
        await event.message.edit_text(await dashboard_text(bot), reply_markup=admin_menu())  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "admin:stats")
    async def admin_stats(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        now_msk = datetime.now(ZoneInfo("Europe/Moscow"))
        today = now_msk.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(UTC)
        async with db.sessions() as session:
            created = await session.scalar(select(func.count()).select_from(Secret).where(Secret.created_at >= today)) or 0
            opened = await session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= today, AuditEvent.event_type == "secret_opened")) or 0
            expired = await session.scalar(select(func.count()).select_from(Secret).where(Secret.destroyed_at >= today, Secret.destroy_reason == DestroyReason.EXPIRED)) or 0
            manual = await session.scalar(select(func.count()).select_from(Secret).where(Secret.destroyed_at >= today, Secret.destroy_reason == DestroyReason.MANUAL)) or 0
            type_rows = (await session.execute(select(Secret.content_type, func.count()).group_by(Secret.content_type))).all()
            request_count = await session.scalar(select(func.count()).select_from(SecretRequest)) or 0
            avg_ttl = await session.scalar(select(func.avg(func.extract("epoch", Secret.expires_at - Secret.created_at))).where(Secret.expires_at.is_not(None))) or 0
        total = sum(count for _, count in type_rows) + request_count
        labels = {ContentType.TEXT: "📝 Text", ContentType.FILE: "📎 File", ContentType.PASSWORD: "🔑 Password", ContentType.GENERATED: "🎲 Generated"}
        types = [f"{labels[kind]} — {count * 100 // max(1, total)}%" for kind, count in type_rows]
        types.append(f"📥 Request — {request_count * 100 // max(1, total)}%")
        hours, minutes = int(avg_ttl) // 3600, int(avg_ttl) % 3600 // 60
        text = (f"📊 <b>Статистика</b>\n\nСегодня:\nСоздано: {created}\nОткрыто: {opened}\n"
                f"Истекло: {expired}\nУдалено вручную: {manual}\n\nТипы:\n" + "\n".join(types) +
                f"\n\nСредний TTL: {hours} ч {minutes} мин")
        await event.message.edit_text(text, reply_markup=back_admin())  # type: ignore[union-attr]
        await event.answer()

    async def user_card(telegram_id: int) -> tuple[str, object] | None:
        async with db.sessions() as session:
            user = await session.scalar(select(User).where(User.telegram_id == telegram_id))
            if user is None:
                return None
            created = await session.scalar(select(func.count()).select_from(Secret).where(Secret.creator_id == telegram_id)) or 0
            opened = await session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.owner_id == telegram_id, AuditEvent.event_type == "secret_opened")) or 0
            active = await session.scalar(select(func.count()).select_from(Secret).where(Secret.creator_id == telegram_id, Secret.status == SecretStatus.ACTIVE)) or 0
        text = (f"👤 <b>User #{user.id}</b>\n\nTelegram ID: <code>{telegram_id}</code>\n"
                f"Первый запуск: {dt(user.first_seen_at)}\nПоследняя активность: {dt(user.last_seen_at)}\n\n"
                f"Создано секретов: {created}\nОткрыто: {opened}\nАктивных: {active}\n\nСтатус: {user.status.value}\n"
                f"Причина: {user.restriction_reason or '—'}")
        return text, admin_user_markup(telegram_id)

    async def show_users_page(event: CallbackQuery, sort_key: str = "activity", page: int = 0) -> None:
        if sort_key not in USER_SORTS:
            sort_key = "activity"
        page_size = 20
        order = {
            "activity": User.last_seen_at.desc(),
            "new": User.first_seen_at.desc(),
            "telegram": User.telegram_id.asc(),
        }[sort_key]
        async with db.sessions() as session:
            total = await session.scalar(select(func.count()).select_from(User)) or 0
            total_pages = max(1, (total + page_size - 1) // page_size)
            page = min(max(page, 0), total_pages - 1)
            users = list((await session.scalars(
                select(User).order_by(order, User.id.asc()).offset(page * page_size).limit(page_size)
            )).all())
        await event.message.edit_text(  # type: ignore[union-attr]
            f"👥 <b>Пользователи</b>\n\nВсего: {total} · По 20 на странице",
            reply_markup=users_list_markup(users, page, total_pages, sort_key),
        )
        await event.answer()

    @router.callback_query(F.data.in_({"admin:users", "admin:restrictions"}))
    async def admin_users(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id): return
        await state.clear()
        await show_users_page(event)

    @router.callback_query(F.data.regexp(r"^admin:users:(activity|new|telegram):\d+$"))
    async def admin_users_page(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id): return
        await state.clear()
        _, _, sort_key, page_raw = event.data.split(":")  # type: ignore[union-attr]
        await show_users_page(event, sort_key, int(page_raw))

    @router.callback_query(F.data == "admin:users:page")
    async def admin_users_page_number(event: CallbackQuery) -> None:
        await event.answer("Текущая страница")

    @router.callback_query(F.data.regexp(r"^admin:users:sort:(activity|new|telegram)$"))
    async def admin_users_sort(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        sort_key = event.data.rsplit(":", 1)[1]  # type: ignore[union-attr]
        await event.message.edit_text(  # type: ignore[union-attr]
            "↕️ <b>Сортировка пользователей</b>\n\nВыберите порядок списка:",
            reply_markup=users_sort_markup(sort_key),
        )
        await event.answer()

    @router.callback_query(F.data == "admin:users:search")
    async def admin_users_search(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id): return
        await state.set_state(AdminUserSearch.query)
        b = InlineKeyboardBuilder()
        b.button(text="⬅️ К пользователям", callback_data="admin:users:activity:0")
        await event.message.edit_text(  # type: ignore[union-attr]
            "🔎 <b>Поиск пользователя</b>\n\nВведите Telegram ID или внутренний номер, например <code>#71</code>.",
            reply_markup=b.as_markup(),
        )
        await event.answer()

    @router.message(AdminUserSearch.query)
    async def admin_users_search_value(message: Message, state: FSMContext) -> None:
        if not allowed(message.from_user.id): return
        raw = (message.text or "").strip()
        try:
            value = int(raw.removeprefix("#").strip())
        except ValueError:
            await message.answer("Введите только Telegram ID или внутренний номер вида <code>#71</code>.")
            return
        async with db.sessions() as session:
            if raw.startswith("#"):
                user = await session.scalar(select(User).where(User.id == value))
                telegram_id = user.telegram_id if user else None
            else:
                user = await session.scalar(select(User).where(User.telegram_id == value))
                telegram_id = user.telegram_id if user else None
        if telegram_id is None:
            await message.answer("Пользователь не найден. Попробуйте другой ID.")
            return
        await state.clear()
        card = await user_card(telegram_id)
        if card is not None:
            await message.answer(card[0], reply_markup=card[1])

    @router.callback_query(F.data.startswith("admin:user:"))
    async def admin_user(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        telegram_id = int(event.data.rsplit(":", 1)[1])  # type: ignore[union-attr]
        card = await user_card(telegram_id)
        if card is None: await event.answer("Не найден", show_alert=True); return
        await event.message.edit_text(card[0], reply_markup=card[1])  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data.startswith("admin:restrict:"))
    async def admin_restrict(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        _, _, action, telegram_raw = event.data.split(":")  # type: ignore[union-attr]
        telegram_id = int(telegram_raw)
        async with db.sessions() as session:
            user = await session.scalar(select(User).where(User.telegram_id == telegram_id).with_for_update())
            if user is None: await event.answer("Не найден", show_alert=True); return
            reason = f"admin action by {event.from_user.id}"
            if action == "ban": user.status = UserStatus.BANNED
            elif action == "temp": user.status = UserStatus.TEMP_BANNED; user.ban_until = datetime.now(UTC) + timedelta(hours=24)
            elif action == "readonly": user.read_only = not user.read_only
            elif action == "creation": user.creation_disabled = not user.creation_disabled
            elif action == "files": user.file_uploads_disabled = not user.file_uploads_disabled
            elif action == "rate": user.rate_limited = not user.rate_limited
            elif action == "clear":
                user.status = UserStatus.ACTIVE; user.ban_until = None; user.read_only = False
                user.creation_disabled = user.file_uploads_disabled = user.rate_limited = False
            user.restriction_reason = None if action == "clear" else reason
            await session.commit()
        await write_audit(db, "admin_action", actor_id=event.from_user.id,
                          metadata={"restriction": action, "reason": reason})
        await event.answer("Настройка применена", show_alert=True)

    async def audit_page(event: CallbackQuery, page: int = 0, owner_id: int | None = None) -> None:
        page_size = 10
        async with db.sessions() as session:
            count_query = select(func.count()).select_from(AuditEvent)
            query = select(AuditEvent)
            if owner_id is not None:
                count_query = count_query.where(AuditEvent.owner_id == owner_id)
                query = query.where(AuditEvent.owner_id == owner_id)
            total = await session.scalar(count_query) or 0
            total_pages = max(1, (total + page_size - 1) // page_size)
            page = min(max(page, 0), total_pages - 1)
            query = query.order_by(AuditEvent.created_at.desc()).offset(page * page_size).limit(page_size)
            rows = list((await session.scalars(query)).all())
        title = "📜 <b>Аудит пользователя</b>" if owner_id is not None else "📜 <b>Журнал аудита</b>"
        await event.message.edit_text(  # type: ignore[union-attr]
            f"{title}\n\nСобытий: {total} · Нажмите на запись для подробностей.",
            reply_markup=audit_list_markup(rows, page, total_pages, owner_id),
        )
        await event.answer()

    @router.callback_query(F.data == "admin:audit")
    async def admin_audit(event: CallbackQuery) -> None:
        if allowed(event.from_user.id): await audit_page(event)

    @router.callback_query(F.data.startswith("admin:useraudit:"))
    async def admin_user_audit(event: CallbackQuery) -> None:
        if allowed(event.from_user.id):
            await audit_page(event, owner_id=int(event.data.rsplit(":", 1)[1]))  # type: ignore[union-attr]

    @router.callback_query(F.data.regexp(r"^admin:audit:page:\d+:\d+$"))
    async def admin_audit_page(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        _, _, _, page_raw, owner_raw = event.data.split(":")  # type: ignore[union-attr]
        owner_id = int(owner_raw) or None
        await audit_page(event, int(page_raw), owner_id)

    @router.callback_query(F.data == "admin:audit:page-number")
    async def admin_audit_page_number(event: CallbackQuery) -> None:
        await event.answer("Текущая страница")

    @router.callback_query(F.data.regexp(r"^admin:audit:event:\d+:\d+:\d+$"))
    async def admin_audit_event(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        _, _, _, event_raw, page_raw, owner_raw = event.data.split(":")  # type: ignore[union-attr]
        async with db.sessions() as session:
            row = await session.get(AuditEvent, int(event_raw))
        if row is None:
            await event.answer("Событие не найдено", show_alert=True)
            return
        created_msk = row.created_at.astimezone(ZoneInfo("Europe/Moscow"))
        details = [
            f"📜 <b>{audit_event_label(row.event_type)}</b>",
            "",
            f"Время: <b>{created_msk:%d.%m.%Y %H:%M:%S} МСК</b>",
            f"Секрет: <code>{row.secret_public_code or '—'}</code>",
            f"Владелец: <code>{row.owner_id or '—'}</code>",
            f"Получатель: <code>{row.viewer_id or '—'}</code>",
            f"Инициатор: <code>{row.actor_id or '—'}</code>",
        ]
        if row.metadata_json:
            safe_metadata = html.escape(", ".join(f"{key}: {value}" for key, value in row.metadata_json.items()))
            details.extend(("", f"Детали: <code>{safe_metadata}</code>"))
        b = InlineKeyboardBuilder()
        b.button(text="⬅️ К журналу", callback_data=f"admin:audit:page:{page_raw}:{owner_raw}")
        await event.message.edit_text("\n".join(details), reply_markup=b.as_markup())  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "admin:secrets")
    async def admin_secrets(event: CallbackQuery) -> None:
        if not allowed(event.from_user.id): return
        async with db.sessions() as session:
            rows = (await session.execute(select(Secret.status, func.count()).group_by(Secret.status))).all()
        await event.message.edit_text("🔐 <b>Секреты — только metadata</b>\n\n" + "\n".join(f"{status.value}: {count}" for status, count in rows), reply_markup=back_admin())  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "admin:system")
    async def admin_system(event: CallbackQuery, bot: Bot) -> None:
        if not allowed(event.from_user.id): return
        await event.message.edit_text(await dashboard_text(bot), reply_markup=back_admin())  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data.in_({"admin:emoji", "admin:emoji:0"}))
    async def admin_emoji_home(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            await event.answer("Недоступно", show_alert=True)
            return
        await state.clear()
        await emoji_page(event, 0)

    @router.callback_query(F.data.startswith("admin:emoji:slot:"))
    async def admin_emoji_choose(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            return
        _, _, _, slot, page_raw = event.data.split(":")  # type: ignore[union-attr]
        if slot not in CATALOG:
            await event.answer("Элемент не найден", show_alert=True)
            return
        fallback, label = CATALOG[slot]
        await state.set_state(AdminEmoji.waiting_emoji)
        await state.update_data(emoji_slot=slot, emoji_page=int(page_raw))
        b = InlineKeyboardBuilder()
        if custom_id(slot):
            b.button(text="🗑 Сбросить premium-эмодзи", callback_data=f"admin:emoji:reset:{slot}:{page_raw}")
        b.button(text="⬅️ Назад", callback_data=f"admin:emoji:{page_raw}")
        b.adjust(1)
        await event.message.edit_text(  # type: ignore[union-attr]
            f"🎨 <b>Назначение эмодзи</b>\n\n{fallback} — {label}\n\n"
            "Пришлите <b>один premium-эмодзи</b> отдельным сообщением.",
            reply_markup=b.as_markup(),
        )
        await event.answer()

    @router.callback_query(F.data.in_({"admin:emoji:wizard:missing", "admin:emoji:wizard:all"}))
    async def admin_emoji_wizard_start(event: CallbackQuery, state: FSMContext, bot: Bot) -> None:
        if not allowed(event.from_user.id):
            return
        mode = event.data.rsplit(":", 1)[1]  # type: ignore[union-attr]
        sequence = [slot for slot in CATALOG if mode == "all" or not custom_id(slot)]
        if not sequence:
            await event.answer("Все позиции уже заполнены. Можно пройти их заново.", show_alert=True)
            return
        await state.set_state(AdminEmoji.waiting_emoji)
        await state.update_data(emoji_sequence=sequence, emoji_position=0,
                                emoji_slot=sequence[0], emoji_prompt_chat_id=event.message.chat.id,
                                emoji_prompt_message_id=event.message.message_id)  # type: ignore[union-attr]
        await show_wizard(bot, event.message.chat.id, event.message.message_id, sequence, 0)  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "admin:emoji:wizard:skip")
    async def admin_emoji_wizard_skip(event: CallbackQuery, state: FSMContext, bot: Bot) -> None:
        if not allowed(event.from_user.id):
            return
        data = await state.get_data()
        sequence = list(data.get("emoji_sequence") or [])
        position = int(data.get("emoji_position", 0)) + 1
        if not sequence:
            await event.answer("Мастер уже завершён", show_alert=True)
            return
        if position >= len(sequence):
            await state.clear()
        else:
            await state.update_data(emoji_position=position, emoji_slot=sequence[position])
        await show_wizard(bot, event.message.chat.id, event.message.message_id, sequence, position)  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "admin:emoji:wizard:stop")
    async def admin_emoji_wizard_stop(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            return
        await state.clear()
        await emoji_page(event, 0)

    @router.message(AdminEmoji.waiting_emoji)
    async def admin_emoji_receive(message: Message, state: FSMContext) -> None:
        if not allowed(message.from_user.id):
            return
        entities = [entity for entity in (message.entities or []) if entity.type == "custom_emoji"]
        if len(entities) != 1 or not entities[0].custom_emoji_id or len((message.text or "").strip()) > 2:
            await message.answer("Нужен ровно один premium-эмодзи. Обычный эмодзи не подойдёт.")
            return
        data = await state.get_data()
        slot = data.get("emoji_slot")
        page = int(data.get("emoji_page", 0))
        if slot not in CATALOG:
            await state.clear()
            await message.answer("Настройка устарела. Откройте редактор заново.", reply_markup=back_admin())
            return
        emoji_id = entities[0].custom_emoji_id
        async with db.sessions() as session:
            setting = await session.get(UiEmojiSetting, slot)
            if setting is None:
                session.add(UiEmojiSetting(slot=slot, custom_emoji_id=emoji_id, updated_by=message.from_user.id))
            else:
                setting.custom_emoji_id = emoji_id
                setting.updated_by = message.from_user.id
            await session.commit()
        set_custom_id(slot, emoji_id)
        try:
            await message.delete()
        except TelegramBadRequest:
            pass
        sequence = list(data.get("emoji_sequence") or [])
        if sequence:
            position = int(data.get("emoji_position", 0)) + 1
            chat_id = int(data["emoji_prompt_chat_id"])
            message_id = int(data["emoji_prompt_message_id"])
            if position >= len(sequence):
                await state.clear()
            else:
                await state.update_data(emoji_position=position, emoji_slot=sequence[position])
            await show_wizard(message.bot, chat_id, message_id, sequence, position)
            return
        await state.clear()
        fallback, label = CATALOG[slot]
        b = InlineKeyboardBuilder()
        b.button(text="🎨 Продолжить настройку", callback_data=f"admin:emoji:{page}", style="primary")
        b.button(text="⬅️ Admin", callback_data="admin:home")
        b.adjust(1)
        await message.answer(f"✅ Назначено: {fallback} — {label}\n\nИзменение уже применяется.", reply_markup=b.as_markup())

    @router.callback_query(F.data.startswith("admin:emoji:reset:"))
    async def admin_emoji_reset(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            return
        _, _, _, slot, page_raw = event.data.split(":")  # type: ignore[union-attr]
        async with db.sessions() as session:
            setting = await session.get(UiEmojiSetting, slot)
            if setting is not None:
                await session.delete(setting)
                await session.commit()
        set_custom_id(slot, None)
        await state.clear()
        await emoji_page(event, int(page_raw))

    @router.callback_query(F.data.regexp(r"^admin:emoji:[1-9]\d*$"))
    async def admin_emoji_list(event: CallbackQuery, state: FSMContext) -> None:
        if not allowed(event.from_user.id):
            return
        await state.clear()
        await emoji_page(event, int(event.data.rsplit(":", 1)[1]))  # type: ignore[union-attr]

    return router
