import asyncio
import base64
import html
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aiogram import Bot, F, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import CommandObject, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, FSInputFile, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from redis.asyncio import Redis

from app.audit import write_audit
from app.config import Settings
from app.crypto import EncryptedSecret, SecretCipher, token_digest
from app.db import Database
from app.file_store import EncryptedFileStore
from app.generator import generated_value, password
from app.keyboards import (
    back_menu,
    content_type_menu,
    created_menu,
    delete_message_menu,
    destroy_timer_menu,
    file_reveal_menu,
    generated_menu,
    generator_menu,
    identity_confirmation,
    main_menu,
    more_menu,
    my_secrets_menu,
    notifications_menu,
    password_length_menu,
    pin_choice_menu,
    protection_advanced_menu,
    protection_menu,
    recipient_input_menu,
    recipient_menu,
    request_created_menu,
    reveal_menu,
    ttl_menu,
    views_menu,
)
from app.models import (
    ContentType,
    DestroyReason,
    RecipientMode,
    RequestStatus,
    SecretRequest,
)
from app.pin import build_hasher, generate_pin, valid_pin, verify_pin
from app.rate_limit import RateLimiter
from app.services import (
    cancel_request,
    consume_secret,
    count_active_owned,
    create_request,
    create_secret,
    destroy_all_owned,
    destroy_owned,
    fulfill_request,
    is_available,
    list_owned,
    recover_token,
    request_by_token,
    request_prompt,
    secret_by_id,
    secret_by_token,
)
from app.states import CreateSecret, Generator, OpenSecret, SecretRequestFlow
from app.text import dt, remaining

WELCOME = """🔐 <b>T-Secret</b>

Передал. Прочитал. Исчезло.

Безопасно передавайте текст, пароли и файлы.
Секрет исчезнет после просмотра или по таймеру."""


async def safe_edit(event: CallbackQuery, text: str, reply_markup=None, *, answer: bool = True) -> None:
    if isinstance(event.message, Message):
        try:
            await event.message.edit_text(text, reply_markup=reply_markup)
        except TelegramBadRequest as exc:
            if "message is not modified" not in str(exc).lower():
                await event.message.answer(text, reply_markup=reply_markup)
    if answer:
        await event.answer()


def pack(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def unpack(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


async def delete_later(bot: Bot, chat_id: int, message_id: int, delay: int) -> None:
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, message_id)
    except TelegramBadRequest:
        pass


def build_router(settings: Settings, db: Database, cipher: SecretCipher, redis: Redis,
                 file_store: EncryptedFileStore) -> Router:
    router = Router()
    limiter = RateLimiter(redis)
    hasher = build_hasher(settings)

    @router.message(CommandStart())
    async def start(message: Message, command: CommandObject, state: FSMContext) -> None:
        old = await state.get_data()
        file_store.delete(old.get("encrypted_file_path"))
        await state.clear()
        payload = command.args or ""
        if message.chat.type != "private" and payload.startswith(("s_", "rq_")):
            private_url = f"https://t.me/{settings.bot_username}?start={payload}"
            markup = InlineKeyboardBuilder()
            markup.button(text="💬 Открыть в личке", url=private_url)
            await message.answer("🔐 Для безопасности секрет можно открыть только в личном чате с T-Secret.", reply_markup=markup.as_markup())
            return
        if payload.startswith("rq_"):
            token = payload[3:]
            async with db.sessions() as session:
                request = await request_by_token(session, token)
                if (request is None or request.status != RequestStatus.ACTIVE
                        or request.expires_at <= datetime.now(UTC) or request.uses >= request.max_uses):
                    await message.answer("Запрос недействителен, истёк или уже использован.", reply_markup=back_menu())
                    return
                prompt = html.escape(request_prompt(request, cipher))
            markup = InlineKeyboardBuilder()
            markup.button(text="🔐 Передать секрет", callback_data=f"request:submit:{request.id}")
            markup.button(text="❌ Отмена", callback_data="menu")
            markup.adjust(1)
            await message.answer("📥 <b>Запрос защищённой информации</b>\n\nПользователь просит передать:\n\n"
                                 f"«{prompt}»\n\nПереданный секрет будет доступен ему через T-Secret.", reply_markup=markup.as_markup())
            return
        if payload.startswith("s_"):
            token = payload[2:]
            user_ok, user_ttl = await limiter.hit(f"open_user:{message.from_user.id}", settings.open_rate_limit, settings.open_rate_window)
            token_key = token_digest(token).hex()
            token_ok, token_ttl = await limiter.hit(f"open_token:{token_key}", settings.token_rate_limit, settings.token_rate_window)
            if not user_ok or not token_ok:
                await message.answer(f"🚫 Слишком много запросов. Попробуйте через {max(user_ttl, token_ttl)} сек.")
                return
            async with db.sessions() as session:
                secret = await secret_by_token(session, token)
                if secret is None or not is_available(secret):
                    await message.answer("Ссылка недействительна, истекла или секрет уже уничтожен.", reply_markup=back_menu())
                    return
                if secret.recipient_mode == RecipientMode.SPECIFIC and secret.recipient_telegram_id != message.from_user.id:
                    if secret.notify_wrong_user:
                        try:
                            await message.bot.send_message(secret.creator_id, f"⚠️ <b>Попытка доступа</b>\n\nК секрету <code>{secret.public_code}</code> попытался получить доступ пользователь, которому он не предназначен.")
                        except TelegramBadRequest:
                            pass
                    await write_audit(db, "secret_access_attempt", secret_code=secret.public_code,
                                      owner_id=secret.creator_id, viewer_id=message.from_user.id,
                                      actor_id=message.from_user.id, metadata={"reason": "wrong_user"})
                    await message.answer("⛔ Этот секрет предназначен другому пользователю.")
                    return
                if secret.recipient_mode == RecipientMode.FIRST and secret.claimed_by_telegram_id not in (None, message.from_user.id):
                    await message.answer("⛔ Этот секрет уже закреплён за другим получателем.")
                    return
                if secret.available_at is not None and secret.available_at > datetime.now(UTC):
                    await message.answer("⏳ Этот секрет пока недоступен.\n\n"
                                         f"Будет доступен: {dt(secret.available_at)}", reply_markup=back_menu())
                    return
                if secret.content_type == ContentType.FILE and all((secret.encrypted_filename, secret.filename_nonce, secret.filename_auth_tag)):
                    filename = html.escape(cipher.decrypt(secret.encrypted_filename, secret.filename_nonce, secret.filename_auth_tag).decode())
                    size_kb = (secret.file_size or 0) / 1024
                    text = ("📎 <b>Защищённый файл</b>\n\n"
                            f"Имя: {filename}\nРазмер: {size_kb:.1f} KB\n\nПосле последней загрузки файл будет уничтожен.")
                    markup = file_reveal_menu(str(secret.id))
                else:
                    text = ("🔐 <b>Вам передан секрет</b>\n\n"
                            "⚠️ После открытия количество доступных просмотров уменьшится.\n\n"
                            f"Осталось просмотров: {secret.views_allowed - secret.views_used}\n"
                            f"Истекает через: {remaining(secret.expires_at)}")
                    markup = reveal_menu(str(secret.id))
                await message.answer(text, reply_markup=markup)
            return
        await message.answer(WELCOME, reply_markup=main_menu(message.from_user.id in settings.admin_id_set))

    @router.callback_query(F.data == "help")
    async def help_callback(event: CallbackQuery) -> None:
        await safe_edit(event, "❓ <b>Как пользоваться</b>\n\n1. Создайте секрет.\n2. Выберите срок и число просмотров.\n3. Отправьте готовую ссылку получателю.\n\nПосле уничтожения содержимое восстановить нельзя.", more_menu())

    @router.callback_query(F.data == "my:secrets")
    async def my_secrets(event: CallbackQuery) -> None:
        async with db.sessions() as session:
            active_count = await count_active_owned(session, event.from_user.id)
        await safe_edit(event, "📂 <b>Мои секреты</b>\n\n"
                               f"Активно сейчас: <b>{active_count}</b>\n\n"
                               "Откройте активные ссылки или историю.", my_secrets_menu())

    @router.callback_query(F.data == "more")
    async def more(event: CallbackQuery) -> None:
        await safe_edit(event, "••• <b>Ещё</b>\n\nСправка и управление безопасностью.", more_menu())

    @router.callback_query(F.data == "menu")
    async def menu_callback(event: CallbackQuery, state: FSMContext) -> None:
        old = await state.get_data()
        file_store.delete(old.get("encrypted_file_path"))
        await state.clear()
        await safe_edit(event, WELCOME, main_menu(event.from_user.id in settings.admin_id_set))

    @router.callback_query(F.data == "cancel")
    async def cancel_callback(event: CallbackQuery, state: FSMContext) -> None:
        old = await state.get_data()
        file_store.delete(old.get("encrypted_file_path"))
        await state.clear()
        await safe_edit(event, WELCOME, main_menu(event.from_user.id in settings.admin_id_set))

    @router.callback_query(F.data.in_({"create", "nav:create"}))
    async def begin_create(event: CallbackQuery, state: FSMContext) -> None:
        old = await state.get_data()
        file_store.delete(old.get("encrypted_file_path"))
        await state.clear()
        await state.set_state(CreateSecret.choosing_type)
        await safe_edit(event, "🔐 <b>Новый секрет · 1/4</b>\n\nЧто хотите передать?", content_type_menu())

    @router.callback_query(F.data == "type:text")
    async def choose_text(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(content_type="text")
        await state.set_state(CreateSecret.waiting_text)
        await safe_edit(event, "📝 Отправьте текст. После получения бот попытается удалить сообщение.", back_menu("nav:create"))

    @router.callback_query(F.data == "type:password")
    async def choose_password(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(content_type="password")
        await state.set_state(CreateSecret.waiting_password)
        await safe_edit(event, "🔑 Отправьте пароль. Сообщение будет удалено сразу после шифрования.", back_menu("nav:create"))

    @router.callback_query(F.data == "type:file")
    async def choose_file(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(content_type="file")
        await state.set_state(CreateSecret.waiting_file)
        await safe_edit(event, f"📎 Отправьте документ или фотографию размером до {settings.max_secret_file_size_mb} МБ.", back_menu("nav:create"))

    @router.message(CreateSecret.waiting_text)
    @router.message(CreateSecret.waiting_password)
    async def receive_plaintext(message: Message, state: FSMContext) -> None:
        if not message.text:
            await message.answer("Пожалуйста, отправьте именно текстовое сообщение.")
            return
        if len(message.text) > 3500:
            await message.answer("Секрет слишком длинный. Максимум — 3500 символов.")
            return
        plaintext = bytearray(message.text.encode())
        try:
            try:
                await message.delete()
            except TelegramBadRequest:
                pass
            encrypted = cipher.encrypt(bytes(plaintext))
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0
        data = await state.get_data()
        await state.update_data(ciphertext=pack(encrypted.ciphertext), nonce=pack(encrypted.nonce),
                                auth_tag=pack(encrypted.auth_tag), content_type=data.get("content_type", "text"),
                                ttl=86400, views=1)
        await state.set_state(CreateSecret.choosing_ttl)
        await message.answer("⏳ <b>Срок действия · 2/4</b>\n\nКак долго будет работать ссылка?", reply_markup=ttl_menu())

    @router.message(CreateSecret.waiting_file)
    async def receive_file(message: Message, state: FSMContext) -> None:
        document = message.document
        photo = message.photo[-1] if message.photo else None
        source = document or photo
        if source is None:
            await message.answer("Нужен документ или фотография.")
            return
        file_size = source.file_size or 0
        limit = settings.max_secret_file_size_mb * 1024 * 1024
        if file_size > limit:
            await message.answer(f"Файл превышает лимит {settings.max_secret_file_size_mb} МБ.")
            return
        original_name = document.file_name if document and document.file_name else "photo.jpg"
        mime_type = document.mime_type if document else "image/jpeg"
        fd, temp_name = tempfile.mkstemp(prefix="tsecret-upload-", dir=tempfile.gettempdir())
        os.close(fd)
        temp_path = Path(temp_name)
        try:
            telegram_file = await message.bot.get_file(source.file_id)
            await message.bot.download_file(telegram_file.file_path, destination=temp_path)
            actual_size = temp_path.stat().st_size
            if actual_size > limit:
                raise ValueError("file too large")
            stored_name, encrypted, _ = await asyncio.to_thread(file_store.save_plaintext, temp_path)
            encrypted_name = cipher.encrypt(original_name.encode())
        except ValueError:
            temp_path.unlink(missing_ok=True)
            await message.answer(f"Файл превышает лимит {settings.max_secret_file_size_mb} МБ.")
            return
        except Exception:  # noqa: BLE001 - every failed upload path must remove plaintext
            temp_path.unlink(missing_ok=True)
            await message.answer("Не удалось безопасно обработать файл. Попробуйте ещё раз.")
            return
        try:
            await message.delete()
        except TelegramBadRequest:
            pass
        await state.update_data(content_type="file", ciphertext="", nonce=pack(encrypted.nonce), auth_tag=pack(encrypted.auth_tag),
                                encrypted_file_path=stored_name, file_nonce=pack(encrypted.nonce),
                                file_auth_tag=pack(encrypted.auth_tag), encrypted_filename=pack(encrypted_name.ciphertext),
                                filename_nonce=pack(encrypted_name.nonce), filename_auth_tag=pack(encrypted_name.auth_tag),
                                file_size=actual_size, mime_type=mime_type, ttl=86400, views=1)
        await write_audit(db, "file_uploaded", actor_id=message.from_user.id,
                          metadata={"file_size": actual_size, "content_type": "file"})
        await state.set_state(CreateSecret.choosing_ttl)
        await message.answer("✅ Файл зашифрован.\n\n⏳ <b>Срок действия · 2/4</b>\nКак долго будет работать ссылка?", reply_markup=ttl_menu())

    @router.callback_query(F.data == "type:generator")
    async def generator_start(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(Generator.choosing_kind)
        await safe_edit(event, "🎲 <b>Генератор</b>\n\nВыберите тип:", generator_menu())

    async def save_generated(state: FSMContext, value: str, label: str, entropy: int, kind: str) -> None:
        raw = bytearray(value.encode())
        try:
            encrypted = cipher.encrypt(bytes(raw))
        finally:
            for index in range(len(raw)):
                raw[index] = 0
        await state.update_data(content_type="generated", ciphertext=pack(encrypted.ciphertext),
                                nonce=pack(encrypted.nonce), auth_tag=pack(encrypted.auth_tag),
                                generated_kind=kind, generated_label=label,
                                generated_entropy=entropy, generated_length=len(value))
        await state.set_state(Generator.preview)

    async def show_generated(event: CallbackQuery, state: FSMContext, value: str,
                             label: str, entropy: int, kind: str) -> None:
        await save_generated(state, value, label, entropy, kind)
        icon = "🔑" if kind == "password" else "🔐"
        await safe_edit(event, f"{icon} <b>{label} создан</b>\n\n{'•' * min(len(value), 64)}\n\n"
                               f"Длина: {len(value)}\nЭнтропия: ~{entropy} bit", generated_menu())

    @router.callback_query(Generator.choosing_kind, F.data == "gen:password")
    async def generator_password(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(gen_upper=True, gen_lower=True, gen_digits=True, gen_symbols=True)
        await state.set_state(Generator.choosing_password_length)
        await safe_edit(event, "🔑 <b>Пароль</b>\n\nВыберите длину и наборы символов:", password_length_menu(await state.get_data()))

    @router.callback_query(Generator.choosing_password_length, F.data.startswith("genopt:"))
    async def generator_toggle_option(event: CallbackQuery, state: FSMContext) -> None:
        field = event.data.split(":", 1)[1]  # type: ignore[union-attr]
        allowed = {"gen_upper", "gen_lower", "gen_digits", "gen_symbols"}
        data = await state.get_data()
        if field not in allowed:
            await event.answer()
            return
        if data.get(field, True) and sum(bool(data.get(item, True)) for item in allowed) == 1:
            await event.answer("Нужен хотя бы один набор символов.", show_alert=True)
            return
        await state.update_data(**{field: not data.get(field, True)})
        await safe_edit(event, "🔑 <b>Пароль</b>\n\nВыберите длину и наборы символов:", password_length_menu(await state.get_data()))

    @router.callback_query(Generator.choosing_password_length, F.data.startswith("gen_password:"))
    async def generator_password_value(event: CallbackQuery, state: FSMContext) -> None:
        length = int(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        data = await state.get_data()
        value, entropy = password(length, data.get("gen_upper", True), data.get("gen_lower", True),
                                  data.get("gen_digits", True), data.get("gen_symbols", True))
        await show_generated(event, state, value, "Пароль", entropy, "password")

    @router.callback_query(Generator.choosing_kind, F.data.in_({"gen:pin", "gen:token", "gen:uuid", "gen:key"}))
    async def generator_other(event: CallbackQuery, state: FSMContext) -> None:
        kind = event.data.split(":", 1)[1]  # type: ignore[union-attr]
        value, label, entropy = generated_value(kind)
        await show_generated(event, state, value, label, entropy, kind)

    @router.callback_query(Generator.preview, F.data == "generated:new")
    async def generator_repeat(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        kind = data.get("generated_kind")
        if kind == "password":
            length = int(data.get("generated_length", 32))
            value, entropy = password(length, data.get("gen_upper", True), data.get("gen_lower", True),
                                      data.get("gen_digits", True), data.get("gen_symbols", True))
            await show_generated(event, state, value, "Пароль", entropy, "password")
            return
        if kind in {"pin", "token", "uuid", "key"}:
            value, label, entropy = generated_value(kind)
            await show_generated(event, state, value, label, entropy, kind)
            return
        await event.answer("Не удалось определить тип. Выберите генератор ещё раз.", show_alert=True)

    @router.callback_query(Generator.preview, F.data == "generated:show")
    async def generator_show(event: CallbackQuery, state: FSMContext, bot: Bot) -> None:
        data = await state.get_data()
        encrypted = EncryptedSecret(unpack(data["ciphertext"]), unpack(data["nonce"]), unpack(data["auth_tag"]))
        raw = bytearray(cipher.decrypt(encrypted.ciphertext, encrypted.nonce, encrypted.auth_tag))
        try:
            value = html.escape(raw.decode())
            sent = await bot.send_message(event.from_user.id, f"🔐 <code>{value}</code>\n\nСообщение будет удалено через {settings.generator_message_ttl} секунд.", reply_markup=delete_message_menu())
        finally:
            for index in range(len(raw)):
                raw[index] = 0
        asyncio.create_task(delete_later(bot, sent.chat.id, sent.message_id, settings.generator_message_ttl))
        await event.answer()

    @router.callback_query(Generator.preview, F.data == "generated:transfer")
    async def generator_transfer(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(ttl=86400, views=1)
        await state.set_state(CreateSecret.choosing_ttl)
        await safe_edit(event, "⏳ <b>Срок действия · 2/4</b>\n\nКак долго будет работать ссылка?", ttl_menu())

    @router.callback_query(CreateSecret.choosing_ttl, F.data.regexp(r"^ttl:\d+$"))
    async def choose_ttl(event: CallbackQuery, state: FSMContext) -> None:
        ttl = int(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        await state.update_data(ttl=ttl)
        await safe_edit(event, "⏳ <b>Срок действия · 2/4</b>\n\nКак долго будет работать ссылка?", ttl_menu(ttl))

    @router.callback_query(CreateSecret.choosing_ttl, F.data == "ttl:continue")
    async def continue_after_ttl(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        if "ttl" not in data:
            await state.update_data(ttl=86400)
            data["ttl"] = 86400
        if "views" not in data:
            await state.update_data(views=1)
            data["views"] = 1
        await state.set_state(CreateSecret.choosing_views)
        await safe_edit(event, "👁 <b>Просмотры · 3/4</b>\n\nСколько раз можно открыть секрет?",
                        views_menu(data.get("views")))

    @router.callback_query(F.data == "nav:ttl")
    async def back_to_ttl(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.choosing_ttl)
        data = await state.get_data()
        await safe_edit(event, "⏳ <b>Срок действия · 2/4</b>\n\nКак долго будет работать ссылка?",
                        ttl_menu(data.get("ttl")))

    @router.callback_query(F.data == "nav:views")
    async def back_to_views(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.choosing_views)
        data = await state.get_data()
        await safe_edit(event, "👁 <b>Просмотры · 3/4</b>\n\nСколько раз можно открыть секрет?",
                        views_menu(data.get("views")))

    @router.callback_query(CreateSecret.choosing_views, F.data.regexp(r"^views:\d+$"))
    async def choose_views(event: CallbackQuery, state: FSMContext) -> None:
        views = int(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        await state.update_data(views=views)
        await safe_edit(event, "👁 <b>Просмотры · 3/4</b>\n\nСколько раз можно открыть секрет?", views_menu(views))

    @router.callback_query(CreateSecret.choosing_views, F.data == "views:continue")
    async def continue_after_views(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        if "views" not in data:
            await state.update_data(views=1)
            data["views"] = 1
        if "recipient_mode" not in data:
            await state.update_data(recipient_mode="any", recipient_telegram_id=None,
                                    require_identity_confirmation=False, notify_open=True,
                                    notify_wrong_pin=False, notify_wrong_user=True,
                                    notify_expiry=True, notify_destroy=True,
                                    available_at=None, destroy_after_open_seconds=3600)
        await state.set_state(CreateSecret.protection)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    def protection_text(data: dict) -> str:
        recipient = {
            "any": "👥 Любой",
            "first": "🥇 Первый открывший",
            "specific": "🎯 Конкретный пользователь",
        }.get(data.get("recipient_mode", "any"), "👥 Любой")
        return (
            "🛡 <b>Защита · 4/4</b>\n\n"
            f"Получатель: {recipient}\n"
            f"PIN-защита: {'включена' if data.get('pin_hash') else 'выключена'}\n\n"
            "Секрет уже готов. При необходимости измените защиту."
        )

    @router.callback_query(CreateSecret.protection, F.data == "protect:advanced")
    async def protection_advanced(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        await safe_edit(
            event,
            "⚙️ <b>Дополнительная защита</b>\n\nНастройки доступа, удаления и уведомлений.",
            protection_advanced_menu(data),
        )

    @router.callback_query(F.data == "protect:back")
    async def protection_back(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.protection)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    @router.callback_query(CreateSecret.protection, F.data.in_({"protect:preset:normal", "protect:preset:strict"}))
    async def protection_preset(event: CallbackQuery, state: FSMContext) -> None:
        strict = event.data == "protect:preset:strict"
        values = {
            "pin_hash": None,
            "recipient_mode": "first" if strict else "any",
            "recipient_telegram_id": None,
            "require_identity_confirmation": strict,
            "notify_open": True,
            "notify_wrong_pin": strict,
            "notify_wrong_user": True,
            "notify_expiry": True,
            "notify_destroy": True,
            "available_at": None,
            "destroy_after_open_seconds": 300 if strict else 3600,
        }
        await state.update_data(**values)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    @router.callback_query(CreateSecret.protection, F.data == "protect:pin")
    async def protection_pin(event: CallbackQuery) -> None:
        await safe_edit(event, "🔢 <b>Защита PIN-кодом</b>\n\nВыберите вариант:", pin_choice_menu())

    @router.callback_query(F.data == "pin:generate")
    async def pin_generate(event: CallbackQuery, state: FSMContext) -> None:
        pin = generate_pin()
        await state.update_data(pin_hash=await asyncio.to_thread(hasher.hash, pin))
        await state.set_state(CreateSecret.protection)
        await safe_edit(event, f"🎲 PIN создан: <code>{pin}</code>\n\nСохраните и передайте его получателю отдельно. После ухода с экрана PIN восстановить нельзя.", protection_menu(await state.get_data()))

    @router.callback_query(F.data == "pin:custom")
    async def pin_custom(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.entering_custom_pin)
        await safe_edit(event, "⌨️ Отправьте PIN из 6 цифр. Сообщение будет сразу удалено.", back_menu("protect:back"))

    @router.message(CreateSecret.entering_custom_pin)
    async def pin_custom_value(message: Message, state: FSMContext) -> None:
        value = message.text or ""
        try:
            await message.delete()
        except TelegramBadRequest:
            pass
        if not valid_pin(value):
            await message.answer("PIN должен состоять ровно из 6 цифр. Попробуйте ещё раз.")
            return
        await state.update_data(pin_hash=await asyncio.to_thread(hasher.hash, value))
        await state.set_state(CreateSecret.protection)
        await message.answer("✅ PIN установлен.", reply_markup=protection_menu(await state.get_data()))

    @router.callback_query(F.data == "pin:remove")
    async def pin_remove(event: CallbackQuery, state: FSMContext) -> None:
        await state.update_data(pin_hash=None)
        await state.set_state(CreateSecret.protection)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    @router.callback_query(F.data == "protect:recipient")
    async def protection_recipient(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        await safe_edit(event, "👤 <b>Получатель</b>\n\nВыберите режим доступа:", recipient_menu(data.get("recipient_mode", "any")))

    @router.callback_query(F.data.in_({"recipient:any", "recipient:first"}))
    async def recipient_simple(event: CallbackQuery, state: FSMContext) -> None:
        mode = event.data.split(":", 1)[1]  # type: ignore[union-attr]
        await state.update_data(recipient_mode=mode, recipient_telegram_id=None)
        await state.set_state(CreateSecret.protection)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    @router.callback_query(F.data == "recipient:specific")
    async def recipient_specific(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.choosing_recipient)
        await safe_edit(event, "👤 Выберите способ указать конкретного получателя:", recipient_input_menu())

    @router.callback_query(F.data == "recipient:enter_id")
    async def recipient_enter_id(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.entering_recipient_id)
        await safe_edit(event, "🆔 Отправьте числовой Telegram ID получателя.", back_menu("nav:recipient-input"))

    @router.message(CreateSecret.entering_recipient_id)
    async def recipient_id_value(message: Message, state: FSMContext) -> None:
        value = (message.text or "").strip()
        if not value.isdigit() or int(value) <= 0:
            await message.answer("Нужен положительный числовой Telegram ID.")
            return
        await state.update_data(recipient_mode="specific", recipient_telegram_id=int(value))
        await state.set_state(CreateSecret.protection)
        await message.answer("✅ Получатель установлен. Его данные не будут показаны при отказе.", reply_markup=protection_menu(await state.get_data()))

    @router.callback_query(F.data == "recipient:forward")
    async def recipient_forward(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.forwarding_recipient)
        await safe_edit(event, "📨 Перешлите сюда сообщение нужного пользователя. Если Telegram скрывает автора пересылки, потребуется ввести ID вручную.", back_menu("nav:recipient-input"))

    @router.callback_query(F.data == "nav:recipient-input")
    async def back_to_recipient_input(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.choosing_recipient)
        await safe_edit(event, "👤 Выберите способ указать конкретного получателя:", recipient_input_menu())

    @router.message(CreateSecret.forwarding_recipient)
    async def recipient_forward_value(message: Message, state: FSMContext) -> None:
        origin = getattr(message, "forward_origin", None)
        sender = getattr(origin, "sender_user", None)
        if sender is None:
            await message.answer("Telegram не передал ID автора. Используйте ручной ввод Telegram ID.", reply_markup=recipient_input_menu())
            return
        await state.update_data(recipient_mode="specific", recipient_telegram_id=sender.id)
        await state.set_state(CreateSecret.protection)
        await message.answer("✅ Получатель определён по пересланному сообщению.", reply_markup=protection_menu(await state.get_data()))

    @router.callback_query(CreateSecret.protection, F.data == "protect:confirm")
    async def toggle_confirmation(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        enabled = not data.get("require_identity_confirmation", False)
        await state.update_data(require_identity_confirmation=enabled)
        data = await state.get_data()
        await event.answer(
            "Включено: получатель подтвердит свой Telegram ID перед открытием. Сейчас ничего вводить не нужно."
            if enabled else "Проверка Telegram ID выключена.",
            show_alert=True,
        )
        await safe_edit(
            event,
            "⚙️ <b>Дополнительная защита</b>\n\nНастройки доступа, удаления и уведомлений.",
            protection_advanced_menu(data),
            answer=False,
        )

    @router.callback_query(CreateSecret.protection, F.data == "protect:destroy_timer")
    async def protection_destroy_timer(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.destroy_timer)
        data = await state.get_data()
        await safe_edit(event, "💥 <b>Самоуничтожение после первого открытия</b>",
                        destroy_timer_menu(data.get("destroy_after_open_seconds", 3600)))

    @router.callback_query(CreateSecret.destroy_timer, F.data.startswith("destroy_timer:"))
    async def destroy_timer_value(event: CallbackQuery, state: FSMContext) -> None:
        seconds = int(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        await state.update_data(destroy_after_open_seconds=seconds)
        await state.set_state(CreateSecret.protection)
        data = await state.get_data()
        await safe_edit(event, protection_text(data), protection_menu(data))

    @router.callback_query(CreateSecret.protection, F.data == "protect:notifications")
    async def protection_notifications(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(CreateSecret.notifications)
        await safe_edit(event, "🔔 <b>Уведомления</b>", notifications_menu(await state.get_data()))

    @router.callback_query(CreateSecret.notifications, F.data.startswith("notify:"))
    async def toggle_notification(event: CallbackQuery, state: FSMContext) -> None:
        field = event.data.split(":", 1)[1]  # type: ignore[union-attr]
        allowed = {"notify_open", "notify_wrong_pin", "notify_wrong_user", "notify_expiry", "notify_destroy"}
        if field not in allowed:
            await event.answer()
            return
        data = await state.get_data()
        await state.update_data(**{field: not data.get(field, False)})
        await safe_edit(event, "🔔 <b>Уведомления</b>", notifications_menu(await state.get_data()))

    @router.callback_query(CreateSecret.protection, F.data == "protect:continue")
    async def finalize_secret(event: CallbackQuery, state: FSMContext) -> None:
        data = await state.get_data()
        if data.get("recipient_mode") == "specific" and not data.get("recipient_telegram_id"):
            await event.answer("Сначала укажите конкретного получателя.", show_alert=True)
            return
        payload = EncryptedSecret(unpack(data.get("ciphertext", "")), unpack(data["nonce"]), unpack(data["auth_tag"]))
        protection = dict(data)
        for field in ("file_nonce", "file_auth_tag", "encrypted_filename", "filename_nonce", "filename_auth_tag"):
            if protection.get(field):
                protection[field] = unpack(protection[field])
        if protection.get("available_at"):
            protection["available_at"] = datetime.fromisoformat(protection["available_at"]).astimezone(UTC)
        async with db.sessions() as session:
            secret, token = await create_secret(session, event.from_user.id, payload, int(data["ttl"]), int(data["views"]), cipher, protection)
        await state.clear()
        text = ("✅ <b>Секрет создан</b>\n\n"
                f"ID: <code>{secret.public_code}</code>\n"
                f"Создан: {dt(secret.created_at)}\n"
                f"Истекает: {remaining(secret.expires_at)}\n"
                f"Просмотров: 0 / {secret.views_allowed}\n\nПосле последнего просмотра секрет будет уничтожен.")
        await safe_edit(event, text, created_menu(token, settings.bot_username, str(secret.id)))

    async def send_wrong_user_notice(bot: Bot, secret_id: UUID, viewer_id: int) -> None:
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
        if secret is not None and secret.notify_wrong_user:
            try:
                await bot.send_message(secret.creator_id, f"⚠️ <b>Попытка доступа</b>\n\nК секрету <code>{secret.public_code}</code> попытался получить доступ пользователь, которому он не предназначен.")
            except TelegramBadRequest:
                pass
        if secret is not None:
            await write_audit(db, "secret_access_attempt", secret_code=secret.public_code,
                              owner_id=secret.creator_id, viewer_id=viewer_id, actor_id=viewer_id,
                              metadata={"reason": "wrong_user"})

    async def deliver_secret(bot: Bot, viewer_id: int, secret_id: UUID) -> str | None:
        async with db.sessions() as session:
            result, denial = await consume_secret(session, secret_id, viewer_id)
        if result is None:
            if denial == "wrong_user":
                await send_wrong_user_notice(bot, secret_id, viewer_id)
            if denial and denial.startswith("expired_file:"):
                file_store.delete(denial.split(":", 1)[1])
                denial = "unavailable"
            return denial or "unavailable"
        if result.content_type == ContentType.FILE:
            if not all((result.encrypted_file_path, result.file_nonce, result.file_auth_tag,
                        result.encrypted_filename, result.filename_nonce, result.filename_auth_tag)):
                return "unavailable"
            filename = cipher.decrypt(result.encrypted_filename, result.filename_nonce, result.filename_auth_tag).decode()
            temp_path = await asyncio.to_thread(file_store.decrypt_to_temporary, result.encrypted_file_path,
                                                result.file_nonce, result.file_auth_tag)
            relay_copy = await asyncio.to_thread(file_store.clone_encrypted, result.encrypted_file_path)
            relay_key = f"relay:{secret_id}:{viewer_id}"
            await redis.hset(relay_key, mapping={"content_type": "file", "encrypted_file_path": relay_copy,
                             "file_nonce": result.file_nonce, "file_auth_tag": result.file_auth_tag,
                             "encrypted_filename": result.encrypted_filename, "filename_nonce": result.filename_nonce,
                             "filename_auth_tag": result.filename_auth_tag, "file_size": result.file_size or 0,
                             "mime_type": result.mime_type or "application/octet-stream"})
            await redis.expire(relay_key, 300)
            try:
                await bot.send_document(viewer_id, FSInputFile(temp_path, filename=filename),
                                        caption="📎 Защищённый файл получен. Локальная расшифрованная копия удалена.",
                                        reply_markup=delete_message_menu(str(secret_id)))
            except Exception:
                await redis.delete(relay_key)
                file_store.delete(relay_copy)
                raise
            finally:
                temp_path.unlink(missing_ok=True)
            async def delete_relay_copy_later() -> None:
                await asyncio.sleep(305)
                if not await redis.exists(relay_key):
                    file_store.delete(relay_copy)
            asyncio.create_task(delete_relay_copy_later())
            if result.destroyed:
                file_store.delete(result.encrypted_file_path)
        else:
            if result.payload is None:
                return "unavailable"
            await redis.hset(f"relay:{secret_id}:{viewer_id}", mapping={
                "ciphertext": result.payload.ciphertext, "nonce": result.payload.nonce,
                "auth_tag": result.payload.auth_tag, "content_type": result.content_type.value})
            await redis.expire(f"relay:{secret_id}:{viewer_id}", 300)
            plaintext = bytearray(cipher.decrypt(result.payload.ciphertext, result.payload.nonce, result.payload.auth_tag))
            try:
                content = html.escape(plaintext.decode())
                storage_notice = "\nИсходный секрет уже удалён из хранилища T-Secret." if result.destroyed else ""
                sent = await bot.send_message(
                    viewer_id,
                    f"🔐 <b>СЕКРЕТ</b>\n\n<pre>{content}</pre>\n\n"
                    f"⚠️ Это сообщение будет автоматически удалено через {settings.secret_message_ttl} секунд."
                    f"{storage_notice}",
                    reply_markup=delete_message_menu(str(secret_id)),
                )
            finally:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
            asyncio.create_task(delete_later(bot, sent.chat.id, sent.message_id, settings.secret_message_ttl))
        if result.notify_open:
            try:
                suffix = (
                    "\n\nДанные секрета удалены из хранилища T-Secret. "
                    f"Показанное получателю сообщение исчезнет через {settings.secret_message_ttl} секунд."
                    if result.destroyed else ""
                )
                await bot.send_message(result.creator_id, f"👁 <b>Ваш секрет был открыт</b>\n\nID: <code>{result.public_code}</code>{suffix}")
            except TelegramBadRequest:
                pass
        return None

    @router.callback_query(F.data.startswith("relay:"))
    async def relay_secret(event: CallbackQuery) -> None:
        source_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        cached = await redis.hgetall(f"relay:{source_id}:{event.from_user.id}")
        if not cached:
            await event.answer("Время для передачи дальше истекло.", show_alert=True)
            return
        content_type = cached.get(b"content_type", b"text").decode()
        protection: dict = {"content_type": content_type}
        if content_type == "file":
            cache_path = cached[b"encrypted_file_path"].decode()
            permanent_path = await asyncio.to_thread(file_store.clone_encrypted, cache_path)
            protection.update(encrypted_file_path=permanent_path, file_nonce=cached[b"file_nonce"],
                              file_auth_tag=cached[b"file_auth_tag"], encrypted_filename=cached[b"encrypted_filename"],
                              filename_nonce=cached[b"filename_nonce"], filename_auth_tag=cached[b"filename_auth_tag"],
                              file_size=int(cached.get(b"file_size", b"0")),
                              mime_type=cached.get(b"mime_type", b"application/octet-stream").decode())
            payload = EncryptedSecret(b"", cached[b"file_nonce"], cached[b"file_auth_tag"])
        else:
            payload = EncryptedSecret(cached[b"ciphertext"], cached[b"nonce"], cached[b"auth_tag"])
        async with db.sessions() as session:
            secret, token = await create_secret(session, event.from_user.id, payload, 86400, 1, cipher,
                                                protection)
        if content_type == "file":
            file_store.delete(cache_path)
        await redis.delete(f"relay:{source_id}:{event.from_user.id}")
        await event.message.answer("🔁 <b>Создана новая защищённая копия</b>\n\nTTL: 24 часа\nПросмотров: 1",
                                   reply_markup=created_menu(token, settings.bot_username, str(secret.id)))  # type: ignore[union-attr]
        await event.answer()

    async def request_confirmation(bot: Bot, viewer_id: int, secret_id: UUID) -> None:
        await bot.send_message(viewer_id, "🔐 <b>Подтверждение</b>\n\nЭтот секрет защищён дополнительной проверкой.\n\n"
                               f"Telegram ID: <code>{viewer_id}</code>", reply_markup=identity_confirmation(str(secret_id), viewer_id))

    @router.callback_query(F.data.startswith("reveal:"))
    async def reveal(event: CallbackQuery, bot: Bot, state: FSMContext) -> None:
        secret_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        if isinstance(event.message, Message) and event.message.chat.type != "private":
            async with db.sessions() as session:
                group_secret = await secret_by_id(session, secret_id)
                token = recover_token(group_secret, cipher) if group_secret and is_available(group_secret) else None
            if not token:
                await event.answer("Секрет недоступен.", show_alert=True)
                return
            markup = InlineKeyboardBuilder()
            markup.button(text="💬 Открыть в личке", url=f"https://t.me/{settings.bot_username}?start=s_{token}")
            await event.message.answer("🔐 Для безопасности секрет можно открыть только в личном чате с T-Secret.", reply_markup=markup.as_markup())
            await event.answer()
            return
        allowed, ttl = await limiter.hit(f"open_user:{event.from_user.id}", settings.open_rate_limit, settings.open_rate_window)
        if not allowed:
            await event.answer(f"Слишком много запросов. Повторите через {ttl} сек.", show_alert=True)
            return
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
        if secret is None or not is_available(secret):
            await event.answer("Секрет недоступен или уже был открыт.", show_alert=True)
            return
        if secret.available_at is not None and secret.available_at > datetime.now(UTC):
            await event.answer(f"Секрет будет доступен {dt(secret.available_at)}.", show_alert=True)
            return
        if secret.recipient_mode == RecipientMode.SPECIFIC and secret.recipient_telegram_id != event.from_user.id:
            await send_wrong_user_notice(bot, secret_id, event.from_user.id)
            await event.answer("Этот секрет предназначен другому пользователю.", show_alert=True)
            return
        if secret.recipient_mode == RecipientMode.FIRST and secret.claimed_by_telegram_id not in (None, event.from_user.id):
            await send_wrong_user_notice(bot, secret_id, event.from_user.id)
            await event.answer("Секрет уже закреплён за другим получателем.", show_alert=True)
            return
        if secret.pin_hash:
            attempts, lock_ttl = await limiter.pin_status(str(secret_id), event.from_user.id)
            if attempts >= settings.pin_max_attempts:
                await event.answer(f"Доступ временно заблокирован. Повторите через {lock_ttl} сек.", show_alert=True)
                return
            await state.set_state(OpenSecret.entering_pin)
            await state.update_data(open_secret_id=str(secret_id))
            await event.message.answer("🔐 <b>Защищённый секрет</b>\n\nДля просмотра требуется PIN-код.\n\nВведите PIN:", reply_markup=back_menu())  # type: ignore[union-attr]
            await event.answer()
            return
        if secret.require_identity_confirmation:
            await request_confirmation(bot, event.from_user.id, secret_id)
            await event.answer()
            return
        denial = await deliver_secret(bot, event.from_user.id, secret_id)
        await event.answer("Секрет открыт" if denial is None else "Доступ запрещён", show_alert=denial is not None)

    @router.message(OpenSecret.entering_pin)
    async def receive_open_pin(message: Message, bot: Bot, state: FSMContext) -> None:
        pin_value = message.text or ""
        try:
            await message.delete()
        except TelegramBadRequest:
            pass
        data = await state.get_data()
        secret_id = UUID(data["open_secret_id"])
        attempts, lock_ttl = await limiter.pin_status(str(secret_id), message.from_user.id)
        if attempts >= settings.pin_max_attempts:
            await message.answer(f"🚫 Доступ временно заблокирован. Повторная попытка через {lock_ttl // 60 + 1} мин.")
            await state.clear()
            return
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
        if secret is None or not is_available(secret) or not secret.pin_hash:
            await state.clear()
            await message.answer("Секрет больше недоступен.")
            return
        pin_ok = valid_pin(pin_value) and await asyncio.to_thread(verify_pin, hasher, secret.pin_hash, pin_value)
        if not pin_ok:
            count, ttl = await limiter.pin_failure(str(secret_id), message.from_user.id, settings.pin_max_attempts, settings.pin_lockout_seconds)
            remaining_attempts = max(0, settings.pin_max_attempts - count)
            if secret.notify_wrong_pin:
                try:
                    await bot.send_message(secret.creator_id, f"⚠️ Для секрета <code>{secret.public_code}</code> введён неправильный PIN.")
                except TelegramBadRequest:
                    pass
            await write_audit(db, "secret_pin_failed", secret_code=secret.public_code,
                              owner_id=secret.creator_id, viewer_id=message.from_user.id,
                              actor_id=message.from_user.id)
            if remaining_attempts == 0:
                await message.answer(f"🚫 Доступ временно заблокирован. Повторная попытка будет доступна через {ttl // 60 + 1} мин.")
                await state.clear()
            else:
                await message.answer(f"⚠️ Неверный PIN. Осталось попыток: {remaining_attempts}.\n\nВведите PIN:")
            return
        await limiter.clear_pin_failures(str(secret_id), message.from_user.id)
        await redis.setex(f"pin_grant:{secret_id}:{message.from_user.id}", 300, "1")
        await state.clear()
        if secret.require_identity_confirmation:
            await request_confirmation(bot, message.from_user.id, secret_id)
            return
        await redis.delete(f"pin_grant:{secret_id}:{message.from_user.id}")
        denial = await deliver_secret(bot, message.from_user.id, secret_id)
        if denial:
            await message.answer("⛔ Доступ запрещён.")

    @router.callback_query(F.data.startswith("confirm:"))
    async def confirm_identity(event: CallbackQuery, bot: Bot) -> None:
        secret_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
        if secret is None or not is_available(secret):
            await event.answer("Секрет недоступен.", show_alert=True)
            return
        if secret.pin_hash and not await redis.get(f"pin_grant:{secret_id}:{event.from_user.id}"):
            await event.answer("Сначала необходимо ввести PIN.", show_alert=True)
            return
        await redis.delete(f"pin_grant:{secret_id}:{event.from_user.id}")
        denial = await deliver_secret(bot, event.from_user.id, secret_id)
        await event.answer("Секрет открыт" if denial is None else "Доступ запрещён", show_alert=denial is not None)

    @router.callback_query(F.data == "delete_message")
    async def delete_now(event: CallbackQuery) -> None:
        if isinstance(event.message, Message):
            try:
                await event.message.delete()
            except TelegramBadRequest:
                pass
        await event.answer()

    @router.callback_query(F.data.startswith("link:"))
    async def get_link(event: CallbackQuery) -> None:
        secret_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
            if secret is None or secret.creator_id != event.from_user.id or not is_available(secret):
                await event.answer("Секрет больше недоступен.", show_alert=True)
                return
            token = recover_token(secret, cipher)
        await event.message.answer(f"<code>https://t.me/{settings.bot_username}?start=s_{token}</code>")  # type: ignore[union-attr]
        await event.answer()

    @router.callback_query(F.data == "request:create")
    async def request_create_start(event: CallbackQuery, state: FSMContext) -> None:
        await state.set_state(SecretRequestFlow.entering_prompt)
        await safe_edit(event, "📥 <b>Запросить секрет</b>\n\nЧто вы хотите получить?\n\nНапример: «API-ключ Cloudflare»", back_menu())

    @router.message(SecretRequestFlow.entering_prompt)
    async def request_prompt_value(message: Message, state: FSMContext) -> None:
        prompt = (message.text or "").strip()
        if not prompt or len(prompt) > 500:
            await message.answer("Опишите запрос текстом длиной до 500 символов.")
            return
        async with db.sessions() as session:
            request, token = await create_request(session, message.from_user.id, prompt, settings.request_ttl, cipher)
        await state.clear()
        await message.answer("📥 <b>Запрос секрета создан</b>\n\n"
                             f"Запрос:\n{html.escape(prompt)}\n\nДействует: {settings.request_ttl // 3600} ч\nИспользований: 1",
                             reply_markup=request_created_menu(token, settings.bot_username, str(request.id)))

    @router.callback_query(F.data.startswith("request:cancel:"))
    async def request_cancel(event: CallbackQuery) -> None:
        request_id = UUID(event.data.rsplit(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            success = await cancel_request(session, request_id, event.from_user.id)
        await safe_edit(event, "🔥 Запрос отменён." if success else "Запрос уже недоступен.", back_menu())

    @router.callback_query(F.data.startswith("request:submit:"))
    async def request_submit_start(event: CallbackQuery, state: FSMContext) -> None:
        request_id = UUID(event.data.rsplit(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            request = await session.get(SecretRequest, request_id)
        if request is None or request.status != RequestStatus.ACTIVE or request.expires_at <= datetime.now(UTC):
            await event.answer("Запрос больше недоступен.", show_alert=True)
            return
        await state.set_state(SecretRequestFlow.submitting_secret)
        await state.update_data(request_id=str(request_id))
        await safe_edit(event, "🔐 Отправьте текстовый секрет. Сообщение будет удалено сразу после шифрования.", back_menu())

    @router.message(SecretRequestFlow.submitting_secret)
    async def request_submit_value(message: Message, state: FSMContext, bot: Bot) -> None:
        value = message.text or ""
        if not value or len(value) > 3500:
            await message.answer("Нужен текстовый секрет длиной до 3500 символов.")
            return
        raw = bytearray(value.encode())
        try:
            try:
                await message.delete()
            except TelegramBadRequest:
                pass
            encrypted = cipher.encrypt(bytes(raw))
        finally:
            for index in range(len(raw)):
                raw[index] = 0
        request_id = UUID((await state.get_data())["request_id"])
        async with db.sessions() as session:
            request = await session.get(SecretRequest, request_id)
            prompt = request_prompt(request, cipher) if request else "Запрос"
        async with db.sessions() as session:
            secret, _, owner_id = await fulfill_request(session, request_id, message.from_user.id, encrypted, cipher)
        await state.clear()
        if secret is None or owner_id is None:
            await message.answer("Запрос уже использован или истёк.", reply_markup=back_menu())
            return
        await message.answer("✅ Секрет безопасно передан инициатору запроса.", reply_markup=main_menu(message.from_user.id in settings.admin_id_set))
        try:
            await bot.send_message(owner_id, "📥 <b>Получен новый секрет</b>\n\n"
                                   f"Запрос:\n{html.escape(prompt)}", reply_markup=reveal_menu(str(secret.id)))
        except TelegramBadRequest:
            pass

    @router.callback_query(F.data.startswith("destroy:"))
    async def destroy(event: CallbackQuery) -> None:
        secret_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            success, file_path = await destroy_owned(session, secret_id, event.from_user.id)
        file_store.delete(file_path)
        await safe_edit(event, "🔥 Секрет уничтожен." if success else "Секрет уже недоступен.", back_menu())

    @router.callback_query(F.data.startswith("active:"))
    async def active(event: CallbackQuery) -> None:
        page = max(0, int(event.data.split(":", 1)[1]))  # type: ignore[union-attr]
        async with db.sessions() as session:
            fetched = await list_owned(session, event.from_user.id, True, page * 8, 9)
        items, has_next = fetched[:8], len(fetched) > 8
        lines = [f"📨 <b>Активные секреты · {page + 1}</b>", ""]
        b = InlineKeyboardBuilder()
        for item in items:
            lines.append(f"🔐 {item.public_code} · ⏳ {remaining(item.expires_at)} · 👁 {item.views_used}/{item.views_allowed}")
            b.button(text=item.public_code, callback_data=f"card:{item.id}")
        if not items:
            lines.append("Активных секретов нет.")
        b.adjust(2)
        if page > 0:
            b.button(text="◀️", callback_data=f"active:{page - 1}")
        if has_next:
            b.button(text="▶️", callback_data=f"active:{page + 1}")
        b.button(text="🔥 Уничтожить все", callback_data="panic")
        b.button(text="⬅️ Мои секреты", callback_data="my:secrets")
        b.adjust(2)
        await safe_edit(event, "\n".join(lines), b.as_markup())

    @router.callback_query(F.data.startswith("card:"))
    async def card(event: CallbackQuery) -> None:
        secret_id = UUID(event.data.split(":", 1)[1])  # type: ignore[union-attr]
        async with db.sessions() as session:
            secret = await secret_by_id(session, secret_id)
            if secret is None or secret.creator_id != event.from_user.id or not is_available(secret):
                await event.answer("Секрет недоступен.", show_alert=True)
                return
            token = recover_token(secret, cipher)
        text = (f"🔐 <b>{secret.public_code}</b>\n\nСтатус: 🟢 Активен\nСоздан: {dt(secret.created_at)}\n"
                f"Истекает: {dt(secret.expires_at)}\nПросмотров: {secret.views_used} / {secret.views_allowed}")
        await safe_edit(event, text, created_menu(token or "", settings.bot_username, str(secret.id)))

    @router.callback_query(F.data == "panic")
    async def panic_start(event: CallbackQuery) -> None:
        async with db.sessions() as session:
            count = await count_active_owned(session, event.from_user.id)
        markup = InlineKeyboardBuilder()
        markup.button(text="🔥 УНИЧТОЖИТЬ ВСЕ", callback_data="panic:confirm")
        markup.button(text="⬅️ Назад", callback_data="my:secrets")
        markup.adjust(1)
        await safe_edit(event, "🚨 <b>Экстренное удаление</b>\n\nБудут уничтожены ВСЕ ваши активные секреты.\n\n"
                        f"Количество: {count}\n\nОперацию нельзя отменить.", markup.as_markup())

    @router.callback_query(F.data == "panic:quick")
    async def panic_quick_confirm(event: CallbackQuery) -> None:
        async with db.sessions() as session:
            count = await count_active_owned(session, event.from_user.id)
        if count == 0:
            await event.answer("Активных секретов нет", show_alert=True)
            return
        markup = InlineKeyboardBuilder()
        markup.button(text=f"🔥 Уничтожить {count} секретов", callback_data="panic:execute", style="danger")
        markup.button(text="❌ Отмена", callback_data="menu", style="primary")
        markup.adjust(1)
        await safe_edit(event, "🚨 <b>Удалить все секреты?</b>\n\n"
                        f"Активных секретов: <b>{count}</b>\n\n"
                        "Содержимое и зашифрованные файлы будут уничтожены. Операцию нельзя отменить.",
                        markup.as_markup())

    @router.callback_query(F.data == "panic:confirm")
    async def panic_confirm(event: CallbackQuery) -> None:
        async with db.sessions() as session:
            count = await count_active_owned(session, event.from_user.id)
        markup = InlineKeyboardBuilder()
        markup.button(text=f"🔥 Да, уничтожить {count} секретов", callback_data="panic:execute")
        markup.button(text="⬅️ Назад", callback_data="panic")
        markup.adjust(1)
        await safe_edit(event, "🚨 <b>Подтвердите ещё раз</b>", markup.as_markup())

    @router.callback_query(F.data == "panic:execute")
    async def panic_execute(event: CallbackQuery) -> None:
        async with db.sessions() as session:
            count, file_paths = await destroy_all_owned(session, event.from_user.id)
        for path in file_paths:
            file_store.delete(path)
        await safe_edit(event, f"🔥 Уничтожено секретов: {count}", back_menu())

    @router.callback_query(F.data.startswith("history:"))
    async def history(event: CallbackQuery) -> None:
        page = max(0, int(event.data.split(":", 1)[1]))  # type: ignore[union-attr]
        async with db.sessions() as session:
            fetched = await list_owned(session, event.from_user.id, False, page * 10, 11)
        items, has_next = fetched[:10], len(fetched) > 10
        labels = {DestroyReason.VIEW_LIMIT: "✅ Открыт и уничтожен", DestroyReason.EXPIRED: "⌛ Истёк", DestroyReason.MANUAL: "🔥 Удалён вручную"}
        lines = [f"🕘 <b>История · {page + 1}</b>", ""]
        for item in items:
            lines.append(f"{item.public_code}\n{labels.get(item.destroy_reason, 'Завершён')}\n{dt(item.destroyed_at)}\n")
        if not items:
            lines.append("История пока пуста.")
        b = InlineKeyboardBuilder()
        if page > 0:
            b.button(text="◀️", callback_data=f"history:{page - 1}")
        if has_next:
            b.button(text="▶️", callback_data=f"history:{page + 1}")
        b.button(text="⬅️ Мои секреты", callback_data="my:secrets")
        b.adjust(2, 1)
        await safe_edit(event, "\n".join(lines), b.as_markup())

    @router.callback_query(F.data == "settings")
    async def settings_page(event: CallbackQuery) -> None:
        await safe_edit(event, "⚙️ <b>Настройки</b>\n\nЗначения по умолчанию: 24 часа и один просмотр. Расширенные персональные настройки появятся на следующем этапе.", back_menu())

    @router.callback_query(F.data == "security")
    async def security_page(event: CallbackQuery) -> None:
        b = InlineKeyboardBuilder()
        b.button(text="🚨 Экстренное удаление", callback_data="panic")
        b.button(text="⬅️ Назад", callback_data="more")
        b.adjust(1)
        await safe_edit(event, "🛡 <b>Безопасность</b>\n\nAES-256-GCM · Argon2id · SHA-256 token lookup\n"
                        "PIN anti-bruteforce · PostgreSQL row locking · metadata-only audit", b.as_markup())

    @router.callback_query(F.data == "about")
    async def about(event: CallbackQuery) -> None:
        await safe_edit(event, "ℹ️ <b>О T-Secret</b>\n\nСекреты шифруются AES-256-GCM. После истечения срока или последнего просмотра зашифрованные данные и материал ссылки удаляются.", more_menu())

    return router
