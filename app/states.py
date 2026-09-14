from aiogram.fsm.state import State, StatesGroup


class CreateSecret(StatesGroup):
    choosing_type = State()
    waiting_text = State()
    waiting_file = State()
    waiting_password = State()
    choosing_ttl = State()
    choosing_views = State()
    protection = State()
    entering_custom_pin = State()
    choosing_recipient = State()
    entering_recipient_id = State()
    forwarding_recipient = State()
    notifications = State()
    destroy_timer = State()


class Generator(StatesGroup):
    choosing_kind = State()
    choosing_password_length = State()
    preview = State()


class SecretRequestFlow(StatesGroup):
    entering_prompt = State()
    submitting_secret = State()


class OpenSecret(StatesGroup):
    entering_pin = State()


class AdminEmoji(StatesGroup):
    waiting_emoji = State()


class AdminUserSearch(StatesGroup):
    query = State()
