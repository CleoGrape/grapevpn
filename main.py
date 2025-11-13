"""
bot.py — расширенный aiogram VPN-bot (всё в одном файле)

Требования (пример):
  pip install aiogram aiohttp PyJWT python-dotenv

Опционально (для настоящих WireGuard ключей и графиков):
  sudo apt install wireguard-tools   # для wg genkey / wg pubkey
  pip install matplotlib

Настройки — замените константы ниже:
  BOT_TOKEN, REQUIRED_CHANNEL, ADMIN_IDS и т.д.

Запуск:
  python bot.py
"""

import asyncio
import sqlite3
import secrets
import datetime
import subprocess
import io
import csv
import os
from typing import Optional

from aiohttp import web
import jwt  # PyJWT
from aiogram import Bot, Dispatcher, F
from aiogram.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    Message, CallbackQuery, InputFile
)
from aiogram.filters import Command
from aiogram.exceptions import TelegramBadRequest

# -------------------------
#  НАСТРОЙКИ — ЗАМЕНИТЕ
# -------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "8238322781:AAHQjNqlWO5ILeqArXHNodmF1j2sdvZm3m0")
REQUIRED_CHANNEL = os.getenv("REQUIRED_CHANNEL", "@grapevpnn")  # пример "@vpn_ch"
DB_PATH = os.getenv("DB_PATH", "vpn_full.db")
TOKEN_LIFETIME_HOURS = int(os.getenv("TOKEN_LIFETIME_HOURS", "24"))
TOKENS_PER_DAY_LIMIT = int(os.getenv("TOKENS_PER_DAY_LIMIT", "1"))
REF_REWARD = int(os.getenv("REF_REWARD", "1"))  # сколько токенов давать за реферала
ADMIN_IDS = set(int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()) or {6979133757}
JWT_SECRET = os.getenv("JWT_SECRET", "super_jwt_secret_change_me")  # для подписи JWT
JWT_ALGO = "HS256"
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")  # имя интерфейса в конфиге (инфо-текст)
HOST_PUBLIC_IP = os.getenv("HOST_PUBLIC_IP", "vpn.example.com")  # адрес VPN сервера
WG_LISTEN_PORT = int(os.getenv("WG_LISTEN_PORT", "51820"))
SERVER_PUBLIC_KEY = os.getenv("SERVER_PUBLIC_KEY", "")  # если уже есть
DEFAULT_TOKEN_BYTES = 32

# -------------------------
#  Инициализация бота
# -------------------------
bot = Bot(BOT_TOKEN)
dp = Dispatcher()

# -------------------------
#  Работа с базой SQLite
# -------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    # users: ref_by — кто пригласил; paid — пометка оплаты
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            ref_by INTEGER,
            refs_count INTEGER DEFAULT 0,
            joined_at TEXT,
            paid INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            created_at TEXT,
            expires_at TEXT,
            used INTEGER DEFAULT 0,
            wg_private TEXT,
            wg_public TEXT
        )
    """)
    # для anti-fraud: сохраняем кто пришёл по рефу (чтобы не начислять дважды)
    c.execute("""
        CREATE TABLE IF NOT EXISTS referrals (
            new_user INTEGER PRIMARY KEY,
            ref_by INTEGER,
            credited INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# -------------------------
#  Вспомогательные функции
# -------------------------
def register_user(user_id: int, ref_by: Optional[int]):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT user_id FROM users WHERE user_id=?", (user_id,))
    if c.fetchone():
        conn.close()
        return False
    now = datetime.datetime.utcnow().isoformat()
    # защита: не позволяем self-ref
    if ref_by == user_id:
        ref_by = None
    # вставка пользователя
    c.execute("INSERT INTO users (user_id, ref_by, refs_count, joined_at) VALUES (?, ?, ?, ?)",
              (user_id, ref_by, 0, now))
    # если есть реф, добавляем запись в referrals и увеличиваем счётчик приглашений (но начисление награды отдельно)
    if ref_by:
        c.execute("INSERT OR IGNORE INTO referrals (new_user, ref_by, credited, created_at) VALUES (?, ?, 0, ?)",
                  (user_id, ref_by, now))
    conn.commit()
    conn.close()
    return True

def credit_referral_for(new_user: int):
    """
    Попытаться начислить награду рефералу, с защитой от накрутки:
      - начисляем только один раз за каждого new_user
      - ref_by должен существовать в users
      - self-ref запрещён уже при регистрации
    Возвращает (credited: bool, ref_by_id or None)
    """
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT ref_by, credited FROM referrals WHERE new_user=?", (new_user,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, None
    ref_by, credited = row
    if credited:
        conn.close()
        return False, ref_by
    # проверка существования пригласителя
    c.execute("SELECT user_id FROM users WHERE user_id=?", (ref_by,))
    if not c.fetchone():
        conn.close()
        return False, ref_by
    # защита: не начисляем, если у пригласителя уже слишком много рефов? (опционально) — можно добавить порог
    # начисляем: просто увеличим refs_count и добавим токены наградой (реализовано как создание токенов)
    c.execute("UPDATE users SET refs_count = refs_count + 1 WHERE user_id=?", (ref_by,))
    # создаём REF_REWARD токенов для ref_by (можно ужать, чтобы каждый токен был помечен как "реф")
    for _ in range(REF_REWARD):
        token, exp, priv, pub = _create_token_db(ref_by, generate_wg_keys=True)
        # пометка: wg keys и т.д. (уже внутри)
    c.execute("UPDATE referrals SET credited=1 WHERE new_user=?", (new_user,))
    conn.commit()
    conn.close()
    return True, ref_by

def user_tokens_last_24h_count(user_id: int) -> int:
    conn = get_conn()
    c = conn.cursor()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).isoformat()
    c.execute("SELECT COUNT(*) FROM tokens WHERE user_id=? AND created_at >= ?", (user_id, cutoff))
    n = c.fetchone()[0]
    conn.close()
    return n

# -------------------------
#  WireGuard key/gen & config
# -------------------------
def generate_wg_keypair():
    """
    Попытка получить реальный ключ через wg genkey / wg pubkey.
    Если эти утилиты недоступны — используем безопасный fallback (псевдоключи, основанные на случайных байтах).
    Возвращает (private_key, public_key, used_real_tools_bool)
    """
    try:
        p = subprocess.run(["wg", "genkey"], capture_output=True, check=True, text=True, timeout=3)
        priv = p.stdout.strip()
        q = subprocess.run(["echo", priv], capture_output=True, text=True)
        # get pubkey via pipe to wg pubkey
        p2 = subprocess.Popen(["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p2.communicate(priv + "\n", timeout=3)
        pub = out.strip()
        if priv and pub:
            return priv, pub, True
    except Exception:
        # fallback
        raw = secrets.token_bytes(DEFAULT_TOKEN_BYTES)
        priv = secrets.token_urlsafe(32)
        # public placeholder: base64-like
        pub = secrets.token_urlsafe(32)
        return priv, pub, False

def generate_wg_config(client_public_key: str, client_ip: str = "10.66.66.2/32"):
    """
    Шаблон WireGuard-konfig для клиента, используя known SERVER_PUBLIC_KEY, HOST_PUBLIC_IP и WG_LISTEN_PORT.
    Возвращает текст конфига.
    """
    server_pub = SERVER_PUBLIC_KEY or "<SERVER_PUBLIC_KEY>"
    cfg = f"""[Interface]
PrivateKey = <client_private_key_replace_on_server>
Address = {client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = {HOST_PUBLIC_IP}:{WG_LISTEN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    # note: we will replace <client_private_key_replace_on_server> with actual private when giving true keys
    return cfg

def _create_token_db(user_id: int, generate_wg_keys: bool = True):
    """
    Внутренний: создаёт запись токена в БД и (опционально) генерирует wg-ключи.
    Возвращает (token, expires_iso, private_key, public_key)
    """
    conn = get_conn()
    c = conn.cursor()
    token = secrets.token_urlsafe(16)
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(hours=TOKEN_LIFETIME_HOURS)
    priv, pub = None, None
    used_real = False
    if generate_wg_keys:
        priv, pub, used_real = generate_wg_keypair()
    c.execute(
        "INSERT INTO tokens (token, user_id, created_at, expires_at, used, wg_private, wg_public) VALUES (?, ?, ?, ?, 0, ?, ?)",
        (token, user_id, now.isoformat(), expires.isoformat(), priv or "", pub or "")
    )
    conn.commit()
    conn.close()
    return token, expires.isoformat(), priv, pub

def create_token_for_user(user_id: int):
    """
    Основная функция для создания токена (с учётом лимита 1 в сутки).
    Возвращает (ok:bool, message_or_dict)
    """
    # лимит в день
    if user_tokens_last_24h_count(user_id) >= TOKENS_PER_DAY_LIMIT:
        return False, f"Лимит токенов за 24 часа достигнут ({TOKENS_PER_DAY_LIMIT})."

    token, expires, priv, pub = _create_token_db(user_id, generate_wg_keys=True)
    # сформируем клиентский конфиг: заполним приватный ключ клиента (priv) в шаблоне
    client_ip_base = "10.66.66."  # очень простое распределение — можно улучшить
    # count tokens for user to assign IP suffix
    cnt = user_tokens_last_24h_count(user_id)
    suffix = 2 + cnt  # простая логика, можно улучшить
    client_ip = f"10.66.66.{suffix}/32"
    cfg = generate_wg_config(pub or "<pubkey>", client_ip)
    # вставляем реальный private в [Interface] при возможности (если priv есть)
    if priv:
        cfg = cfg.replace("<client_private_key_replace_on_server>", priv)
    return True, {"token": token, "expires": expires, "wg_config": cfg, "priv": priv, "pub": pub}

def list_user_tokens(user_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT token, created_at, expires_at, used, wg_public FROM tokens WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows

def redeem_token_api(token: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT token, user_id, expires_at, used, wg_private, wg_public FROM tokens WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "not_found", None
    token_v, user_id, expires_at, used, wg_priv, wg_pub = row
    exp = datetime.datetime.fromisoformat(expires_at)
    now = datetime.datetime.utcnow()
    if used:
        conn.close()
        return False, "already_used", None
    if now > exp:
        conn.close()
        return False, "expired", None
    # пометка как использован
    c.execute("UPDATE tokens SET used=1 WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return True, "ok", {"user_id": user_id, "wg_private": wg_priv, "wg_public": wg_pub, "expires_at": expires_at}

# -------------------------
#  Проверка подписки
# -------------------------
async def check_subscription(user_id: int) -> bool:
    try:
        mem = await bot.get_chat_member(chat_id=REQUIRED_CHANNEL, user_id=user_id)
        return mem.status in ("member", "administrator", "creator")
    except TelegramBadRequest:
        return False

def sub_keyboard():
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Подписаться 📢", url=f"https://t.me/{REQUIRED_CHANNEL[1:]}")],
        [InlineKeyboardButton(text="Проверить 🔄", callback_data="check_sub")]
    ])
    return kb

def main_menu():
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Получить токен 🔐", callback_data="get_token")],
        [InlineKeyboardButton(text="Мои токены 📄", callback_data="my_tokens")],
        [InlineKeyboardButton(text="Реферальная панель 👥", callback_data="ref_panel")],
        [InlineKeyboardButton(text="Помощь ❓", callback_data="help")]
    ])
    return kb

# -------------------------
#  Обработчики aiogram
# -------------------------
@dp.message(Command("start"))
async def cmd_start(message: Message):
    user_id = message.from_user.id
    args = message.text.split()
    ref_by = None
    if len(args) > 1 and args[1].startswith("ref"):
        try:
            ref_by = int(args[1][3:])
            if ref_by == user_id:
                ref_by = None
        except Exception:
            ref_by = None

    new = register_user(user_id, ref_by)
    # если регистрация новая — попробуем начислить реф-награду
    if new:
        credited, ref_id = credit_referral_for(user_id)
        # credited True/False — не обязательно что-то писать пользователю здесь

    # подписка
    if not await check_subscription(user_id):
        await message.answer("Привет! Чтобы пользоваться ботом — подпишитесь на канал:", reply_markup=sub_keyboard())
        return
    await message.answer("Главное меню:", reply_markup=main_menu())

@dp.callback_query(F.data == "check_sub")
async def cb_check_sub(query: CallbackQuery):
    if await check_subscription(query.from_user.id):
        await query.message.answer("Вы подписаны ✔", reply_markup=main_menu())
    else:
        await query.message.answer("❌ Вы не подписаны", reply_markup=sub_keyboard())

@dp.callback_query(F.data == "get_token")
async def cb_get_token(query: CallbackQuery):
    uid = query.from_user.id
    if not await check_subscription(uid):
        await query.message.answer("Сначала подпишитесь на канал", reply_markup=sub_keyboard())
        return
    ok, res = create_token_for_user(uid)
    if not ok:
        await query.message.answer(res, reply_markup=main_menu())
        return
    # res содержит token, expires, wg_config ...
    await query.message.answer(
        f"Ваш токен: `{res['token']}`\nДействует до (UTC): {res['expires']}\n\nWireGuard-конфиг прилагается (содержит приватный ключ клиента).",
        parse_mode="Markdown"
    )
    # отправим конфиг как файл
    cfg_bytes = res["wg_config"].encode("utf-8")
    bio = io.BytesIO(cfg_bytes)
    bio.name = f"wg_{res['token']}.conf"
    await query.message.answer_document(InputFile(bio))

@dp.callback_query(F.data == "my_tokens")
async def cb_my_tokens(query: CallbackQuery):
    uid = query.from_user.id
    rows = list_user_tokens(uid)
    if not rows:
        await query.message.answer("У вас нет токенов.", reply_markup=main_menu())
        return
    text = "Ваши токены:\n\n"
    for token, created, expires, used, wg_pub in rows:
        text += f"`{token}`\nСоздан: {created}\nИстекает: {expires}\nИспользован: {'да' if used else 'нет'}\nWG pub: {wg_pub or '-'}\n\n"
    await query.message.answer(text, parse_mode="Markdown")

@dp.callback_query(F.data == "ref_panel")
async def cb_ref_panel(query: CallbackQuery):
    uid = query.from_user.id
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT refs_count FROM users WHERE user_id=?", (uid,))
    row = c.fetchone()
    refs = row[0] if row else 0
    link = f"https://t.me/{(await bot.get_me()).username}?start=ref{uid}"
    await query.message.answer(f"Ваша реферальная ссылка:\n`{link}`\nПриглашено: {refs}\nНаграда: {REF_REWARD} токен(ов)",
                               parse_mode="Markdown")

@dp.callback_query(F.data == "help")
async def cb_help(query: CallbackQuery):
    text = (
        "Как это работает:\n"
        "- Подпишитесь на канал -> получите токен\n"
        "- Токен действителен ограниченное время\n"
        "- Админ может вручную выдать токены/пометить оплату\n"
        "- Рефералы дают награду (автоматически создаются токены для пригласителя)\n\n"
        "Команды для админа: /admin"
    )
    await query.message.answer(text)

# -------------------------
#  Админ: панель и фичи
# -------------------------
@dp.message(Command("admin"))
async def cmd_admin(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton("Пользователи 🧑‍💻", callback_data="adm_users"),
         InlineKeyboardButton("Токены 🔐", callback_data="adm_tokens")],
        [InlineKeyboardButton("Разослать всем ✉️", callback_data="adm_broadcast")],
        [InlineKeyboardButton("Выдать токен пользователю", callback_data="adm_give_token")],
        [InlineKeyboardButton("Выдать JWT для серверов", callback_data="adm_issue_jwt")],
        [InlineKeyboardButton("Экспорт CSV", callback_data="adm_export")]
    ])
    await message.answer("Админ-панель", reply_markup=kb)

@dp.callback_query(F.data == "adm_users")
async def cb_adm_users(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT user_id, ref_by, refs_count, joined_at, paid FROM users ORDER BY joined_at DESC")
    rows = c.fetchall()
    conn.close()
    text = "Пользователи:\n\n"
    for u, r, cnt, joined, paid in rows[:200]:
        text += f"{u} | ref_by={r} | refs={cnt} | joined={joined} | paid={paid}\n"
    await query.message.answer(text[:4000])

@dp.callback_query(F.data == "adm_tokens")
async def cb_adm_tokens(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT token, user_id, created_at, expires_at, used FROM tokens ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    text = "Токены:\n\n"
    for t, u, created, exp, used in rows[:200]:
        text += f"{t} | user={u} | created={created} | exp={exp} | used={used}\n"
    await query.message.answer(text[:4000])

@dp.callback_query(F.data == "adm_broadcast")
async def cb_adm_broadcast(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    await query.message.answer("Введите сообщение для рассылки (админ). Отправьте /cancel чтобы отменить.")
    # простейший state-machine без state — чтение следующего сообщения от этого админа
    @dp.message()
    async def accept_broadcast(msg: Message):
        if msg.from_user.id not in ADMIN_IDS:
            return
        if msg.text == "/cancel":
            await msg.answer("Рассылка отменена.")
            dp.message_handlers.unregister(accept_broadcast)
            return
        text = msg.text
        # рассылка всем пользователям (внимание: большое количество — потребует очередей и пауз)
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT user_id FROM users")
        rows = c.fetchall()
        conn.close()
        success = 0
        for (uid,) in rows:
            try:
                await bot.send_message(uid, f"📣 Сообщение от админа:\n\n{text}")
                success += 1
            except Exception:
                pass
        await msg.answer(f"Рассылка завершена. Отправлено примерно: {success}")
        dp.message_handlers.unregister(accept_broadcast)

@dp.callback_query(F.data == "adm_give_token")
async def cb_adm_give_token(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    await query.message.answer("Отправьте ID пользователя, которому дать токен (или /cancel).")
    @dp.message()
    async def accept_uid(msg: Message):
        if msg.from_user.id not in ADMIN_IDS:
            return
        if msg.text == "/cancel":
            await msg.answer("Отмена.")
            dp.message_handlers.unregister(accept_uid)
            return
        try:
            uid = int(msg.text.strip())
        except:
            await msg.answer("Неправильный ID. Попробуйте ещё раз или /cancel")
            return
        tok, exp, priv, pub = _create_token_db(uid, generate_wg_keys=True)
        await msg.answer(f"Токен выдан: `{tok}` (user {uid})", parse_mode="Markdown")
        dp.message_handlers.unregister(accept_uid)

@dp.callback_query(F.data == "adm_issue_jwt")
async def cb_adm_issue_jwt(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    # выдаём JWT для сервера, срок 24 часа
    now = datetime.datetime.utcnow()
    payload = {"iss": "vpn_bot", "iat": int(now.timestamp()), "exp": int((now + datetime.timedelta(hours=24)).timestamp())}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    await query.message.answer(f"JWT (валиден 24ч):\n`{token}`", parse_mode="Markdown")

@dp.callback_query(F.data == "adm_export")
async def cb_adm_export(query: CallbackQuery):
    if query.from_user.id not in ADMIN_IDS:
        return
    # экспорт пользователей и токенов в CSV и отправка админу
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT user_id, ref_by, refs_count, joined_at, paid FROM users")
    users = c.fetchall()
    c.execute("SELECT token, user_id, created_at, expires_at, used FROM tokens")
    tokens = c.fetchall()
    conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["user_id", "ref_by", "refs_count", "joined_at", "paid"])
    for row in users:
        w.writerow(row)
    w.writerow([])
    w.writerow(["token", "user_id", "created_at", "expires_at", "used"])
    for row in tokens:
        w.writerow(row)
    buf.seek(0)
    bio = io.BytesIO(buf.read().encode("utf-8"))
    bio.name = "export_vpn.csv"
    await query.message.answer_document(InputFile(bio))

# -------------------------
#  API: /redeem + /verify_jwt
# -------------------------
async def api_redeem(request):
    try:
        data = await request.json()
    except:
        return web.json_response({"ok": False, "error": "bad_json"}, status=400)
    # expect jwt and token OR secret
    jwt_token = data.get("jwt")
    token = data.get("token")
    if not jwt_token or not token:
        return web.json_response({"ok": False, "error": "missing_jwt_or_token"}, status=400)
    # validate jwt
    try:
        payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception as e:
        return web.json_response({"ok": False, "error": "bad_jwt", "detail": str(e)}, status=403)
    ok, code, info = redeem_token_api(token)
    if not ok:
        return web.json_response({"ok": False, "error": code}, status=400)
    # on success return wg private/public so vpn server can configure interface
    return web.json_response({"ok": True, "status": "redeemed", "info": info})

async def api_issue_jwt(request):
    # simple endpoint to issue a JWT for a server; protected by simple shared secret in header (for demo)
    secret = request.headers.get("X-ADMIN-SECRET")
    if secret != JWT_SECRET:
        return web.json_response({"ok": False, "error": "bad_secret"}, status=403)
    now = datetime.datetime.utcnow()
    payload = {"iss": "vpn_bot", "iat": int(now.timestamp()), "exp": int((now + datetime.timedelta(hours=24)).timestamp())}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return web.json_response({"ok": True, "jwt": token})

async def start_api():
    app = web.Application()
    app.router.add_post("/redeem", api_redeem)
    app.router.add_post("/issue_jwt", api_issue_jwt)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=5001)
    await site.start()

# -------------------------
#  Запуск
# -------------------------
async def main():
    init_db()
    await start_api()
    print("API запущен на порту 5001")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
