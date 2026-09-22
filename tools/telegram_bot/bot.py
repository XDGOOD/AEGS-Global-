# -*- coding: utf-8 -*-
"""
AEGS Titan Telegram Bot - Core Service Module
Features:
- Strict Admin authorization: Only @Balbes_ls has access to admin panel & approvals
- Mandatory manual payment approval workflow by @Balbes_ls before key issuance
- Free 3-day trial completely disabled per owner request
- Direct payment routing to @Balbes_ls with 4-device maximum limit prescription
- Synchronization with AEGS C++ Core & Server DB
"""

import os
import sys
import time
import json
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Any, Optional, List

from . import config
from . import database
from .subscription_worker import start_worker
from .qr_generator import get_qr_image_bytes as generate_qr_code_png

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(name)s) %(message)s'
)
logger = logging.getLogger("aegs_bot")

class AegsTelegramBot:
    def __init__(self, token: str):
        self.token = token
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.offset = 0

    def _api_call(self, method: str, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/{method}"
        try:
            if files:
                boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                crlf = b"\r\n"
                body = bytearray()
                for key, val in (data or {}).items():
                    body.extend(b"--" + boundary.encode() + crlf)
                    body.extend(f'Content-Disposition: form-data; name="{key}"'.encode() + crlf + crlf)
                    body.extend(str(val).encode() + crlf)
                for field_name, (filename, filedata, content_type) in files.items():
                    body.extend(b"--" + boundary.encode() + crlf)
                    body.extend(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'.encode() + crlf)
                    body.extend(f'Content-Type: {content_type}'.encode() + crlf + crlf)
                    body.extend(filedata + crlf)
                body.extend(b"--" + boundary.encode() + b"--" + crlf)
                req = urllib.request.Request(url, data=bytes(body), headers={
                    'Content-Type': f'multipart/form-data; boundary={boundary}'
                })
            else:
                json_data = json.dumps(data or {}).encode('utf-8')
                req = urllib.request.Request(url, data=json_data, headers={
                    'Content-Type': 'application/json'
                })

            with urllib.request.urlopen(req, timeout=30) as resp:
                res_bytes = resp.read()
                return json.loads(res_bytes.decode('utf-8'))
        except urllib.error.HTTPError as e:
            try:
                err_text = e.read().decode('utf-8')
                logger.warning(f"Telegram API error in {method}: {err_text}")
            except Exception:
                logger.warning(f"Telegram HTTPError in {method}: {e.code}")
            return None
        except Exception as e:
            logger.error(f"Failed Telegram API call to {method}: {e}")
            return None

    def send_message(self, chat_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        payload: Dict[str, Any] = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode}
        if reply_markup:
            payload['reply_markup'] = reply_markup
        return self._api_call('sendMessage', payload)

    def edit_message_text(self, chat_id: int, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        payload: Dict[str, Any] = {'chat_id': chat_id, 'message_id': message_id, 'text': text, 'parse_mode': parse_mode}
        if reply_markup:
            payload['reply_markup'] = reply_markup
        res = self._api_call('editMessageText', payload)
        if not res or not res.get('ok'):
            cap_payload: Dict[str, Any] = {'chat_id': chat_id, 'message_id': message_id, 'caption': text, 'parse_mode': parse_mode}
            if reply_markup:
                cap_payload['reply_markup'] = reply_markup
            cap_res = self._api_call('editMessageCaption', cap_payload)
            if not cap_res or not cap_res.get('ok'):
                return self.send_message(chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
            return cap_res
        return res

    def send_document(self, chat_id: int, doc_bytes: bytes, filename: str, caption: str = '', reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        files = {'document': (filename, doc_bytes, 'application/vnd.android.package-archive')}
        data: Dict[str, Any] = {'chat_id': chat_id, 'caption': caption, 'parse_mode': parse_mode}
        if reply_markup:
            data['reply_markup'] = json.dumps(reply_markup)
        return self._api_call('sendDocument', data=data, files=files)

    def send_apk_file(self, chat_id: int):
        import glob
        apk_candidates = [
            "AEGS-v6.0-titan.apk",
            os.path.join(os.path.dirname(__file__), "..", "..", "AEGS-v6.0-titan.apk"),
            os.path.join(os.getcwd(), "AEGS-v6.0-titan.apk")
        ]
        apk_path = None
        for cand in apk_candidates:
            if os.path.exists(cand):
                apk_path = cand
                break
        
        if not apk_path:
            # Search by pattern
            found = glob.glob("**/*titan*.apk", recursive=True)
            if found:
                apk_path = found[0]

        if apk_path and os.path.exists(apk_path):
            self.send_message(chat_id, "⏳ <i>Отправляю APK-файл приложения AEGS Titan... Пожалуйста, подождите.</i>")
            with open(apk_path, "rb") as f:
                apk_bytes = f.read()
            caption = (
                "📱 <b>AEGS VPN Client — v6.5 Titan</b>\n\n"
                "• <b>Что нового в обновлении:</b>\n"
                "  ✓ Убран оранжевый артефакт в правом верхнем углу\n"
                "  ✓ Скрыты внутренние системные процессы (отображаются только ваши реальные приложения)\n"
                "  ✓ Добавлена возможность делиться ключом с друзьями (до 4 устройств одновременно)\n"
                "  ✓ Прямой переход к покупке ключа в боте и вставка из буфера\n"
                "  ✓ Поддержка Android 8.0 - 15.0+\n\n"
                "📌 <i>Установите файл, вставьте ваш ключ доступа и нажмите «Подключиться»!</i>"
            )
            markup = {
                'inline_keyboard': [
                    [{'text': '🔑 Получить мой ключ', 'callback_data': 'get_key'}],
                    [{'text': '💎 Купить подписку (100 руб)', 'callback_data': 'buy_menu'}],
                    [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
                ]
            }
            self.send_document(chat_id, apk_bytes, "AEGS-v6.5-titan.apk", caption=caption, reply_markup=markup)
        else:
            self.send_message(chat_id, f"📥 APK-файл можно скачать по ссылке:\n{config.APK_DOWNLOAD_URL}")

    def send_photo(self, chat_id: int, photo_bytes: bytes, caption: str = '', reply_markup: Optional[Dict[str, Any]] = None, parse_mode: str = 'HTML') -> Optional[Dict[str, Any]]:
        files = {'photo': ('qr.png', photo_bytes, 'image/png')}
        data: Dict[str, Any] = {'chat_id': chat_id, 'caption': caption, 'parse_mode': parse_mode}
        if reply_markup:
            data['reply_markup'] = json.dumps(reply_markup)
        return self._api_call('sendPhoto', data=data, files=files)

    def answer_callback_query(self, callback_query_id: str, text: Optional[str] = None):
        payload: Dict[str, Any] = {'callback_query_id': callback_query_id}
        if text:
            payload['text'] = text
        self._api_call('answerCallbackQuery', payload)

    def is_admin(self, chat_id: int, username: Optional[str] = None) -> bool:
        if chat_id in config.ADMIN_IDS:
            return True
        if username:
            clean_un = username.lower().lstrip('@')
            admin_uns = [u.lower().lstrip('@') for u in config.ADMIN_USERNAMES]
            if clean_un in admin_uns:
                if chat_id not in config.ADMIN_IDS:
                    config.ADMIN_IDS.append(chat_id)
                return True
        return False

    # --- Keyboards ---
    def get_main_keyboard(self, user_id: int) -> Dict[str, Any]:
        user = database.get_user(user_id)
        admin_btn = []
        user_un = (user.get('username') or '') if user else ''
        if self.is_admin(user_id, user_un):
            admin_btn = [[{'text': '⚙️ Панель администратора', 'callback_data': 'admin_panel'}]]

        keyboard = admin_btn + [
            [
                {'text': '📊 Мой профиль и статус', 'callback_data': 'status'},
                {'text': '💎 Купить подписку', 'callback_data': 'buy_menu'}
            ],
            [
                {'text': '🔑 Получить ключ / QR-код', 'callback_data': 'get_key'},
                {'text': '📥 Скачать клиент', 'callback_data': 'downloads'}
            ],
            [
                {'text': '📥 Скачать APK прямо в чат', 'callback_data': 'send_apk_file'},
                {'text': '🛡️ О протоколе AEGS', 'callback_data': 'about_proto'}
            ],
            [
                {'text': '💬 Написать создателю (@Balbes_ls)', 'url': 'https://t.me/Balbes_ls'}
            ]
        ]
        return {'inline_keyboard': keyboard}

    def get_buy_keyboard(self) -> Dict[str, Any]:
        p = config.PLANS.get('1_month', {'price_rub': 100})
        buttons = [
            [{'text': f"💎 Оформить подписку на 1 месяц — {p['price_rub']} RUB", 'callback_data': "select_plan:1_month"}],
            [{'text': '💬 Написать создателю (@Balbes_ls)', 'url': 'https://t.me/Balbes_ls'}],
            [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
        ]
        return {'inline_keyboard': buttons}

    # --- Handlers ---
    def handle_start(self, chat_id: int, username: Optional[str], first_name: str, args: str):
        user = database.get_or_create_user(chat_id, username, first_name)
        status = database.check_subscription_status(chat_id)

        # Ensure admin ID is registered if Balbes_ls starts bot
        if self.is_admin(chat_id, username) and chat_id not in config.ADMIN_IDS:
            config.ADMIN_IDS.append(chat_id)

        welcome_text = (
            f"👋 Добро пожаловать в <b>AEGS Titan Protocol</b>!\n\n"
            f"👤 ID аккаунта: <code>{chat_id}</code>\n"
            f"📌 Статус подписки: <b>{status['status_label']}</b>\n"
        )

        if status['active']:
            welcome_text += (
                f"⏳ Срок действия: до <b>{status['expires_at']} UTC</b> "
                f"({status['days_left']} д. {status['hours_left'] % 24} ч.)\n"
                f"📱 <b>Лимит устройств: до 4 шт одновременно</b> (ПК, Android, iOS)\n"
            )
        else:
            welcome_text += (
                "💎 <b>Стоимость подписки:</b> всего от <b>100 рублей в месяц</b>!\n"
                "⚡ <b>Правило подписки:</b> при покупке любого тарифа вы автоматически получаете "
                "возможность одновременного подключения <b>до 4 устройств (максимум 4 шт и не более)</b>.\n"
            )

        welcome_text += "\nВыберите интересующий раздел:"
        self.send_message(chat_id, welcome_text, reply_markup=self.get_main_keyboard(chat_id))

    def handle_status(self, chat_id: int, message_id: Optional[int] = None):
        status = database.check_subscription_status(chat_id)
        user = status.get('user', {})

        text = (
            "📊 <b>Информация о вашей учетной записи:</b>\n"
            "----------------------------------------\n"
            f"👤 ID аккаунта: <code>{chat_id}</code>\n"
            f"🔑 Идентификатор ключа: <code>{status['key_id']}</code>\n"
            f"🌐 Сервер: <b>{config.SERVER_IP}:{config.SERVER_PORT}</b>\n"
            f"📱 <b>Максимум устройств: 4 шт (одновременно)</b>\n"
            f"📌 Статус подписки: <b>{status['status_label']}</b>\n"
        )

        if status['active']:
            text += f"⏳ Активна до: <b>{status['expires_at']} UTC</b> ({status['days_left']} д. {status['hours_left'] % 24} ч.)\n"
        else:
            text += "⚠️ Подписка не активна. Оформите доступ всего от 100 RUB/мес.\n"

        text += (
            "----------------------------------------\n"
            f"💬 Поддержка создателя: @{config.SUPPORT_USERNAME}"
        )

        markup = {
            'inline_keyboard': [
                [{'text': '🔑 Открыть ключ и QR-код', 'callback_data': 'get_key'}],
                [{'text': '💎 Продлить / Купить подписку', 'callback_data': 'buy_menu'}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }

        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_buy_menu(self, chat_id: int, message_id: Optional[int] = None):
        plan = config.PLANS.get('1_month', {'price_rub': 100, 'name': '1 месяц (30 дней)'})
        text = (
            "💎 <b>Подписка на протокол AEGS Titan VPN:</b>\n\n"
            "Доступен единый ежемесячный тариф:\n"
            f"• <b>{plan['name']}</b> — <b>{plan['price_rub']} RUB</b>\n\n"
            "📱 <b>Лимит устройств:</b> до <b>4 устройств одновременно (макс. 4 шт)</b>.\n"
            "🛡️ <b>Функции:</b> Anti-DPI QUIC Mimicry, нулевой пинг, скорость до 940 Мбит/с.\n\n"
            "💳 Оплата производится переводом на карту / СБП лично администратору @Balbes_ls.\n"
            "Нажмите кнопку ниже для оформления заявки на подписку:"
        )
        markup = self.get_buy_keyboard()
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_select_plan(self, chat_id: int, message_id: int, plan_id: str):
        plan = config.PLANS.get(plan_id)
        if not plan:
            return

        text = (
            f"📋 <b>Выбранный тариф:</b> {plan['name']}\n"
            f"⏳ Срок действия: <b>{plan['days']} дней</b>\n"
            f"💰 Стоимость: <b>{plan['price_rub']} RUB</b>\n"
            f"📱 Лимит: <b>до 4 устройств одновременно (макс. 4 шт)</b>\n\n"
            f"💳 <b>Как произвести оплату:</b>\n"
            f"Оплата принимается переводом на карту / СБП напрямую администратору:\n"
            f"👉 <b>@{config.SUPPORT_USERNAME}</b>\n\n"
            f"📌 <b>Порядок действий:</b>\n"
            f"1. Переведите <b>{plan['price_rub']} RUB</b> по СБП или напишите @{config.SUPPORT_USERNAME} для получения номера карты.\n"
            f"2. После перевода нажмите кнопку <b>«✅ Я оплатил (Отправить заявку)»</b> ниже.\n\n"
            f"⚠️ <i>Заявка моментально поступит администратору @{config.SUPPORT_USERNAME} с вопросом «Вам пришла оплата {plan['price_rub']} RUB от пользователя?». "
            f"И ТОЛЬКО ПОСЛЕ ТОГО, как @{config.SUPPORT_USERNAME} нажмет подтверждение, бот автоматически сгенерирует и выдаст вам реальный рабочий ключ!</i>"
        )

        markup = {
            'inline_keyboard': [
                [{'text': f"✅ Я оплатил {plan['price_rub']} RUB (Отправить заявку)", 'callback_data': f"submit_order:{plan_id}"}],
                [{'text': f'💬 Написать администратору (@{config.SUPPORT_USERNAME})', 'url': f'https://t.me/{config.SUPPORT_USERNAME}'}],
                [{'text': '◀️ Назад к тарифам', 'callback_data': 'buy_menu'}]
            ]
        }
        self.edit_message_text(chat_id, message_id, text, reply_markup=markup)

    def handle_get_key(self, chat_id: int):
        status = database.check_subscription_status(chat_id)
        user = status.get('user')
        if not user:
            self.send_message(chat_id, "Пользователь не найден.")
            return

        if not status['active']:
            text = (
                "⚠️ <b>У вас нет активной подписки.</b>\n\n"
                "Стоимость подписки: <b>от 100 рублей в месяц</b>.\n"
                "При оформлении подписки вы получаете ключ с возможностью "
                "подключения <b>до 4 устройств максимум</b>.\n"
                "Нажмите кнопку ниже, чтобы выбрать тариф:"
            )
            markup = {
                'inline_keyboard': [
                    [{'text': '💎 Купить подписку (от 100 руб)', 'callback_data': 'buy_menu'}],
                    [{'text': '💬 Связаться с @Balbes_ls', 'url': 'https://t.me/Balbes_ls'}],
                    [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
                ]
            }
            self.send_message(chat_id, text, reply_markup=markup)
            return

        aegs_uri = f"aegs://{config.SERVER_IP}:{config.SERVER_PORT}?token={user['aegs_token']}&proto=titan_quic&key_id={user['aegs_key_id']}"
        
        caption = (
            f"🔑 <b>Ваш персональный ключ AEGS Titan:</b>\n\n"
            f"<code>{aegs_uri}</code>\n\n"
            f"📱 <b>Разрешено устройств: до 4 шт одновременно</b> (ПК, Android, iOS)\n"
            f"⏳ Активен до: <b>{status['expires_at']} UTC</b>\n"
            f"🌐 Сервер: {config.SERVER_IP}:{config.SERVER_PORT}\n\n"
            "📌 <b>Инструкция по подключению:</b>\n"
            "1. Скопируйте ссылку нажатием на текст выше.\n"
            "2. Откройте приложение AEGS VPN на Android или ПК.\n"
            "3. Нажмите «Вставить ключ из буфера» или отсканируйте QR-код ниже.\n"
            "4. Включите переключатель и пользуйтесь свободным интернетом!"
        )

        markup = {
            'inline_keyboard': [
                [{'text': '📥 Скачать клиент AEGS', 'callback_data': 'downloads'}],
                [{'text': '📊 Проверить статус', 'callback_data': 'status'}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }

        qr_bytes = generate_qr_code_png(aegs_uri)
        if qr_bytes:
            self.send_photo(chat_id, qr_bytes, caption=caption, reply_markup=markup)
        else:
            self.send_message(chat_id, caption, reply_markup=markup)

    def handle_downloads(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "📥 <b>Клиентские приложения AEGS Titan Protocol:</b>\n\n"
            "📱 <b>Android:</b>\n"
            f"• Прямая загрузка APK: <a href='{config.APK_DOWNLOAD_URL}'>AEGS-v6.0-titan.apk</a>\n"
            "• Поддержка: Android 8.0 - 15.0+, Split-Tunneling для сервисов РФ (банки напрямую), встроенный Anti-DPI.\n\n"
            "💻 <b>Windows / Linux (ПК):</b>\n"
            "• Клиент для ПК доступен в репозитории проекта.\n"
            "• Запуск в 1 клик через скрипт <code>AEGS.bat</code> (GUI с поддержкой импорта ключа и раздельного туннелирования).\n\n"
            "📱 <b>Лимит:</b> один ключ можно использовать одновременно на <b>4 любых ваших устройствах</b>."
        )
        markup = {
            'inline_keyboard': [
                [{'text': '📥 Отправить APK файл прямо сюда в чат', 'callback_data': 'send_apk_file'}],
                [{'text': '🌐 Скачать APK с GitHub', 'url': config.APK_DOWNLOAD_URL}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_support_menu(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "💬 <b>Служба поддержки пользователей:</b>\n\n"
            "Главный администратор и создатель: <b>@Balbes_ls</b>\n\n"
            "Вы можете написать администратору напрямую в Telegram для решения любых вопросов по оплате, "
            "настройке приложений или работе серверов."
        )
        markup = {
            'inline_keyboard': [
                [{'text': '💬 Написать @Balbes_ls в Telegram', 'url': 'https://t.me/Balbes_ls'}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def handle_about_proto(self, chat_id: int, message_id: Optional[int] = None):
        text = (
            "🛡️ <b>О протоколе AEGS v6 Titan:</b>\n\n"
            "• <b>Полная невидимость для DPI:</b> маскировка заголовков под QUIC Initial и STUN Binding.\n"
            "• <b>Асимметричная криптография:</b> X25519 (ECDH) + ChaCha20-Poly1305 + Blake2b.\n"
            "• <b>Защита от активного зондирования:</b> Drop-mode с эмуляцией ответа STUN.\n"
            "• <b>Скорость:</b> прямое туннелирование UDP на скорости до 940 Мбит/с с нулевыми накладными расходами.\n"
            "• <b>Лимит устройств:</b> до 4 устройств на один ключ одновременно."
        )
        markup = {
            'inline_keyboard': [
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)


    def handle_create_manual_key(self, chat_id: int, days: int = 30, speed: int = 940, note: str = ""):
        res = database.create_manual_key(days=days, speed_mbps=speed, note=note, admin_id=chat_id)
        token = res['token']
        key_id = res['key_id']
        expires_at = res['expires_at']

        aegs_uri = f"aegs://{config.SERVER_IP}:{config.SERVER_PORT}?token={token}&proto=titan_quic&key_id={key_id}&speed={speed}"

        speed_label = f"{speed} Мбит/с" if speed < 1000 else "1 Гбит/с (Безлимит)"
        duration_label = f"{days} дней" if days < 9000 else "Бессрочно / Навсегда"

        caption = (
            "🔑 <b>РУЧНОЙ КЛЮЧ ДОСТУПА СОЗДАН!</b>\n\n"
            f"👤 Создатель: <b>@{config.SUPPORT_USERNAME}</b>\n"
            f"⏳ Срок действия: <b>{duration_label}</b> (до {expires_at} UTC)\n"
            f"⚡ Скорость туннеля: <b>{speed_label}</b>\n"
            f"📱 Разрешено устройств: <b>до 4 шт одновременно</b>\n"
            f"🌐 Сервер: <code>{config.SERVER_IP}:{config.SERVER_PORT}</code>\n"
            f"🏷️ Заметка/Клиент: <i>{note or 'Ручная выдача'}</i>\n\n"
            f"🔗 <b>Ссылка для подключения (aegs://):</b>\n"
            f"<code>{aegs_uri}</code>\n\n"
            "📌 <i>Ключ уже синхронизирован с сервером! Вы можете переслать это сообщение клиенту. "
            "Клиент сможет вставить ссылку в приложении на Android или ПК.</i>"
        )

        markup = {
            'inline_keyboard': [
                [{'text': '⚙️ Панель управления', 'callback_data': 'admin_panel'}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }

        qr_bytes = generate_qr_code_png(aegs_uri)
        if qr_bytes:
            self.send_photo(chat_id, qr_bytes, caption=caption, reply_markup=markup)
        else:
            self.send_message(chat_id, caption, reply_markup=markup)

    def broadcast_app_update(self, admin_chat_id: int, custom_text: Optional[str] = None):
        user_ids = database.get_all_user_chat_ids()
        if not user_ids:
            self.send_message(admin_chat_id, "⚠️ Нет пользователей в базе данных для рассылки.")
            return

        self.send_message(admin_chat_id, f"📢 Начинаю рассылку обновления для {len(user_ids)} пользователей...")

        broadcast_text = custom_text or (
            "🚀 <b>ВЫШЛО ОБНОВЛЕНИЕ AEGS TITAN VPN — v6.5!</b>\n\n"
            "• <b>Что нового в этой версии:</b>\n"
            "  ✓ Убран оранжевый артефакт с главного экрана\n"
            "  ✓ В настройках скрыты лишние системные службы — отображаются только ваши реальные приложения\n"
            "  ✓ Добавлена кнопка «Поделиться ключом» (до 4 устройств одновременно)\n"
            "  ✓ Удобное подключение и прямая вставка ключа\n"
            "  ✓ Повышена скорость туннеля и стабильность соединения\n\n"
            "📥 Нажмите кнопку ниже, чтобы получить файл APK прямо в чат Telegram:"
        )

        markup = {
            'inline_keyboard': [
                [{'text': '📥 Скачать APK файл прямо в чат', 'callback_data': 'send_apk_file'}],
                [{'text': '🔑 Мой профиль и ключ', 'callback_data': 'get_key'}]
            ]
        }

        success = 0
        failed = 0
        for uid in user_ids:
            try:
                res = self.send_message(uid, broadcast_text, reply_markup=markup)
                if res and res.get('ok'):
                    success += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        self.send_message(admin_chat_id, f"✅ <b>Рассылка завершена!</b>\n\nУспешно доставлено: {success}\nОшибок/заблокировано: {failed}")

    def handle_admin_panel(self, chat_id: int, message_id: Optional[int] = None):
        user = database.get_user(chat_id)
        user_un = (user.get('username') or '') if user else ''
        if not self.is_admin(chat_id, user_un):
            self.send_message(chat_id, "⛔ Доступ запрещен. Панель управления доступна только главному администратору @Balbes_ls.")
            return

        stats = database.get_admin_stats()
        text = (
            "⚙️ <b>Панель администратора (@Balbes_ls):</b>\n"
            "----------------------------------------\n"
            f"Всего пользователей: {stats['total_users']}\n"
            f"Активных подписок: {stats['active_subs']}\n"
            f"Оплаченных заказов: {stats['paid_cnt']}\n"
            f"Общая выручка: {stats['total_revenue']} RUB\n"
            f"Сервер VPN: {config.SERVER_IP}:{config.SERVER_PORT}\n"
            "----------------------------------------\n"
            "Все входящие заявки на оплату приходят сюда с кнопками подтверждения."
        )
        markup = {
            'inline_keyboard': [
                [{'text': '🔑 Создать ключ вручную (любой срок/скорость)', 'callback_data': 'admin_manual_key_menu'}],
                [{'text': '📢 Разослать уведомление об обновлении', 'callback_data': 'admin_broadcast_prompt'}],
                [{'text': '🔄 Обновить статистику', 'callback_data': 'admin_panel'}],
                [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
            ]
        }
        if message_id:
            self.edit_message_text(chat_id, message_id, text, reply_markup=markup)
        else:
            self.send_message(chat_id, text, reply_markup=markup)

    def process_update(self, update: Dict[str, Any]):
        if 'message' in update:
            msg = update['message']
            chat_id = msg['chat']['id']
            username = msg.get('from', {}).get('username')
            first_name = msg.get('from', {}).get('first_name', 'User')
            text = msg.get('text', '').strip()

            # Automatically register Balbes_ls chat ID if username matches
            if username and username.lower().lstrip('@') == 'balbes_ls':
                if chat_id not in config.ADMIN_IDS:
                    config.ADMIN_IDS.append(chat_id)

            if text.startswith('/start'):
                args = text[7:].strip()
                self.handle_start(chat_id, username, first_name, args)
            elif text.startswith('/status') or text.lower() == 'статус':
                self.handle_status(chat_id)
            elif text.startswith('/buy') or text.lower() == 'купить':
                self.handle_buy_menu(chat_id)
            elif text.startswith('/key') or text.lower() == 'ключ':
                self.handle_get_key(chat_id)
            elif text.startswith('/trial'):
                self.send_message(chat_id, "❌ Бесплатный тестовый период отключен. Подписка доступна всего от 100 руб/мес на 4 устройства в меню /buy.")
            elif text.startswith('/apk'):
                self.send_apk_file(chat_id)
            elif text.startswith('/create_key'):
                if not self.is_admin(chat_id, username):
                    self.send_message(chat_id, "⛔ Доступ запрещен. Только администратор @Balbes_ls может создавать ключи.")
                else:
                    parts = text.split()
                    days = 30
                    speed = 940
                    note = ""
                    if len(parts) > 1 and parts[1].isdigit():
                        days = int(parts[1])
                    if len(parts) > 2 and parts[2].isdigit():
                        speed = int(parts[2])
                    if len(parts) > 3:
                        note = " ".join(parts[3:])
                    self.handle_create_manual_key(chat_id, days=days, speed=speed, note=note)
            elif text.startswith('/broadcast_update'):
                if not self.is_admin(chat_id, username):
                    self.send_message(chat_id, "⛔ Доступ запрещен. Только администратор @Balbes_ls может запускать рассылку.")
                else:
                    custom = text[17:].strip()
                    self.broadcast_app_update(chat_id, custom or None)
            elif text.startswith('/admin'):
                self.handle_admin_panel(chat_id)
            elif text.startswith('/promo'):
                parts = text.split(maxsplit=1)
                if len(parts) > 1:
                    ok, res = database.apply_promocode(chat_id, parts[1])
                    self.send_message(chat_id, res, reply_markup=self.get_main_keyboard(chat_id))
                else:
                    self.send_message(chat_id, "Формат: /promo <код>")
            else:
                self.send_message(chat_id, "Главное меню:", reply_markup=self.get_main_keyboard(chat_id))

        elif 'callback_query' in update:
            cb = update['callback_query']
            cb_id = cb['id']
            chat_id = cb['message']['chat']['id']
            message_id = cb['message']['message_id']
            sender_un = cb.get('from', {}).get('username')
            sender_fn = cb.get('from', {}).get('first_name', 'User')
            data = cb.get('data', '')

            self.answer_callback_query(cb_id)

            if sender_un and sender_un.lower().lstrip('@') == 'balbes_ls':
                if chat_id not in config.ADMIN_IDS:
                    config.ADMIN_IDS.append(chat_id)

            if data == 'main_menu':
                self.handle_start(chat_id, sender_un, sender_fn, '')
            elif data == 'status':
                self.handle_status(chat_id, message_id)
            elif data == 'buy_menu':
                self.handle_buy_menu(chat_id, message_id)
            elif data.startswith('select_plan:'):
                plan_id = data.split(':', 1)[1]
                self.handle_select_plan(chat_id, message_id, plan_id)

            # Workflow: User submits payment request
            elif data.startswith('submit_order:'):
                plan_id = data.split(':', 1)[1]
                plan = config.PLANS.get(plan_id, config.PLANS.get('1_month'))

                order_id = database.create_order(
                    user_id=chat_id,
                    username=sender_un,
                    first_name=sender_fn,
                    plan_id=plan_id,
                    amount=plan['price_rub'],
                    currency='RUB'
                )

                # Buyer confirmation
                buyer_text = (
                    f"⏳ <b>Заявка #{order_id} отправлена администратору!</b>\n\n"
                    f"📦 Тариф: <b>{plan['name']}</b> ({plan['price_rub']} RUB)\n"
                    f"📱 Лимит: до 4 устройств одновременно (макс. 4 шт)\n\n"
                    f"Администратор <b>@Balbes_ls</b> проверяет поступление оплаты.\n"
                    f"Как только @Balbes_ls подтвердит перевод, бот мгновенно отправит вам рабочий ключ доступа!\n\n"
                    f"💬 Отправить чек или написать администратору: @Balbes_ls"
                )
                self.edit_message_text(chat_id, message_id, buyer_text, reply_markup={
                    'inline_keyboard': [
                        [{'text': '💬 Написать @Balbes_ls в Telegram', 'url': 'https://t.me/Balbes_ls'}],
                        [{'text': '🔄 Проверить статус заявки', 'callback_data': f"check_order:{order_id}"}],
                        [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
                    ]
                })

                # Admin notification directly to @Balbes_ls
                admin_text = (
                    f"🔔 <b>ВНИМАНИЕ: Новая заявка на покупку!</b>\n\n"
                    f"📦 <b>Заказ:</b> <code>#{order_id}</code>\n"
                    f"👤 <b>Покупатель:</b> @{sender_un or 'нет_юзернейма'} (ID: <code>{chat_id}</code>, Имя: {sender_fn})\n"
                    f"💳 <b>Тариф:</b> {plan['name']}\n"
                    f"💰 <b>Сумма к получению:</b> {plan['price_rub']} RUB\n\n"
                    f"❓ <b>Вам пришла оплата {plan['price_rub']} RUB от @{sender_un or sender_fn}?</b>"
                )
                admin_markup = {
                    'inline_keyboard': [
                        [
                            {'text': '✅ Да, пришла (Выдать ключ)', 'callback_data': f"admin_approve:{order_id}"},
                            {'text': '❌ Отклонить', 'callback_data': f"admin_reject:{order_id}"}
                        ]
                    ]
                }
                for adm_id in config.ADMIN_IDS:
                    self.send_message(adm_id, admin_text, reply_markup=admin_markup)

            # Workflow: Admin approves payment
            elif data.startswith('admin_approve:'):
                if not self.is_admin(chat_id, sender_un):
                    self.send_message(chat_id, "⛔ Доступ запрещен. Только администратор @Balbes_ls может одобрять заявки.")
                    return

                order_id = data.split(':', 1)[1]
                ok, note, order = database.approve_order(order_id, chat_id)
                if ok and order:
                    self.edit_message_text(chat_id, message_id,
                        f"✅ <b>Заказ #{order_id} подтвержден!</b>\n\n"
                        f"👤 Пользователь: @{order.get('username') or order['user_id']}\n"
                        f"💰 Сумма: {order['amount']} RUB\n"
                        f"🎉 Ключ успешно сгенерирован и отправлен покупателю!"
                    )
                    buyer_id = order['user_id']
                    plan = config.PLANS.get(order['plan_id'], config.PLANS.get('1_month'))
                    self.send_message(buyer_id,
                        f"🎉 <b>Оплата по заказу #{order_id} успешно подтверждена администратором @Balbes_ls!</b>\n\n"
                        f"✅ Ваша подписка на тариф <b>«{plan['name']}»</b> активна!\n"
                        f"📱 Доступно подключение: <b>до 4 устройств одновременно (макс. 4 шт)</b>.\n\n"
                        f"Ниже сформирован ваш персональный ключ доступа:"
                    )
                    self.handle_get_key(buyer_id)
                else:
                    self.send_message(chat_id, f"⚠️ Не удалось подтвердить заказ: {note}")

            # Workflow: Admin rejects payment
            elif data.startswith('admin_reject:'):
                if not self.is_admin(chat_id, sender_un):
                    self.send_message(chat_id, "⛔ Доступ запрещен. Только администратор @Balbes_ls может отклонять заявки.")
                    return

                order_id = data.split(':', 1)[1]
                ok, note, order = database.reject_order(order_id, chat_id)
                if ok and order:
                    self.edit_message_text(chat_id, message_id,
                        f"❌ <b>Заказ #{order_id} отклонен.</b>"
                    )
                    buyer_id = order['user_id']
                    self.send_message(buyer_id,
                        f"❌ <b>Ваша заявка #{order_id} была отклонена администратором @Balbes_ls.</b>\n\n"
                        f"Если вы совершили перевод средств, свяжитесь напрямую с администратором: @Balbes_ls",
                        reply_markup={'inline_keyboard': [
                            [{'text': '💬 Написать @Balbes_ls', 'url': 'https://t.me/Balbes_ls'}],
                            [{'text': '◀️ Главное меню', 'callback_data': 'main_menu'}]
                        ]}
                    )

            # Check status of order
            elif data.startswith('check_order:'):
                order_id = data.split(':', 1)[1]
                order = database.get_order(order_id)
                if not order:
                    self.send_message(chat_id, "❌ Заказ не найден.")
                elif order['status'] == 'pending':
                    self.send_message(chat_id, f"⏳ Заказ #{order_id} находится на проверке у @Balbes_ls. Пожалуйста, ожидайте или напишите @Balbes_ls.")
                elif order['status'] == 'approved':
                    self.send_message(chat_id, f"✅ Заказ #{order_id} подтвержден! Нажмите кнопку ниже для получения ключа:", reply_markup={
                        'inline_keyboard': [[{'text': '🔑 Открыть ключ', 'callback_data': 'get_key'}]]
                    })
                elif order['status'] == 'rejected':
                    self.send_message(chat_id, f"❌ Заказ #{order_id} отклонен администратором. Напишите @Balbes_ls.")

            elif data == 'activate_trial':
                self.send_message(chat_id, "❌ Бесплатный тестовый период отключен. Подписка доступна всего от 100 руб/мес на 4 устройства в меню /buy.")
            elif data == 'get_key':
                self.handle_get_key(chat_id)
            elif data == 'downloads':
                self.handle_downloads(chat_id, message_id)
            elif data == 'support_menu':
                self.handle_support_menu(chat_id, message_id)

            elif data == 'about_proto':
                self.handle_about_proto(chat_id, message_id)
            elif data == 'admin_panel':
                self.handle_admin_panel(chat_id, message_id)

    def run_polling(self):
        logger.info(f"AEGS Titan Telegram Bot started. Server: {config.SERVER_IP}:{config.SERVER_PORT}")
        while True:
            try:
                updates = self._api_call('getUpdates', {'offset': self.offset, 'timeout': 20})
                if updates and updates.get('ok'):
                    for up in updates.get('result', []):
                        self.offset = up['update_id'] + 1
                        try:
                            self.process_update(up)
                        except Exception as e:
                            logger.error(f"Error handling update {up.get('update_id')}: {e}", exc_info=True)
                else:
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Polling loop error: {e}")
                time.sleep(3)

def main():
    logger.info("Initializing database...")
    database.init_db()

    logger.info("Starting Subscription Lifecycle Worker...")
    start_worker()

    bot = AegsTelegramBot(config.BOT_TOKEN)
    bot.run_polling()

if __name__ == "__main__":
    main()
