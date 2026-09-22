"""
AEGS Titan - Subscription Lifecycle & Expiration Background Worker
"""

import time
import threading
import logging
from typing import Callable, Any
from . import database
from . import config

logger = logging.getLogger('sub_worker')

class SubscriptionWorker:
    def __init__(self, send_message_callback: Callable[[int, str, Any], None]):
        self.send_message = send_message_callback
        self._running = False
        self._thread = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, name="AEGS-SubWorker", daemon=True)
        self._thread.start()
        logger.info("Subscription lifecycle worker initialized.")

    def stop(self):
        self._running = False

    def _run_loop(self):
        while self._running:
            try:
                self._check_expirations()
            except Exception as e:
                logger.error(f"Error in subscription worker loop: {e}")
            for _ in range(60):
                if not self._running:
                    break
                time.sleep(1)

    def _check_expirations(self):
        # 1. 72-hour warning
        users_72h = database.get_expiring_users(hours_left_min=48, hours_left_max=72, flag_col='warned_72h')
        for u in users_72h:
            uid = u['user_id']
            msg = (
                "Уведомление о сроке действия подписки:\n"
                f"Срок действия вашей подписки AEGS Titan истекает через 3 дня ({u['sub_expires_at']} UTC).\n"
                "Для бесперебойного доступа выполните продление в разделе тарифов."
            )
            try:
                self.send_message(uid, msg, {'action': 'extend'})
                database.mark_reminder_sent(uid, 'warned_72h')
                logger.info(f"72h notification sent to {uid}")
            except Exception as e:
                logger.warning(f"Failed to send 72h notification to {uid}: {e}")

        # 2. 24-hour warning
        users_24h = database.get_expiring_users(hours_left_min=0, hours_left_max=24, flag_col='warned_24h')
        for u in users_24h:
            uid = u['user_id']
            msg = (
                "Уведомление о скором окончании подписки:\n"
                f"Срок действия вашей подписки истекает менее чем через 24 часа ({u['sub_expires_at']} UTC).\n"
                "Продление доступно по кнопке ниже."
            )
            try:
                self.send_message(uid, msg, {'action': 'extend'})
                database.mark_reminder_sent(uid, 'warned_24h')
                logger.info(f"24h notification sent to {uid}")
            except Exception as e:
                logger.warning(f"Failed to send 24h notification to {uid}: {e}")

        # 3. Expired users
        expired_users = database.get_expired_active_users()
        for u in expired_users:
            uid = u['user_id']
            database.deactivate_user(uid)
            msg = (
                "Срок действия подписки AEGS Titan завершен.\n"
                "Маршрутизация трафика через сервер приостановлена.\n"
                "Для возобновления доступа выберите тарифный план."
            )
            try:
                self.send_message(uid, msg, {'action': 'buy'})
                logger.info(f"User {uid} subscription expired and deactivated.")
            except Exception as e:
                logger.warning(f"Failed to send expiration message to {uid}: {e}")


_worker_instance = None

def start_worker(send_message_callback=None):
    global _worker_instance
    if _worker_instance is None:
        def dummy_cb(uid, msg, extra=None):
            pass
        cb = send_message_callback or dummy_cb
        _worker_instance = SubscriptionWorker(cb)
        _worker_instance.start()
    return _worker_instance
