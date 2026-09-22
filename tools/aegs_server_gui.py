#!/usr/bin/env python3
"""
==============================================================================
AEGS v4 Pantheon -- Визуальный графический монитор сервера (GUI)
==============================================================================
Наглядное окно для Windows:
- Отображает статус сервера (ОНЛАЙН / ОФФЛАЙН)
- Список всех подключившихся друзей (IP, порт, статус)
- Живой поток сетевых запросов и трафика
- Кнопки управления (Старт / Стоп)
==============================================================================
"""

import sys
import os
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime

# Windows UTF-8 stdout
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from aegs_server import AegsServer

class AegsServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AEGS v4 Pantheon - Панель управления сервером")
        self.root.geometry("860x620")
        self.root.minsize(700, 500)

        self.server = None
        self.server_thread = None
        self.is_running = False
        self.log_queue = queue.Queue()

        self.setup_ui()
        self.root.after(100, self.process_log_queue)

    def setup_ui(self):
        # Цветовая схема
        self.bg_color = "#1e1e2e"
        self.panel_color = "#252538"
        self.text_color = "#cdd6f4"
        self.green_color = "#a6e3a1"
        self.red_color = "#f38ba8"
        self.blue_color = "#89b4fa"

        self.root.configure(bg=self.bg_color)

        # Верхняя панель статуса
        top_frame = tk.Frame(self.root, bg=self.panel_color, pady=12, padx=16)
        top_frame.pack(fill=tk.X, padx=12, pady=(12, 6))

        title_lbl = tk.Label(top_frame, text="AEGS v4 PANTHEON SERVER", font=("Segoe UI", 14, "bold"), fg=self.blue_color, bg=self.panel_color)
        title_lbl.pack(side=tk.LEFT)

        self.status_lbl = tk.Label(top_frame, text="● ОФФЛАЙН", font=("Segoe UI", 12, "bold"), fg=self.red_color, bg=self.panel_color)
        self.status_lbl.pack(side=tk.RIGHT, padx=10)

        # Информационная карточка
        card_frame = tk.Frame(self.root, bg=self.panel_color, pady=8, padx=16)
        card_frame.pack(fill=tk.X, padx=12, pady=4)

        self.info_port_lbl = tk.Label(card_frame, text="Порты: 50001-50005 (Port Hopping x5)", font=("Segoe UI", 10), fg=self.text_color, bg=self.panel_color)
        self.info_port_lbl.pack(side=tk.LEFT)

        self.clients_count_lbl = tk.Label(card_frame, text="Подключено друзей: 0", font=("Segoe UI", 10, "bold"), fg=self.green_color, bg=self.panel_color)
        self.clients_count_lbl.pack(side=tk.RIGHT)

        # Таблица подключенных клиентов
        table_frame = tk.LabelFrame(self.root, text=" Активные подключения ", font=("Segoe UI", 10, "bold"), fg=self.blue_color, bg=self.panel_color, padx=8, pady=8)
        table_frame.pack(fill=tk.X, padx=12, pady=6)

        columns = ("ip", "port", "time", "proto", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=4)
        self.tree.heading("ip", text="IP Адрес")
        self.tree.heading("port", text="Порт")
        self.tree.heading("time", text="Время подключения")
        self.tree.heading("proto", text="Протокол")
        self.tree.heading("status", text="Статус")

        self.tree.column("ip", width=150)
        self.tree.column("port", width=80)
        self.tree.column("time", width=140)
        self.tree.column("proto", width=240)
        self.tree.column("status", width=120)
        self.tree.pack(fill=tk.X)

        # Лог событий в реальном времени
        log_frame = tk.LabelFrame(self.root, text=" Живой мониторинг трафика и событий ", font=("Segoe UI", 10, "bold"), fg=self.blue_color, bg=self.panel_color, padx=8, pady=8)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#11111b", fg="#a6adc8", font=("Consolas", 10), insertbackground="white")
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Нижняя панель кнопок
        btn_frame = tk.Frame(self.root, bg=self.bg_color, pady=8)
        btn_frame.pack(fill=tk.X, padx=12)

        self.start_btn = tk.Button(btn_frame, text="▶ Запустить сервер", font=("Segoe UI", 10, "bold"), bg="#a6e3a1", fg="#11111b", padx=16, pady=6, command=self.start_server, relief=tk.FLAT)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = tk.Button(btn_frame, text="⏹ Остановить", font=("Segoe UI", 10, "bold"), bg="#f38ba8", fg="#11111b", padx=16, pady=6, command=self.stop_server, state=tk.DISABLED, relief=tk.FLAT)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        clear_btn = tk.Button(btn_frame, text="Очистить лог", font=("Segoe UI", 9), bg="#45475a", fg=self.text_color, padx=12, pady=6, command=self.clear_log, relief=tk.FLAT)
        clear_btn.pack(side=tk.RIGHT, padx=4)

        # Автоматический старт сервера при открытии окна
        self.root.after(300, self.start_server)

    def log(self, message: str):
        self.log_queue.put(message)

    def process_log_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)

        # Обновляем список клиентов из сервера если он запущен
        if self.server:
            with self.server.stats_lock:
                clients = list(self.server.active_clients.values())
            
            # Обновляем счетчик
            self.clients_count_lbl.config(text=f"Подключено друзей: {len(clients)}")

            # Обновляем таблицу если изменилось
            existing = {self.tree.item(item)["values"][0]: item for item in self.tree.get_children()}
            for c in clients:
                ip = c["addr"][0]
                port = str(c["addr"][1])
                t = c["connected_at"]
                proto = "AEGS v4 Pantheon (X25519+ChaCha20)"
                st = "АКТИВЕН"
                if ip in existing:
                    pass
                else:
                    self.tree.insert("", tk.END, values=(ip, port, t, proto, st))

        self.root.after(150, self.process_log_queue)

    def start_server(self):
        if self.is_running:
            return

        self.is_running = True
        self.server = AegsServer(base_port=50001, port_count=5)
        
        # Перехватываем вывод сервера в наш GUI лог
        original_print = self.server.print_client_connected_banner
        def gui_banner(addr, mode):
            original_print(addr, mode)
            self.log(f"[{datetime.now().strftime('%H:%M:%S')}] [+] ДРУГ ПОДКЛЮЧИЛСЯ: {addr[0]}:{addr[1]} ({mode})")
        self.server.print_client_connected_banner = gui_banner

        original_handle = self.server.handle_client_payload
        def gui_handle(pt, client_addr):
            if len(pt) >= 5:
                cmd = pt[4]
                if cmd == 1: # CMD_CONNECT
                    host_len = pt[5]
                    host = pt[6:6 + host_len].decode(errors="replace")
                    port = int.from_bytes(pt[6 + host_len:8 + host_len], "big")
                    self.log(f"[{datetime.now().strftime('%H:%M:%S')}] [ТРАФИК] Клиент {client_addr[0]} -> {host}:{port}")
            original_handle(pt, client_addr)
        self.server.handle_client_payload = gui_handle

        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        self.status_lbl.config(text="● ОНЛАЙН (Слушает 50001-50005)", fg=self.green_color)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] [✓] Сервер AEGS v4 успешно запущен и ожидает подключений!")

    def stop_server(self):
        if not self.is_running:
            return
        self.is_running = False
        if self.server:
            for s in self.server.sockets:
                try:
                    s.close()
                except Exception:
                    pass
        self.status_lbl.config(text="● ОФФЛАЙН", fg=self.red_color)
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] [*] Сервер остановлен.")

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)

def main():
    root = tk.Tk()
    app = AegsServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
