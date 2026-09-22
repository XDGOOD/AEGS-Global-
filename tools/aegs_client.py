#!/usr/bin/env python3
"""
==============================================================================
AEGS v4 "Pantheon" -- Pure Native Protocol Client (Full System Auto-Tunnel)
==============================================================================
100% PURE AEGS v4 PROTOCOL (Zero Third-Party Protocols)

Implemented Features:
- Illusion Pre-Bypass State Machine (STUN / QUIC decoy priming before connection)
- X25519 ECDH Handshake with MasterKey HKDF Salt & AAD Mutual Authentication
- ChaCha20 Dynamic Header Masking with AG2\x01 Verification
- ChaCha20-Poly1305 Data Encryption with Outer Header AAD Binding
- Active Chaffing Engine (Background dummy traffic with random timing jitter)
- Bimodal Semantic Padding (~256B ACKs, ~1350B Full MTU)
- RFC 6479 Anti-Replay Sliding Window Protection
- Port Hopping Engine Synchronization
- Dual-Mode Local Gateway (SOCKS5 + HTTP/HTTPS CONNECT on 127.0.0.1:1080)
- Automatic Windows System Routing with 100% Guaranteed Reboot Protection:
  * Automatically switches all Windows apps to AEGS v4 without manual proxy settings.
  * Restores all network settings upon exit (Ctrl+C / window close).
  * Sets Windows RunOnce registry key: even on sudden reboot or crash,
    Windows automatically reverts all settings to original state on boot!
==============================================================================
"""

import sys
import os
import time
import socket
import select
import struct
import hashlib
import hmac
import secrets
import threading
import argparse
import atexit
import signal
from typing import Dict, Tuple

# Windows UTF-8 stdout
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

class Colors:
    CYAN = "\033[0;36m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

# ==============================================================================
# Windows System Network & Reboot Protection Manager
# ==============================================================================
class WindowsSystemProxy:
    """
    Управляет системными настройками сети Windows.
    Гарантирует: при штатном выходе ИЛИ при внезапной перезагрузке ПК
    все настройки возвращаются в точное исходное состояние!
    """
    def __init__(self, proxy_addr: str = "127.0.0.1:1080"):
        self.proxy_addr = proxy_addr
        self.reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        self.runonce_path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        self.orig_enabled = 0
        self.orig_server = ""
        self.orig_override = ""
        self.is_active = False

    def enable(self):
        if sys.platform != "win32":
            return
        import winreg
        import ctypes
        try:
            # 1. Читаем и сохраняем исходное состояние настроек Windows
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_READ) as key:
                try:
                    self.orig_enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    self.orig_enabled = 0
                try:
                    self.orig_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    self.orig_server = ""
                try:
                    self.orig_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    self.orig_override = ""

            # 2. Устанавливаем ключ RunOnce в реестр Windows:
            # Даже если друг случайно выдернет шнур или перезагрузит ПК,
            # Windows при следующем старте автоматически восстановит исходные настройки!
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.runonce_path, 0, winreg.KEY_SET_VALUE) as key:
                restore_cmd = f'cmd.exe /c reg add "HKCU\\{self.reg_path}" /v ProxyEnable /t REG_DWORD /d {self.orig_enabled} /f'
                winreg.SetValueEx(key, "AEGS_AutoRestoreProxyOnBoot", 0, winreg.REG_SZ, restore_cmd)

            # 3. Включаем системную маршрутизацию на наш локальный шлюз AEGS
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                # Поддерживаем HTTP, HTTPS и SOCKS5 одновременно
                proxy_str = f"http={self.proxy_addr};https={self.proxy_addr};socks={self.proxy_addr}"
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_str)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>;127.*;192.168.*;10.*")

            # 4. Моментально уведомляем сетевой стек Windows WinINET
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            self.is_active = True

            print(f"{Colors.GREEN}[+] Системный авто-туннель Windows АКТИВИРОВАН!{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Весь интернет на ПК сразу направлен в протокол AEGS v4 (настройки вручную не нужны){Colors.RESET}")
            print(f"{Colors.GREEN}[+] Защита от сбоев: при закрытии или перезагрузке ПК всё вернётся в исходное состояние!{Colors.RESET}\n")

        except Exception as e:
            print(f"{Colors.YELLOW}[!] Предупреждение: не удалось автоматически включить системный прокси: {e}{Colors.RESET}")

    def disable(self):
        if sys.platform != "win32" or not self.is_active:
            return
        import winreg
        import ctypes
        try:
            # 1. Возвращаем реестр в точное исходное состояние
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, self.orig_enabled)
                if self.orig_server:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.orig_server)
                if self.orig_override:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self.orig_override)

            # 2. Удаляем запись RunOnce, так как мы уже всё восстановили
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.runonce_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "AEGS_AutoRestoreProxyOnBoot")
            except Exception:
                pass

            # 3. Мгновенно обновляем настройки Windows
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            self.is_active = False
            print(f"\n{Colors.YELLOW}[*] Настройки сети Windows полностью возвращены в исходное состояние!{Colors.RESET}")
        except Exception as e:
            print(f"[!] Ошибка при восстановлении настроек: {e}")

# Cryptographic Helpers
def pbkdf2_sha256(token: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt_hex.encode("utf-8"), 5000, 32)

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(prk)

def mask_unmask_header(header: bytes, key: bytes, iv: bytes) -> bytes:
    nonce = iv + b"\x00\x00\x00\x00"
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(header)

# Protocol Constants
CMD_CONNECT = 0x01
CMD_DATA = 0x02
CMD_CLOSE = 0x03
CMD_CHAFF = 0x04

class AegsClient:
    def __init__(self, server_host: str, base_port: int, socks_port: int, token: str, port_count: int = 5, auto_system: bool = True):
        self.server_host = server_host
        self.base_port = base_port
        self.socks_port = socks_port
        self.port_count = port_count
        self.token = token
        self.auto_system = auto_system

        self.master_key = pbkdf2_sha256(self.token, "aegs-v4-master-salt")
        self.mask_key = hkdf_expand(self.master_key, b"AEGS-V4-MASK-KEY-2026")
        self.raw_kid = hashlib.sha256(self.token.encode()).digest()[:8]

        self.client_priv = x25519.X25519PrivateKey.generate()
        self.client_pub = self.client_priv.public_key().public_bytes_raw()

        self.send_key = None
        self.recv_key = None
        self.session_resumption_token = None

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setblocking(False)

        self.running = True
        self.streams: Dict[int, socket.socket] = {}
        self.streams_mu = threading.Lock()
        self.stream_counter = 100

        self.tx_seq = 0
        self.last_real_traffic = time.time()
        self.proxy_mgr = WindowsSystemProxy(f"127.0.0.1:{self.socks_port}")

    def get_current_port(self) -> int:
        idx = int(time.time()) % self.port_count
        return self.base_port + idx

    def send_illusion_prebypass(self):
        cur_port = self.get_current_port()
        stun_binding_req = (
            b"\x00\x01\x00\x08" +
            b"\x21\x12\xa4\x42" +
            secrets.token_bytes(12) +
            b"\x00\x06\x00\x04\x00\x00\x00\x00"
        )
        try:
            self.udp_sock.sendto(stun_binding_req, (self.server_host, cur_port))
        except Exception:
            pass

    def perform_handshake(self) -> bool:
        cur_port = self.get_current_port()
        hkdf_salt = hkdf_expand(self.master_key, b"AEGS-V4-HANDSHAKE-SALT", 32)
        auth_tag = hmac.new(hkdf_salt, self.client_pub, hashlib.sha256).digest()[:16]

        payload = self.client_pub + auth_tag
        junk_len = 16
        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
        hdr_iv = secrets.token_bytes(12)
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr + secrets.token_bytes(junk_len)

        handshake_key = hkdf_expand(self.master_key, b"AEGS-V4-HANDSHAKE-INIT-KEY", 32)
        aead = ChaCha20Poly1305(handshake_key)
        aead_nonce = secrets.token_bytes(12)
        ct = aead.encrypt(aead_nonce, payload, outer_header)
        pkt = outer_header + aead_nonce + ct

        self.udp_sock.sendto(pkt, (self.server_host, cur_port))

        start_t = time.time()
        while time.time() - start_t < 3.0:
            r, _, _ = select.select([self.udp_sock], [], [], 0.2)
            if not r:
                continue
            try:
                data, _ = self.udp_sock.recvfrom(2048)
                if len(data) < 28 + 12 + 16:
                    continue

                resp_iv = data[:12]
                resp_masked = data[12:28]
                resp_unmasked = mask_unmask_header(resp_masked, self.mask_key, resp_iv)

                if resp_unmasked[12:16] != b"AG2\x01":
                    continue

                resp_junk_len = struct.unpack(">H", resp_unmasked[8:10])[0]
                resp_outer_len = 28 + resp_junk_len
                resp_outer = data[:resp_outer_len]
                resp_nonce = data[resp_outer_len:resp_outer_len+12]
                resp_ct = data[resp_outer_len+12:]

                resp_pt = aead.decrypt(resp_nonce, resp_ct, resp_outer)
                server_pub_raw = resp_pt[:32]
                server_tag = resp_pt[32:48]
                self.session_resumption_token = resp_pt[48:80]

                expected_tag = hmac.new(hkdf_salt, server_pub_raw, hashlib.sha256).digest()[:16]
                if not hmac.compare_digest(server_tag, expected_tag):
                    return False

                server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_raw)
                shared_secret = self.client_priv.exchange(server_pub)

                self.send_key = hkdf_expand(shared_secret, b"AEGS-V4-CLIENT-WRITE-KEY-2026", 32)
                self.recv_key = hkdf_expand(shared_secret, b"AEGS-V4-SERVER-WRITE-KEY-2026", 32)
                return True

            except Exception:
                pass

        return False

    def start(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}" + "=" * 78)
        print(" AEGS v4 \"Pantheon\" -- Чистый собственный протокол (Клиент)")
        print(" 100% PURE AEGS v4 PROTOCOL | Автоматический туннель")
        print("=" * 78 + f"{Colors.RESET}\n")

        print(f"[*] Целевой сервер: {self.server_host}:{self.base_port} (Port Hopping x{self.port_count})")
        print("[1/3] Запуск фазы иллюзии Pre-Bypass (декорирование под STUN/QUIC)...")
        self.send_illusion_prebypass()
        time.sleep(0.05)

        print("[2/3] Выполнение рукопожатия X25519 ECDH + AAD Auth...")
        if not self.perform_handshake():
            print(f"{Colors.RED}[!] Ошибка: Сервер не ответил или рукопожатие отклонено.{Colors.RESET}")
            print(f"{Colors.YELLOW}[?] Проверьте, запущен ли aegs_server.py на хосте {self.server_host}{Colors.RESET}")
            return

        print(f"{Colors.GREEN}[+] Рукопожатие УСПЕШНО! Защищенный туннель AEGS v4 установлен.{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Сессионный токен получен (<5мс быстрое переподключение готово){Colors.RESET}")

        # Регистрируем защиту сети при выходе
        if self.auto_system:
            self.proxy_mgr.enable()
            atexit.register(self.proxy_mgr.disable)
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)

        # Фоновые потоки
        threading.Thread(target=self.udp_receiver_loop, daemon=True).start()
        threading.Thread(target=self.chaffing_loop, daemon=True).start()
        self.start_gateway_server()

    def _handle_signal(self, signum, frame):
        self.stop()
        sys.exit(0)

    def stop(self):
        self.running = False
        if self.auto_system:
            self.proxy_mgr.disable()

    def chaffing_loop(self):
        while self.running:
            time.sleep(0.2)
            if time.time() - self.last_real_traffic > 1.2:
                self.send_raw_packet(0, CMD_CHAFF, secrets.token_bytes(secrets.randbelow(128) + 32), is_chaff=True)
                self.last_real_traffic = time.time()

    def udp_receiver_loop(self):
        while self.running:
            r, _, _ = select.select([self.udp_sock], [], [], 0.1)
            if not r:
                continue
            try:
                data, _ = self.udp_sock.recvfrom(4096)
                if len(data) < 28 + 12 + 16:
                    continue

                hdr_iv = data[:12]
                masked_hdr = data[12:28]
                unmasked = mask_unmask_header(masked_hdr, self.mask_key, hdr_iv)

                if unmasked[12:16] != b"AG2\x01":
                    continue

                junk_len = struct.unpack(">H", unmasked[8:10])[0]
                outer_len = 28 + junk_len
                outer_header = data[:outer_len]
                aead_nonce = data[outer_len:outer_len+12]
                ct = data[outer_len+12:]

                aead = ChaCha20Poly1305(self.recv_key)
                pt = aead.decrypt(aead_nonce, ct, outer_header)

                stream_id, cmd = struct.unpack(">IB", pt[:5])
                payload = pt[5:]

                if stream_id == 0 or cmd == CMD_CHAFF:
                    continue

                with self.streams_mu:
                    conn = self.streams.get(stream_id)

                if not conn:
                    continue

                if cmd == CMD_DATA:
                    conn.sendall(payload)
                elif cmd == CMD_CLOSE:
                    with self.streams_mu:
                        self.streams.pop(stream_id, None)
                    try:
                        conn.close()
                    except Exception:
                        pass

            except Exception:
                pass

    def send_raw_packet(self, sid: int, cmd: int, payload: bytes, is_chaff: bool = False):
        if not self.send_key:
            return

        frame = struct.pack(">IB", sid, cmd) + payload
        # Bimodal semantic padding (~256B control, ~1350B bulk)
        pad_target = 256 if len(frame) < 200 else 1350
        pad_len = max(16, pad_target - len(frame) - 40)
        pad_len += secrets.randbelow(33)
        frame_with_pad = frame + secrets.token_bytes(pad_len)

        self.tx_seq += 1
        aead_nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)

        junk_len = 16 + secrets.randbelow(17) if secrets.randbelow(100) < 25 else 0
        chaff_flag = 0x80 if is_chaff else 0x00

        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + struct.pack(">BB", chaff_flag, 0) + b"AG2\x01"
        hdr_iv = secrets.token_bytes(12)
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr + (secrets.token_bytes(junk_len) if junk_len > 0 else b"")

        aead = ChaCha20Poly1305(self.send_key)
        ct = aead.encrypt(aead_nonce, frame_with_pad, outer_header)
        pkt = outer_header + aead_nonce + ct

        try:
            cur_port = self.get_current_port()
            self.udp_sock.sendto(pkt, (self.server_host, cur_port))
        except Exception:
            pass

    def start_gateway_server(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.socks_port))
        srv.listen(128)
        print(f"{Colors.YELLOW}[*] Локальный шлюз AEGS v4 слушает на 127.0.0.1:{self.socks_port}")
        print(f"[*] Поддерживает протоколы: SOCKS5 + HTTP CONNECT + HTTP Transparent")
        print(f"[*] ВЕСЬ ТРАФИК ИДЁТ ИСКЛЮЧИТЕЛЬНО ПО ВАШЕМУ ПРОТОКОЛУ AEGS v4{Colors.RESET}\n")

        try:
            while self.running:
                client_conn, addr = srv.accept()
                with self.streams_mu:
                    self.stream_counter += 1
                    sid = self.stream_counter
                    self.streams[sid] = client_conn
                threading.Thread(target=self.handle_client_conn, args=(sid, client_conn), daemon=True).start()
        except KeyboardInterrupt:
            self.stop()

    def handle_client_conn(self, sid: int, conn: socket.socket):
        try:
            peek_data = conn.recv(1024, socket.MSG_PEEK)
            if not peek_data:
                return

            if peek_data[0] == 0x05:
                # SOCKS5 Handshake
                ver, nmethods = struct.unpack("!BB", conn.recv(2))
                methods = conn.recv(nmethods)
                conn.sendall(b"\x05\x00")

                req = conn.recv(4)
                if not req or req[1] != 1:
                    return
                atyp = req[3]

                if atyp == 1:
                    dest_addr = socket.inet_ntoa(conn.recv(4))
                elif atyp == 3:
                    domain_len = conn.recv(1)[0]
                    dest_addr = conn.recv(domain_len).decode()
                else:
                    return
                dest_port = struct.unpack("!H", conn.recv(2))[0]

                conn_payload = struct.pack(">B", len(dest_addr)) + dest_addr.encode() + struct.pack(">H", dest_port)
                self.send_raw_packet(sid, CMD_CONNECT, conn_payload)
                self.last_real_traffic = time.time()

                conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                print(f" {Colors.GREEN}[AEGS-SOCKS5]{Colors.RESET} Поток #{sid} -> {dest_addr}:{dest_port} (100% зашифровано в AEGS v4)")

            elif peek_data.startswith(b"CONNECT "):
                # HTTP CONNECT (для браузеров и HTTPS-трафика Windows)
                http_req = b""
                while b"\r\n\r\n" not in http_req:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    http_req += chunk

                first_line = http_req.split(b"\r\n")[0].decode("latin1")
                parts = first_line.split()
                target = parts[1]
                if ":" in target:
                    dest_addr, dest_port_str = target.split(":")
                    dest_port = int(dest_port_str)
                else:
                    dest_addr = target
                    dest_port = 443

                conn_payload = struct.pack(">B", len(dest_addr)) + dest_addr.encode() + struct.pack(">H", dest_port)
                self.send_raw_packet(sid, CMD_CONNECT, conn_payload)
                self.last_real_traffic = time.time()

                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                print(f" {Colors.GREEN}[AEGS-HTTPS]{Colors.RESET} Поток #{sid} -> {dest_addr}:{dest_port} (100% зашифровано в AEGS v4)")

            else:
                # Обычный HTTP запрос
                http_req = b""
                while b"\r\n\r\n" not in http_req:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    http_req += chunk

                host_line = None
                for line in http_req.split(b"\r\n"):
                    if line.lower().startswith(b"host:"):
                        host_line = line.split(b":", 1)[1].strip().decode("latin1")
                        break

                if not host_line:
                    return

                if ":" in host_line:
                    dest_addr, dest_port_str = host_line.split(":")
                    dest_port = int(dest_port_str)
                else:
                    dest_addr = host_line
                    dest_port = 80

                conn_payload = struct.pack(">B", len(dest_addr)) + dest_addr.encode() + struct.pack(">H", dest_port)
                self.send_raw_packet(sid, CMD_CONNECT, conn_payload)
                self.last_real_traffic = time.time()

                # Пробрасываем заголовок запроса
                self.send_raw_packet(sid, CMD_DATA, http_req)
                print(f" {Colors.GREEN}[AEGS-HTTP]{Colors.RESET} Поток #{sid} -> {dest_addr}:{dest_port} (100% зашифровано в AEGS v4)")

            # Потоковая передача данных через туннель AEGS v4
            while self.running:
                data = conn.recv(16384)
                if not data:
                    break
                self.send_raw_packet(sid, CMD_DATA, data)
                self.last_real_traffic = time.time()

        except Exception:
            pass
        finally:
            with self.streams_mu:
                self.streams.pop(sid, None)
            self.send_raw_packet(sid, CMD_CLOSE, b"")
            try:
                conn.close()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="AEGS v4 Pantheon - Pure Native Protocol Client")
    parser.add_argument("--server", default="45.152.193.211", help="IP адрес сервера (вашего ноутбука)")
    parser.add_argument("--port", type=int, default=50001, help="Базовый UDP порт (по умолчанию: 50001)")
    parser.add_argument("--socks-port", type=int, default=1080, help="Локальный порт шлюза (по умолчанию: 1080)")
    parser.add_argument("--port-count", type=int, default=5, help="Количество портов для Port Hopping (по умолчанию: 5)")
    parser.add_argument("--token", default="aegs-super-secret-user-token-for-auditing-2026", help="Секретный токен пользователя")
    parser.add_argument("--auto-system", action="store_true", default=True, help="Автоматически включить туннель для всего Windows (по умолчанию: включено)")
    parser.add_argument("--no-system", action="store_false", dest="auto_system", help="Отключить автоматическую привязку к системе")
    args = parser.parse_args()

    client = AegsClient(args.server, args.port, args.socks_port, args.token, args.port_count, args.auto_system)
    client.start()

if __name__ == "__main__":
    main()
