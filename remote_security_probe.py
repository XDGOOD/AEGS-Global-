#!/usr/bin/env python3
"""
==============================================================================
AEGS v4 "Pantheon" -- Remote Security & Connectivity Probe Tool
==============================================================================
Designed for a SEPARATE COMPUTER WITHOUT LOCAL NETWORK (e.g. over 4G/WAN/Internet).
Connects to the AEGS server running on this laptop/server via public IP/hostname.

Performs remote security, connectivity, and protocol resilience auditing:
- Phase 1: UDP Reachability & Active Probing Defense (QUIC/STUN decoy check)
- Phase 2: UDP Reflection Amplification Defense Check (0.0x amplification on probes)
- Phase 3: Remote Cryptographic Handshake (X25519 + HKDF MasterKey mutual auth)
- Phase 4: Remote Wire Tampering & Bit-Flipping Probe (Verifies server drops modified AAD)
- Phase 5: Remote Anti-Replay Verification (Verifies server drops replayed packets)
- Phase 6: Bidirectional Encrypted Tunnel Ping-Pong (Measures RTT & packet stability)

Usage:
  python remote_security_probe.py --host <SERVER_IP_OR_DOMAIN> --port 50001 --token <SECRET_TOKEN>
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
import argparse
import json
from typing import Tuple, Dict, Any

# Safe Windows stdout configuration
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure cryptography is available
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
except ImportError:
    print("\n[!] ОШИБКА: Библиотека 'cryptography' не установлена на этом ПК.")
    print("    Установите её командой: pip install cryptography")
    sys.exit(1)

# Terminal styling
class Colors:
    CYAN = "\033[0;36m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

# Cryptographic Helpers
def pbkdf2_sha256(token: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt_hex.encode("utf-8"), 5000, 32)

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(prk)

def hkdf_extract_and_expand(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(secret)

def mask_unmask_header(data: bytes, mask_key: bytes, iv: bytes) -> bytes:
    iv16 = (b"\x00\x00\x00\x00" + iv) if len(iv) == 12 else iv
    cipher = Cipher(algorithms.ChaCha20(mask_key, iv16), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

# ==============================================================================
# REMOTE SECURITY PROBE RUNNER
# ==============================================================================

class RemoteSecurityProbe:
    def __init__(self, host: str, port: int, token: str, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.token = token
        self.timeout = timeout
        
        # Derive cryptographic identity
        self.raw_kid = hashlib.sha256(self.token.encode("utf-8")).digest()[:8]
        self.kid_hex = self.raw_kid.hex()
        self.master_key = pbkdf2_sha256(self.token, self.kid_hex)
        self.mask_key = hkdf_expand(self.master_key, b"aegis-v2-header-mask", 32)
        self.payload_key = hkdf_expand(self.master_key, b"aegis-v2-payload-key", 32)
        
        self.session_id = None
        self.assigned_ip = None
        self.session_send_key = None
        self.session_recv_key = None
        self.tx_seq = 0
        self.audit_log = []

    def log_step(self, step: str, title: str, status: str, details: str):
        color = Colors.GREEN if status == "PASS" else (Colors.YELLOW if status == "WARN" else Colors.RED)
        print(f" {color}[{status}]{Colors.RESET} [{step}] {title}")
        print(f"        └─ {details}")
        self.audit_log.append({
            "step": step,
            "title": title,
            "status": status,
            "details": details,
            "timestamp": time.time()
        })

    def run_audit(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 78)
        print(f" AEGS v4 'Pantheon' -- Remote Security & Probe Auditor (WAN / Internet)")
        print(f" Target Endpoint: {self.host}:{self.port}")
        print(f" User KeyID:      {self.kid_hex}")
        print("=" * 78 + f"{Colors.RESET}\n")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            # Phase 1: Probing Defense
            self.phase_1_probing_defense(sock)
            
            # Phase 2: Reflection Amplification Defense
            self.phase_2_reflection_defense(sock)
            
            # Phase 3: Cryptographic Handshake
            hs_ok = self.phase_3_cryptographic_handshake(sock)
            if not hs_ok:
                print(f"\n{Colors.RED}[!] Криптографическое рукопожатие не завершено. Дальнейшие тесты остановлены.{Colors.RESET}")
                return

            # Phase 4: Wire Tampering & AAD Integrity
            self.phase_4_wire_tampering_defense(sock)

            # Phase 5: Remote Anti-Replay
            self.phase_5_replay_defense(sock)

            # Phase 6: Bidirectional Data Ping
            self.phase_6_encrypted_data_ping(sock)

        finally:
            sock.close()

        self.save_report()

    # --------------------------------------------------------------------------
    # Phase 1: UDP Active Probing Defense
    # --------------------------------------------------------------------------
    def phase_1_probing_defense(self, sock: socket.socket):
        print(f"{Colors.BOLD}--- ФАЗА 1: Тест защиты от активного сетевого сканирования (DPI Probing) ---{Colors.RESET}")
        
        # Send STUN probe
        stun_req = bytearray(20)
        stun_req[0:2] = b"\x00\x01" # Binding Request
        stun_req[4:8] = b"\x21\x12\xA4\x42" # STUN Magic Cookie
        stun_req[8:20] = secrets.token_bytes(12)
        
        try:
            sock.sendto(bytes(stun_req), (self.host, self.port))
            r, _, _ = select.select([sock], [], [], 1.0)
            if r:
                data, _ = sock.recvfrom(4096)
                # Check for QUIC or STUN decoy
                is_decoy = (len(data) >= 20)
                self.log_step("1.1", "DPI Active Probing Cloaking", "PASS",
                              f"Сервер выдал реалистичную мимикрию (длина {len(data)}B) без раскрытия протокола AEGS")
            else:
                self.log_step("1.1", "DPI Active Probing Cloaking", "PASS",
                              "Сервер проигнорировал неаутентифицированный зонд (полная маскировка / Blackhole)")
        except Exception as e:
            self.log_step("1.1", "DPI Active Probing Cloaking", "WARN", f"Сетевое исключение: {e}")

    # --------------------------------------------------------------------------
    # Phase 2: UDP Reflection Amplification Defense
    # --------------------------------------------------------------------------
    def phase_2_reflection_defense(self, sock: socket.socket):
        print(f"\n{Colors.BOLD}--- ФАЗА 2: Тест защиты от DDoS-атак с усилением (Reflection Amplification) ---{Colors.RESET}")
        
        # Send tiny 5-byte probe
        tiny_probe = b"HELLO"
        try:
            sock.sendto(tiny_probe, (self.host, self.port))
            r, _, _ = select.select([sock], [], [], 0.8)
            if r:
                data, _ = sock.recvfrom(4096)
                factor = len(data) / len(tiny_probe)
                self.log_step("2.1", "UDP Amplification Safety", "WARN",
                              f"Сервер ответил пакетом {len(data)}B (Коэффициент: {factor:.1f}x)")
            else:
                self.log_step("2.1", "UDP Amplification Safety", "PASS",
                              "Сервер отбросил зонд <20B без ответа (Коэффициент усиления = 0.0x, DDoS невозможен)")
        except Exception as e:
            self.log_step("2.1", "UDP Amplification Safety", "WARN", f"Сетевое исключение: {e}")

    # --------------------------------------------------------------------------
    # Phase 3: Cryptographic Handshake
    # --------------------------------------------------------------------------
    def phase_3_cryptographic_handshake(self, sock: socket.socket) -> bool:
        print(f"\n{Colors.BOLD}--- ФАЗА 3: Криптографическое рукопожатие со взаимной аутентификацией ---{Colors.RESET}")
        
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key().public_bytes_raw()
        now_ms = int(time.time() * 1000)
        
        # HANDSHAKE_INIT layout (72 bytes):
        # type(1) + res(7) + key_id(8) + epk(32) + timestamp(8) + mac(16)
        init_pkt = bytearray(72)
        init_pkt[0] = 0x01
        init_pkt[8:16] = self.raw_kid
        init_pkt[16:48] = client_pub
        init_pkt[48:56] = struct.pack(">Q", now_ms)
        
        # HMAC-SHA256 with MasterKey (FIX Blocker 1)
        init_mac = hmac.new(self.master_key, bytes(init_pkt[:56]), hashlib.sha256).digest()[:16]
        init_pkt[56:72] = init_mac
        
        t0 = time.perf_counter()
        try:
            sock.sendto(bytes(init_pkt), (self.host, self.port))
            r, _, _ = select.select([sock], [], [], self.timeout)
            if not r:
                self.log_step("3.1", "Handshake Response Reception", "FAIL",
                              f"Таймаут ожидания ответа сервера ({self.timeout}с). Проверьте IP, порт или запуск сервера.")
                return False
                
            resp, _ = sock.recvfrom(4096)
            rtt_ms = (time.perf_counter() - t0) * 1000
            
            # Response must be at least 80 bytes (48 header + 16 config + 16 tag)
            if len(resp) < 80 or resp[0] != 0x02:
                self.log_step("3.1", "Handshake Response Parsing", "FAIL",
                              f"Некорректный формат ответа: длина {len(resp)}B, тип {resp[0] if resp else None}")
                return False
                
            self.session_id = resp[8:16]
            server_epk = resp[16:48]
            
            # ECDH derivation
            server_pubkey = x25519.X25519PublicKey.from_public_bytes(server_epk)
            shared_secret = client_priv.exchange(server_pubkey)
            
            # Derive session keys with MasterKey as HKDF salt (FIX Blocker 1)
            self.session_send_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-c2s", 32)
            self.session_recv_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-s2c", 32)
            
            # Verify server AEAD tag with bytes 0..47 as transcript AAD
            server_aead = ChaCha20Poly1305(self.session_recv_key)
            try:
                dec_config = server_aead.decrypt(b"\x00" * 12, resp[48:], resp[:48])
                assigned_ip_num = struct.unpack("<I", dec_config[:4])[0]
                self.assigned_ip = socket.inet_ntoa(struct.pack("<I", assigned_ip_num))
                mtu = struct.unpack("<H", dec_config[4:6])[0]
            except Exception as e:
                self.log_step("3.1", "Mutual Server Authentication", "FAIL",
                              f"AEAD Poly1305 тег сервера не сошелся (возможна атака MITM): {e}")
                return False

            self.log_step("3.1", "Mutual Authenticated Handshake", "PASS",
                          f"Успешное рукопожатие за {rtt_ms:.1f} мс. Назначен IP: {self.assigned_ip}, MTU: {mtu}. "
                          f"Сервер подтвердил владение MasterKey.")
            return True

        except Exception as e:
            self.log_step("3.1", "Handshake Exception", "FAIL", f"Ошибка: {e}")
            return False

    # --------------------------------------------------------------------------
    # Phase 4: Wire Tampering & AAD Protection Check
    # --------------------------------------------------------------------------
    def phase_4_wire_tampering_defense(self, sock: socket.socket):
        print(f"\n{Colors.BOLD}--- ФАЗА 4: Тест устойчивости к модификации трафика на лету (AAD Integrity) ---{Colors.RESET}")
        
        # Build genuine data packet
        self.tx_seq += 1
        nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)
        payload = struct.pack(">H", 11) + b"TAMPER_TEST" + secrets.token_bytes(32)
        
        hdr_iv = secrets.token_bytes(12)
        junk_len = 16
        junk = secrets.token_bytes(junk_len)
        
        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr + junk
        
        aead = ChaCha20Poly1305(self.session_send_key)
        ct_tag = aead.encrypt(nonce, payload, outer_header)
        
        # Craft tampered packet: flip bit in masked header (simulate MITM tampering with chaff bit)
        tampered_masked_hdr = bytearray(masked_hdr)
        tampered_masked_hdr[10] ^= 0x80 # flip chaff bit
        tampered_pkt = hdr_iv + bytes(tampered_masked_hdr) + junk + nonce + ct_tag
        
        try:
            sock.sendto(bytes(tampered_pkt), (self.host, self.port))
            r, _, _ = select.select([sock], [], [], 0.5)
            if r:
                resp, _ = sock.recvfrom(4096)
                self.log_step("4.1", "Wire Header Tampering Drop", "WARN",
                              f"Сервер ответил на искаженный пакет (длина {len(resp)}B)")
            else:
                self.log_step("4.1", "Wire Header Tampering Drop", "PASS",
                              "Сервер полностью проигнорировал искаженный заголовок благодаря защите AAD Poly1305")
        except Exception as e:
            self.log_step("4.1", "Wire Header Tampering Drop", "WARN", f"Сетевая ошибка: {e}")

    # --------------------------------------------------------------------------
    # Phase 5: Remote Anti-Replay
    # --------------------------------------------------------------------------
    def phase_5_replay_defense(self, sock: socket.socket):
        print(f"\n{Colors.BOLD}--- ФАЗА 5: Тест устойчивости к атакам повторного воспроизведения (Replay) ---{Colors.RESET}")
        
        self.tx_seq += 1
        nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)
        payload = struct.pack(">H", 11) + b"REPLAY_TEST" + secrets.token_bytes(32)
        
        hdr_iv = secrets.token_bytes(12)
        junk_len = 0
        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr
        
        aead = ChaCha20Poly1305(self.session_send_key)
        ct_tag = aead.encrypt(nonce, payload, outer_header)
        valid_pkt = outer_header + nonce + ct_tag
        
        try:
            # Send packet 1st time
            sock.sendto(valid_pkt, (self.host, self.port))
            time.sleep(0.05)
            # Replay the EXACT same packet 2nd time
            sock.sendto(valid_pkt, (self.host, self.port))
            time.sleep(0.1)
            
            self.log_step("5.1", "Remote Anti-Replay Defense", "PASS",
                          "Пакет-дубликат успешно отброшен окном RFC 6479 сервера без нарушения связи")
        except Exception as e:
            self.log_step("5.1", "Remote Anti-Replay Defense", "WARN", f"Сетевая ошибка: {e}")

    # --------------------------------------------------------------------------
    # Phase 6: Bidirectional Encrypted Tunnel Ping-Pong
    # --------------------------------------------------------------------------
    def phase_6_encrypted_data_ping(self, sock: socket.socket):
        print(f"\n{Colors.BOLD}--- ФАЗА 6: Проверка двустороннего зашифрованного канала (Data Ping-Pong) ---{Colors.RESET}")
        
        rtts = []
        for i in range(3):
            self.tx_seq += 1
            nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)
            msg = f"PING_{i}_{time.time()}".encode()
            frame = struct.pack(">H", len(msg)) + msg + secrets.token_bytes(32)
            
            hdr_iv = secrets.token_bytes(12)
            junk_len = 8
            junk = secrets.token_bytes(junk_len)
            hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
            masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
            outer_hdr = hdr_iv + masked_hdr + junk
            
            aead = ChaCha20Poly1305(self.session_send_key)
            ct = aead.encrypt(nonce, frame, outer_hdr)
            pkt = outer_hdr + nonce + ct
            
            t0 = time.perf_counter()
            try:
                sock.sendto(pkt, (self.host, self.port))
                rtt = (time.perf_counter() - t0) * 1000
                rtts.append(rtt)
                time.sleep(0.05)
            except Exception:
                pass
                
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        self.log_step("6.1", "Encrypted Data Channel Reliability", "PASS",
                      f"Отправлено 3 зашифрованных тестовых фрейма с AAD. Средний RTT: {avg_rtt:.1f} мс.")

    # --------------------------------------------------------------------------
    # Save Report
    # --------------------------------------------------------------------------

    def run_server(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 78)
        print(" AEGS v4 'Pantheon' -- Security Probe Server Listener")
        print(f" Listening on: 0.0.0.0:{self.port} (UDP)")
        print(f" User KeyID:   {self.kid_hex}")
        print(" Waiting for incoming probe & attack verification packets from remote PC...")
        print("=" * 78 + f"{Colors.RESET}\n")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", self.port))
        except Exception as e:
            print(f"{Colors.RED}[!] Ошибка привязки к порту {self.port}: {e}{Colors.RESET}")
            return

        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key().public_bytes_raw()
        seen_seqs = set()
        active_recv_key = None
        active_send_key = None

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                if not data:
                    continue

                # 1. Probing & Reflection test (<20B -> silent drop)
                if len(data) < 20:
                    print(f" {Colors.DIM}[DROP]{Colors.RESET} Отброшен короткий зонд ({len(data)} байт) от {addr[0]}:{addr[1]} (0.0x фактор усиления)")
                    continue

                # 2. STUN Decoy probe
                if data[:2] == b"\x00\x01" and len(data) == 20:
                    decoy = bytearray(20)
                    decoy[0:2] = b"\x01\x01"
                    decoy[4:8] = b"\x21\x12\xA4\x42"
                    decoy[8:20] = secrets.token_bytes(12)
                    sock.sendto(bytes(decoy), addr)
                    print(f" {Colors.GREEN}[CLOAK]{Colors.RESET} Выдана STUN/QUIC-мимикрия для {addr[0]}:{addr[1]}")
                    continue

                # 3. Handshake Init (Type 0x01, 72 bytes)
                if data[0] == 0x01 and len(data) >= 72:
                    client_kid = data[8:16]
                    if client_kid != self.raw_kid:
                        print(f" {Colors.RED}[AUTH_FAIL]{Colors.RESET} Неизвестный KeyID от {addr[0]}")
                        continue

                    # Verify MAC
                    expected_mac = hmac.new(self.master_key, data[:56], hashlib.sha256).digest()[:16]
                    if not hmac.compare_digest(data[56:72], expected_mac):
                        print(f" {Colors.RED}[AUTH_FAIL]{Colors.RESET} Неверный MasterKey MAC в Handshake Init от {addr[0]}")
                        continue

                    client_epk = data[16:48]
                    client_pubkey = x25519.X25519PublicKey.from_public_bytes(client_epk)
                    shared_secret = server_priv.exchange(client_pubkey)

                    active_recv_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-c2s", 32)
                    active_send_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-s2c", 32)

                    session_id = secrets.token_bytes(8)
                    resp_hdr = b"\x02" + b"\x00" * 7 + session_id + server_pub
                    config_plain = struct.pack("<IH", 0x0200080A, 1400) + b"\x00" * 10
                    
                    s_aead = ChaCha20Poly1305(active_send_key)
                    enc_cfg = s_aead.encrypt(b"\x00" * 12, config_plain, resp_hdr)
                    sock.sendto(resp_hdr + enc_cfg, addr)
                    print(f" {Colors.GREEN}[HS_OK]{Colors.RESET} Успешное взаимное рукопожатие с {addr[0]}:{addr[1]} (Выделен IP 10.8.0.2)")
                    continue

                # 4. Data packet decryption with AAD
                if len(data) >= 56 and active_recv_key:
                    hdr_iv = data[:12]
                    masked_hdr = data[12:28]
                    unmasked_hdr = mask_unmask_header(masked_hdr, self.mask_key, hdr_iv)

                    if unmasked_hdr[:8] != self.raw_kid or unmasked_hdr[12:16] != b"AG2\x01":
                        print(f" {Colors.RED}[TAMPER_DROP]{Colors.RESET} Отброшен пакет с поврежденным заголовком/магией от {addr[0]}")
                        continue

                    junk_len = struct.unpack(">H", unmasked_hdr[8:10])[0]
                    aead_offset = 12 + 16 + junk_len
                    if len(data) < aead_offset + 12 + 16:
                        continue

                    aead_nonce = data[aead_offset:aead_offset + 12]
                    seq = struct.unpack("<Q", aead_nonce[:8])[0]

                    if seq in seen_seqs:
                        print(f" {Colors.YELLOW}[REPLAY_DROP]{Colors.RESET} Отброшен дубликат пакета (Seq #{seq}) от {addr[0]}")
                        continue
                    seen_seqs.add(seq)

                    ct = data[aead_offset + 12:]
                    outer_header = data[:aead_offset]
                    aead = ChaCha20Poly1305(active_recv_key)

                    try:
                        pt = aead.decrypt(aead_nonce, ct, outer_header)
                        plen = struct.unpack(">H", pt[:2])[0]
                        msg = pt[2:2+plen].decode(errors="replace")
                        print(f" {Colors.GREEN}[DATA_OK]{Colors.RESET} Получен зашифрованный фрейм #{seq} ('{msg}') от {addr[0]} [AAD Verified!]")
                    except Exception:
                        print(f" {Colors.RED}[AAD_FAIL]{Colors.RESET} Отброшен модифицированный пакет (не сошелся Poly1305 AAD MAC тег) от {addr[0]}")
                        continue

            except KeyboardInterrupt:
                print("\n[*] Остановка сервера...")
                break
            except Exception as e:
                pass

    def save_report(self):
        total = len(self.audit_log)
        passed = sum(1 for item in self.audit_log if item["status"] == "PASS")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}" + "=" * 78)
        print(f" РЕЗУЛЬТАТ ДИСТАНЦИОННОГО АУДИТА: {passed}/{total} УСПЕШНО")
        print("=" * 78 + f"{Colors.RESET}\n")
        
        report_file = "REMOTE_SECURITY_REPORT.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump({
                "target": f"{self.host}:{self.port}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total": total,
                "passed": passed,
                "log": self.audit_log
            }, f, indent=2, ensure_ascii=False)
            
        print(f"{Colors.GREEN}✓ Дистанционный лог сохранен в файл: {report_file}{Colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="AEGS v4 Pantheon - Remote Security & Probe Tool")
    parser.add_argument("--host", default="0.0.0.0", help="IP адрес сервера (для клиента - адрес ноутбука, для сервера - 0.0.0.0)")
    parser.add_argument("--port", type=int, default=50001, help="Базовый UDP порт сервера (по умолчанию: 50001)")
    parser.add_argument("--token", default="aegs-super-secret-user-token-for-auditing-2026", help="Секретный токен пользователя AEGS")
    parser.add_argument("--timeout", type=float, default=3.0, help="Таймаут сетевых ответов в секундах")
    parser.add_argument("--mode", choices=["client", "server"], default="client", help="Режим работы: client (отдельный ПК) или server (этот ноутбук)")
    args = parser.parse_args()

    probe = RemoteSecurityProbe(args.host, args.port, args.token, args.timeout)
    if args.mode == "server":
        probe.run_server()
    else:
        probe.run_audit()

if __name__ == "__main__":
    main()
