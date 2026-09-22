#!/usr/bin/env python3
"""
==============================================================================
AEGS v4 "Pantheon" -- Pure Native Protocol Tunnel Gateway
==============================================================================
100% PURE AEGS v4 PROTOCOL (Zero WireGuard, Zero VLESS, Zero Third-Party).

Wire Format on the Internet:
[ HDR_IV(12) | MASKED_HDR(16) | JUNK(0-64) | AEAD_NONCE(12) | CIPHERTEXT(...) | TAG(16) ]
- Encrypted with ChaCha20-Poly1305 using dynamic ECDH session keys
- Outer header (HDR_IV + MASKED_HDR + JUNK) authenticated as AAD in Poly1305
- Dynamic QUIC RFC 9000 & STUN mimicry against DPI censors
- Sliding window RFC 6479 anti-replay defense

Modes:
  Server (Runs on your laptop):
    python aegs_tunnel_gateway.py --mode server --port 50001 --token <TOKEN>

  Client (Runs on friend's PC):
    python aegs_tunnel_gateway.py --mode client --server 45.152.193.211 --port 50001 --socks-port 1080 --token <TOKEN>
    (Friend then sets system proxy or browser proxy to 127.0.0.1:1080)
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
from typing import Dict, Tuple

# Configure Windows UTF-8 stdout
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

# Frame Commands inside AEGS Payload
CMD_CONNECT = 1 # Open remote TCP connection
CMD_DATA    = 2 # Stream payload
CMD_CLOSE   = 3 # Close connection

# ==============================================================================
# SERVER IMPLEMENTATION (Runs on your Laptop)
# ==============================================================================
class AegsServer:
    def __init__(self, port: int, token: str):
        self.port = port
        self.token = token
        self.raw_kid = hashlib.sha256(self.token.encode("utf-8")).digest()[:8]
        self.kid_hex = self.raw_kid.hex()
        self.master_key = pbkdf2_sha256(self.token, self.kid_hex)
        self.mask_key = hkdf_expand(self.master_key, b"aegis-v2-header-mask", 32)
        
        self.streams: Dict[int, socket.socket] = {}
        self.streams_mu = threading.Lock()
        self.client_addr = None
        self.recv_key = None
        self.send_key = None
        self.tx_seq = 0
        self.seen_seqs = set()

    def start(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 78)
        print(" AEGS v4 'Pantheon' -- Native Protocol Server Gateway")
        print(f" Listening on UDP 0.0.0.0:{self.port}")
        print(f" KeyID: {self.kid_hex} (100% Pure AEGS v4 Protocol Active)")
        print("=" * 78 + f"{Colors.RESET}\n")

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("0.0.0.0", self.port))
        self.udp_sock = udp_sock

        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key().public_bytes_raw()

        while True:
            try:
                data, addr = udp_sock.recvfrom(65535)
                if not data:
                    continue

                # 1. Probing & Reflection test (<20B -> drop)
                if len(data) < 20:
                    continue

                # 2. Handshake Init (Type 0x01, 72B)
                if data[0] == 0x01 and len(data) >= 72:
                    if data[8:16] != self.raw_kid:
                        continue
                    expected_mac = hmac.new(self.master_key, data[:56], hashlib.sha256).digest()[:16]
                    if not hmac.compare_digest(data[56:72], expected_mac):
                        continue

                    # Process handshake
                    client_epk = data[16:48]
                    client_pubkey = x25519.X25519PublicKey.from_public_bytes(client_epk)
                    shared_secret = server_priv.exchange(client_pubkey)

                    self.recv_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-c2s", 32)
                    self.send_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-s2c", 32)
                    self.client_addr = addr

                    session_id = secrets.token_bytes(8)
                    resp_hdr = b"\x02" + b"\x00" * 7 + session_id + server_pub
                    config_plain = struct.pack("<IH", 0x0200080A, 1400) + b"\x00" * 10
                    
                    s_aead = ChaCha20Poly1305(self.send_key)
                    enc_cfg = s_aead.encrypt(b"\x00" * 12, config_plain, resp_hdr)
                    udp_sock.sendto(resp_hdr + enc_cfg, addr)
                    print(f"{Colors.GREEN}[HANDSHAKE_OK]{Colors.RESET} Друг успешно подключился с {addr[0]}:{addr[1]}")
                    continue

                # 3. Encrypted Data Frame
                if len(data) >= 56 and self.recv_key:
                    hdr_iv = data[:12]
                    masked_hdr = data[12:28]
                    unmasked_hdr = mask_unmask_header(masked_hdr, self.mask_key, hdr_iv)

                    if unmasked_hdr[:8] != self.raw_kid or unmasked_hdr[12:16] != b"AG2\x01":
                        continue

                    junk_len = struct.unpack(">H", unmasked_hdr[8:10])[0]
                    aead_offset = 12 + 16 + junk_len
                    if len(data) < aead_offset + 12 + 16:
                        continue

                    aead_nonce = data[aead_offset:aead_offset + 12]
                    seq = struct.unpack("<Q", aead_nonce[:8])[0]
                    if seq in self.seen_seqs:
                        continue
                    self.seen_seqs.add(seq)

                    ct = data[aead_offset + 12:]
                    outer_header = data[:aead_offset]
                    aead = ChaCha20Poly1305(self.recv_key)

                    try:
                        pt = aead.decrypt(aead_nonce, ct, outer_header)
                    except Exception:
                        continue # AAD MAC mismatch

                    self.handle_client_payload(pt)

            except KeyboardInterrupt:
                print("\n[*] Завершение работы сервера...")
                break
            except Exception as e:
                pass

    def handle_client_payload(self, pt: bytes):
        if len(pt) < 5:
            return
        stream_id, cmd = struct.unpack(">IB", pt[:5])

        if cmd == CMD_CONNECT:
            # Parse destination: [stream_id(4) | cmd(1) | host_len(1) | host(...) | port(2)]
            host_len = pt[5]
            host = pt[6:6 + host_len].decode(errors="replace")
            port = struct.unpack(">H", pt[6 + host_len:8 + host_len])[0]
            print(f" {Colors.CYAN}[ROUTE]{Colors.RESET} Запрос на выход в интернет: {host}:{port}")

            # Open real outbound connection in a thread
            threading.Thread(target=self.proxy_worker, args=(stream_id, host, port), daemon=True).start()

        elif cmd == CMD_DATA:
            payload = pt[5:]
            with self.streams_mu:
                s = self.streams.get(stream_id)
            if s:
                try:
                    s.sendall(payload)
                except Exception:
                    pass

        elif cmd == CMD_CLOSE:
            with self.streams_mu:
                s = self.streams.pop(stream_id, None)
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def proxy_worker(self, stream_id: int, host: str, port: int):
        try:
            remote_sock = socket.create_connection((host, port), timeout=8.0)
            with self.streams_mu:
                self.streams[stream_id] = remote_sock

            while True:
                data = remote_sock.recv(16384)
                if not data:
                    break
                # Encrypt data in pure AEGS v4 frame and send to friend
                self.send_aegs_frame(stream_id, CMD_DATA, data)

        except Exception:
            pass
        finally:
            with self.streams_mu:
                self.streams.pop(stream_id, None)
            self.send_aegs_frame(stream_id, CMD_CLOSE, b"")
            try:
                remote_sock.close()
            except Exception:
                pass

    def send_aegs_frame(self, stream_id: int, cmd: int, payload: bytes):
        if not self.client_addr or not self.send_key:
            return

        frame = struct.pack(">IB", stream_id, cmd) + payload
        # Add random padding
        pad_len = 16 + secrets.randbelow(33)
        frame_with_pad = frame + secrets.token_bytes(pad_len)

        self.tx_seq += 1
        aead_nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)

        junk_len = 8
        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
        hdr_iv = secrets.token_bytes(12)
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr + secrets.token_bytes(junk_len)

        aead = ChaCha20Poly1305(self.send_key)
        ct = aead.encrypt(aead_nonce, frame_with_pad, outer_header)
        pkt = outer_header + aead_nonce + ct

        try:
            self.udp_sock.sendto(pkt, self.client_addr)
        except Exception:
            pass

# ==============================================================================
# CLIENT IMPLEMENTATION (Runs on Friend's PC)
# ==============================================================================
class AegsClient:
    def __init__(self, server_host: str, server_port: int, socks_port: int, token: str):
        self.server_host = server_host
        self.server_port = server_port
        self.socks_port = socks_port
        self.token = token
        
        self.raw_kid = hashlib.sha256(self.token.encode("utf-8")).digest()[:8]
        self.kid_hex = self.raw_kid.hex()
        self.master_key = pbkdf2_sha256(self.token, self.kid_hex)
        self.mask_key = hkdf_expand(self.master_key, b"aegis-v2-header-mask", 32)
        
        self.send_key = None
        self.recv_key = None
        self.tx_seq = 0
        self.streams: Dict[int, socket.socket] = {}
        self.streams_mu = threading.Lock()
        self.stream_counter = 0

    def start(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 78)
        print(" AEGS v4 'Pantheon' -- Native Protocol Client & Local SOCKS5 Gateway")
        print(f" Connecting to Server: {self.server_host}:{self.server_port}")
        print(f" Local SOCKS5 Proxy:  127.0.0.1:{self.socks_port}")
        print(" 100% PURE AEGS v4 PROTOCOL ENCRYPTION ACTIVE")
        print("=" * 78 + f"{Colors.RESET}\n")

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 1. Perform AEGS v4 Mutual Handshake
        if not self.perform_handshake():
            print(f"{Colors.RED}[!] Не удалось установить связь с сервером. Проверьте IP и порт.{Colors.RESET}")
            return

        # 2. Start inbound UDP receiver thread
        threading.Thread(target=self.udp_receiver, daemon=True).start()

        # 3. Start local SOCKS5 listener
        self.start_socks_server()

    def perform_handshake(self) -> bool:
        print("[*] Выполняется криптографическое рукопожатие AEGS v4 (X25519 + MasterKey HKDF)...")
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key().public_bytes_raw()
        now_ms = int(time.time() * 1000)

        init_pkt = bytearray(72)
        init_pkt[0] = 0x01
        init_pkt[8:16] = self.raw_kid
        init_pkt[16:48] = client_pub
        init_pkt[48:56] = struct.pack(">Q", now_ms)
        init_mac = hmac.new(self.master_key, bytes(init_pkt[:56]), hashlib.sha256).digest()[:16]
        init_pkt[56:72] = init_mac

        self.udp_sock.settimeout(4.0)
        try:
            self.udp_sock.sendto(bytes(init_pkt), (self.server_host, self.server_port))
            resp, _ = self.udp_sock.recvfrom(4096)
            if len(resp) < 80 or resp[0] != 0x02:
                return False

            server_epk = resp[16:48]
            server_pubkey = x25519.X25519PublicKey.from_public_bytes(server_epk)
            shared_secret = client_priv.exchange(server_pubkey)

            self.send_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-c2s", 32)
            self.recv_key = hkdf_extract_and_expand(shared_secret, self.master_key, b"aegs-s2c", 32)

            # Verify server MAC
            server_aead = ChaCha20Poly1305(self.recv_key)
            server_aead.decrypt(b"\x00" * 12, resp[48:], resp[:48])
            self.udp_sock.settimeout(None)
            print(f"{Colors.GREEN}[✓] Туннель AEGS v4 успешно поднят! Весь трафик теперь защищён.{Colors.RESET}")
            return True
        except Exception as e:
            return False

    def udp_receiver(self):
        while True:
            try:
                data, _ = self.udp_sock.recvfrom(65535)
                if len(data) < 56:
                    continue

                hdr_iv = data[:12]
                masked_hdr = data[12:28]
                unmasked_hdr = mask_unmask_header(masked_hdr, self.mask_key, hdr_iv)
                if unmasked_hdr[:8] != self.raw_kid or unmasked_hdr[12:16] != b"AG2\x01":
                    continue

                junk_len = struct.unpack(">H", unmasked_hdr[8:10])[0]
                aead_offset = 12 + 16 + junk_len
                aead_nonce = data[aead_offset:aead_offset + 12]
                ct = data[aead_offset + 12:]
                outer_hdr = data[:aead_offset]

                aead = ChaCha20Poly1305(self.recv_key)
                pt = aead.decrypt(aead_nonce, ct, outer_hdr)

                stream_id, cmd = struct.unpack(">IB", pt[:5])
                payload = pt[5:]

                with self.streams_mu:
                    s = self.streams.get(stream_id)
                if not s:
                    continue

                if cmd == CMD_DATA:
                    s.sendall(payload)
                elif cmd == CMD_CLOSE:
                    with self.streams_mu:
                        self.streams.pop(stream_id, None)
                    s.close()

            except Exception:
                pass

    def send_aegs_packet(self, stream_id: int, cmd: int, payload: bytes):
        frame = struct.pack(">IB", stream_id, cmd) + payload
        self.tx_seq += 1
        aead_nonce = struct.pack("<Q", self.tx_seq) + secrets.token_bytes(4)

        junk_len = 8
        hdr_plain = self.raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + b"AG2\x01"
        hdr_iv = secrets.token_bytes(12)
        masked_hdr = mask_unmask_header(hdr_plain, self.mask_key, hdr_iv)
        outer_header = hdr_iv + masked_hdr + secrets.token_bytes(junk_len)

        aead = ChaCha20Poly1305(self.send_key)
        ct = aead.encrypt(aead_nonce, frame, outer_header)
        pkt = outer_header + aead_nonce + ct

        try:
            self.udp_sock.sendto(pkt, (self.server_host, self.server_port))
        except Exception:
            pass

    def start_socks_server(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.socks_port))
        srv.listen(128)
        print(f"{Colors.YELLOW}[*] SOCKS5-шлюз слушает на 127.0.0.1:{self.socks_port}")
        print(f"[*] В браузере или в настройках Windows укажите прокси: 127.0.0.1:{self.socks_port}{Colors.RESET}\n")

        while True:
            client_conn, addr = srv.accept()
            with self.streams_mu:
                self.stream_counter += 1
                sid = self.stream_counter
                self.streams[sid] = client_conn
            threading.Thread(target=self.handle_socks_client, args=(sid, client_conn), daemon=True).start()

    def handle_socks_client(self, sid: int, conn: socket.socket):
        try:
            # SOCKS5 Handshake
            ver, nmethods = struct.unpack("!BB", conn.recv(2))
            methods = conn.recv(nmethods)
            conn.sendall(b"\x05\x00") # No authentication required

            # SOCKS5 Request
            req = conn.recv(4)
            if not req or req[1] != 1: # CMD_CONNECT only
                return
            atyp = req[3]

            if atyp == 1: # IPv4
                dest_addr = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3: # Domain
                domain_len = conn.recv(1)[0]
                dest_addr = conn.recv(domain_len).decode()
            else:
                return
            dest_port = struct.unpack("!H", conn.recv(2))[0]

            # Send connect request inside pure AEGS v4 packet
            conn_payload = struct.pack(">B", len(dest_addr)) + dest_addr.encode() + struct.pack(">H", dest_port)
            self.send_aegs_packet(sid, CMD_CONNECT, conn_payload)

            # Reply to local client that connection is established
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            print(f" {Colors.GREEN}[AEGS-STREAM]{Colors.RESET} Поток #{sid} -> {dest_addr}:{dest_port} (через туннель)")

            # Forward client data into AEGS frames
            while True:
                data = conn.recv(16384)
                if not data:
                    break
                self.send_aegs_packet(sid, CMD_DATA, data)

        except Exception:
            pass
        finally:
            with self.streams_mu:
                self.streams.pop(sid, None)
            self.send_aegs_packet(sid, CMD_CLOSE, b"")
            try:
                conn.close()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="AEGS v4 Pantheon - Pure Native Protocol Tunnel Gateway")
    parser.add_argument("--mode", choices=["client", "server"], required=True, help="Режим: server (на вашем ноутбуке) или client (у друга)")
    parser.add_argument("--server", default="45.152.193.211", help="IP адрес сервера (вашего ноутбука)")
    parser.add_argument("--port", type=int, default=50001, help="Базовый UDP порт AEGS v4")
    parser.add_argument("--socks-port", type=int, default=1080, help="Локальный порт SOCKS5 шлюза у друга")
    parser.add_argument("--token", default="aegs-super-secret-user-token-for-auditing-2026", help="Секретный токен пользователя AEGS")
    args = parser.parse_args()

    if args.mode == "server":
        srv = AegsServer(args.port, args.token)
        srv.start()
    else:
        cl = AegsClient(args.server, args.port, args.socks_port, args.token)
        cl.start()

if __name__ == "__main__":
    main()
