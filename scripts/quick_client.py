#!/usr/bin/env python3
"""
AEGS v2 Protocol - Cross-Platform Client Proxy & Management Tool
High-Performance Zero-DPI WireGuard UDP Obfuscator (Linux, macOS, Windows)

Features:
- Native binary supervisor with auto-detection & fallback
- Integrated pure-Python ChaCha20-Poly1305 wire-compatible fallback engine
- KeyID calculator & token validator (PBKDF2 / HKDF-SHA256)
- Automated WireGuard config generation
- Interactive setup wizard
"""

from __future__ import annotations
import os
import sys
import time
import socket
import select
import struct
import secrets
import hashlib
import hmac
import argparse
import subprocess
from pathlib import Path

# Safe encoding configuration for Windows terminals
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# --- Protocol Constants ---
VER_MAGIC = b"AG2\x01"
DEFAULT_LOCAL_PORT = 51821
DEFAULT_SERVER_PORT = 50001
PBKDF2_ITERATIONS = 200000
BUFFER_SIZE = 65535
PAD_MIN = 32
PAD_MAX = 256
FRAME_HDR = 2
TAG_LEN = 16

# --- Colors for Terminal ---
class Colors:
    CYAN = "\033[0;36m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        cls.CYAN = cls.GREEN = cls.YELLOW = cls.RED = cls.WHITE = cls.BOLD = cls.DIM = cls.RESET = ""

if os.name == 'nt' and not os.environ.get('TERM'):
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass

def banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"""
    ___    ______ _____ ____         ____             __  __                      
   /   |  / ____// ___// __ \ _   __/ __ \____ _____ / /_/ /_  ___  ____  ____ 
  / /| | / __/  / / _ / / / /| | / / /_/ / __ `/ __ \/ __/ __ \/ _ \/ __ \/ __ \
 / ___ |/ /___ / /_/ // /_/ / | |/ / ____/ /_/ / / / / /_/ / / /  __/ /_/ / / / /
/_/  |_/_____/ \____(_)____/  |___/_/    \__,_/_/ /_/\__/_/ /_/\___/\____/_/ /_/ 
    AEGS v4 "Pantheon" — Zero-DPI Anti-ML Obfuscated UDP Tunnel (127.0.0.1:51821)
""")
    print(f"{Colors.RESET}")

# --- Cryptographic Helpers ---
def compute_key_id(token: str) -> tuple[bytes, str]:
    """Computes 8-byte raw KeyID and 16-character hex KeyID from secret token."""
    h = hashlib.sha256(token.encode('utf-8')).digest()
    raw_kid = h[:8]
    kid_hex = raw_kid.hex()
    return raw_kid, kid_hex

def derive_keys(token: str, kid_hex: str):
    """
    Derives master_key via PBKDF2-HMAC-SHA256,
    then expands mask_key and payload_key via HKDF-SHA256.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        token.encode('utf-8'),
        kid_hex.encode('utf-8'),
        PBKDF2_ITERATIONS,
        dklen=32
    )

    # Derive mask_key (info: "aegis-v2-header-mask")
    hkdf_mask = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-v2-salt",
        info=b"aegis-v2-header-mask"
    )
    mask_key = hkdf_mask.derive(master_key)

    # Derive payload_key (info: "aegis-v2-payload-key")
    hkdf_payload = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aegis-v2-salt",
        info=b"aegis-v2-payload-key"
    )
    payload_key = hkdf_payload.derive(master_key)

    return master_key, mask_key, payload_key

def mask_unmask_header(data: bytes, mask_key: bytes, hdr_iv: bytes) -> bytes:
    """ChaCha20 stream cipher masking for the 16-byte header."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    full_nonce = b"\x00\x00\x00\x00" + hdr_iv
    cipher = Cipher(algorithms.ChaCha20(mask_key, full_nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def semantic_pad(payload_len: int) -> int:
    """AEGS v4 Bimodal Semantic Shaping (Anti-ML traffic profile)."""
    # 5% medium noise packet (512-768B)
    if secrets.randbelow(100) < 5:
        target = 512 + secrets.randbelow(257)
        needed = FRAME_HDR + payload_len
        return max(0, target - needed)

    needed = FRAME_HDR + payload_len
    if payload_len <= 200:
        # Small packet: target ~256B (QUIC ACK profile)
        jitter = secrets.randbelow(33) - 16
        target = max(0, 256 + jitter)
        return max(0, target - needed)
    else:
        # Large packet: target ~1350B (Full MTU QUIC frame)
        if needed >= 1350:
            return secrets.randbelow(33)
        jitter = secrets.randbelow(65) - 32
        target = max(0, 1350 + jitter)
        return max(0, target - needed)

def send_illusion_sequence(sock: socket.socket, server_addr: tuple[str, int]):
    """AEGS v4 State-Machine Pre-Bypass: sends 1-3 STUN / QUIC Initial decoys."""
    import zlib
    count = 1 + secrets.randbelow(3)
    for _ in range(count):
        if secrets.randbelow(2) == 0:
            # RFC 5389 STUN Binding Request decoy with USERNAME and FINGERPRINT
            pkt = bytearray(40)
            pkt[0:2] = b"\x00\x01" # Binding Request
            pkt[2:4] = b"\x00\x14" # 20 bytes attribute length
            pkt[4:8] = b"\x21\x12\xA4\x42" # Magic Cookie
            pkt[8:20] = secrets.token_bytes(12)
            # USERNAME (0x0006), len 8
            pkt[20:22] = b"\x00\x06"
            pkt[22:24] = b"\x00\x08"
            pkt[24:32] = secrets.token_bytes(8)
            # FINGERPRINT (0x8028), len 4
            pkt[32:34] = b"\x80\x28"
            pkt[34:36] = b"\x00\x04"
            crc = zlib.crc32(pkt[:32]) & 0xFFFFFFFF
            fp = crc ^ 0x5354554E
            pkt[36:40] = struct.pack(">I", fp)
        else:
            # RFC 9000 QUIC Initial decoy (>=1200 bytes, exact varint 0x4496)
            pkt = bytearray(1200)
            pkt[0] = 0xC3 # Long header Initial
            pkt[1:5] = b"\x00\x00\x00\x01" # QUIC v1
            pkt[5] = 8; pkt[6:14] = secrets.token_bytes(8)
            pkt[14] = 8; pkt[15:23] = secrets.token_bytes(8)
            pkt[24:26] = b"\x44\x96" # Length varint: 1174 bytes
            pkt[26:30] = secrets.token_bytes(4)
            pkt[30:1200] = secrets.token_bytes(1170)
        try:
            sock.sendto(bytes(pkt), server_addr)
            # Non-blocking check for response to simulate complete RTT for stateful DPI
            r, _, _ = select.select([sock], [], [], 0.025 + secrets.randbelow(35) / 1000.0)
            if r:
                try:
                    sock.recvfrom(2048)
                except OSError:
                    pass
        except OSError:
            pass

def find_native_binary() -> Path | None:
    """Searches for native compiled aegs-client binary."""
    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent

    candidates = [
        script_dir / "aegs-client",
        script_dir / "aegs-client.exe",
        script_dir / "client",
        root_dir / "aegs-client",
        root_dir / "aegs-client.exe",
        root_dir / "client",
        root_dir / "aegis_client",
        root_dir / "aegis_client.exe",
        Path("/usr/local/bin/aegs-client"),
        Path("/usr/local/bin/aegis_client"),
    ]

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c

    # Search in PATH
    for name in ["aegs-client", "aegis_client", "aegs-client.exe", "aegis_client.exe"]:
        p = shutil_which(name)
        if p:
            return Path(p)

    return None

def shutil_which(cmd: str) -> str | None:
    import shutil
    return shutil.which(cmd)

def compute_hopper_port(key: bytes, base_port: int, count: int, interval: int) -> int:
    epoch = int(time.time()) // (interval if interval > 0 else 30)
    epoch_bytes = struct.pack('>Q', epoch)
    h = hmac.new(key, epoch_bytes, hashlib.sha256).digest()
    val = struct.unpack('<I', h[:4])[0]
    return base_port + (val % (count if count > 0 else 1))

def enable_killswitch(server_ip: str, base_port: int, port_count: int):
    print(f"{Colors.YELLOW}[KillSwitch] Engaging traffic isolation rules...{Colors.RESET}")
    if os.name == 'nt':
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=AEGS-KS-Allow-Loopback", "dir=out", "action=allow", "remoteip=127.0.0.1", "enable=yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=AEGS-KS-Allow-DHCP", "dir=out", "action=allow", "protocol=UDP", "localport=68", "remoteport=67", "enable=yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=AEGS-KS-Allow-Server", "dir=out", "action=allow", f"remoteip={server_ip}", "protocol=UDP", f"remoteport={base_port}-{base_port+port_count-1}", "enable=yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=AEGS-KS-Block-All", "dir=out", "action=block", "enable=yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.GREEN}[KillSwitch] Windows Firewall rules active (Direct leaks blocked).{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[KillSwitch] Firewall rule setup failed (admin required): {e}{Colors.RESET}")
    else:
        try:
            subprocess.run(["iptables", "-N", "AEGS_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "AEGS_KILLSWITCH", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "AEGS_KILLSWITCH", "-o", "lo", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "AEGS_KILLSWITCH", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            port_spec = f"{base_port}:{base_port+port_count-1}" if port_count > 1 else str(base_port)
            subprocess.run(["iptables", "-A", "AEGS_KILLSWITCH", "-d", server_ip, "-p", "udp", "--dport", port_spec, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-A", "AEGS_KILLSWITCH", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "AEGS_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.GREEN}[KillSwitch] Linux iptables rules active.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[KillSwitch] Iptables setup failed (root required): {e}{Colors.RESET}")

def disable_killswitch():
    print(f"{Colors.YELLOW}[KillSwitch] Clearing traffic isolation rules...{Colors.RESET}")
    if os.name == 'nt':
        for r in ["AEGS-KS-Allow-Loopback", "AEGS-KS-Allow-DHCP", "AEGS-KS-Allow-Server", "AEGS-KS-Block-All", "AEGS-KS-Block-DNS"]:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "AEGS_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-F", "AEGS_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", "AEGS_KILLSWITCH"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "AEGS_DNS_SHIELD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-F", "AEGS_DNS_SHIELD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", "AEGS_DNS_SHIELD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{Colors.GREEN}[KillSwitch] Cleaned up.{Colors.RESET}")

def enable_dns_shield():
    print(f"{Colors.YELLOW}[DNS-Shield] Enforcing DNS leak shield (Blocking port 53 on physical adapters)...{Colors.RESET}")
    if os.name == 'nt':
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=AEGS-KS-Block-DNS", "dir=out", "action=block", "protocol=UDP", "remoteport=53", "remoteip=!127.0.0.1", "enable=yes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["iptables", "-N", "AEGS_DNS_SHIELD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", "AEGS_DNS_SHIELD", "-o", "lo", "-p", "udp", "--dport", "53", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", "AEGS_DNS_SHIELD", "-p", "udp", "--dport", "53", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "AEGS_DNS_SHIELD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{Colors.GREEN}[DNS-Shield] Plaintext DNS blocked.{Colors.RESET}")

# --- AEGS v3/v4 ECDH Handshake ---
def perform_v3_handshake(sock: socket.socket, server_addr: tuple[str, int], raw_kid: bytes, master_key: bytes) -> tuple[bytes, bytes, int, str]:
    """
    Executes AEGS v3/v4 ECDH Mutual Authentication Handshake with Server:
    - Generates Ephemeral X25519 Keypair
    - Sends 72-byte HANDSHAKE_INIT with HMAC-SHA256 (MasterKey)
    - Verifies 80-byte HANDSHAKE_RESP with transcript AAD
    - Derives forward-secret session keys: c2s (send_key) and s2c (recv_key)
    - Returns (c2s_key, s2c_key, session_id, assigned_ip_str)
    """
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    client_priv = x25519.X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes_raw()

    now_ms = int(time.time() * 1000)
    # Type(1) + Reserved(7) + KeyID(8) + EphemeralPub(32) + Timestamp(8) = 56 bytes
    init_body = b"\x01" + b"\x00" * 7 + raw_kid + client_pub + struct.pack(">Q", now_ms)
    # HMAC-SHA256 truncated to 16 bytes
    mac = hmac.new(master_key, init_body, hashlib.sha256).digest()[:16]
    init_pkt = init_body + mac # 72 bytes

    max_retries = 3
    for attempt in range(max_retries):
        print(f"{Colors.CYAN}[*] Sending AEGS v4 HANDSHAKE_INIT (attempt {attempt+1}/{max_retries})...{Colors.RESET}")
        sock.sendto(init_pkt, server_addr)
        r, _, _ = select.select([sock], [], [], 3.0)
        if not r:
            continue

        resp_data, resp_src = sock.recvfrom(2048)
        if len(resp_data) < 80 or resp_data[0] != 0x02:
            continue

        # Process HANDSHAKE_RESP
        session_id = struct.unpack("<Q", resp_data[8:16])[0]
        server_pub_bytes = resp_data[16:48]
        try:
            server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared_secret = client_priv.exchange(server_pub)
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to compute X25519 shared secret: {e}{Colors.RESET}")
            continue

        # Derive forward-secret session keys with MasterKey as salt
        def hkdf_derive_key(info: bytes) -> bytes:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=master_key,
                info=info
            )
            return hkdf.derive(shared_secret)

        send_key = hkdf_derive_key(b"aegs-c2s")
        recv_key = hkdf_derive_key(b"aegs-s2c")
        cfg_key = hkdf_derive_key(b"aegs-cfg")

        # Decrypt config using cfg_key with AAD = resp_data[:48]
        try:
            cfg_aead = ChaCha20Poly1305(cfg_key)
            cfg_plain = cfg_aead.decrypt(b"\x00" * 12, resp_data[48:80], resp_data[:48])
        except Exception as e:
            print(f"{Colors.RED}[!] Handshake response authentication failed (MITM detected): {e}{Colors.RESET}")
            continue

        assigned_ip_int = struct.unpack("<I", cfg_plain[:4])[0]
        mtu = struct.unpack("<H", cfg_plain[4:6])[0]
        assigned_ip = socket.inet_ntoa(struct.pack("<I", assigned_ip_int))

        print(f"{Colors.GREEN}[OK] AEGS v4 Mutual Authentication Handshake Complete!{Colors.RESET}")
        print(f"     - Session ID:  0x{session_id:016x}")
        print(f"     - Assigned IP: {assigned_ip}")
        print(f"     - MTU:         {mtu}")

        # Receive optional ResumptionToken (packet 0x03) if server sends it
        r_tok, _, _ = select.select([sock], [], [], 0.5)
        if r_tok:
            try:
                tok_data, _ = sock.recvfrom(2048)
                if len(tok_data) >= 97 and tok_data[0] == 0x03:
                    print(f"{Colors.GREEN}[OK] ResumptionToken received (96 bytes).{Colors.RESET}")
            except OSError:
                pass

        return send_key, recv_key, session_id, assigned_ip

    raise RuntimeError(f"Handshake failed after {max_retries} attempts. Server did not respond or authentication rejected.")

# --- Pure-Python Proxy Engine ---
def run_python_proxy(server_host: str, token: str, local_port: int = DEFAULT_LOCAL_PORT,
                     kill_switch: bool = False, dns_protect: bool = False,
                     port_count: int = 10, hop_interval: int = 30):
    """
    Pure Python zero-dependency (cryptography required) AEGS v4 proxy client.
    Listens on 127.0.0.1:local_port, forwards encrypted UDP datagrams to server_host.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        print(f"{Colors.RED}[!] 'cryptography' library is required for pure-Python mode.{Colors.RESET}")
        print(f"    Install it with: {Colors.CYAN}pip install cryptography{Colors.RESET}")
        sys.exit(1)

    raw_kid, kid_hex = compute_key_id(token)
    master_key, mask_key, _ = derive_keys(token, kid_hex)

    # Resolve server address
    try:
        server_ip = socket.gethostbyname(server_host)
    except socket.gaierror as e:
        print(f"{Colors.RED}[!] Failed to resolve server '{server_host}': {e}{Colors.RESET}")
        sys.exit(1)

    server_addr = (server_ip, DEFAULT_SERVER_PORT)

    if kill_switch:
        enable_killswitch(server_ip, DEFAULT_SERVER_PORT, port_count)
    if dns_protect:
        enable_dns_shield()

    # Bind local UDP listener for WireGuard
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind(("127.0.0.1", local_port))
    sock.setblocking(False)

    print(f"{Colors.GREEN}[OK] Python AEGS v4 Pantheon Proxy Active on 127.0.0.1:{local_port}{Colors.RESET}")
    print(f"     - Remote Server: {server_host} ({server_ip}:{DEFAULT_SERVER_PORT})")
    print(f"     - Key ID:        {kid_hex}")
    print(f"     - WireGuard:     Set Endpoint = 127.0.0.1:{local_port}")
    print(f"     - Anti-DPI:      Illusion Pre-Bypass + Bimodal Shaping + Active Chaffing + Port Hopping\n")

    # State-Machine Pre-Bypass: send STUN / QUIC Initial decoys before flow
    print(f"{Colors.CYAN}[*] Sending State-Machine Pre-Bypass decoys (STUN / QUIC)...{Colors.RESET}")
    send_illusion_sequence(sock, server_addr)
    print(f"{Colors.GREEN}[OK] DPI State-Machine Pre-Bypass armed.{Colors.RESET}")

    # Establish AEGS v3/v4 forward-secret session keys via ECDH handshake
    print(f"{Colors.CYAN}[*] Initiating ECDH handshake with server...{Colors.RESET}")
    send_key, recv_key, session_id, assigned_ip = perform_v3_handshake(sock, server_addr, raw_kid, master_key)
    aead_send = ChaCha20Poly1305(send_key)
    aead_recv = ChaCha20Poly1305(recv_key)

    print(f"{Colors.YELLOW}Proxying packets with Zero-DPI protection (Press Ctrl+C to stop)...{Colors.RESET}")

    wg_client_addr = None
    client_tx_seq = 0
    replay_last_seq = 0
    replay_bitmap = 0
    last_real_packet = time.monotonic()
    next_chaff_time = last_real_packet + 0.05 + secrets.randbelow(10) / 100.0

    def check_replay(seq: int) -> bool:
        nonlocal replay_last_seq, replay_bitmap
        if seq == 0:
            return True
        if seq > replay_last_seq:
            diff = seq - replay_last_seq
            if diff < 64:
                replay_bitmap = ((replay_bitmap << diff) | 1) & 0xFFFFFFFFFFFFFFFF
            else:
                replay_bitmap = 1
            replay_last_seq = seq
            return False
        diff = replay_last_seq - seq
        if diff >= 64:
            return True
        if replay_bitmap & (1 << diff):
            return True
        replay_bitmap |= (1 << diff)
        return False

    try:
        while True:
            # Active Chaffing: send dummy packets if idle > 500ms
            now = time.monotonic()
            if (now - last_real_packet) > 0.50:
                if now >= next_chaff_time:
                    next_chaff_time = now + 0.05 + secrets.randbelow(15) / 100.0
                    chaff_pad = 64 + secrets.randbelow(65)
                    chaff_frame = b"\x00\x00" + secrets.token_bytes(chaff_pad)
                    client_tx_seq += 1
                    chaff_nonce = struct.pack("<Q", client_tx_seq) + secrets.token_bytes(4)
                    chaff_hdr = bytearray(16)
                    chaff_hdr[0:8] = raw_kid
                    chaff_hdr[10] = 0x80 # CHAFF flag (silent drop on server)
                    chaff_hdr[12:16] = VER_MAGIC
                    chaff_iv = secrets.token_bytes(12)
                    chaff_masked = mask_unmask_header(bytes(chaff_hdr), mask_key, chaff_iv)
                    chaff_aad = chaff_iv + chaff_masked
                    chaff_ct = aead_send.encrypt(chaff_nonce, chaff_frame, chaff_aad)
                    try:
                        cur_port = compute_hopper_port(send_key, DEFAULT_SERVER_PORT, port_count, hop_interval)
                        sock.sendto(chaff_iv + chaff_masked + chaff_nonce + chaff_ct, (server_ip, cur_port))
                    except OSError:
                        pass

            r, _, _ = select.select([sock], [], [], 0.1)
            if not r:
                continue

            data, addr = sock.recvfrom(BUFFER_SIZE)
            if not data:
                continue

            is_server = (addr[0] == server_ip and DEFAULT_SERVER_PORT <= addr[1] < DEFAULT_SERVER_PORT + port_count)
            if is_server:
                # Inbound packet from remote AEGS server -> decrypt -> send to local WireGuard
                if len(data) < 56:
                    continue

                hdr_iv = data[:12]
                masked_hdr = data[12:28]
                unmasked_hdr = mask_unmask_header(masked_hdr, mask_key, hdr_iv)

                # Verify KeyID and VerMagic
                if unmasked_hdr[:8] != raw_kid or unmasked_hdr[12:16] != VER_MAGIC:
                    continue

                junk_len = struct.unpack(">H", unmasked_hdr[8:10])[0]
                aead_offset = 12 + 16 + junk_len
                if len(data) < aead_offset + 12 + TAG_LEN:
                    continue

                aead_nonce = data[aead_offset : aead_offset + 12]
                rx_seq = struct.unpack("<Q", aead_nonce[:8])[0]
                if check_replay(rx_seq):
                    continue

                ct = data[aead_offset + 12 :]
                try:
                    # FIX Blocker 3: Authenticate outer header data[:aead_offset] as AAD
                    pt = aead_recv.decrypt(aead_nonce, ct, data[:aead_offset])
                except Exception:
                    continue

                if len(pt) < 2:
                    continue

                plen = struct.unpack(">H", pt[:2])[0]
                if wg_client_addr and plen <= len(pt) - 2:
                    sock.sendto(pt[2 : 2 + plen], wg_client_addr)

            else:
                # Outbound packet from local WireGuard -> encrypt & pad -> send to server
                wg_client_addr = addr
                last_real_packet = time.monotonic()
                next_chaff_time = last_real_packet + 0.1

                plen = len(data)
                # Bimodal Semantic Padding (~256B for ACKs, ~1350B for Full MTU)
                pad_len = semantic_pad(plen)
                frame = struct.pack(">H", plen) + data + secrets.token_bytes(pad_len)

                client_tx_seq += 1
                aead_nonce = struct.pack("<Q", client_tx_seq) + secrets.token_bytes(4)

                # 20% chance of junk insertion
                junk_len = 16 + secrets.randbelow(49) if secrets.randbelow(100) < 20 else 0

                hdr_plain = raw_kid + struct.pack(">H", junk_len) + b"\x00\x00" + VER_MAGIC
                hdr_iv = secrets.token_bytes(12)
                masked_hdr = mask_unmask_header(hdr_plain, mask_key, hdr_iv)

                out_hdr = bytearray()
                out_hdr.extend(hdr_iv)
                out_hdr.extend(masked_hdr)
                if junk_len > 0:
                    out_hdr.extend(secrets.token_bytes(junk_len))

                # FIX Blocker 3: Authenticate outer header as AAD in AEAD Poly1305
                ct = aead_send.encrypt(aead_nonce, frame, bytes(out_hdr))

                out_pkt = bytearray(out_hdr)
                out_pkt.extend(aead_nonce)
                out_pkt.extend(ct)

                cur_port = compute_hopper_port(send_key, DEFAULT_SERVER_PORT, port_count, hop_interval)
                sock.sendto(bytes(out_pkt), (server_ip, cur_port))

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Stopping AEGS client proxy...{Colors.RESET}")
    finally:
        if kill_switch or dns_protect:
            disable_killswitch()
        sock.close()

# --- Config & CLI Handlers ---
def generate_wg_config(local_port: int, output_file: str = "aegis-wg.conf"):
    content = f"""# ==============================================================================
# WireGuard Client Configuration with AEGS v2 Zero-DPI Obfuscator
# ==============================================================================
[Interface]
# Replace with your assigned WireGuard Client Private Key and Address:
PrivateKey = YOUR_CLIENT_PRIVATE_KEY_HERE
Address = 10.8.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
# Replace with your server's WireGuard Public Key:
PublicKey = YOUR_SERVER_WIREGUARD_PUBLIC_KEY_HERE
# CRITICAL: Point Endpoint to local AEGS proxy port!
Endpoint = 127.0.0.1:{local_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    Path(output_file).write_text(content, encoding='utf-8')
    print(f"{Colors.GREEN}[OK] WireGuard configuration template saved -> {output_file}{Colors.RESET}")

def run_command(args):
    banner()
    server = args.server
    token = args.token
    port = args.port

    if not server or not token:
        print(f"{Colors.RED}[!] Server address and secret token are required.{Colors.RESET}")
        print(f"    Usage: python quick_client.py run --server <HOST> --token <TOKEN>")
        sys.exit(1)

    native_bin = find_native_binary()
    kill_switch = getattr(args, 'kill_switch', False)
    dns_protect = getattr(args, 'dns_protect', False)

    if native_bin and not args.force_python:
        print(f"{Colors.GREEN}[OK] Using native compiled binary: {native_bin}{Colors.RESET}")
        cmd = [str(native_bin), "--server", server, "--token", token, "--port", str(port)]
        if kill_switch: cmd.append("--kill-switch")
        if dns_protect: cmd.append("--dns-protect")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            pass
    else:
        if args.force_python:
            print(f"{Colors.CYAN}[*] Running with pure-Python proxy engine (--force-python requested)...{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[*] Native binary not found. Falling back to built-in pure-Python engine...{Colors.RESET}")
        run_python_proxy(server, token, port, kill_switch=kill_switch, dns_protect=dns_protect)

def keyid_command(args):
    _, kid_hex = compute_key_id(args.token)
    print(f"\n{Colors.BOLD}Secret Token:{Colors.RESET} {args.token}")
    print(f"{Colors.CYAN}{Colors.BOLD}Key ID (Hex):{Colors.RESET} {kid_hex}\n")

def interactive_wizard():
    banner()
    print(f"{Colors.WHITE}{Colors.BOLD}AEGS v2 Client Setup Wizard{Colors.RESET}\n")

    server = input("Enter Server IP or Hostname: ").strip()
    token = input("Enter Secret Token: ").strip()
    port_input = input(f"Enter Local UDP Port [{DEFAULT_LOCAL_PORT}]: ").strip()
    port = int(port_input) if port_input else DEFAULT_LOCAL_PORT

    if not server or not token:
        print(f"{Colors.RED}[!] Server and token are required.{Colors.RESET}")
        return

    generate_wg_config(port)
    print("")
    native_bin = find_native_binary()
    if native_bin:
        print(f"{Colors.GREEN}[OK] Found native binary: {native_bin}{Colors.RESET}")
        try:
            subprocess.run([str(native_bin), "--server", server, "--token", token, "--port", str(port)])
        except KeyboardInterrupt:
            pass
    else:
        run_python_proxy(server, token, port)

def main():
    parser = argparse.ArgumentParser(description="AEGS v2 Client Management & Proxy CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Run command
    run_parser = subparsers.add_parser("run", help="Launch AEGS obfuscator client proxy")
    run_parser.add_argument("-s", "--server", help="AEGS server IP or domain")
    run_parser.add_argument("-t", "--token", help="User authentication secret token")
    run_parser.add_argument("-p", "--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local UDP port (default: 51821)")
    run_parser.add_argument("--kill-switch", action="store_true", help="Enable hardware/firewall Kill-Switch")
    run_parser.add_argument("--dns-protect", action="store_true", help="Enable DNS Leak Protection shield")
    run_parser.add_argument("--force-python", action="store_true", help="Force pure-Python proxy instead of native binary")

    # KeyID command
    kid_parser = subparsers.add_parser("keyid", help="Calculate KeyID for a given token")
    kid_parser.add_argument("-t", "--token", required=True, help="Secret token")

    # Config command
    cfg_parser = subparsers.add_parser("gen-wg", help="Generate sample WireGuard client config")
    cfg_parser.add_argument("-p", "--port", type=int, default=DEFAULT_LOCAL_PORT, help="Local port")
    cfg_parser.add_argument("-o", "--out", default="aegis-wg.conf", help="Output file path")

    # Interactive wizard
    subparsers.add_parser("wizard", help="Interactive setup wizard")

    args = parser.parse_args()

    if args.command == "run":
        run_command(args)
    elif args.command == "keyid":
        keyid_command(args)
    elif args.command == "gen-wg":
        generate_wg_config(args.port, args.out)
    elif args.command == "wizard" or args.command is None:
        interactive_wizard()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
