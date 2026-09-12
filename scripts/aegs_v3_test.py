#!/usr/bin/env python3
"""AEGS v3 Protocol Test Suite - Windows Compatible"""
from __future__ import annotations
import sys, struct, hashlib, hmac, secrets

G='\033[0;32m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[1m'; X='\033[0m'
passed = 0
failed = 0

def ok(name):
    global passed
    passed += 1
    print(f'  {G}[PASS]{X} {name}')

def fail(name, reason=''):
    global failed
    failed += 1
    msg = f'  {R}[FAIL]{X} {name}'
    if reason:
        msg += f': {reason}'
    print(msg)

def section(name):
    print(f'\n{C}{B}=== {name} ==={X}')

# ── Crypto helpers ──────────────────────────────────────────────────────────
def compute_key_id(token):
    return hashlib.sha256(token.encode()).digest()[:8]

def derive_master_key(token, salt_hex):
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac('sha256', token.encode(), salt, 200000, 32)

def hkdf_expand(prk, info, length=32):
    T = b''
    okm = b''
    i = 1
    while len(okm) < length:
        T = hmac.new(prk, T + info.encode() + bytes([i]), 'sha256').digest()
        okm += T
        i += 1
    return okm[:length]

def chacha_enc(pt, key, nonce):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305(key).encrypt(nonce, pt, None)

def chacha_dec(ct, key, nonce):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)

def header_mask(data, mask_key, hdr_iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    full_nonce = b'\x00\x00\x00\x00' + hdr_iv
    enc = Cipher(algorithms.ChaCha20(mask_key, full_nonce), mode=None).encryptor()
    return enc.update(data)

# ── Test 1: Key Derivation ───────────────────────────────────────────────────
section('TEST 1: Key Derivation')
token_alice = 'alice_secret_token_v3'
token_bob = 'bob_secret_token_v3'

kid_alice = compute_key_id(token_alice)
kid_bob = compute_key_id(token_bob)

if kid_alice != kid_bob:
    ok('KeyID alice != bob (no collision)')
else:
    fail('KeyID collision')

if len(kid_alice) == 8:
    ok(f'KeyID alice = {kid_alice.hex()} (8 bytes)')
else:
    fail('KeyID length')

mk_alice = derive_master_key(token_alice, kid_alice.hex())
mk_bob = derive_master_key(token_bob, kid_bob.hex())

if mk_alice != mk_bob:
    ok('MasterKey alice != bob')
else:
    fail('MasterKey isolation')

mk_alice2 = derive_master_key(token_alice, kid_alice.hex())
if mk_alice == mk_alice2:
    ok('Key derivation is deterministic')
else:
    fail('Key derivation determinism')

mask_key_alice = hkdf_expand(mk_alice, 'aegis-v2-header-mask')
payload_key_alice = hkdf_expand(mk_alice, 'aegis-v2-payload-key')
mask_key_bob = hkdf_expand(mk_bob, 'aegis-v2-header-mask')
payload_key_bob = hkdf_expand(mk_bob, 'aegis-v2-payload-key')

if mask_key_alice != mask_key_bob and payload_key_alice != payload_key_bob:
    ok('HKDF keys: per-user isolation confirmed')
else:
    fail('HKDF per-user isolation')

# ── Test 2: Header Masking ───────────────────────────────────────────────────
section('TEST 2: Header Masking')
hdr_plain = bytes([0xAA, 0xBB, 0xCC, 0xDD] * 4)
hdr_iv = secrets.token_bytes(12)

masked = header_mask(hdr_plain, mask_key_alice, hdr_iv)
unmasked = header_mask(masked, mask_key_alice, hdr_iv)

if masked != hdr_plain:
    ok('Masking changes data')
else:
    fail('Masking no effect')

if unmasked == hdr_plain:
    ok('Unmask roundtrip correct')
else:
    fail('Unmask roundtrip')

wrong_unmask = header_mask(masked, mask_key_bob, hdr_iv)
if wrong_unmask != hdr_plain:
    ok('Wrong key cannot unmask (security check)')
else:
    fail('Wrong-key security check')

# ── Test 3: ChaCha20-Poly1305 ────────────────────────────────────────────────
section('TEST 3: ChaCha20-Poly1305 AEAD')
pt = b'Hello AEGS v3 World! IP packet simulation data'
nonce12 = secrets.token_bytes(12)

ct = chacha_enc(pt, payload_key_alice, nonce12)
pt2 = chacha_dec(ct, payload_key_alice, nonce12)

if pt == pt2:
    ok('Encrypt/decrypt roundtrip')
else:
    fail('Roundtrip')

if ct != pt:
    ok('Ciphertext != plaintext')
else:
    fail('Ciphertext same as plaintext')

tampered = bytearray(ct)
tampered[8] ^= 0xFF
try:
    chacha_dec(bytes(tampered), payload_key_alice, nonce12)
    fail('Tamper detection: should have raised')
except Exception:
    ok('Tamper detection: AEAD rejected modified ciphertext')

try:
    chacha_dec(ct, payload_key_bob, nonce12)
    fail('Wrong-key decryption: should have raised')
except Exception:
    ok('Wrong-key decryption: correctly rejected')

# ── Test 4: Anti-Replay Filter ───────────────────────────────────────────────
section('TEST 4: Anti-Replay Filter (RFC 6479)')

class AntiReplay:
    def __init__(self):
        self.last_seq = 0
        self.bitmap = 0
    def check(self, seq):
        MASK = 0xFFFFFFFFFFFFFFFF
        if seq == 0:
            return True
        if seq > self.last_seq:
            d = seq - self.last_seq
            self.bitmap = ((self.bitmap << d) & MASK) | 1 if d < 64 else 1
            self.last_seq = seq
            return False
        d = self.last_seq - seq
        if d >= 64:
            return True
        if self.bitmap & (1 << d):
            return True
        self.bitmap |= (1 << d)
        return False

ar = AntiReplay()
errors = [i for i in range(1, 200) if ar.check(i)]
if not errors:
    ok('Forward sequence 1-199: all accepted')
else:
    fail('Forward sequence', str(errors[:3]))

if ar.check(100):
    ok('Replay seq=100: rejected')
else:
    fail('Replay detection')

ar2 = AntiReplay()
ar2.check(200)
if ar2.check(100):
    ok('Too-old packet (window=64): rejected')
else:
    fail('Too-old rejection')

ar3 = AntiReplay()
ar3.check(100)
ar3.check(105)
ar3.check(103)
if ar3.check(103):
    ok('Out-of-order replay seq=103: rejected')
else:
    fail('Out-of-order replay')

# ── Test 5: IP Pool Simulation ───────────────────────────────────────────────
section('TEST 5: IP Pool Manager')

pool = list(range(0x0A080002, 0x0A0800FF))
allocated = {}

def pool_alloc():
    for ip in pool:
        if ip not in allocated:
            allocated[ip] = True
            return ip
    return None

def pool_free(ip):
    allocated.pop(ip, None)

def ip_str(ip):
    return f'{(ip>>24)&255}.{(ip>>16)&255}.{(ip>>8)&255}.{ip&255}'

ip1 = pool_alloc()
ip2 = pool_alloc()
ip3 = pool_alloc()

if ip1 is not None and ip_str(ip1) == '10.8.0.2':
    ok(f'First allocation: {ip_str(ip1)}')
else:
    fail('First allocation')

if ip1 != ip2 and ip2 != ip3 and ip1 != ip3:
    ok(f'Allocations unique: {ip_str(ip1)}, {ip_str(ip2)}, {ip_str(ip3)}')
else:
    fail('Unique allocation')

pool_free(ip2)
new_ip2 = pool_alloc()
if new_ip2 == ip2:
    ok(f'Release+realloc: {ip_str(ip2)} reused')
else:
    fail('Release and realloc')

if len(pool) == 253:
    ok('Pool size: 253 addresses (10.8.0.2 - 10.8.0.254)')
else:
    fail(f'Pool size: got {len(pool)}')

# ── Test 6: Wire Format Roundtrip ────────────────────────────────────────────
section('TEST 6: Full Wire Format Roundtrip')

VER_MAGIC = b'AG2\x01'

fake_ip_pkt = bytes([0x45, 0x00, 0x00, 0x28]) + secrets.token_bytes(36)

pad = secrets.token_bytes(48)
frame = struct.pack('>H', len(fake_ip_pkt)) + fake_ip_pkt + pad

nonce_w = secrets.token_bytes(12)
ct_w = chacha_enc(frame, payload_key_alice, nonce_w)

hdr_plain = kid_alice + b'\x00\x00\x00\x00' + VER_MAGIC
hdr_iv_w = secrets.token_bytes(12)
masked_hdr = header_mask(hdr_plain, mask_key_alice, hdr_iv_w)

wire = hdr_iv_w + masked_hdr + nonce_w + ct_w

if len(wire) >= 56:
    ok(f'Wire packet: {len(wire)} bytes')
else:
    fail('Wire packet too small')

um_hdr = header_mask(wire[12:28], mask_key_alice, wire[:12])
if um_hdr[:8] == kid_alice and um_hdr[12:16] == VER_MAGIC:
    ok('Header unmask + KeyID verify: OK')
else:
    fail('Header verify')

dec_frame = chacha_dec(wire[40:], payload_key_alice, wire[28:40])
plen = struct.unpack('>H', dec_frame[:2])[0]
if dec_frame[2:2+plen] == fake_ip_pkt:
    ok('Full roundtrip: IP payload recovered correctly')
else:
    fail('IP payload recovery')

bob_hdr = header_mask(wire[12:28], mask_key_bob, wire[:12])
if bob_hdr[:8] != kid_alice:
    ok('Cross-user isolation: Bob cannot decode Alice packet')
else:
    fail('Cross-user isolation')

# ── Summary ──────────────────────────────────────────────────────────────────
total = passed + failed
print(f'\n{C}={"="*40}{X}')
print(f'{B}AEGS v3 Test Results{X}')
print(f'{C}={"="*40}{X}')
print(f'  {G}Passed: {passed}/{total}{X}')
if failed:
    print(f'  {R}Failed: {failed}/{total}{X}')
    sys.exit(1)
else:
    print(f'  {G}{B}ALL TESTS PASSED{X}')
    sys.exit(0)
