# AEGS v4 Pantheon Protocol Specification

## 1. Introduction
- Problem: stateful DPI systems (ТСПУ, GFW, Cloudflare Magic Firewall) identify VPN protocols by static signatures and flow behavior
- Solution: AEGS v4 — transport protocol with per-packet randomized wire format, header masking, and behavioral evasion
- Scope: UDP transport, IPv4 tunneling, multi-user

## 2. Terminology
- Token: 256-bit pre-shared secret (user credential)
- KeyID: first 8 bytes of SHA-256(Token)
- MasterKey: PBKDF2-HMAC-SHA256(Token, KeyID, 200000 iterations, 32 bytes)
- MaskKey: HKDF-Expand(MasterKey, "aegis-v2-header-mask", 32)
- PayloadKey: HKDF-Expand(MasterKey, "aegis-v2-payload-key", 32)
- Session: active connection identified by KeyID and client UDP endpoint
- SessionKey: ephemeral per-session Curve25519 ECDH-derived key (provides PFS)

## 3. Cryptographic Primitives
- Symmetric encryption: ChaCha20-Poly1305 (RFC 8439), 256-bit key, 96-bit nonce
- Key derivation: PBKDF2-HMAC-SHA256 + HKDF-SHA256 (RFC 5869)
- Asymmetric: X25519 (Curve25519 ECDH, RFC 7748)
- MAC: HMAC-SHA256 truncated to 16 bytes
- CSPRNG: OpenSSL RAND_bytes

## 4. Session Establishment (Handshake)

### 4.1 HANDSHAKE_INIT (Client → Server)
Exact byte layout (72 bytes):
```
Offset  Len  Field
0       1    Type = 0x01
1       7    Reserved = 0x00...
8       8    KeyID = SHA-256(Token)[:8]
16      32   ClientEphemeralPublicKey (X25519)
48      8    Timestamp_ms (uint64 big-endian, Unix ms)
56      16   MAC = HMAC-SHA256(MasterKey, bytes[0:56])[:16]
```

Security properties:
- MAC authenticates that the sender knows the per-user Token (via MasterKey)
- Timestamp within ±30 seconds (anti-replay)
- Server rejects duplicate timestamps (sliding window, bounded at 100k entries)
- Pending handshake states bounded at 1024 with 30-second TTL (DoS protection)

### 4.2 HANDSHAKE_RESP (Server → Client)
Byte layout (80 bytes):
```
Offset  Len  Field
0       1    Type = 0x02
1       7    Reserved = 0x00...
8       8    SessionID (random uint64)
16      32   ServerEphemeralPublicKey (X25519)
48      16   EncryptedConfig = ChaCha20-Poly1305({AssignedIP[4], MTU[2], zeros[10]}, key=ConfigKey, nonce=0, AAD=Header[0..48])
64      16   AEAD_Tag (Poly1305 authentication tag for EncryptedConfig)
```

### 4.3 Session Key Derivation
```
SharedSecret = X25519(ClientEphPri, ServerEphPub)
ConfigKey = HKDF(SharedSecret, salt=MasterKey, info="aegs-cfg", len=32)
C2S_Key   = HKDF(SharedSecret, salt=MasterKey, info="aegs-c2s", len=32)
S2C_Key   = HKDF(SharedSecret, salt=MasterKey, info="aegs-s2c", len=32)
```
Provides Perfect Forward Secrecy: session keys are ephemeral and not recoverable from Token.
`MasterKey` is used as HKDF salt to prevent MITM ephemeral tampering.
`ConfigKey` separates handshake response configuration encryption from data-plane S2C traffic to guarantee cryptographic domain separation and prevent nonce reuse attacks.

## 5. Data Packet Format

### 5.1 Wire Packet Structure
```
+------------------+------------------+-------------+----------+------------------+
| HDR_IV (12)      | MASKED_HDR (16)  | JUNK (0-N)  | NONCE(12)| CIPHERTEXT (var) |
+------------------+------------------+-------------+----------+------------------+
```

All fields in order:
- `HDR_IV` (12 bytes): random per-packet IV for header masking
- `MASKED_HDR` (16 bytes): ChaCha20(PlainHDR, MaskKey, 0x00000000||HDR_IV)
- `JUNK` (0-N bytes): random bytes, length encoded in PlainHDR
- `AEAD_NONCE` (12 bytes): first 8 bytes = tx_seq (little-endian uint64), last 4 = random
- `CIPHERTEXT`: ChaCha20-Poly1305(FRAME, SessionKey, AEAD_NONCE, AAD=OuterHeader)
  * Note: Outer header `[HDR_IV || MASKED_HDR || JUNK]` is bound as Additional Authenticated Data (AAD) to prevent wire tampering.

### 5.2 PlainHDR Structure (16 bytes, before masking)
```
Offset  Len  Field
0       8    KeyID
8       2    JunkLen (big-endian uint16)
10      1    ChaffFlag (0x80 = chaff, 0x00 = data)
11      1    Reserved = 0x00
12      4    VER_MAGIC = 0x41473201 ("AG2\x01")
```

VER_MAGIC is NEVER visible on wire (always masked with per-packet ChaCha20 stream).

### 5.3 Frame Structure (inside AEAD)
```
Offset  Len   Field
0       2     PayloadLen (big-endian uint16)
2       P     IP Packet (raw IPv4)
2+P     R     Random padding (R = secure_random(32..256))
```

## 6. Anti-Replay
Sliding window per RFC 6479 (2048 packets window):
- Reject: seq == 0, seq older than window, seq already seen
- Accept: new seq (advance window), out-of-order within window

## 7. IP Address Management
- Server pool: 10.8.0.2 – 10.8.0.254 (253 concurrent clients)
- Server address: 10.8.0.1/24 on aegs0
- Assignment: during HANDSHAKE_RESP, in EncryptedConfig field
- Release: on session idle timeout (180 seconds)

## 8. DPI Evasion Properties (AEGS v4 Pantheon)

### 8.1 State-Machine Pre-Bypass ("AEGS Illusion")
Before sending `HANDSHAKE_INIT`, the client transmits decoy packets mimicking standard STUN Binding Requests (RFC 5389) or QUIC Initial packets (RFC 9000).
- **Current Behavior:** Decoys prime stateless / first-packet DPI heuristics into classifying the 5-tuple as WebRTC or HTTP/3.
- **Limitation & Threat Model:** Stateful DPI reassembling full bidirectional flows expects a matching STUN Success Response or QUIC ServerHello. An unmatched request followed by opaque high-entropy traffic can be flagged as an anomaly by advanced deep state trackers. Full in-band transaction spoofing is recommended against advanced stateful inspection.

### 8.2 Semantic Padding ("Bimodal Shaping" — Anti-ML)
Replaces uniform random padding with intelligent bimodal shaping:
- Small packets (≤200 B) → padded to ~256 B (QUIC ACK profile, ±16 B jitter)
- Large packets (>200 B) → padded to ~1350 B (full MTU QUIC frame, ±32 B jitter)
- 5% probability of medium packets (512-768 B) to prevent fingerprinting the bimodal distribution itself.

### 8.3 Active Chaffing (Anti-Timing Analysis)
During idle periods, client generates chaff packets. Chaff packets use the standard AEGS wire frame with bit `0x80` set in PlainHDR byte 10. Server authenticates and silently discards them.
- **Threat Model & Battery Considerations:** Continuous 50-200 ms constant-rate chaffing draws substantial battery and cellular data on mobile devices, and lacks real WebRTC codec dynamics (Voice Activity Detection / DTX pauses). Adaptive burst-and-silence shaping with exponential backoff on sustained idle (>15s) is required for mobile profiles.

### 8.4 Cryptographic Blackhole (Anti Active Probing)
When receiving invalid probe packets, server responds with realistic QUIC packets derived from probe entropy (0.0x amplification on small UDP probes, Version Negotiation, Retry, Connection Close).

## 9. Port Hopping (Active Transport Evasion)
AEGS v4 rotates active UDP ports every `hop_interval` seconds using HMAC-SHA256:
```
epoch = floor(time() / hop_interval)
hmac = HMAC-SHA256(session_key, epoch_be64)
port = base_port + (le32(hmac[0:4]) % port_count)
```
- **Deployment Note:** Default deployment keeps `port_count` small (e.g. 5 ports, 50001-50005) or utilizes dynamic single-port redirection via kernel iptables / eBPF to prevent automated port-scan detection from flagging large contiguous blocks of open UDP ports on a single host.

## 10. Session Resumption (Zero-RTT Reconnect)
After successful ECDH handshake, server issues a **ResumptionToken** (96 bytes):
- Nonce (12 B), Encrypted Session State (52 B), Poly1305 Tag (16 B), Reserved (16 B)
- Client resumes with `0x04 || token`, server verifies and restores keys in <5ms without full ECDH recalculation.

## 11. Network Security & Reliability Suite

### 11.1 Hardware Kill-Switch Isolation
Strict firewall isolation (`iptables` on Linux, WinFilter on Windows) ensures zero packet leaks if the tunnel drops:
- Dedicated chain `AEGS_KILLSWITCH` drops all traffic on physical interfaces except tunnel, loopback, DHCP, and VPN server port range.

### 11.2 DNS Leak Protection Shield
Blocks all unencrypted port 53 traffic across external physical adapters, enforcing exclusive resolution through internal tunnel DNS (`10.8.0.1`).

### 11.3 Transport Failure Detection (Advisory Monitor)
`TransportFailureDetector` continuously monitors transport health:
- Tracks consecutive timeout counts, sustained blackouts, and packet loss (>75%).
- **Current Status:** Currently implemented as an **in-memory advisory detector & telemetry logger** (`should_fallback_to_tcp() -> bool`). It raises structured alerts for client orchestrators to prompt fallback, rather than an automatic in-engine socket migration to TCP/TLS 1.3.

## 12. Security Considerations
- Token brute-force: 200,000 PBKDF2 iterations (~1s on modern CPU)
- DoS: rate limiter (5 responses/sec per IP), IP banning after 10 weight points
- Replay: RFC 6479 2048-packet sliding window
- Forward secrecy: ephemeral X25519 per session
- Header authentication: Outer header authenticated via Poly1305 AAD

## 13. Comparison with Related Protocols
| Feature | WireGuard | AmneziaWG 3.1 | XTLS-Reality | AEGS v4 Pantheon |
|---|---|---|---|---|
| Static handshake signature | Yes | Masked | N/A (TCP) | Masked + Illusion decoys |
| Padding | None | Uniform random (Jc) | None | Bimodal semantic (anti-ML) |
| Timing obfuscation | None | None | None | Active chaffing |
| Active probe resistance | None | DNS FORMERR | TLS camouflage | QUIC blackhole (3 strategies) |
| Forward secrecy | Yes | Yes | Yes | Yes (X25519 per session) |
| Protocol | UDP | UDP | TCP | UDP |
