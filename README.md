# AEGS v5 "Pantheon" - Global Enterprise Edition 🌐

[![Tests](https://img.shields.io/badge/Tests-21%2F21%20PASS%20(100%25)-brightgreen.svg)](#)
[![Attacks](https://img.shields.io/badge/Attack%20Defense-9%2F9%20PASS-brightgreen.svg)](#)
[![Chaos](https://img.shields.io/badge/Chaos%20Resilience-5%2F5%20PASS-brightgreen.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17%20%2F%20C%2B%2B20-blue.svg)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Sharded%20Data--Plane-critical.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Status](https://img.shields.io/badge/Status-Production%20Hardened-brightgreen.svg)](#)

> **Carrier-Grade, Multi-Core, Sharded UDP Tunnel Protocol (10+ Gbps Target)**  
> Engineered to decouple the Control Plane from the Data Plane, eliminate lock contention, and scale linearly across hardware cores.

---

## 🏛️ System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Control Plane                         │
│ (PBKDF2 / Handshake / PFS Resume / Epoch Rotations / GC)     │
└──────────────────────────────┬───────────────────────────────┘
                               │ Copy-On-Write Snapshots
 ┌─────────────────────────────┼───────────────────────────────┐
 │                             │                               │
 ▼                             ▼                               ▼
RX Workers                TX Workers                      TUN Worker
 │                             │                               │
 ▼                             ▼                               ▼
Endpoint Lookup           Per-Session TX                  Route Lookup
 │                             │                               │
 └──────────────────────► Sharded State ◄──────────────────────┘
                     (64 Independent Shards)
                               │
                               ▼
                      Bounded Ring Queues
                               │
                               ▼
                   Batch I/O (recvmmsg / sendmmsg)
```

### Key Engineering Principles:
1. **Control Plane Decoupled from Data Plane**: Handshakes, token verification, and garbage collection run asynchronously without taking global locks on active UDP forwarding.
2. **64-Shard Partitioned Session State**: 64 independent shards (`splitmix64(key_id) % 64`) eliminate lock contention across worker threads.
3. **Lock-Free COW TUN Routing**: Copy-On-Write `/32` IP route table allows TUN packet forwarding with **0 locks** on the packet path.
4. **Symmetric Batch I/O**: High-throughput packet processing via `recvmmsg()` (RX) and `sendmmsg()` (TX).
5. **Zero-Allocation Hot Path**: Thread-local scratch arenas (`thread_local PacketScratch`) ensure 0 heap allocations per forwarded packet.
6. **AIMD Congestion Control**: Multiplicative decrease and additive increase backpressure controller prevents bufferbloat and socket drops under load.
7. **Perfect Forward Secrecy on Resumption (PFS)**: Opcode `0x05` performs fresh Ephemeral X25519 ECDH exchanges on reconnects while preserving <5ms latency.
8. **Fail-Closed Transactional Network State**: `prepare -> apply -> verify -> commit / rollback` state machine guarantees zero firewall or DNS leaks.

---

## 📊 Roadmap & Implemented Phases

- [x] **Phase 1 — Core Hardening & Security Audit**
  - P0/P1 cryptographic vulnerability remediation.
  - Context isolation via HKDF-SHA256 separate sub-keys.
  - Shannon entropy randomization (~7.8 / 8.0 bits/byte).
  - RFC 6479 2048-packet multi-word sliding window anti-replay.
- [x] **Phase 2 — Sharded Data-Plane Architecture**
  - Complete elimination of global `sessions_mu` and `g_endpoint_mu` from the packet path.
  - 64 independent shards with `splitmix64` dispersion.
  - Lock-free Copy-On-Write (COW/RCU) route table for TUN egress.
  - Safe generation-counted `SessionHandle` preventing use-after-free.
- [x] **Phase 3 — High-Performance Hot Path & Batching**
  - Symmetric `sendmmsg()` batch egress.
  - 64-byte aligned `thread_local PacketScratch` (0 heap allocs/packet).
  - O(1) ring-buffered rate limiters (`FastRateLimiter<4096>`).
- [x] **Phase 4 — Reliability & Chaos Engineering**
  - AIMD adaptive backpressure controller (halves batch on congestion, dynamically scales pacing delay).
  - Network chaos simulation test runner (`tests/chaos_runner.py`: 1-10% loss, reordering, duplication, bit-flips).
  - Parser fuzz harness (`fuzzing/fuzz_parsers.cpp` + `aegs_fuzz` CMake target).
  - Transactional firewall & DNS leak state machine with automated rollback.
- [x] **Phase 5 — Observability & Profiles**
  - Zero-lock atomic Prometheus & JSON metrics exporter (`aegs_metrics.h`).
  - Structured logging level system (`aegs_log.h` TRACE, DEBUG, INFO, WARN, ERROR).
  - Modular profiles (`AEGS_PROFILE=lite`, `AEGS_PROFILE=stealth`, `AEGS_PROFILE=balanced`).

---

## 🧪 Verification & Test Suites

```bash
# Run 12-Pillar Advanced Security Suite (21/21 PASS)
python test_suite_v4.py

# Run Attack & Exploitation Simulation (9/9 PASS)
python run_attack_tests.py

# Run Chaos & Network Resilience Simulator (5/5 PASS)
python tests/chaos_runner.py
```

---

## 🏠 Looking for the Home Version?
For personal use, home setups, friends & family (up to 50 users) with a lightweight single-binary footprint, 1-click server installer, and OpenWrt router support, see **[AEGS Home Edition](https://github.com/XDGOOD/net-packet-handler)**.
