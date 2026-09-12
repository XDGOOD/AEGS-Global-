# AEGS v5 "Pantheon" — Global Enterprise Edition 🌐

[![Tests](https://img.shields.io/badge/Tests-12%2F12%20Pillars%20PASS-brightgreen.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17%20%2F%20C%2B%2B20-blue.svg)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Sharded%20Data--Plane-critical.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg)](#)

> **Carrier-Grade, Multi-Core, Sharded UDP Tunnel Protocol (10+ Gbps Target)**  
> Engineered to decouple the Control Plane from the Data Plane, eliminate lock contention, and scale linearly across hardware cores.

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────┐
│              Control Plane              │
│    (Handshake / Resume / Database / GC) │
└────────────────────┬────────────────────┘
                     │ Immutable Session Object
 ┌───────────────────┼───────────────────┐
 │                   │                   │
 ▼                   ▼                   ▼
RX Workers          TX Workers          TUN Worker
 │                   │                   │
 ▼                   ▼                   ▼
Endpoint Lookup      Per-Session TX      Route Lookup
 │                   │                   │
 └─────────────► Sharded State ◄─────────┘
            (64 Independent Shards)
                     │
                     ▼ Bounded Ring Queues
                     │
                     ▼ Batch I/O (recvmmsg / sendmmsg)
```

### Key Engineering Principles:
1. **Control Plane does not block Data Plane**: Handshakes, token verification, and garbage collection run asynchronously without taking global locks on active UDP forwarding.
2. **Sharded Session State**: 64 independent shards (`hash(key_id) % 64`) eliminate lock contention across worker threads.
3. **Symmetric Batch I/O**: High-throughput packet processing via `recvmmsg()` (RX) and `sendmmsg()` (TX).
4. **Zero-Allocation Hot Path**: Thread-local scratch arenas (`thread_local PacketScratch`) ensure 0 heap allocations per forwarded packet.
5. **Fail-Closed Network Isolation**: Transactional network management with automated rollback.

---

## 🧭 Roadmap & Engineering Phases

- [x] **Phase 1 — Core Hardening & Security Audit** (P0/P1 fixes, fail-closed killswitch, client isolation, boot-secret tokens).
- [ ] **Phase 2 — Sharded Data-Plane Architecture** (`SessionTable` 64 shards, immutable routing, lock-free lookups).
- [ ] **Phase 3 — High-Performance Hot Path** (`sendmmsg()` batching, zero-copy packet arenas, thread-local scratch buffers).
- [ ] **Phase 4 — Reliability & Chaos Engineering** (72h soak tests, packet loss / reordering chaos simulation).
- [ ] **Phase 5 — Adaptive Stealth Profiles** (LITE fast profile vs STEALTH anti-DPI profile).

---

## 🏠 Looking for the Home Version?
For personal use, home setups, friends & family (up to 50 users) with a lightweight single-binary footprint, see **[AEGS Home Edition](https://github.com/XDGOOD/net-packet-handler)**.
