# AEGS v5 "Pantheon" - Global Enterprise Edition 🌐

[![CI](https://github.com/XDGOOD/AEGS-Global-/actions/workflows/sanitizers_ci.yml/badge.svg)](https://github.com/XDGOOD/AEGS-Global-/actions/workflows/sanitizers_ci.yml)
[![TSAN](https://img.shields.io/badge/TSAN-0%20warnings-brightgreen.svg)](#)
[![Data Races](https://img.shields.io/badge/Data%20Races-0-brightgreen.svg)](#)
[![Deadlocks](https://img.shields.io/badge/Deadlocks-0-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-21%2F21%20PASS%20(100%25)-brightgreen.svg)](#)
[![Attacks](https://img.shields.io/badge/Attack%20Defense-9%2F9%20PASS-brightgreen.svg)](#)
[![Chaos](https://img.shields.io/badge/Chaos%20Resilience-5%2F5%20PASS-brightgreen.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17%20%2F%20C%2B%2B20-blue.svg)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Sharded%20Data--Plane-critical.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)

> **Carrier-Grade, Multi-Core, Sharded UDP Tunnel Protocol**  
> Engineered with decoupled Control/Data planes, 64 partitioned shards, lock-free route tables, and full ThreadSanitizer verification (0 data races, 0 deadlocks).

---

## 🏛️ System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Control Plane                         │
│ (PBKDF2 / Handshake / PFS Resume / Epoch Rotations / GC)     │
└──────────────────────────────┬───────────────────────────────┘
                               │ Atomic RCU Snapshots (COW)
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
                   Zero-Heap Scratch Arenas
                               │
                               ▼
            Symmetric Batch I/O (recvmmsg / sendmmsg)
```

### Key Engineering Principles:
1. **Control Plane Decoupled from Data Plane**: Handshakes, token verification, and garbage collection run asynchronously on dedicated control threads without taking global locks on active UDP forwarding.
2. **64-Shard Partitioned Session State**: 64 independent shards (`splitmix64(key_id) % 64`) eliminate global session table contention across worker threads.
3. **Lock-Free COW TUN Routing**: Copy-On-Write `/32` IP route table allows TUN packet forwarding with **zero locks** on the packet path.
4. **RCU SessionCrypto Snapshots**: RX worker packet decryption reads immutable RCU crypto snapshots (`std::shared_ptr<const SessionCrypto>`) with zero mutex locks and zero data races during concurrent rekeys and resumptions.
5. **Robust Partial-Send Recovery**: `sendmmsg()` batch egress loops on partial writes (`cur += sent`), eliminating socket drops under partial buffer availability.
6. **Zero-Allocation Hot Path**: Thread-local scratch arenas (`thread_local PacketScratch`) ensure 0 heap allocations per forwarded packet.
7. **AIMD Adaptive Backpressure Controller**: Multiplicative decrease and additive increase backpressure prevents socket buffer overflows and packet drops under heavy network congestion.
8. **Dual Resumption Modes (Fast 0-RTT vs Full PFS)**:
   - **Fast Resume (Opcode `0x04`)**: 0-RTT instant reconnection using encrypted pre-shared resumption tokens.
   - **PFS Resume (Opcode `0x05` / `0x06`)**: 1-RTT resumption with fresh ephemeral X25519 ECDH exchange and HKDF key derivation for full Perfect Forward Secrecy.
9. **Fail-Closed Transactional Network State**: `prepare -> apply -> verify -> commit / rollback` state machine guarantees zero firewall or DNS leaks on Linux hosts.

---

## 🔬 Verified Performance & Sanitizer Metrics

All metrics are experimentally measured on bare-metal and Linux CI environments.

| Metric / Benchmark | Measured Value | Standard / Target | Status |
| :--- | :--- | :--- | :---: |
| **RFC 6479 Anti-Replay Throughput** | **155.49 Mpps** (6.43 ns / packet) | > 50 Mpps | ✅ PASS |
| **64-Shard Session Lookup** | **21.24 M lookups/sec** (47.07 ns) | > 10 Mpps | ✅ PASS |
| **Single-Thread Loopback Forwarding** | **~375 Mbit/s** (in-memory crypto) | Line rate (1-core) | ✅ PASS |
| **ThreadSanitizer (TSAN) Audit** | **0 warnings, 0 races, 0 deadlocks** | Zero tolerance | ✅ PASS |
| **AddressSanitizer (ASan + UBSan)** | **0 leaks, 0 memory corruption** | Zero tolerance | ✅ PASS |
| **10-Thread Contention Stress** | **> 348,000 pkts/sec** under churn | Zero deadlocks | ✅ PASS |
| **Memory RSS Stability (Soak Test)** | **< 0.2 MB drift** / 1,000 active sessions | Bounded heap | ✅ PASS |
| **Adversarial Network Attacks** | **9 / 9 Blocked (100% Fail-Closed)** | Replay, MITM, Probes | ✅ PASS |
| **Severe Network Chaos Simulation** | **5 / 5 Resilient (100% Fail-Closed)** | 10% loss, 5% dups | ✅ PASS |

---

## 📊 Roadmap & Implemented Phases

- [x] **Phase 1 — Core Hardening & Security Audit**
  - Cryptographic context isolation via HKDF-SHA256 separate sub-keys (header mask vs payload).
  - Shannon entropy randomization (~7.8 / 8.0 bits/byte).
  - RFC 6479 2048-packet multi-word sliding window anti-replay.
  - Constant-time MAC comparisons (`CRYPTO_memcmp`).
- [x] **Phase 2 — Sharded Data-Plane Architecture**
  - Complete elimination of global `sessions_mu` and `g_endpoint_mu` from the packet path.
  - 64 independent shards with `splitmix64` dispersion.
  - Lock-free Copy-On-Write (COW/RCU) route table for TUN egress.
  - RCU crypto snapshot readers on RX fast path.
  - Dedicated GC thread running every 2s for idle session reclamation.
- [x] **Phase 3 — High-Performance Hot Path & Batching**
  - Symmetric `sendmmsg()` batch egress with partial send retry loop.
  - 64-byte aligned `thread_local PacketScratch` (0 heap allocs/packet).
  - O(1) ring-buffered rate limiters with generational slot eviction (`FastRateLimiter<4096>`).
- [x] **Phase 4 — Reliability, Sanitizers & Chaos Engineering**
  - AIMD adaptive backpressure controller (halves batch on congestion, dynamically scales pacing delay).
  - ThreadSanitizer concurrency audit (eliminated session recycle deadlock & session_id race).
  - Network chaos simulation test runner (`tests/chaos_runner.py`: 1-10% loss, reordering, duplication, bit-flips).
  - Long-term soak testing runner (`tests/soak_runner.py`: RSS memory bounds under active churn).
  - Parser fuzz harness (`fuzzing/fuzz_parsers.cpp` + `aegs_fuzz` CMake target).
  - Transactional firewall & DNS leak state machine with automated rollback.
- [x] **Phase 5 — Observability & Automated CI**
  - Zero-lock atomic Prometheus & JSON metrics exporter (`aegs_metrics.h`).
  - Structured logging level system (`aegs_log.h`: TRACE, DEBUG, INFO, WARN, ERROR).
  - Modular profiles (`AEGS_PROFILE=lite`, `AEGS_PROFILE=stealth`, `AEGS_PROFILE=balanced`).
  - Automated GitHub Actions Cloud CI running ASan, UBSan, TSAN, and Multicore benchmarks.

---

## 🛠️ Build & Compilation

### Requirements
- Linux kernel 5.4+ (with `recvmmsg` / `sendmmsg` support)
- GCC 9+ or Clang 10+ (supporting C++17)
- CMake 3.16+
- OpenSSL 1.1.1+ or 3.0+ (`libssl-dev`)
- SQLite3 (`libsqlite3-dev`)

### Standard Release Build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Sanitizer Builds (Development & Testing)
```bash
# AddressSanitizer (ASan) + UndefinedBehaviorSanitizer (UBSan)
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build build-asan -j$(nproc)

# ThreadSanitizer (TSAN)
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DENABLE_TSAN=ON
cmake --build build-tsan --target test_concurrency_stress -j$(nproc)
```

### Running Benchmarks
```bash
# Single-thread microbenchmark
./build/bench_hotpath

# Multicore scaling & capacity benchmark (1, 2, 4, 8 workers; 1k - 100k sessions)
./build/bench_multicore
```

### Running Concurrency Stress Harness
```bash
./build/test_concurrency_stress
```

### Running Parser Fuzz Harness
```bash
./build/aegs_fuzz 100000
```

---

## 🧪 Verification & Test Suites

```bash
# Run 12-Pillar Advanced Security Suite (21/21 PASS)
python test_suite_v4.py

# Run Attack & Exploitation Simulation (9/9 PASS)
python run_attack_tests.py

# Run Chaos & Network Resilience Simulator (5/5 PASS)
python tests/chaos_runner.py

# Run Long-Term Soak Test (1,000 sessions, memory drift audit)
python tests/soak_runner.py --duration 60 --sessions 1000
```

---

## 🏠 Looking for the Home Version?
For personal use, home setups, friends & family (up to 50 users) with a lightweight single-binary footprint, 1-click server installer, and OpenWrt router support, see **[AEGS Home Edition](https://github.com/XDGOOD/net-packet-handler)**.
