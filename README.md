# AEGS Titan Global — Защищенный оверлейный сетевой протокол

[![Language](https://img.shields.io/badge/Language-C%2B%2B17%20%2F%20C%2B%2B20-blue.svg)](#)
[![Platforms](https://img.shields.io/badge/Platforms-Android%20%7C%20Windows%20%7C%20Linux-green.svg)](#клиентские-приложения-и-загрузка)
[![Crypto](https://img.shields.io/badge/Crypto-ChaCha20--Poly1305%20%7C%20X25519-orange.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)
[![CI](https://github.com/XDGOOD/AEGS-Global-/actions/workflows/build_apk.yml/badge.svg)](https://github.com/XDGOOD/AEGS-Global-/actions/workflows/build_apk.yml)

> **Carrier-Grade, Multi-Core, Sharded UDP Tunnel Protocol (AEGS v6.5 Titan)**  
> Архитектура протокола с разделением плоскостей управления и данных (Control/Data planes), 64 шардированными аренами сессий, Copy-on-Write маршрутизацией ядра TUN, адаптивным контроллером противодавления AIMD и маскировкой сессий TLS 1.3 Reality ECH.

---

## Архитектура системы (AEGS v6.5 Titan)

```text
┌─────────────────────────────────────────────────────────────┐
│                        Control Plane                        │
│ (PBKDF2 / Handshake / PFS Resume / Epoch Rotations / GC)    │
└──────────────────────────────┬──────────────────────────────┘
                               │ Atomic RCU Snapshots (COW)
 ┌─────────────────────────────┼─────────────────────────────┐
 │                             │                             │
 ▼                             ▼                             ▼
RX Workers                TX Workers                    TUN Worker
 │                             │                             │
 ▼                             ▼                             ▼
Endpoint Lookup           Per-Session TX                Route Lookup
 │                             │                             │
 └─────────────────────────────┼─────────────────────────────┘
                     (64 Independent Shards)
                               │
                               ▼
                   Zero-Heap Scratch Arenas
                               │
                               ▼
            Symmetric Batch I/O (recvmmsg / sendmmsg)
```

### Ключевые архитектурные свойства:
1. **Control Plane Decoupled from Data Plane**: рукопожатия, деривация ключей и аудит сессий изолированы от горячего сетевого цикла передачи пакетов.
2. **64-Shard Partitioned Session State**: 64 независимые шарды (`splitmix64(key_id) % 64`) исключают межъядерную конкуренцию за блокировки.
3. **Lock-Free COW TUN Routing**: Copy-On-Write `/32` IP-маршрутизация гарантирует быстрый и безопасный роутинг пакетов ядра без задержек.
4. **RCU SessionCrypto Snapshots**: RX-воркеры получают неизменяемый снимок крипто-состояния (`std::shared_ptr<const SessionCrypto>`) без глобальных мьютексов.
5. **Robust Partial-Send Recovery**: пакетная отправка `sendmmsg()` с обработкой частичных сбросов сокета предотвращает утечки очередей.
6. **Zero-Allocation Hot Path**: потокобезопасные scratch-арены (`thread_local PacketScratch`) обеспечивают 0 аллокаций в куче на пакет данных.
7. **AIMD Adaptive Egress Pacing**: встроенный контроллер противодавления для предотвращения Bufferbloat и всплесков джиттера на нестабильных каналах связи.
8. **Два режима возобновления сессий (Fast 0-RTT и Full PFS)**:
   - **Fast Resume (Opcode `0x04`)**: мгновенное 0-RTT восстановление сессии при смене сети (Wi-Fi <-> LTE).
   - **PFS Resume (Opcode `0x05` / `0x06`)**: 1-RTT пересогласование ключей через эфемерный X25519 ECDH для гарантии Perfect Forward Secrecy.
9. **Стелс-маскировка TLS 1.3 Reality ECH**: обрамление сессий в легитимные структуры TLS 1.3 (Application Data 0x17 0x03 0x03) на порту 443 с реальным SNI.

---

## Синтетические тесты производительности

| Тест / Метрика | Результат ядра | Порог спецификации | Статус |
| :--- | :--- | :--- | :---: |
| **RFC 6479 Anti-Replay Throughput** | **155.49 Mpps** (6.43 нс / пакет) | > 50 Mpps | PASS |
| **64-Shard Session Lookup** | **21.24 M lookups/sec** (47.07 нс) | > 10 Mpps | PASS |
| **Single-Thread Loopback Forwarding** | **~375 Mbit/s** (in-memory crypto) | Line rate (1 поток) | PASS |
| **ThreadSanitizer (TSAN) Audit** | **0 warnings, 0 races, 0 deadlocks** | Полная стабильность | PASS |
| **AddressSanitizer (ASan + UBSan)** | **0 leaks, 0 memory corruption** | Чистая память | PASS |
| **10-Thread Contention Stress** | **> 348,000 pkts/sec** under churn | Без просадок | PASS |
| **Memory RSS Stability (Soak Test)** | **< 0.2 MB drift** / 1,000 сессий | Утечек нет | PASS |
| **Adversarial Network Attacks** | **9 / 9 отражено (100% Fail-Closed)** | Replay, MITM, Probes | PASS |

---

## Сборка и запуск сервера

```bash
# 1. Клонирование репозитория
git clone https://github.com/XDGOOD/AEGS-Global-.git
cd AEGS-Global-

# 2. Сборка через CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2

# 3. Запуск сервера
./build/aegs_server --port 50001 --token "my_secure_token"
```

---

## Клиентские приложения и загрузка

### Мобильное приложение для Android (Titan v6.5)

Нативный клиент на чистой Java для мобильных устройств:
- Полная реализация протокола AEGS v6.5 Titan с криптографией X25519 и ChaCha20-Poly1305.
- 4 профиля маскировки: Стелс Reality ECH, Fast Emergency 0-RTT, Turbo PQC, Hybrid Auto.
- Умная раздельная маршрутизация (Split-Routing) для прямого доступа к отечественным сервисам и банкам.
- Информативная шторка уведомлений со спидометром трафика в реальном времени (`↓ X МБ/с  ↑ Y КБ/с`), быстрой паузой на 5 минут и кнопкой отключения.
- Поддержка плитки быстрых настроек (Quick Settings Tile) в системной шторке Android.
- Полная поддержка Android 13+ (включая рантайм-разрешение уведомлений и предотвращение троттлинга).

* **Загрузка APK**:
  - [AEGS-v6.5-titan.apk (Релиз v6.5)](https://github.com/XDGOOD/AEGS-Global-/releases/download/v6.0-titan/AEGS-v6.5-titan.apk)
  - [AEGS-v6.0-titan.apk (Зеркало)](https://github.com/XDGOOD/AEGS-Global-/releases/download/v6.0-titan/AEGS-v6.0-titan.apk)
  - Страница релизов: [GitHub Releases](https://github.com/XDGOOD/AEGS-Global-/releases)

### Настольный клиент для Windows

* Нативное приложение на **.NET 10 WPF** (директория `windows/AegsTitan`).
* Реализация протокола на C# с аппаратной поддержкой криптографических примитивов.
* Темный интерфейс Obsidian/Amber, переключение режимов, живые счетчики сетевой скорости и пинга.

---

## Лицензия

Проект распространяется под открытой лицензией [MIT License](LICENSE).
Copyright (c) 2026 XDGOOD.
