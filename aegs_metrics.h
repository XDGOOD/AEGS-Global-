#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Stage 19: Observability & Metrics
// Cache-line aligned, zero-lock lock-free atomic counters for data plane
// ==============================================================================
#include <atomic>
#include <cstdint>
#include <string>
#include <sstream>

struct alignas(64) AegsMetrics {
    // Wire RX/TX Counters
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> tx_bytes{0};

    // Crypto & Session Security
    std::atomic<uint64_t> handshake_ok{0};
    std::atomic<uint64_t> handshake_fail{0};
    std::atomic<uint64_t> resume_fast_ok{0};
    std::atomic<uint64_t> resume_pfs_ok{0};
    std::atomic<uint64_t> resume_fail{0};
    std::atomic<uint64_t> decrypt_ok{0};
    std::atomic<uint64_t> decrypt_fail{0};

    // Drops & Filtering
    std::atomic<uint64_t> replay_drop{0};
    std::atomic<uint64_t> spoof_drop{0};
    std::atomic<uint64_t> acl_drop{0};
    std::atomic<uint64_t> blackhole_triggers{0};
    std::atomic<uint64_t> roaming_hits{0};
    std::atomic<uint64_t> egress_failures{0};

    static AegsMetrics& instance() noexcept {
        static AegsMetrics inst;
        return inst;
    }

    std::string to_json() const {
        std::ostringstream ss;
        ss << "{\n"
           << "  \"rx_packets\": " << rx_packets.load(std::memory_order_relaxed) << ",\n"
           << "  \"tx_packets\": " << tx_packets.load(std::memory_order_relaxed) << ",\n"
           << "  \"rx_bytes\": " << rx_bytes.load(std::memory_order_relaxed) << ",\n"
           << "  \"tx_bytes\": " << tx_bytes.load(std::memory_order_relaxed) << ",\n"
           << "  \"handshake_ok\": " << handshake_ok.load(std::memory_order_relaxed) << ",\n"
           << "  \"handshake_fail\": " << handshake_fail.load(std::memory_order_relaxed) << ",\n"
           << "  \"resume_fast_ok\": " << resume_fast_ok.load(std::memory_order_relaxed) << ",\n"
           << "  \"resume_pfs_ok\": " << resume_pfs_ok.load(std::memory_order_relaxed) << ",\n"
           << "  \"resume_fail\": " << resume_fail.load(std::memory_order_relaxed) << ",\n"
           << "  \"decrypt_ok\": " << decrypt_ok.load(std::memory_order_relaxed) << ",\n"
           << "  \"decrypt_fail\": " << decrypt_fail.load(std::memory_order_relaxed) << ",\n"
           << "  \"replay_drop\": " << replay_drop.load(std::memory_order_relaxed) << ",\n"
           << "  \"spoof_drop\": " << spoof_drop.load(std::memory_order_relaxed) << ",\n"
           << "  \"acl_drop\": " << acl_drop.load(std::memory_order_relaxed) << ",\n"
           << "  \"blackhole_triggers\": " << blackhole_triggers.load(std::memory_order_relaxed) << ",\n"
           << "  \"roaming_hits\": " << roaming_hits.load(std::memory_order_relaxed) << ",\n"
           << "  \"egress_failures\": " << egress_failures.load(std::memory_order_relaxed) << "\n"
           << "}";
        return ss.str();
    }

    std::string to_prometheus() const {
        std::ostringstream ss;
        #define PROM_LINE(name, val) ss << "# TYPE aegs_" #name " counter\naegs_" #name " " << val.load(std::memory_order_relaxed) << "\n"
        PROM_LINE(rx_packets_total, rx_packets);
        PROM_LINE(tx_packets_total, tx_packets);
        PROM_LINE(rx_bytes_total, rx_bytes);
        PROM_LINE(tx_bytes_total, tx_bytes);
        PROM_LINE(handshake_ok_total, handshake_ok);
        PROM_LINE(handshake_fail_total, handshake_fail);
        PROM_LINE(resume_fast_ok_total, resume_fast_ok);
        PROM_LINE(resume_pfs_ok_total, resume_pfs_ok);
        PROM_LINE(resume_fail_total, resume_fail);
        PROM_LINE(decrypt_ok_total, decrypt_ok);
        PROM_LINE(decrypt_fail_total, decrypt_fail);
        PROM_LINE(replay_drop_total, replay_drop);
        PROM_LINE(spoof_drop_total, spoof_drop);
        PROM_LINE(acl_drop_total, acl_drop);
        PROM_LINE(blackhole_triggers_total, blackhole_triggers);
        PROM_LINE(roaming_hits_total, roaming_hits);
        PROM_LINE(egress_failures_total, egress_failures);
        #undef PROM_LINE
        return ss.str();
    }
};
