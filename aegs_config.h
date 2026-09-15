#pragma once
// ==============================================================================
// AEGS v6 "Titan" Global Edition -- Central Configuration & Profiles
// ==============================================================================
#include <cstdint>
#include <string>
#include <cstdlib>

enum class AegsProfile {
    BALANCED,   // Default: standard bimodal shaping, moderate jitter
    LITE,       // High-Throughput (10+ Gbps): zero-chaff, minimal padding, 0ms jitter
    STEALTH     // Deep Anti-DPI: aggressive bimodal padding, timing chaff, protocol mimicry
};

struct AegsConfig {
    // --- Performance Profile (Stage 28 / 29) ---------------------------------
    AegsProfile profile       = AegsProfile::BALANCED;

    // --- Network / port hopping (Component 3) --------------------------------
    uint16_t base_port        = 50001;
    int      port_count       = 10;              // number of ports to bind
    uint32_t hop_interval_sec = 30;

    // --- DPI bypass options (Component 3) ------------------------------------
    bool     quic_mimicry     = false;           // AEGS_QUIC_MIMICRY=1
    bool     traffic_shaping  = false;           // AEGS_TRAFFIC_SHAPING=1
    bool     semantic_padding = true;            // AEGS_SEMANTIC_PADDING=1 (bimodal shaping)
    int      jitter_ms        = 5;               // AEGS_JITTER_MS

    // --- TUN / routing -------------------------------------------------------
    std::string tun_name      = "aegs0";
    std::string tun4_cidr     = "10.8.0.1/24";
    std::string tun6_prefix   = "fd00:ae95::/64";
    int         mtu           = 1400;

    // --- Persistence / auth --------------------------------------------------
    std::string db_path       = "/app/data/aegis.db";
    std::string key_path      = "server_key.bin";

    // --- Operational tuning --------------------------------------------------
    double session_idle_timeout = 180.0;
    double cleanup_interval     = 30.0;
    int    worker_threads       = 0;
    int    recv_batch_size      = 32;
    bool   client_isolation     = true;            // AEGS_CLIENT_ISOLATION=0 to allow inter-client

    // Convenience accessor - alias for tun4_cidr (matches spec field tun_addr)
    const std::string& tun_addr() const noexcept { return tun4_cidr; }

    static AegsConfig from_env() {
        AegsConfig c;
        auto gi = [](const char* n, int d)         { const char* v=std::getenv(n); return v?std::atoi(v):d; };
        auto gb = [](const char* n, bool d)        { const char* v=std::getenv(n); if(!v)return d; return std::string(v)=="1"; };
        auto gs = [](const char* n, std::string d) { const char* v=std::getenv(n); return v?std::string(v):d; };

        c.base_port        = (uint16_t)gi("AEGS_PORT",              50001);
        c.port_count       = gi("AEGS_PORT_COUNT",                   10);
        c.hop_interval_sec = (uint32_t)gi("AEGS_HOP_INTERVAL",      30);
        c.quic_mimicry     = gb("AEGS_QUIC_MIMICRY",                false);
        c.traffic_shaping  = gb("AEGS_TRAFFIC_SHAPING",             false);
        c.semantic_padding = gb("AEGS_SEMANTIC_PADDING",             true);
        c.jitter_ms        = gi("AEGS_JITTER_MS",                   5);
        c.mtu              = gi("AEGS_MTU",                          1400);
        c.worker_threads   = gi("AEGS_WORKERS",                     0);
        c.recv_batch_size  = gi("AEGS_RECV_BATCH_SIZE",             32);
        c.db_path          = gs("AEGS_DB_PATH",                     "/app/data/aegis.db");
        c.key_path         = gs("AEGS_KEY_PATH",                    "server_key.bin");
        c.session_idle_timeout = (double)gi("AEGS_SESSION_TIMEOUT", 180);
        c.client_isolation     = gb("AEGS_CLIENT_ISOLATION",          true);

        std::string p = gs("AEGS_PROFILE", "balanced");
        if (p == "lite" || p == "fast") {
            c.profile = AegsProfile::LITE;
            c.semantic_padding = false;
            c.traffic_shaping = false;
            c.jitter_ms = 0;
            c.quic_mimicry = false;
        } else if (p == "stealth") {
            c.profile = AegsProfile::STEALTH;
            c.semantic_padding = true;
            c.traffic_shaping = true;
            c.jitter_ms = 5;
            c.quic_mimicry = true;
        } else {
            c.profile = AegsProfile::BALANCED;
        }

        if (c.port_count < 1)  c.port_count = 1;
        if (c.port_count > 64) c.port_count = 64;
        return c;
    }
};
