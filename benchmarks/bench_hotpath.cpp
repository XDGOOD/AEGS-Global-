// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Stage 26 Benchmark Suite
// Measures hot-path throughput, lookup latency, and crypto operations per second
// ==============================================================================
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <random>
#include <cassert>
#include "../session_table.h"
#include "../crypto_utils.h"
#include "../network_security.h"
#include "../packet_scratch.h"

int main() {
    std::cout << "====================================================================\n";
    std::cout << "      AEGS v5 PANTHEON -- CARRIER-GRADE HOT-PATH BENCHMARK SUITE    \n";
    std::cout << "====================================================================\n\n";

    // 1. SessionTable 64-Shard Benchmark
    std::cout << "[1] BENCHMARKING 64-SHARD SESSION TABLE LOOKUPS (10,000 SESSIONS)...\n";
    SessionTable table;
    std::vector<uint64_t> key_ids;
    std::vector<uint32_t> ips;
    std::vector<uint64_t> endpoints;

    for (uint32_t i = 1; i <= 10000; ++i) {
        Session* s = new Session();
        s->identity.key_id_raw = 0xA000000000000000ULL + i;
        s->identity.key_id_hex = SessionTable::u64_to_hex(s->identity.key_id_raw);
        SessionRouting r;
        r.assigned_ip = 0x0A080000 + i; // 10.8.0.x
        r.has_client = true;
        r.last_server_fd = 3;
        s->set_routing(r);

        uint64_t ep = (static_cast<uint64_t>(r.assigned_ip) << 16) | (50000 + (i % 1000));
        table.insert_session(s);
        table.map_ip(r.assigned_ip, s);
        table.update_endpoint(ep, s);

        key_ids.push_back(s->identity.key_id_raw);
        ips.push_back(r.assigned_ip);
        endpoints.push_back(ep);
    }
    assert(table.total_sessions() == 10000);
    std::cout << "  ✓ 10,000 sessions populated across 64 shards successfully.\n";

    // Benchmark Endpoint lookups (Data-plane RX fast path)
    const size_t NUM_LOOKUPS = 1000000;
    auto t0 = std::chrono::high_resolution_clock::now();
    size_t hits = 0;
    for (size_t i = 0; i < NUM_LOOKUPS; ++i) {
        uint64_t ep = endpoints[i % endpoints.size()];
        SessionHandle s = table.find_by_endpoint(ep);
        if (s) hits++;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double ns_per_lookup = std::chrono::duration<double, std::nano>(t1 - t0).count() / NUM_LOOKUPS;
    double lookups_per_sec = NUM_LOOKUPS / std::chrono::duration<double>(t1 - t0).count();

    std::cout << "  Endpoint RX Lookups: " << NUM_LOOKUPS << " in " 
              << std::fixed << std::setprecision(2) 
              << std::chrono::duration<double, std::milli>(t1 - t0).count() << " ms\n";
    std::cout << "  Speed: " << (lookups_per_sec / 1e6) << " Million lookups/sec ("
              << ns_per_lookup << " ns/lookup)\n\n";

    // 2. Anti-Replay Sliding Window Benchmark
    std::cout << "[2] BENCHMARKING RFC 6479 ANTI-REPLAY FILTER (2048-BIT WINDOW)...\n";
    AntiReplayFilter filter;
    const size_t NUM_REPLAY_TESTS = 2000000;
    t0 = std::chrono::high_resolution_clock::now();
    for (uint64_t seq = 1; seq <= NUM_REPLAY_TESTS; ++seq) {
        filter.check_and_update(seq);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double replay_pps = NUM_REPLAY_TESTS / std::chrono::duration<double>(t1 - t0).count();
    std::cout << "  Processed " << NUM_REPLAY_TESTS << " sequence checks in "
              << std::chrono::duration<double, std::milli>(t1 - t0).count() << " ms\n";
    std::cout << "  Throughput: " << (replay_pps / 1e6) << " Million pps ("
              << (std::chrono::duration<double, std::nano>(t1 - t0).count() / NUM_REPLAY_TESTS) << " ns/pkt)\n\n";

    // 3. Header Masking & Unmasking Benchmark
    std::cout << "[3] BENCHMARKING HEADER MASKING / UNMASKING (CHACHARX)...\n";
    uint8_t mask_key[32];
    uint8_t hdr_iv[12];
    uint8_t plain_hdr[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 'A', 'G', '2', 0x01};
    uint8_t masked_hdr[16];
    uint8_t unmasked_hdr[16];
    RAND_bytes(mask_key, 32);
    RAND_bytes(hdr_iv, 12);

    const size_t NUM_MASKS = 500000;
    t0 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_MASKS; ++i) {
        mask_unmask_header(plain_hdr, 16, mask_key, hdr_iv, masked_hdr);
        mask_unmask_header(masked_hdr, 16, mask_key, hdr_iv, unmasked_hdr);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double mask_rate = (NUM_MASKS * 2) / std::chrono::duration<double>(t1 - t0).count();
    std::cout << "  Masked & Unmasked " << (NUM_MASKS * 2) << " headers in "
              << std::chrono::duration<double, std::milli>(t1 - t0).count() << " ms\n";
    std::cout << "  Speed: " << (mask_rate / 1e6) << " Million headers/sec\n\n";

    // 4. Zero-Alloc Thread-Local Scratchpad Verification
    std::cout << "[4] VERIFYING ZERO-ALLOC SCRATCHPAD ARENAS...\n";
    auto& scratch = get_packet_scratch();
    scratch.reset_tx();
    struct sockaddr_in mock_addr{};
    mock_addr.sin_family = AF_INET;
    mock_addr.sin_port = htons(50001);
    mock_addr.sin_addr.s_addr = htonl(0x0A080005);

    uint8_t test_payload[1350];
    std::memset(test_payload, 0xAA, sizeof(test_payload));
    for (size_t i = 0; i < PacketScratch::MAX_BATCH; ++i) {
        scratch.queue_tx(3, mock_addr, test_payload, sizeof(test_payload));
    }
    assert(scratch.tx_count == PacketScratch::MAX_BATCH);
    std::cout << "  ✓ 64 batch slots staged in zero-heap aligned arena successfully.\n";

    std::cout << "\n====================================================================\n";
    std::cout << "               ALL HOT-PATH BENCHMARKS COMPLETED                    \n";
    std::cout << "====================================================================\n";
    return 0;
}
