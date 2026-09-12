// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Multicore Scaling & Capacity Benchmark
// Evaluates worker thread scaling (1, 2, 4, 8 workers) and session table scaling
// (1k, 10k, 50k, 100k sessions) with latency percentiles and contention metrics.
// ==============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <cassert>
#include <cstring>
#include "../session_table.h"
#include "../crypto_utils.h"

struct LatencyCollector {
    std::vector<uint32_t> samples_ns;
    
    void record(uint32_t ns) {
        if (samples_ns.size() < 200000) {
            samples_ns.push_back(ns);
        }
    }
    
    void compute_percentiles(double& p50, double& p95, double& p99) {
        if (samples_ns.empty()) {
            p50 = p95 = p99 = 0.0;
            return;
        }
        std::sort(samples_ns.begin(), samples_ns.end());
        p50 = samples_ns[static_cast<size_t>(samples_ns.size() * 0.50)];
        p95 = samples_ns[static_cast<size_t>(samples_ns.size() * 0.95)];
        p99 = samples_ns[static_cast<size_t>(samples_ns.size() * 0.99)];
    }
};

static uint64_t make_endpoint(uint32_t ip, uint16_t port) {
    return (static_cast<uint64_t>(ip) << 16) | port;
}

// ---------------------------------------------------------------------------
// 1. Worker Scaling Benchmark: 1, 2, 4, 8 Workers
// ---------------------------------------------------------------------------
void run_worker_scaling_benchmark(SessionTable& table, const std::vector<uint64_t>& endpoints, int num_workers, size_t ops_per_worker) {
    std::atomic<bool> start_latch{false};
    std::atomic<uint64_t> total_hits{0};
    std::vector<std::thread> threads;
    std::vector<LatencyCollector> collectors(num_workers);

    for (int w = 0; w < num_workers; ++w) {
        threads.emplace_back([&, w]() {
            while (!start_latch.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            size_t ep_count = endpoints.size();
            size_t local_hits = 0;
            auto& collector = collectors[w];

            for (size_t i = 0; i < ops_per_worker; ++i) {
                uint64_t ep = endpoints[(i + w * 17) % ep_count];

                auto t0 = std::chrono::high_resolution_clock::now();
                SessionHandle handle = table.find_by_endpoint(ep);
                auto t1 = std::chrono::high_resolution_clock::now();

                uint32_t elapsed_ns = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
                
                if (handle) {
                    local_hits++;
                    handle->counters.last_activity.store(1.0, std::memory_order_relaxed);
                }
                
                if (i % 10 == 0) {
                    collector.record(elapsed_ns);
                }
            }
            total_hits.fetch_add(local_hits, std::memory_order_relaxed);
        });
    }

    auto start = std::chrono::high_resolution_clock::now();
    start_latch.store(true, std::memory_order_release);

    for (auto& t : threads) {
        t.join();
    }
    auto end = std::chrono::high_resolution_clock::now();

    double elapsed_sec = std::chrono::duration<double>(end - start).count();
    size_t total_ops = num_workers * ops_per_worker;
    double mpps = (total_ops / elapsed_sec) / 1e6;
    double gbps_1350B = (mpps * 1e6 * 1350.0 * 8.0) / 1e9;

    // Aggregate latency samples
    LatencyCollector aggregated;
    for (auto& c : collectors) {
        aggregated.samples_ns.insert(aggregated.samples_ns.end(), c.samples_ns.begin(), c.samples_ns.end());
    }
    double p50, p95, p99;
    aggregated.compute_percentiles(p50, p95, p99);

    std::cout << "  | " << std::setw(7) << num_workers
              << " | " << std::setw(10) << std::fixed << std::setprecision(2) << mpps
              << " | " << std::setw(10) << std::fixed << std::setprecision(2) << gbps_1350B
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << p50 << " ns"
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << p95 << " ns"
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << p99 << " ns"
              << " |\n";
}

// ---------------------------------------------------------------------------
// 2. Capacity Scaling Benchmark: 1k, 10k, 50k, 100k Sessions
// ---------------------------------------------------------------------------
void run_capacity_benchmark(size_t session_count) {
    SessionTable table;
    std::vector<uint64_t> endpoints;
    endpoints.reserve(session_count);

    auto t0 = std::chrono::high_resolution_clock::now();
    for (size_t i = 1; i <= session_count; ++i) {
        Session* s = new Session();
        s->identity.key_id_raw = 0xB000000000000000ULL + i;
        s->identity.key_id_hex = SessionTable::u64_to_hex(s->identity.key_id_raw);
        s->identity.session_id.store(i, std::memory_order_relaxed);

        uint32_t ip = 0x0A080000 + static_cast<uint32_t>(i);
        uint16_t port = static_cast<uint16_t>(10000 + (i % 50000));
        uint64_t ep = make_endpoint(ip, port);

        SessionRouting r;
        r.assigned_ip = ip;
        r.has_client = true;
        r.last_server_fd = 42;
        s->set_routing(r);

        table.insert_session(s);
        table.map_ip(ip, s);
        table.update_endpoint(ep, s);
        endpoints.push_back(ep);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double populate_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Benchmark lookup latency at this scale
    const size_t NUM_LOOKUPS = 500000;
    LatencyCollector collector;
    size_t hits = 0;

    auto t_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_LOOKUPS; ++i) {
        uint64_t ep = endpoints[i % session_count];
        auto l0 = std::chrono::high_resolution_clock::now();
        SessionHandle h = table.find_by_endpoint(ep);
        auto l1 = std::chrono::high_resolution_clock::now();
        if (h) hits++;
        if (i % 5 == 0) {
            collector.record(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(l1 - l0).count()));
        }
    }
    auto t_end = std::chrono::high_resolution_clock::now();
    double mpps = (NUM_LOOKUPS / std::chrono::duration<double>(t_end - t_start).count()) / 1e6;

    double p50, p95, p99;
    collector.compute_percentiles(p50, p95, p99);

    size_t approx_bytes = session_count * (sizeof(Session) + 64);
    double approx_mb = approx_bytes / (1024.0 * 1024.0);

    std::cout << "  | " << std::setw(10) << session_count
              << " | " << std::setw(9) << std::fixed << std::setprecision(1) << approx_mb << " MB"
              << " | " << std::setw(11) << std::fixed << std::setprecision(1) << populate_ms << " ms"
              << " | " << std::setw(10) << std::fixed << std::setprecision(2) << mpps
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << p50 << " ns"
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << p99 << " ns"
              << " |\n";

    table.clear();
}

int main() {
    std::cout << "=================================================================================\n";
    std::cout << "       AEGS v5 PANTHEON -- MULTICORE SCALING & CAPACITY BENCHMARK               \n";
    std::cout << "=================================================================================\n\n";

    // --- Part 1: Worker Scaling Benchmark ---
    std::cout << "[PART 1] WORKER THREAD SCALING (10,000 SESSIONS, 64 SHARDS, 1M LOOKUPS/WORKER)\n";
    std::cout << "  +---------+------------+------------+----------+----------+----------+\n";
    std::cout << "  | Workers | Throughput | Gbps (MTU) | Latency  | Latency  | Latency  |\n";
    std::cout << "  |         |   (Mpps)   |  (1350 B)  |   p50    |   p95    |   p99    |\n";
    std::cout << "  +---------+------------+------------+----------+----------+----------+\n";

    SessionTable table;
    std::vector<uint64_t> endpoints;
    const size_t NUM_SESSIONS = 10000;
    for (size_t i = 1; i <= NUM_SESSIONS; ++i) {
        Session* s = new Session();
        s->identity.key_id_raw = 0xA000000000000000ULL + i;
        uint32_t ip = 0x0A080000 + static_cast<uint32_t>(i);
        uint16_t port = static_cast<uint16_t>(50000 + (i % 1000));
        uint64_t ep = make_endpoint(ip, port);

        SessionRouting r;
        r.assigned_ip = ip;
        r.has_client = true;
        r.last_server_fd = 42;
        s->set_routing(r);

        table.insert_session(s);
        table.map_ip(ip, s);
        table.update_endpoint(ep, s);
        endpoints.push_back(ep);
    }

    std::vector<int> worker_counts = {1, 2, 4, 8};
    for (int w : worker_counts) {
        run_worker_scaling_benchmark(table, endpoints, w, 500000);
    }
    std::cout << "  +---------+------------+------------+----------+----------+----------+\n\n";

    table.clear();

    // --- Part 2: Session Capacity Scaling Benchmark ---
    std::cout << "[PART 2] SESSION CAPACITY & MEMORY SCALING (1k -> 100k SESSIONS)\n";
    std::cout << "  +------------+-----------+-------------+------------+----------+----------+\n";
    std::cout << "  |  Sessions  | Est. Heap | Populate Tm | Throughput | Latency  | Latency  |\n";
    std::cout << "  |            |  Memory   |             |   (Mpps)   |   p50    |   p99    |\n";
    std::cout << "  +------------+-----------+-------------+------------+----------+----------+\n";

    std::vector<size_t> capacities = {1000, 10000, 50000, 100000};
    for (size_t cap : capacities) {
        run_capacity_benchmark(cap);
    }
    std::cout << "  +------------+-----------+-------------+------------+----------+----------+\n\n";

    std::cout << "[SUCCESS] Multicore scaling & capacity benchmark finished.\n";
    return 0;
}
