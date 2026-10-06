#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>

#include "tun_interface.h"
#include "handshake.h"
#include "ip_pool.h"
#include "nat_manager.h"
#include "blackhole_responder.h"
#include "traffic_shaper.h"
#include "protocol_mimicry.h"
#include "port_hopper.h"
#include "session_resumption.h"
#include "session.h"
#include "packet_scratch.h"
#include "aegs_metrics.h"
#include "aegs_log.h"
#include "session_table.h"
#include "aegs_config.h"
#include "network_security.h"
#include "backpressure.h"
#include "crypto_utils.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

// Server-specific constants
const std::string WG_HOST = "wg-core";
const int WG_PORT = 51820;
const int MAX_EVENTS = 1024;


// FIX Phase 2: Sharded Session Table (64 independent shards)
// Completely eliminates global sessions_mu contention across worker threads
SessionTable g_sessions;
static std::unordered_map<uint64_t, std::vector<uint64_t>> g_user_slots;

static inline uint64_t make_endpoint_key(uint32_t ip, uint16_t port) {
    return (static_cast<uint64_t>(ip) << 16) | static_cast<uint64_t>(port);
}

static inline void update_endpoint_cache(uint64_t ep_key, Session* s) {
    g_sessions.update_endpoint(ep_key, s);
}

struct FailRecord { 
    double weight = 0; 
    double last_seen = 0; 
    int level = 0; 
    double last_fallback_dns = 0; // Token bucket rate limiter for DNS mimicry
};
const size_t MAX_FAILED_RECORDS = 10000;
const size_t MAX_BANNED_RECORDS = 10000;

std::unordered_map<uint32_t, FailRecord> failed_attempts;
std::atomic<size_t> g_failed_attempts_count{0};
std::unordered_map<uint32_t, double> banned_ips;
const int ban_levels[] = {0, 10, 30, 60};
std::mutex security_mu;
std::mutex tun_write_mu;

// FIX Phase 3 (Stage 17): O(1) Ring-Buffered Rate Limiter
// Eliminates O(N) linear scans when limit table reaches capacity
template <size_t CAPACITY = 4096>
class FastRateLimiter {
public:
    FastRateLimiter() : head_(0) {
        for (auto& slot : ring_) slot = {0, 0};
    }

    bool check(uint32_t ip_num, double now, int max_per_sec) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = map_.find(ip_num);
        if (it == map_.end()) {
            if (map_.size() >= CAPACITY) {
                const auto& evict = ring_[head_];
                if (evict.ip != 0) {
                    auto map_it = map_.find(evict.ip);
                    // Only evict if generation matches, avoiding eviction of re-inserted state
                    if (map_it != map_.end() && map_it->second.generation == evict.generation) {
                        map_.erase(map_it);
                    }
                }
            }
            uint64_t gen = ++gen_counter_;
            ring_[head_] = {ip_num, gen};
            head_ = (head_ + 1) % CAPACITY;
            map_[ip_num] = {now, 1, gen};
            return true;
        }
        if (now - it->second.window_start >= 1.0) {
            it->second.window_start = now;
            it->second.count = 1;
            return true;
        }
        it->second.count++;
        return (it->second.count <= max_per_sec);
    }

    void purge_expired(double now, double max_age_sec = 10.0) {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = map_.begin(); it != map_.end(); ) {
            if (now - it->second.window_start > max_age_sec) {
                it = map_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    struct Entry {
        double window_start = 0;
        int count = 0;
        uint64_t generation = 0;
    };
    struct RingSlot {
        uint32_t ip = 0;
        uint64_t generation = 0;
    };
    std::mutex mu_;
    std::unordered_map<uint32_t, Entry> map_;
    std::array<RingSlot, CAPACITY> ring_;
    size_t head_ = 0;
    uint64_t gen_counter_ = 0;
};

static FastRateLimiter<4096> g_hs_limiter;
static FastRateLimiter<4096> g_roam_limiter;
const int MAX_HANDSHAKES_PER_SEC_PER_IP = 10;
const int MAX_ROAMING_SCANS_PER_SEC_PER_IP = 500;

static inline bool check_handshake_rate_limit(uint32_t ip_num, double now) {
    return g_hs_limiter.check(ip_num, now, MAX_HANDSHAKES_PER_SEC_PER_IP);
}

static inline bool check_roaming_rate_limit(uint32_t ip_num, double now) {
    return g_roam_limiter.check(ip_num, now, MAX_ROAMING_SCANS_PER_SEC_PER_IP);
}

static std::atomic<bool> g_running{true};
static void handle_signal(int sig) {
    (void)sig;
    g_running = false;
}

double last_cleanup = 0;
const double CLEANUP_INTERVAL = 30.0;
const double FAIL_IDLE_TTL = 300.0;
const double SESSION_IDLE_TIMEOUT = 600.0; // 10 minutes idle -> close inactive session

void cleanup_maps(double now, IpPool& ip_pool) {
    if (now - last_cleanup < CLEANUP_INTERVAL) return;
    last_cleanup = now;

    // 1. Purge security tables under short-lived security_mu lock (P0-3 & P0-4 fix)
    {
        std::lock_guard<std::mutex> sec_lock(security_mu);
        for (auto it = banned_ips.begin(); it != banned_ips.end(); ) {
            if (now > it->second) it = banned_ips.erase(it); else ++it;
        }
        for (auto it = failed_attempts.begin(); it != failed_attempts.end(); ) {
            if (now - it->second.last_seen > FAIL_IDLE_TTL) it = failed_attempts.erase(it); else ++it;
        }
        g_failed_attempts_count.store(failed_attempts.size(), std::memory_order_relaxed);
    }

    // 2. Purge rate limiters independently (ZERO security_mu held, eliminating deadlock cycles)
    g_hs_limiter.purge_expired(now);
    g_roam_limiter.purge_expired(now);

    // 3. Sharded endpoint cache maintenance
    g_sessions.cleanup_idle_endpoints(now, SESSION_IDLE_TIMEOUT);

    // 4. Session idle cleanup via lock-free RCU snapshots (ZERO security_mu held)
    g_sessions.for_each_session([&](Session* s) {
        auto r = s->get_routing();
        if (r && r->has_client && (now - s->counters.last_activity.load() > SESSION_IDLE_TIMEOUT)) {
            std::cerr << "[GC] Session " << s->identity.key_id_hex << " idle timeout\n";
            uint32_t ip_to_release = r->assigned_ip;
            SessionRouting empty_r{};
            s->set_routing(empty_r);
            auto cur_c = s->get_crypto();
            if (cur_c) {
                SessionCrypto sc = *cur_c;
                sc.v3_handshake_done = false;
                std::memset(&sc.session_keys, 0, sizeof(sc.session_keys));
                s->set_crypto(sc);
            }
            if (ip_to_release) {
                g_sessions.unmap_ip(ip_to_release);
                ip_pool.release(ip_to_release);
            }
        }
    });
}

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

// Global BlackholeResponder for anti active-probing
BlackholeResponder g_blackhole;
ResumptionManager g_resumption;
// FIX Client Isolation: default ON for multi-tenant security (set AEGS_CLIENT_ISOLATION=0 to disable)
static bool g_client_isolation = true;

// Audit Hardening: Silent Drop of unauthorized scanner probes.
// Eliminates UDP amplification reflection and ISP port-scanning blacklisting.
void send_probing_fallback(int fd, const struct sockaddr_in& caddr,
                           const uint8_t* probe_data, size_t probe_len,
                           uint32_t ip_num, double now) {
    (void)fd; (void)caddr; (void)probe_data; (void)probe_len;
    (void)ip_num; (void)now;
    // Silent drop: never reflect or amplify unauthorized traffic on the wire
}

void record_fail(int fd, const struct sockaddr_in& caddr,
                  const uint8_t* probe_data, size_t probe_len,
                  uint32_t ip_num, double now, double weight) {
    // Active client protection: never ban an IP associated with an active authenticated session
    bool is_active_client = false;
    g_sessions.for_each_session([&](Session* s) {
        auto r = s->get_routing();
        if (r && r->has_client && r->client_addr.sin_addr.s_addr == ip_num) {
            is_active_client = true;
        }
    });
    if (is_active_client) return;

    bool do_fallback = false;
    {
        std::lock_guard<std::mutex> lock(security_mu);
        // Bounded map protection against DoS memory exhaustion from spoofed UDP flooding
        if (failed_attempts.size() >= MAX_FAILED_RECORDS && failed_attempts.find(ip_num) == failed_attempts.end()) {
            do_fallback = true;
        } else {
            auto& rec = failed_attempts[ip_num];
            if (rec.level == 0) rec.level = 1;
            if (now - rec.last_seen > 120.0) { rec.weight = 0; }
            rec.last_seen = now;
            rec.weight += weight;
            g_failed_attempts_count.store(failed_attempts.size(), std::memory_order_relaxed);
            do_fallback = true;

            if (rec.weight >= 200.0) {
                int lvl = std::min(rec.level, 3);
                if (banned_ips.size() < MAX_BANNED_RECORDS || banned_ips.find(ip_num) != banned_ips.end()) {
                    banned_ips[ip_num] = now + ban_levels[lvl];
                    std::cerr << "[SECURITY BAN] IP " << inet_ntoa(caddr.sin_addr) << " temporarily banned for " << ban_levels[lvl] << "s\n";
                }
                rec.weight = 0; rec.level = lvl + 1;
            }
        }
    }
    // send_probing_fallback invoked outside security_mu (P0-3 lock order decoupling)
    if (do_fallback) {
        send_probing_fallback(fd, caddr, probe_data, probe_len, ip_num, now);
    }
}

size_t secure_pad_len() {
    uint8_t b = 0;
    if (RAND_bytes(&b, 1) != 1) return PAD_MIN;
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

uint16_t generate_junk_len() {
    uint8_t b = 0;
    if (RAND_bytes(&b, 1) != 1) return 0;
    if (b < 50) {
        return 16 + (b % 49);
    }
    return 0;
}

// Worker thread event loop
void worker_loop(int worker_id, int num_workers, const AegsConfig& cfg,
                 const std::vector<uint16_t>& ports, TunInterface& tun,
                 HandshakeServer& hs_server, IpPool& ip_pool, TrafficShaper& shaper) {
    (void)worker_id;

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return;
    }

    std::vector<int> server_fds;
    std::unordered_set<int> server_fd_set;
    std::unordered_map<int, uint16_t> fd_to_port;
    PortHopper hopper(ports.empty() ? 50001 : ports.front(), ports.size(), 30);
    BackpressureController backpressure(64);

    for (uint16_t port : ports) {
        int sfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sfd < 0) { perror("socket"); return; }
        if (!set_nonblocking(sfd)) { perror("fcntl"); close(sfd); return; }
        int sock_buf_size = 16 * 1024 * 1024;
#ifdef SO_RCVBUFFORCE
        if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUFFORCE, &sock_buf_size, sizeof(sock_buf_size)) < 0) {
            setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
        }
#else
        setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
#endif
#ifdef SO_SNDBUFFORCE
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUFFORCE, &sock_buf_size, sizeof(sock_buf_size)) < 0) {
            setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));
        }
#else
        setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));
#endif
        int reuse = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (num_workers > 1) {
#ifdef SO_REUSEPORT
            if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
                perror("setsockopt SO_REUSEPORT");
            }
#endif
        }
        struct sockaddr_in sa {};
        sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
        if (bind(sfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            perror("bind");
            close(sfd);
            return;
        }
        struct epoll_event ev_s {};
        ev_s.events = EPOLLIN;
        ev_s.data.fd = sfd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev_s) < 0) {
            perror("epoll_ctl");
            close(sfd);
            return;
        }
        server_fds.push_back(sfd);
        server_fd_set.insert(sfd);
        fd_to_port[sfd] = port;
    }

    int tun_fd = tun.fd();
    struct epoll_event ev_tun {};
#ifdef EPOLLEXCLUSIVE
    ev_tun.events = EPOLLIN | EPOLLEXCLUSIVE;
#else
    ev_tun.events = EPOLLIN;
#endif
    ev_tun.data.fd = tun_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev_tun) < 0) {
        ev_tun.events = EPOLLIN;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev_tun);
    }

    const int batch_size = (cfg.recv_batch_size > 0) ? cfg.recv_batch_size : 32;

    // FIX Phase 3: Zero-Allocation Thread-Local Scratch Arenas
    auto& scratch = get_packet_scratch();
    uint8_t* buffer  = scratch.rx_buf;
    uint8_t* dec_buf = scratch.dec_buf;
    uint8_t* enc_buf = scratch.enc_buf;
    uint8_t* out_buf = scratch.tx_buf;

#ifdef __linux__
    struct PacketSlot {
        std::vector<uint8_t> buf;
        struct sockaddr_in addr;
        struct iovec iov;
    };
    std::vector<PacketSlot> slots;
    std::vector<struct mmsghdr> msgvec;
    if (batch_size > 1) {
        slots.resize(batch_size);
        msgvec.resize(batch_size);
        for (int i = 0; i < batch_size; ++i) {
            slots[i].buf.resize(BUFFER_SIZE);
            std::memset(&slots[i].addr, 0, sizeof(slots[i].addr));
            slots[i].iov.iov_base = slots[i].buf.data();
            slots[i].iov.iov_len = slots[i].buf.size();

            std::memset(&msgvec[i], 0, sizeof(msgvec[i]));
            msgvec[i].msg_hdr.msg_iov = &slots[i].iov;
            msgvec[i].msg_hdr.msg_iovlen = 1;
            msgvec[i].msg_hdr.msg_name = &slots[i].addr;
            msgvec[i].msg_hdr.msg_namelen = sizeof(slots[i].addr);
        }
    }
#endif

    auto process_udp_packet = [&](int fd, const struct sockaddr_in& caddr, uint8_t* pkt_data, ssize_t len, double now) {
        if (len < 0) return;
        auto& metrics = AegsMetrics::instance();
        metrics.rx_packets.fetch_add(1, std::memory_order_relaxed);
        metrics.rx_bytes.fetch_add(static_cast<uint64_t>(len), std::memory_order_relaxed);

        uint32_t ip_num = caddr.sin_addr.s_addr;
        {
            std::lock_guard<std::mutex> lock(security_mu);
            auto ban_it = banned_ips.find(ip_num);
            if (ban_it != banned_ips.end() && now < ban_it->second) return;
        }

        // DPI Mimicry Evasion: detect and strip RFC 9000 QUIC, TLS 1.3 Reality ECH, or TLS 1.3 AppData (Factor A)
        uint8_t pkt_mimic_type = 0; // 0 = none, 1 = QUIC, 2 = TLS 1.3 AppData / Reality
        size_t ulen = static_cast<size_t>(len);
        if (ProtocolMimicry::strip_tls_appdata_mimicry(pkt_data, ulen)) {
            len = static_cast<ssize_t>(ulen);
            pkt_mimic_type = 2;
        } else if (ProtocolMimicry::strip_quic_mimicry(pkt_data, ulen)) {
            len = static_cast<ssize_t>(ulen);
            pkt_mimic_type = 1;
        } else if (ProtocolMimicry::strip_tls_reality_mimicry(pkt_data, ulen)) {
            len = static_cast<ssize_t>(ulen);
            pkt_mimic_type = 2;
        }
        bool is_mimicked = (pkt_mimic_type == 1);

        auto send_reply = [&](const void* data, size_t dlen, uint8_t mimic_mode, const uint8_t* seed = nullptr) {
            if (mimic_mode == 1) {
                uint8_t mbuf[2048];
                if (dlen + 24 <= sizeof(mbuf)) {
                    std::memcpy(mbuf, data, dlen);
                    size_t mlen = ProtocolMimicry::wrap_quic_initial(mbuf, dlen, sizeof(mbuf), seed);
                    sendto(fd, reinterpret_cast<const char*>(mbuf), mlen, 0, (struct sockaddr*)&caddr, sizeof(caddr));
                    return;
                }
            } else if (mimic_mode == 2) {
                uint8_t mbuf[2048];
                if (dlen + ProtocolMimicry::kTlsRecordHeaderSize <= sizeof(mbuf)) {
                    std::memcpy(mbuf, data, dlen);
                    size_t mlen = ProtocolMimicry::wrap_tls_appdata(mbuf, dlen, sizeof(mbuf));
                    sendto(fd, reinterpret_cast<const char*>(mbuf), mlen, 0, (struct sockaddr*)&caddr, sizeof(caddr));
                    return;
                }
            }
            sendto(fd, reinterpret_cast<const char*>(data), dlen, 0, (struct sockaddr*)&caddr, sizeof(caddr));
        };

        // =====================================================================
        // Opcode 0x04: Fast Resumption (0-RTT with per-resume derived traffic keys)
        // =====================================================================
        if (pkt_data[0] == OP_FAST_RESUME && (size_t)len == 97) {
            ResumptionToken rtok;
            memcpy(&rtok, pkt_data + 1, 96);
            uint64_t resumed_sid = 0;
            uint32_t resumed_ip = 0;

            char kid_hex[17];
            for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", rtok.key_id[j]);
            kid_hex[16] = 0;

            SessionHandle s = g_sessions.find_by_key_id_hex(kid_hex);
            auto cur_c = s ? s->get_crypto() : nullptr;
            if (!s || !cur_c || !g_resumption.verify(rtok, cur_c->master_key, resumed_sid, resumed_ip)) {
                metrics.resume_fail.fetch_add(1, std::memory_order_relaxed);
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0);
                return;
            }

            s->identity.generation.fetch_add(1, std::memory_order_release);
            s->identity.session_id = resumed_sid;
            s->counters.last_activity.store(now, std::memory_order_relaxed);
            s->counters.tx_seq.store(0, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> slk(s->mu);
                s->replay_filter = AntiReplayFilter();
            }

            auto hex_encode = [](const uint8_t* data, size_t dlen) -> std::string {
                static const char* hexdigits = "0123456789abcdef";
                std::string out; out.reserve(dlen * 2);
                for (size_t i = 0; i < dlen; ++i) {
                    out.push_back(hexdigits[data[i] >> 4]);
                    out.push_back(hexdigits[data[i] & 0xF]);
                }
                return out;
            };
            std::string resume_info = "aegs-resume-" + hex_encode(rtok.nonce, 32);
            std::string recv_info = resume_info + "-s2c";
            std::string send_info = resume_info + "-c2s";
            SessionCrypto sc = *cur_c;
            hkdf_expand(cur_c->master_key, 32, recv_info, sc.session_keys.recv_key, 32);
            hkdf_expand(cur_c->master_key, 32, send_info, sc.session_keys.send_key, 32);
            sc.v3_handshake_done = true;
            s->set_crypto(sc);

            auto cur_r = s->get_routing();
            uint32_t assigned = (cur_r && cur_r->assigned_ip) ? cur_r->assigned_ip : resumed_ip;
            SessionRouting sr;
            sr.client_addr = caddr;
            sr.has_client = true;
            sr.last_server_fd = fd;
            sr.assigned_ip = assigned;
            sr.uses_mimicry = is_mimicked;
            sr.mimic_type = pkt_mimic_type;
            s->set_routing(sr);

            update_endpoint_cache(make_endpoint_key(ip_num, caddr.sin_port), s.get());
            if (assigned) {
                g_sessions.map_ip(assigned, s.get());
            }

            ResumptionToken new_tok;
            if (g_resumption.issue(s->identity.session_id, assigned, cur_c->master_key, new_tok, (const uint8_t*)&s->identity.key_id_raw)) {
                uint8_t rpkt[97];
                rpkt[0] = OP_FAST_RESUME_RESP;
                memcpy(rpkt + 1, &new_tok, 96);
                send_reply(rpkt, 97, pkt_mimic_type, rtok.key_id);
            }
            metrics.resume_fast_ok.fetch_add(1, std::memory_order_relaxed);
            AegsLog::info("[FAST-RESUME] Session resumed for ", inet_ntoa(caddr.sin_addr), " (", IpPool::to_string(assigned), ")");
            return;
        }

        // =====================================================================
        // Opcode 0x05: Full PFS Resumption (RFC Ephemeral X25519 ECDH + Fresh Keys)
        // =====================================================================
        if (pkt_data[0] == OP_PFS_RESUME && (size_t)len == sizeof(PfsResumptionRequest)) {
            const PfsResumptionRequest* req = reinterpret_cast<const PfsResumptionRequest*>(pkt_data);
            const ResumptionToken& rtok = req->token;
            uint64_t resumed_sid = 0;
            uint32_t resumed_ip = 0;

            char kid_hex[17];
            for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", rtok.key_id[j]);
            kid_hex[16] = 0;

            SessionHandle s = g_sessions.find_by_key_id_hex(kid_hex);
            auto cur_c = s ? s->get_crypto() : nullptr;
            if (!s || !cur_c || !g_resumption.verify(rtok, cur_c->master_key, resumed_sid, resumed_ip)) {
                metrics.resume_fail.fetch_add(1, std::memory_order_relaxed);
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0);
                return;
            }

            // Generate fresh ephemeral X25519 keypair for Perfect Forward Secrecy
            EVP_PKEY* s_pkey = ResumptionManager::generate_x25519_key();
            if (!s_pkey) {
                metrics.resume_fail.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            uint8_t s_pub[32];
            uint8_t shared_secret[32];
            uint8_t c2s_key[32], s2c_key[32];

            bool ok = ResumptionManager::extract_x25519_pub(s_pkey, s_pub) &&
                      ResumptionManager::compute_ecdh_shared(s_pkey, req->client_ephemeral_pub, shared_secret) &&
                      ResumptionManager::derive_pfs_keys(shared_secret, cur_c->master_key, rtok.nonce, c2s_key, s2c_key);
            EVP_PKEY_free(s_pkey);

            if (!ok) {
                metrics.resume_fail.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            s->identity.generation.fetch_add(1, std::memory_order_release);
            s->identity.session_id = resumed_sid;
            s->counters.last_activity.store(now, std::memory_order_relaxed);
            s->counters.tx_seq.store(0, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> slk(s->mu);
                s->replay_filter = AntiReplayFilter();
            }

            SessionCrypto sc = *cur_c;
            std::memcpy(sc.session_keys.recv_key, c2s_key, 32);
            std::memcpy(sc.session_keys.send_key, s2c_key, 32);
            sc.v3_handshake_done = true;
            s->set_crypto(sc);

            auto cur_r = s->get_routing();
            uint32_t assigned = (cur_r && cur_r->assigned_ip) ? cur_r->assigned_ip : resumed_ip;
            SessionRouting sr;
            sr.client_addr = caddr;
            sr.has_client = true;
            sr.last_server_fd = fd;
            sr.assigned_ip = assigned;
            sr.uses_mimicry = is_mimicked;
            sr.mimic_type = pkt_mimic_type;
            s->set_routing(sr);

            update_endpoint_cache(make_endpoint_key(ip_num, caddr.sin_port), s.get());
            if (assigned) {
                g_sessions.map_ip(assigned, s.get());
            }

            // Construct 145-byte PFS Resumption Response (Opcode 0x06)
            PfsResumptionResponse resp;
            resp.opcode = OP_PFS_RESUME_RESP;
            std::memcpy(resp.server_ephemeral_pub, s_pub, 32);
            if (g_resumption.issue(s->identity.session_id, assigned, cur_c->master_key, resp.new_token, (const uint8_t*)&s->identity.key_id_raw)) {
                ResumptionManager::compute_pfs_resp_tag(reinterpret_cast<const uint8_t*>(&resp), 1 + 32 + 96, cur_c->master_key, resp.auth_tag);
                send_reply(&resp, sizeof(resp), pkt_mimic_type, rtok.key_id);
            }

            metrics.resume_pfs_ok.fetch_add(1, std::memory_order_relaxed);
            AegsLog::info("[PFS-RESUME] Session resumed with fresh ECDH for ", inet_ntoa(caddr.sin_addr), " (", IpPool::to_string(assigned), ")");
            return;
        }

        if (pkt_data[0] == 0x01 && (size_t)len == 72) {
            // FIX Production DoS: Pre-crypto rate limiting per IP
            if (!check_handshake_rate_limit(ip_num, now)) {
                return;
            }
            uint64_t key_id_out = 0;
            if (!hs_server.process_init(pkt_data, len, key_id_out)) {
                return;
            }
            char kid_hex[17];
            for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", ((uint8_t*)&key_id_out)[j]);
            kid_hex[16] = 0;
            SessionHandle s = g_sessions.find_by_key_id(key_id_out);
            auto cur_c = s ? s->get_crypto() : nullptr;
            if (s && cur_c) {
                SessionHandle orig_s = s;
                auto orig_c = cur_c;
                auto old_r = s->get_routing();

                // Auto-Slot Balancing:
                // If this slot already has an active client with a different endpoint within the last 60 seconds,
                // automatically balance the new incoming device into the next available slot for this user!
                bool is_slot_busy = (old_r && old_r->has_client &&
                                     (old_r->client_addr.sin_addr.s_addr != caddr.sin_addr.s_addr ||
                                      old_r->client_addr.sin_port != caddr.sin_port) &&
                                     (now - s->counters.last_activity.load() < 60.0));

                if (is_slot_busy) {
                    auto it_slots = g_user_slots.find(key_id_out);
                    if (it_slots != g_user_slots.end()) {
                        for (uint64_t alt_kid : it_slots->second) {
                            if (alt_kid == key_id_out) continue;
                            SessionHandle alt_s = g_sessions.find_by_key_id(alt_kid);
                            if (alt_s) {
                                auto alt_r = alt_s->get_routing();
                                if (!alt_r || !alt_r->has_client ||
                                    (now - alt_s->counters.last_activity.load() >= 60.0) ||
                                    (alt_r->client_addr.sin_addr.s_addr == caddr.sin_addr.s_addr &&
                                     alt_r->client_addr.sin_port == caddr.sin_port)) {
                                    AegsLog::info("[AUTO-SLOT] Active device on Slot 1 protected. Balancing new device from ",
                                                  inet_ntoa(caddr.sin_addr), " to Slot ", alt_s->identity.key_id_hex);
                                    s = alt_s;
                                    cur_c = s->get_crypto();
                                    old_r = s->get_routing();
                                    break;
                                }
                            }
                        }
                    }
                }

                uint32_t new_ip = 0;
                if (old_r && old_r->assigned_ip) {
                    new_ip = old_r->assigned_ip;
                } else {
                    auto maybe_ip = ip_pool.allocate();
                    if (!maybe_ip) { std::cerr << "IP pool exhausted\n"; return; }
                    new_ip = *maybe_ip;
                    g_sessions.map_ip(new_ip, s.get());
                }
                
                SessionKeys sk;
                auto resp = hs_server.build_resp(key_id_out, new_ip, 1280, sk);

                s->identity.generation.fetch_add(1, std::memory_order_release);
                s->identity.session_id = sk.session_id;
                s->counters.tx_seq.store(0, std::memory_order_relaxed);
                s->counters.last_activity.store(now, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> slk(s->mu);
                    s->replay_filter = AntiReplayFilter();
                }

                SessionCrypto sc = *cur_c;
                sc.session_keys = sk;
                sc.v3_handshake_done = true;
                if (s != orig_s) {
                    s->identity.base_key_id_raw = key_id_out;
                    std::memcpy(sc.mask_key, orig_c->mask_key, 32);
                    std::memcpy(sc.alt_mask_key, orig_c->alt_mask_key, 32);
                    sc.has_alt_mask_key = orig_c->has_alt_mask_key;
                }
                s->set_crypto(sc);

                SessionRouting nr;
                nr.assigned_ip = new_ip;
                nr.client_addr = caddr;
                nr.has_client = true;
                nr.last_server_fd = fd;
                nr.uses_mimicry = is_mimicked;
                nr.mimic_type = pkt_mimic_type;
                s->set_routing(nr);

                // Register in O(1) fast-path cache
                update_endpoint_cache(make_endpoint_key(ip_num, caddr.sin_port), s.get());
                metrics.handshake_ok.fetch_add(1, std::memory_order_relaxed);
                send_reply(resp.data(), resp.size(), pkt_mimic_type, (const uint8_t*)&key_id_out);
                AegsLog::info("[HS] Client ", inet_ntoa(caddr.sin_addr), " assigned ", IpPool::to_string(new_ip));
                
                ResumptionToken rtok;
                if (g_resumption.issue(s->identity.session_id, new_ip, cur_c->master_key, rtok, (const uint8_t*)&s->identity.key_id_raw)) {
                    uint8_t rtok_pkt[97];
                    rtok_pkt[0] = 0x03; // RESUMPTION_TOKEN
                    memcpy(rtok_pkt + 1, &rtok, 96);
                    send_reply(rtok_pkt, 97, pkt_mimic_type, (const uint8_t*)&key_id_out);
                    std::cout << "[HS] Resumption token issued for " << inet_ntoa(caddr.sin_addr) << "\n";
                }
            } else {
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0);
            }
            return;
        }

        // AEGS v2 Min Outer Size: HDR_IV(12) + MASKED_HDR(16) + AEAD_IV(12) + TAG(16) = 56 bytes
        if (len < 56) { record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0); return; }

        const uint8_t* hdr_iv = pkt_data;
        SessionHandle matched_sess;
        std::shared_ptr<const SessionCrypto> matched_crypto = nullptr;
        uint8_t unmasked_hdr[16];

        // RCU / Copy-On-Write SessionCrypto snapshot lookup (Zero data races with concurrent Handshakes/Resumes)
        uint64_t ep_key = make_endpoint_key(ip_num, caddr.sin_port);
        SessionHandle fast_sess = g_sessions.find_by_endpoint(ep_key);
        bool used_alt_mask = false;
        if (fast_sess) {
            auto fc = fast_sess->get_crypto();
            if (fc && mask_unmask_header(pkt_data + 12, 16, fc->mask_key, hdr_iv, unmasked_hdr)) {
                if ((std::memcmp(unmasked_hdr, &fast_sess->identity.key_id_raw, 8) == 0 ||
                     (fast_sess->identity.base_key_id_raw != 0 && std::memcmp(unmasked_hdr, &fast_sess->identity.base_key_id_raw, 8) == 0)) &&
                    std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                    matched_sess = std::move(fast_sess);
                    matched_crypto = fc;
                    used_alt_mask = false;
                }
            }
            if (!matched_sess && fc && fc->has_alt_mask_key && mask_unmask_header(pkt_data + 12, 16, fc->alt_mask_key, hdr_iv, unmasked_hdr)) {
                if ((std::memcmp(unmasked_hdr, &fast_sess->identity.key_id_raw, 8) == 0 ||
                     (fast_sess->identity.base_key_id_raw != 0 && std::memcmp(unmasked_hdr, &fast_sess->identity.base_key_id_raw, 8) == 0)) &&
                    std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                    matched_sess = std::move(fast_sess);
                    matched_crypto = fc;
                    used_alt_mask = true;
                }
            }
        }

        // Slow-path fallback: scan registered sessions if new connection or roaming
        if (!matched_sess) {
            if (!check_roaming_rate_limit(ip_num, now)) {
                return; // Silently drop roaming rate flood without penalizing carrier IP
            }
            metrics.roaming_scans.fetch_add(1, std::memory_order_relaxed);
            matched_sess = g_sessions.find_if([&](Session* s) -> bool {
                auto sc = s->get_crypto();
                if (!sc) return false;
                if (mask_unmask_header(pkt_data + 12, 16, sc->mask_key, hdr_iv, unmasked_hdr)) {
                    if ((std::memcmp(unmasked_hdr, &s->identity.key_id_raw, 8) == 0 ||
                         (s->identity.base_key_id_raw != 0 && std::memcmp(unmasked_hdr, &s->identity.base_key_id_raw, 8) == 0)) &&
                        std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                        matched_crypto = sc;
                        used_alt_mask = false;
                        return true;
                    }
                }
                if (sc->has_alt_mask_key && mask_unmask_header(pkt_data + 12, 16, sc->alt_mask_key, hdr_iv, unmasked_hdr)) {
                    if ((std::memcmp(unmasked_hdr, &s->identity.key_id_raw, 8) == 0 ||
                         (s->identity.base_key_id_raw != 0 && std::memcmp(unmasked_hdr, &s->identity.base_key_id_raw, 8) == 0)) &&
                        std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                        matched_crypto = sc;
                        used_alt_mask = true;
                        return true;
                    }
                }
                return false;
            });
            if (matched_sess) {
                metrics.roaming_hits.fetch_add(1, std::memory_order_relaxed);
                update_endpoint_cache(ep_key, matched_sess.get());
            }
        }

        if (!matched_sess || !matched_crypto) { record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0); return; }

        SessionHandle s = std::move(matched_sess);

        // Verify incoming port hopping compliance if multi-port listening is active
        if (ports.size() > 1 && matched_crypto->v3_handshake_done) {
            auto pit = fd_to_port.find(fd);
            // Never drop packets arriving on the primary base port (supports mobile/clients without port hopping)
            if (pit != fd_to_port.end() && pit->second != ports.front() && !hopper.is_valid_port(matched_crypto->session_keys.recv_key, pit->second)) {
                // Packet arrived on an unexpected port during rotation: silently drop without IP ban
                return;
            }
        }

        uint16_t junk_len = (unmasked_hdr[8] << 8) | unmasked_hdr[9];
        size_t aead_offset = 12 + 16 + junk_len;
        if ((size_t)len < aead_offset + 12 + TAG_LEN) { record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5); return; }

        const uint8_t* aead_nonce = pkt_data + aead_offset;
        // Two-phase anti-replay Phase 1: Read-only check before expensive decrypt (does NOT commit seq)
        if (s->check_replay_peek(aead_nonce)) {
            metrics.replay_drop.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const uint8_t* ct = pkt_data + aead_offset + 12;
        size_t ct_len = len - (aead_offset + 12);

        if (!matched_crypto->v3_handshake_done) {
            record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5);
            return;
        }

        size_t dec_len = 0;
        // Lock-free decryption using immutable SessionCrypto snapshot (0 mutex locks taken on decrypt path)
        if (!chacha20_poly1305_decrypt(ct, ct_len, matched_crypto->session_keys.recv_key, aead_nonce, dec_buf, dec_len, pkt_data, aead_offset)) {
            metrics.decrypt_fail.fetch_add(1, std::memory_order_relaxed);
            record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5); return;
        }
        // Two-phase anti-replay Phase 2: Commit sequence number ONLY after Poly1305 AEAD succeeds!
        s->commit_replay(aead_nonce);
        metrics.decrypt_ok.fetch_add(1, std::memory_order_relaxed);

        // Authentication passed! Securely update roaming endpoint & cache via lock-free RCU.
        // Generation check (Problem #4 fix): ensure session hasn't resumed or rotated while packet was in flight.
        if (s.is_valid()) {
            auto cur_r = s->get_routing();
            if (!cur_r || !cur_r->has_client ||
                cur_r->client_addr.sin_addr.s_addr != caddr.sin_addr.s_addr ||
                cur_r->client_addr.sin_port != caddr.sin_port ||
                cur_r->last_server_fd != fd ||
                cur_r->uses_alt_mask != used_alt_mask ||
                cur_r->mimic_type != pkt_mimic_type) {
                SessionRouting nr = cur_r ? *cur_r : SessionRouting{};
                nr.client_addr = caddr;
                nr.has_client = true;
                nr.last_server_fd = fd;
                nr.uses_mimicry = is_mimicked;
                nr.mimic_type = pkt_mimic_type;
                nr.uses_alt_mask = used_alt_mask;
                s->set_routing(nr);
            }
            s->counters.last_activity.store(now, std::memory_order_relaxed);
        }
        // Fast path: bypass security_mu completely when failed_attempts table is empty (0 lock contention)
        if (__builtin_expect(g_failed_attempts_count.load(std::memory_order_relaxed) > 0, 0)) {
            std::lock_guard<std::mutex> lock(security_mu);
            if (failed_attempts.erase(ip_num) > 0) {
                g_failed_attempts_count.store(failed_attempts.size(), std::memory_order_relaxed);
            }
        }

        if (unmasked_hdr[10] & 0x80) {
            AegsLog::debug("[CHAFF] Received silent chaff packet");
            return;
        }

        if (dec_len < 2) return;
        uint16_t plen = (dec_buf[0] << 8) | dec_buf[1];
        if (plen > 0 && plen <= dec_len - 2) {
            // FIX P0 TUN ACL: Verify inner packet source IP matches session's assigned IP (P0-7 lock-free)
            // Prevents tunnel users from spoofing arbitrary source addresses
            const uint8_t* inner_pkt = dec_buf + 2;
            if (plen >= 20) { // Minimum IPv4 header size
                uint8_t ip_version = (inner_pkt[0] >> 4) & 0xF;
                if (ip_version == 4) {
                    uint32_t inner_src_ip = (uint32_t(inner_pkt[12]) << 24) |
                                           (uint32_t(inner_pkt[13]) << 16) |
                                           (uint32_t(inner_pkt[14]) << 8)  |
                                            uint32_t(inner_pkt[15]);
                    auto cur_r = s->get_routing();
                    if (cur_r && cur_r->assigned_ip != 0) {
                        uint32_t exp_ip = cur_r->assigned_ip;
                        uint32_t exp_bswap = __builtin_bswap32(exp_ip);
                        if (inner_src_ip != exp_ip && inner_src_ip != exp_bswap) {
                            return; // Drop: source IP spoofing attempt
                        }
                    }
                }
            }
            std::lock_guard<std::mutex> tlk(tun_write_mu);
            tun.write_packet(inner_pkt, plen);
        }
    };

    struct epoll_event events[MAX_EVENTS];

    while (g_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_running) break;
                continue;
            }
            perror("epoll_wait");
            break;
        }

        double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (server_fd_set.count(fd)) {
#ifdef __linux__
                if (batch_size > 1) {
                    for (int b = 0; b < batch_size; ++b) {
                        msgvec[b].msg_hdr.msg_namelen = sizeof(slots[b].addr);
                        slots[b].iov.iov_len = slots[b].buf.size();
                    }
                    int pkts = recvmmsg(fd, msgvec.data(), batch_size, MSG_DONTWAIT, nullptr);
                    if (pkts > 0) {
                        for (int p = 0; p < pkts; ++p) {
#if defined(__GNUC__) || defined(__clang__)
                            if (p + 1 < pkts) {
                                __builtin_prefetch(slots[p + 1].buf.data(), 0, 1);
                            }
#endif
                            ssize_t plen = msgvec[p].msg_len;
                            process_udp_packet(fd, slots[p].addr, slots[p].buf.data(), plen, now);
                        }
                    } else if (pkts < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        // Socket drained
                    } else {
                        // Graceful fallback to recvfrom
                        struct sockaddr_in caddr {};
                        socklen_t clen = sizeof(caddr);
                        ssize_t len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&caddr, &clen);
                        if (len >= 0) {
                            process_udp_packet(fd, caddr, buffer, len, now);
                        }
                    }
                } else {
                    struct sockaddr_in caddr {};
                    socklen_t clen = sizeof(caddr);
                    ssize_t len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&caddr, &clen);
                    if (len >= 0) {
                        process_udp_packet(fd, caddr, buffer, len, now);
                    }
                }
#else
                struct sockaddr_in caddr {};
                socklen_t clen = sizeof(caddr);
                ssize_t len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&caddr, &clen);
                if (len >= 0) {
                    process_udp_packet(fd, caddr, buffer, len, now);
                }
#endif
            } else if (fd == tun_fd) {
                backpressure.apply_pacing();
                if (backpressure.should_pause_tun()) {
                    // Drain any pending outbound packets to allow socket buffers to clear
                    if (scratch.tx_count > 0) {
                        size_t sent = scratch.flush_tx();
                        if (sent > 0) {
                            AegsMetrics::instance().tx_packets.fetch_add(sent, std::memory_order_relaxed);
                            backpressure.record_egress_success();
                        } else if (scratch.tx_count > 0) {
                            backpressure.record_egress_failure(EAGAIN);
                        }
                    }
                    continue; // Egress congested: defer reading from TUN to trigger upstream TCP flow control
                }
                size_t max_batch = backpressure.max_tun_batch();
                for (size_t batch = 0; batch < max_batch; ++batch) {
                    ssize_t n = tun.read_packet(buffer, BUFFER_SIZE);
                    if (n < 0) {
                        break; // EAGAIN / EWOULDBLOCK
                    }
                    if (n < 20) continue; 

                    uint32_t dst_ip = (uint32_t(buffer[16]) << 24) | (uint32_t(buffer[17]) << 16)
                                    | (uint32_t(buffer[18]) << 8)  |  uint32_t(buffer[19]);

                    // FIX Phase 2: Sharded O(1) IP route lookup using safe SessionHandle
                    SessionHandle s = g_sessions.find_by_assigned_ip(dst_ip);
                    if (!s) s = g_sessions.find_by_assigned_ip(__builtin_bswap32(dst_ip));
                    if (!s) continue;

                    // FIX Client Isolation: Drop inter-client traffic when isolation enabled
                    if (g_client_isolation && n >= 20) {
                        uint32_t src_ip = (uint32_t(buffer[12]) << 24) | (uint32_t(buffer[13]) << 16)
                                        | (uint32_t(buffer[14]) << 8)  |  uint32_t(buffer[15]);
                        if (src_ip != dst_ip) {
                            if (g_sessions.find_by_assigned_ip(src_ip)) {
                                AegsMetrics::instance().acl_drop.fetch_add(1, std::memory_order_relaxed);
                                continue; // Drop: client-to-client traffic blocked
                            }
                        }
                    }

                    struct sockaddr_in client_addr {};
                    int send_fd = -1;
                    uint8_t enc_key[32];
                    uint64_t seq = 0;
                    uint64_t s_key_id_raw = 0;
                    uint8_t s_mask_key[32];

                    auto sc = s->get_crypto();
                    if (!sc || !sc->v3_handshake_done) continue;
                    auto routing = s->get_routing();
                    if (!routing || !routing->has_client || routing->last_server_fd < 0) continue;

                    if (routing->uses_alt_mask && sc->has_alt_mask_key) {
                        std::memcpy(s_mask_key, sc->alt_mask_key, 32);
                    } else {
                        std::memcpy(s_mask_key, sc->mask_key, 32);
                    }
                    std::memcpy(enc_key, sc->session_keys.send_key, 32);
                    client_addr = routing->client_addr;
                    send_fd = routing->last_server_fd;
                    s_key_id_raw = s->identity.key_id_raw;
                    s->counters.last_activity.store(now, std::memory_order_relaxed);
                    seq = ++(s->counters.tx_seq);

                    size_t pad_len = shaper.semantic_pad((size_t)n);
                    size_t frame_len = FRAME_HDR + (size_t)n + pad_len;
                    // Ensure wire packet with outer headers (56B) + tag (16B) never exceeds 1380 bytes to eliminate carrier fragmentation
                    if (frame_len + 80 > 1380 || frame_len + TAG_LEN > INTERNAL_BUF_SIZE) {
                        pad_len = 0;
                        frame_len = FRAME_HDR + (size_t)n;
                    }

                    uint16_t plen_be = htons((uint16_t)n);
                    std::memcpy(dec_buf, &plen_be, 2);
                    std::memcpy(dec_buf + 2, buffer, (size_t)n);
                    if (pad_len > 0) TrafficShaper::fill_random_padding(dec_buf + 2 + n, pad_len);

                    uint8_t aead_nonce[12] = {0};
                    std::memcpy(aead_nonce, &seq, sizeof(uint64_t));
                    if (RAND_bytes(aead_nonce + 8, 4) != 1) continue;

                    uint16_t junk_len = generate_junk_len();

                    uint8_t hdr_plain[16];
                    std::memcpy(hdr_plain, &s_key_id_raw, 8);
                    hdr_plain[8] = (junk_len >> 8) & 0xFF;
                    hdr_plain[9] = junk_len & 0xFF;
                    hdr_plain[10] = 0; hdr_plain[11] = 0;
                    std::memcpy(hdr_plain + 12, VER_MAGIC.data(), 4);

                    uint8_t hdr_iv[12];
                    if (RAND_bytes(hdr_iv, 12) != 1) continue;
                    uint8_t masked_hdr[16];
                    if (mask_unmask_header(hdr_plain, 16, s_mask_key, hdr_iv, masked_hdr)) {
                        size_t out_len = 0;
                        std::memcpy(out_buf, hdr_iv, 12); out_len += 12;
                        std::memcpy(out_buf + out_len, masked_hdr, 16); out_len += 16;
                        if (junk_len > 0) {
                            if (RAND_bytes(out_buf + out_len, (int)junk_len) != 1) continue;
                            out_len += junk_len;
                        }
                        size_t aead_offset = out_len;
                        std::memcpy(out_buf + out_len, aead_nonce, 12); out_len += 12;

                        size_t enc_len = 0;
                        // ZERO-COPY: Direct in-place encryption into out_buf (eliminates intermediate buffer copy)
                        if (chacha20_poly1305_encrypt(dec_buf, frame_len, enc_key, aead_nonce, out_buf + out_len, enc_len, out_buf, aead_offset)) {
                            out_len += enc_len;
                            // Proactively flush if batch is full to prevent dropping packets
                            if (scratch.tx_count >= PacketScratch::MAX_BATCH) {
                                size_t sent = scratch.flush_tx();
                                if (sent > 0) {
                                    AegsMetrics::instance().tx_packets.fetch_add(sent, std::memory_order_relaxed);
                                    backpressure.record_egress_success();
                                } else if (scratch.tx_count > 0) {
                                    backpressure.record_egress_failure(EAGAIN);
                                }
                            }
                            // FIX Phase 3: Queue to symmetric sendmmsg batch pipeline
                            if (routing->mimic_type == 2) {
                                scratch.queue_tx_tls_appdata(send_fd, client_addr, out_buf, out_len);
                            } else if (routing->uses_mimicry || routing->mimic_type == 1) {
                                scratch.queue_tx_mimicry(send_fd, client_addr, out_buf, out_len, (const uint8_t*)&s_key_id_raw);
                            } else {
                                scratch.queue_tx(send_fd, client_addr, out_buf, out_len);
                            }
                        }
                    }
                }
                // FIX Phase 3: Flush outbound batch in 1 syscall via sendmmsg()
                size_t sent_count = scratch.flush_tx();
                if (sent_count > 0) {
                    AegsMetrics::instance().tx_packets.fetch_add(sent_count, std::memory_order_relaxed);
                    backpressure.record_egress_success();
                } else if (scratch.tx_count > 0) {
                    AegsMetrics::instance().egress_failures.fetch_add(1, std::memory_order_relaxed);
                    backpressure.record_egress_failure(EAGAIN);
                }
            }
        }
    }

    for (int sfd : server_fds) {
        close(sfd);
    }
    close(epoll_fd);
}

// Dynamic Zero-Downtime Hot-Reload State
static std::mutex g_db_sync_mu;
static std::unordered_map<std::string, uint64_t> g_active_tokens; // token -> kid_raw
static std::unordered_map<uint64_t, std::vector<uint64_t>> g_user_slots; // base_kid_raw -> [slot_kid_raw...]
static sqlite3* g_sync_db = nullptr;
static int64_t g_last_db_data_version = -1;
static std::string g_last_db_path;

static uint64_t register_device_session_helper(const std::string& token, HandshakeServer& hs_server, const std::string& custom_kid_hex = "") {
    std::string kid_hex;
    uint64_t kid_raw = 0;
    if (!custom_kid_hex.empty()) {
        kid_hex = custom_kid_hex;
        for (int k = 0; k < 8; ++k) {
            unsigned int b = 0;
            std::sscanf(kid_hex.c_str() + (k * 2), "%02x", &b);
            ((uint8_t*)&kid_raw)[k] = (uint8_t)b;
        }
    } else {
        uint8_t raw[8];
        compute_key_id(token, raw, kid_hex);
        std::memcpy(&kid_raw, raw, 8);
    }

    if (g_sessions.find_by_key_id(kid_raw)) {
        return kid_raw;
    }

    Session* s = new Session();
    s->identity.key_id_hex = kid_hex;
    s->identity.key_id_raw = kid_raw;

    uint8_t mkey[32];
    uint8_t msk[32];
    uint8_t alt_msk[32];
    if (!derive_master_key(token, s->identity.key_id_hex, mkey) ||
        !hkdf_expand(mkey, 32, "aegis-v2-header-mask", msk, 32)) {
        std::cerr << "[AEGS] Key derivation / HKDF failed for " << s->identity.key_id_hex << "\n";
        delete s;
        return 0;
    }
    bool has_alt = hkdf_expand(mkey, 32, "aegs-v2-header-mask", alt_msk, 32);
    SessionCrypto init_sc;
    std::memcpy(init_sc.master_key, mkey, 32);
    std::memcpy(init_sc.mask_key, msk, 32);
    if (has_alt) {
        std::memcpy(init_sc.alt_mask_key, alt_msk, 32);
        init_sc.has_alt_mask_key = true;
    }
    init_sc.v3_handshake_done = false;
    s->set_crypto(init_sc);
    s->counters.last_activity.store(std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count(), std::memory_order_relaxed);

    hs_server.add_user(kid_raw, s->identity.key_id_hex, std::vector<uint8_t>(mkey, mkey + 32));
    g_sessions.insert_session(s);
    return kid_raw;
}

static void sync_users_from_db(const std::string& db_path, HandshakeServer& hs_server, IpPool& ip_pool) {
    std::lock_guard<std::mutex> lock(g_db_sync_mu);
    if (db_path.empty()) return;

    if (g_sync_db && g_last_db_path != db_path) {
        sqlite3_close(g_sync_db);
        g_sync_db = nullptr;
        g_last_db_data_version = -1;
    }

    if (!g_sync_db) {
        if (sqlite3_open_v2(db_path.c_str(), &g_sync_db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            if (g_sync_db) {
                sqlite3_close(g_sync_db);
                g_sync_db = nullptr;
            }
            return;
        }
        g_last_db_path = db_path;
        g_last_db_data_version = -1;
    }

    // Atomic PRAGMA data_version check (tracks commits across WAL and rollback modes)
    sqlite3_stmt* vstmt = nullptr;
    int64_t current_version = -1;
    if (sqlite3_prepare_v2(g_sync_db, "PRAGMA data_version;", -1, &vstmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(vstmt) == SQLITE_ROW) {
            current_version = sqlite3_column_int64(vstmt, 0);
        }
        sqlite3_finalize(vstmt);
    } else {
        sqlite3_close(g_sync_db);
        g_sync_db = nullptr;
        return;
    }

    if (current_version != -1 && current_version == g_last_db_data_version) {
        return; // Zero changes committed to DB, completely skip query and session updates
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(g_sync_db, "SELECT aegis_key_id, aegis_token FROM users", -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }

    std::unordered_map<std::string, std::string> current_db_users; // token -> kid_hex
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* kid = (const char*)sqlite3_column_text(stmt, 0);
        const char* tok = (const char*)sqlite3_column_text(stmt, 1);
        if (kid && tok) {
            current_db_users[std::string(tok)] = std::string(kid);
        }
    }
    sqlite3_finalize(stmt);

    g_last_db_data_version = current_version;

    // 1. Detect and register new users
    int added_count = 0;
    for (const auto& [token, base_kid_hex] : current_db_users) {
        if (g_active_tokens.find(token) == g_active_tokens.end()) {
            std::vector<uint64_t> slots;
            uint64_t k1 = register_device_session_helper(token, hs_server, base_kid_hex);
            if (k1) {
                slots.push_back(k1);
            }

            // If token is a base token (does not contain explicit slot suffix like #2 or #2_r1)
            // also register the default 4 multi-device slots
            if (token.find('#') == std::string::npos) {
                uint64_t k_slot1 = register_device_session_helper(token + "#1", hs_server);
                if (k_slot1 && k_slot1 != k1) {
                    slots.push_back(k_slot1);
                }

                for (int slot = 2; slot <= 4; ++slot) {
                    uint64_t ks = register_device_session_helper(token + "#" + std::to_string(slot), hs_server);
                    if (ks) {
                        slots.push_back(ks);
                    }
                }
            }

            if (k1) {
                g_user_slots[k1] = slots;
                g_active_tokens[token] = k1;
                added_count++;
            }
        }
    }

    // 2. Detect and remove revoked users
    int removed_count = 0;
    std::vector<std::string> tokens_to_remove;
    for (const auto& [token, base_kid] : g_active_tokens) {
        if (current_db_users.find(token) == current_db_users.end()) {
            tokens_to_remove.push_back(token);
        }
    }

    for (const auto& tok : tokens_to_remove) {
        uint64_t base_kid = g_active_tokens[tok];
        auto slot_it = g_user_slots.find(base_kid);
        if (slot_it != g_user_slots.end()) {
            for (uint64_t kid : slot_it->second) {
                hs_server.remove_user(kid);
                uint32_t assigned_ip = 0;
                {
                    SessionHandle s = g_sessions.find_by_key_id(kid);
                    if (s) {
                        assigned_ip = s->assigned_ip.load(std::memory_order_relaxed);
                    }
                } // s exits scope and decrements active_readers_ before remove_session quiesces
                if (assigned_ip != 0) {
                    ip_pool.release(assigned_ip);
                }
                g_sessions.remove_session(kid);
            }
            g_user_slots.erase(slot_it);
        } else {
            // Standalone slot token removal
            hs_server.remove_user(base_kid);
            uint32_t assigned_ip = 0;
            {
                SessionHandle s = g_sessions.find_by_key_id(base_kid);
                if (s) {
                    assigned_ip = s->assigned_ip.load(std::memory_order_relaxed);
                }
            }
            if (assigned_ip != 0) {
                ip_pool.release(assigned_ip);
            }
            g_sessions.remove_session(base_kid);
        }
        g_active_tokens.erase(tok);
        removed_count++;
    }

    if (added_count > 0 || removed_count > 0) {
        std::cout << "[AEGS Hot-Reload] Synchronized database (data_version=" << current_version
                  << "): +" << added_count << " active user(s), -" << removed_count << " revoked user(s).\n";
    }
}

int main() {
#ifndef _WIN32
    setlinebuf(stdout);
    setlinebuf(stderr);
#endif
    // Setup signal handling for clean shutdown
    struct sigaction sa {};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
    AegsConfig cfg = AegsConfig::from_env();
    g_client_isolation = cfg.client_isolation;
#ifndef _WIN32
    chmod(cfg.db_path.c_str(), 0600);
#endif

    TunInterface tun(cfg.tun_name, cfg.tun_addr(), cfg.mtu);
    if (!tun.open()) {
        std::cerr << "[AEGS v6 Titan Server] Failed to create TUN interface aegs0\n";
        return 1;
    }
    std::cout << "[AEGS v6 Titan Server] TUN interface aegs0 (10.8.0.1/24) ready\n";

    std::string out_iface = NatManager::detect_outbound_iface();
    NatManager nat("aegs0", out_iface, "10.8.0.0/24");
    if (!nat.setup()) {
        std::cerr << "[AEGS v6 Titan Server] Warning: NAT setup failed (may need root)\n";
    } else {
        std::cout << "[AEGS v6 Titan Server] NAT/MASQUERADE active on " << out_iface << "\n";
    }

    IpPool ip_pool("10.8.0.0/24");
    std::unordered_map<uint64_t, std::string> empty_user_map;
    std::unordered_map<uint64_t, std::vector<uint8_t>> empty_key_map;
    HandshakeServer hs_server(empty_user_map, empty_key_map);

    // Initial sync from SQLite database:
    sync_users_from_db(cfg.db_path, hs_server, ip_pool);
    std::cout << "[AEGS v6 Titan Server] Active sessions loaded: " << g_sessions.total_sessions() << " device slot(s)\n";
    auto server_pubkey = hs_server.get_pubkey();

    TrafficShaper shaper(5, false);
    shaper.set_semantic_enabled(true);

    PortHopper hopper(cfg.base_port, cfg.port_count, cfg.hop_interval_sec);
    auto ports = hopper.server_ports();

    // Determine worker thread count:
    // cfg.worker_threads defaulting to 1 if 0, or up to std::thread::hardware_concurrency() when specified
    int num_workers = cfg.worker_threads;
    if (num_workers <= 0) {
        num_workers = 1;
    } else {
        unsigned int hw = std::thread::hardware_concurrency();
        if (hw > 0 && (unsigned int)num_workers > hw) {
            num_workers = static_cast<int>(hw);
        }
    }

    std::cout << "[AEGS v6 Titan Server] Port Hopping active on ports " << cfg.base_port << "-" << (cfg.base_port + cfg.port_count - 1)
              << " (" << cfg.port_count << " ports, " << cfg.hop_interval_sec << "s interval)\n";
    std::cout << "[AEGS v6 Titan Server] Worker threads: " << num_workers
              << (num_workers > 1 ? " (SO_REUSEPORT active)" : "")
              << ", Batch size: " << cfg.recv_batch_size << "\n";

    // Dedicated Control-Plane GC Thread: offloads cleanup, token expiry, rate-limit and dynamic user synchronization
    std::thread gc_thread([&]() {
        while (g_running.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            if (!g_running.load(std::memory_order_relaxed)) break;
            double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
            cleanup_maps(now, ip_pool);
            sync_users_from_db(cfg.db_path, hs_server, ip_pool);
        }
    });

    if (num_workers > 1) {
        std::vector<std::thread> workers;
        workers.reserve(num_workers);
        for (int i = 0; i < num_workers; ++i) {
            workers.emplace_back(worker_loop, i, num_workers, std::cref(cfg), std::cref(ports),
                                 std::ref(tun), std::ref(hs_server), std::ref(ip_pool), std::ref(shaper));
        }
        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }
    } else {
        worker_loop(0, 1, cfg, ports, tun, hs_server, ip_pool, shaper);
    }

    if (gc_thread.joinable()) {
        gc_thread.join();
    }

    std::cout << "[AEGS v6 Titan Server] Shutting down...\n";
    nat.teardown();
    tun.close();

    g_sessions.clear();
    if (g_sync_db) {
        sqlite3_close(g_sync_db);
        g_sync_db = nullptr;
    }

    std::cout << "[AEGS v6 Titan Server] Clean shutdown complete.\n";
    return 0;
}
