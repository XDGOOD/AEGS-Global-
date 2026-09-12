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
#include "ip_router.h"
#include "handshake.h"
#include "ip_pool.h"
#include "nat_manager.h"
#include "blackhole_responder.h"
#include "traffic_shaper.h"
#include "port_hopper.h"
#include "session_resumption.h"
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


struct Session {
    std::string key_id_hex;
    uint64_t key_id_raw = 0;
    uint8_t master_key[32];
    uint8_t mask_key[32];
    struct sockaddr_in client_addr {};
    bool has_client = false;
    double last_activity = 0;
    std::atomic<uint64_t> tx_seq{0};
    AntiReplayFilter replay_filter;
    uint64_t session_id = 0;     // NEW: AEGS v3 session ID from handshake
    uint32_t assigned_ip = 0;    // NEW: assigned TUN IP (host byte order)
    SessionKeys session_keys;    // NEW: ECDH-derived per-session keys
    bool v3_handshake_done = false; // NEW: true after ECDH handshake complete
    int last_server_fd = -1;
    mutable std::mutex mu;

    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    bool check_replay(const uint8_t* n_bytes) {
        std::lock_guard<std::mutex> lk(mu);
        uint64_t seq = 0;
        std::memcpy(&seq, n_bytes, sizeof(uint64_t));
        return replay_filter.check_and_update(seq);
    }
};

std::unordered_map<std::string, Session*> sessions;
std::unordered_map<uint32_t, Session*> ip_to_session;
std::mutex sessions_mu;

// Fast-path O(1) cache: maps 64-bit client endpoint (ip:port) to Session*
std::unordered_map<uint64_t, Session*> g_endpoint_cache;
std::mutex g_endpoint_mu;

static inline uint64_t make_endpoint_key(uint32_t ip, uint16_t port) {
    return (static_cast<uint64_t>(ip) << 16) | static_cast<uint64_t>(port);
}

const size_t MAX_ENDPOINT_CACHE = 4096;

static inline void update_endpoint_cache(uint64_t ep_key, Session* s) {
    std::lock_guard<std::mutex> ep_lock(g_endpoint_mu);
    if (g_endpoint_cache.size() < MAX_ENDPOINT_CACHE || g_endpoint_cache.find(ep_key) != g_endpoint_cache.end()) {
        g_endpoint_cache[ep_key] = s;
    }
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
std::unordered_map<uint32_t, double> banned_ips;
const int ban_levels[] = {0, 30, 300, 3600};
std::mutex security_mu;
std::mutex tun_write_mu;

// FIX Production DoS: Pre-crypto handshake rate limiter per IP
struct HandshakeRateRecord {
    double window_start = 0;
    int count = 0;
};
std::unordered_map<uint32_t, HandshakeRateRecord> g_hs_rate_limit;
std::mutex g_hs_rate_mu;
const int MAX_HANDSHAKES_PER_SEC_PER_IP = 10;
const size_t MAX_HS_RATE_LIMIT_ENTRIES = 4096;

static bool check_handshake_rate_limit(uint32_t ip_num, double now) {
    std::lock_guard<std::mutex> lock(g_hs_rate_mu);
    auto it = g_hs_rate_limit.find(ip_num);
    if (it == g_hs_rate_limit.end()) {
        if (g_hs_rate_limit.size() >= MAX_HS_RATE_LIMIT_ENTRIES) {
            auto oldest = g_hs_rate_limit.begin();
            for (auto e = g_hs_rate_limit.begin(); e != g_hs_rate_limit.end(); ++e) {
                if (e->second.window_start < oldest->second.window_start) oldest = e;
            }
            if (oldest != g_hs_rate_limit.end()) g_hs_rate_limit.erase(oldest);
        }
        g_hs_rate_limit[ip_num] = {now, 1};
        return true;
    }
    if (now - it->second.window_start >= 1.0) {
        it->second.window_start = now;
        it->second.count = 1;
        return true;
    }
    it->second.count++;
    return (it->second.count <= MAX_HANDSHAKES_PER_SEC_PER_IP);
}

// FIX Review Issue 5: Rate limit slow-path roaming unmask scans to prevent CPU-DoS
std::unordered_map<uint32_t, HandshakeRateRecord> g_roam_rate_limit;
std::mutex g_roam_rate_mu;
const int MAX_ROAMING_SCANS_PER_SEC_PER_IP = 5;

static bool check_roaming_rate_limit(uint32_t ip_num, double now) {
    std::lock_guard<std::mutex> lock(g_roam_rate_mu);
    auto it = g_roam_rate_limit.find(ip_num);
    if (it == g_roam_rate_limit.end()) {
        if (g_roam_rate_limit.size() >= 4096) {
            auto oldest = g_roam_rate_limit.begin();
            for (auto e = g_roam_rate_limit.begin(); e != g_roam_rate_limit.end(); ++e) {
                if (e->second.window_start < oldest->second.window_start) oldest = e;
            }
            if (oldest != g_roam_rate_limit.end()) g_roam_rate_limit.erase(oldest);
        }
        g_roam_rate_limit[ip_num] = {now, 1};
        return true;
    }
    if (now - it->second.window_start >= 1.0) {
        it->second.window_start = now;
        it->second.count = 1;
        return true;
    }
    it->second.count++;
    return (it->second.count <= MAX_ROAMING_SCANS_PER_SEC_PER_IP);
}

// Signal handling & clean shutdown
static std::atomic<bool> g_running{true};
static void handle_signal(int sig) {
    (void)sig;
    g_running = false;
}

double last_cleanup = 0;
const double CLEANUP_INTERVAL = 30.0;
const double FAIL_IDLE_TTL = 300.0;
const double SESSION_IDLE_TIMEOUT = 180.0; // 3 minutes idle -> close inactive session

void cleanup_maps(double now, IpPool& ip_pool) {
    if (now - last_cleanup < CLEANUP_INTERVAL) return;
    std::lock_guard<std::mutex> sec_lock(security_mu);
    std::lock_guard<std::mutex> sess_lock(sessions_mu);
    if (now - last_cleanup < CLEANUP_INTERVAL) return;
    last_cleanup = now;

    {
        std::lock_guard<std::mutex> ep_lock(g_endpoint_mu);
        for (auto it = g_endpoint_cache.begin(); it != g_endpoint_cache.end(); ) {
            if (!it->second->has_client || (now - it->second->last_activity > SESSION_IDLE_TIMEOUT)) {
                it = g_endpoint_cache.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto it = banned_ips.begin(); it != banned_ips.end(); ) {
        if (now > it->second) it = banned_ips.erase(it); else ++it;
    }
    for (auto it = failed_attempts.begin(); it != failed_attempts.end(); ) {
        if (now - it->second.last_seen > FAIL_IDLE_TTL) it = failed_attempts.erase(it); else ++it;
    }
    {
        std::lock_guard<std::mutex> hs_lock(g_hs_rate_mu);
        for (auto it = g_hs_rate_limit.begin(); it != g_hs_rate_limit.end(); ) {
            if (now - it->second.window_start > 10.0) it = g_hs_rate_limit.erase(it); else ++it;
        }
    }
    {
        std::lock_guard<std::mutex> roam_lock(g_roam_rate_mu);
        for (auto it = g_roam_rate_limit.begin(); it != g_roam_rate_limit.end(); ) {
            if (now - it->second.window_start > 10.0) it = g_roam_rate_limit.erase(it); else ++it;
        }
    }
    for (auto it = sessions.begin(); it != sessions.end(); ) {
        Session* s = it->second;
        std::lock_guard<std::mutex> slk(s->mu);
        if (s->has_client && (now - s->last_activity > SESSION_IDLE_TIMEOUT)) {
            std::cerr << "[GC] Session " << s->key_id_hex << " idle timeout\n";
            if (s->assigned_ip) {
                ip_to_session.erase(s->assigned_ip);
                ip_pool.release(s->assigned_ip);
            }
            s->has_client = false;
            s->v3_handshake_done = false;
            s->assigned_ip = 0;
        }
        ++it;
    }
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

// Blackhole-enhanced probing fallback: generates varied QUIC-like responses
void send_probing_fallback(int fd, const struct sockaddr_in& caddr,
                           const uint8_t* probe_data, size_t probe_len,
                           uint32_t ip_num, double now) {
    (void)ip_num;
    if (probe_len < BlackholeResponder::kMinProbeLen)
        return; // Drop short probes to prevent UDP amplification reflection (Audit 4.4)
    std::string ip = inet_ntoa(caddr.sin_addr);
    if (!g_blackhole.should_respond(ip, now))
        return;
    auto resp = g_blackhole.generate_response(probe_data, probe_len);
    if (!resp.empty()) {
        g_blackhole.record_response(ip, resp.size());
        sendto(fd, resp.data(), resp.size(), 0,
               (struct sockaddr*)&caddr, sizeof(caddr));
    }
}

void record_fail(int fd, const struct sockaddr_in& caddr,
                  const uint8_t* probe_data, size_t probe_len,
                  uint32_t ip_num, double now, double weight) {
    std::lock_guard<std::mutex> lock(security_mu);
    // Bounded map protection against DoS memory exhaustion from spoofed UDP flooding
    if (failed_attempts.size() >= MAX_FAILED_RECORDS && failed_attempts.find(ip_num) == failed_attempts.end()) {
        send_probing_fallback(fd, caddr, probe_data, probe_len, ip_num, now);
        return;
    }
    auto& rec = failed_attempts[ip_num];
    if (rec.level == 0) rec.level = 1;
    if (now - rec.last_seen > 120.0) { rec.weight = 0; }
    rec.last_seen = now;
    rec.weight += weight;
    
    send_probing_fallback(fd, caddr, probe_data, probe_len, ip_num, now);

    if (rec.weight >= 10.0) {
        int lvl = std::min(rec.level, 3);
        if (banned_ips.size() < MAX_BANNED_RECORDS || banned_ips.find(ip_num) != banned_ips.end()) {
            banned_ips[ip_num] = now + ban_levels[lvl];
        }
        rec.weight = 0; rec.level = lvl + 1;
    }
}

size_t secure_pad_len() {
    uint8_t b;
    RAND_bytes(&b, 1);
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

uint16_t generate_junk_len() {
    uint8_t b; RAND_bytes(&b, 1);
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
        int sock_buf_size = 4 * 1024 * 1024;
        setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
        setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));
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

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    std::vector<uint8_t> dec_buf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> enc_buf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> out_buf(BUFFER_SIZE);

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

        uint32_t ip_num = caddr.sin_addr.s_addr;
        {
            std::lock_guard<std::mutex> lock(security_mu);
            auto ban_it = banned_ips.find(ip_num);
            if (ban_it != banned_ips.end() && now < ban_it->second) return;
        }

        if (pkt_data[0] == 0x04 && (size_t)len >= 97) {
            ResumptionToken rtok;
            memcpy(&rtok, pkt_data + 1, 96);
            uint64_t resumed_sid = 0;
            uint32_t resumed_ip = 0;
            Session* resumed_sess = nullptr;

            char kid_hex[17];
            for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", rtok.key_id[j]);
            kid_hex[16] = 0;

            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                // FIX O(1) Resumption Scaling: Look up session directly by KeyID in token
                auto sit = sessions.find(kid_hex);
                if (sit != sessions.end()) {
                    resumed_sess = sit->second;
                }
                // NOTE: Legacy O(N) fallback loop removed.
                // All tokens now include key_id for O(1) lookup. If key_id is missing
                // or doesn't match, resumption simply fails (client must re-handshake).
            }
            // FIX Concurrency: Verify token OUTSIDE sessions_mu to avoid holding global lock during crypto
            if (resumed_sess) {
                if (!g_resumption.verify(rtok, resumed_sess->master_key, resumed_sid, resumed_ip)) {
                    resumed_sess = nullptr; // Verification failed
                }
            }
            if (resumed_sess) {
                Session* s = resumed_sess;
                {
                    std::lock_guard<std::mutex> slk(s->mu);
                    s->client_addr = caddr;
                    s->has_client = true;
                    s->last_activity = now;
                    s->last_server_fd = fd;
                    s->session_id = resumed_sid;

                    // FIX Blocker 2: Restore full cryptographic state and forward-secret session keys using per‑RESUME secret
                    // Derive a per‑resume key from the token nonce to avoid nonce reuse across resumption.
                    auto hex_encode = [](const uint8_t* data, size_t len) -> std::string {
                        static const char* hexdigits = "0123456789abcdef";
                        std::string out; out.reserve(len * 2);
                        for (size_t i = 0; i < len; ++i) {
                            out.push_back(hexdigits[data[i] >> 4]);
                            out.push_back(hexdigits[data[i] & 0xF]);
                        }
                        return out;
                    };
                    std::string resume_info = "aegs-resume-" + hex_encode(rtok.nonce, 32);
                    std::string recv_info = resume_info + "-s2c";
                    std::string send_info = resume_info + "-c2s";
                    hkdf_expand(s->master_key, 32, recv_info, s->session_keys.recv_key, 32);
                    hkdf_expand(s->master_key, 32, send_info, s->session_keys.send_key, 32);
                    s->v3_handshake_done = true;
                    s->tx_seq = 0;
                    s->replay_filter = AntiReplayFilter();
                }
                // Update O(1) fast-path endpoint cache
                update_endpoint_cache(make_endpoint_key(ip_num, caddr.sin_port), s);
                if (resumed_ip) {
                    std::lock_guard<std::mutex> lk(sessions_mu);
                    if (!s->assigned_ip) {
                        s->assigned_ip = resumed_ip;
                        ip_to_session[s->assigned_ip] = s;
                    }
                }
                ResumptionToken new_tok;
                if (g_resumption.issue(s->session_id, s->assigned_ip, s->master_key, new_tok, (const uint8_t*)&s->key_id_raw)) {
                    uint8_t rpkt[97];
                    rpkt[0] = 0x03;
                    memcpy(rpkt + 1, &new_tok, 96);
                    sendto(fd, rpkt, 97, 0, (struct sockaddr*)&caddr, sizeof(caddr));
                }
                std::cout << "[RESUME] Session resumed with restored crypto state for " << inet_ntoa(caddr.sin_addr) << " (" << IpPool::to_string(s->assigned_ip) << ")\n";
            }
            return;
        }

        if (pkt_data[0] == 0x01) {
            // FIX Production DoS: Reject undersized handshake packets immediately
            if ((size_t)len < 72) {
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0);
                return;
            }
            // FIX Production DoS: Pre-crypto rate limiting per IP
            if (!check_handshake_rate_limit(ip_num, now)) {
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5);
                return;
            }
            uint64_t key_id_out = 0;
            if (!hs_server.process_init(pkt_data, len, key_id_out)) {
                // Invalid KeyID, timestamp or forged MAC: penalize immediately
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0);
                return;
            }
            char kid_hex[17];
            for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", ((uint8_t*)&key_id_out)[j]);
            kid_hex[16] = 0;
            Session* s = nullptr;
            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                auto sit = sessions.find(kid_hex);
                if (sit != sessions.end()) s = sit->second;
            }
            if (s) {
                auto maybe_ip = ip_pool.allocate();
                if (!maybe_ip) { std::cerr << "IP pool exhausted\n"; return; }
                {
                    std::lock_guard<std::mutex> lk(sessions_mu);
                    if (s->assigned_ip) {
                        ip_pool.release(s->assigned_ip);
                        ip_to_session.erase(s->assigned_ip);
                    }
                    s->assigned_ip = *maybe_ip;
                    ip_to_session[s->assigned_ip] = s;
                }
                
                SessionKeys sk;
                auto resp = hs_server.build_resp(key_id_out, s->assigned_ip, 1400, sk);
                {
                    std::lock_guard<std::mutex> slk(s->mu);
                    s->session_keys = sk;
                    s->session_id = sk.session_id;
                    s->client_addr = caddr;
                    s->has_client = true;
                    s->v3_handshake_done = true;
                    s->tx_seq = 0;
                    s->replay_filter = AntiReplayFilter();
                    s->last_activity = now;
                    s->last_server_fd = fd;
                }
                // Register in O(1) fast-path cache
                update_endpoint_cache(make_endpoint_key(ip_num, caddr.sin_port), s);
                sendto(fd, resp.data(), resp.size(), 0, (struct sockaddr*)&caddr, sizeof(caddr));
                std::cout << "[HS] Client " << inet_ntoa(caddr.sin_addr) << " assigned " << IpPool::to_string(s->assigned_ip) << "\n";
                
                ResumptionToken rtok;
                if (g_resumption.issue(s->session_id, s->assigned_ip, s->master_key, rtok, (const uint8_t*)&s->key_id_raw)) {
                    uint8_t rtok_pkt[97];
                    rtok_pkt[0] = 0x03; // RESUMPTION_TOKEN
                    memcpy(rtok_pkt + 1, &rtok, 96);
                    sendto(fd, rtok_pkt, 97, 0, (struct sockaddr*)&caddr, sizeof(caddr));
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
        Session* matched_sess = nullptr;
        uint8_t unmasked_hdr[16];

        // FIX Blocker 5: Fast-path O(1) lookup using client endpoint cache
        uint64_t ep_key = make_endpoint_key(ip_num, caddr.sin_port);
        Session* fast_sess = nullptr;
        {
            std::lock_guard<std::mutex> ep_lock(g_endpoint_mu);
            auto it = g_endpoint_cache.find(ep_key);
            if (it != g_endpoint_cache.end()) fast_sess = it->second;
        }

        if (fast_sess && mask_unmask_header(pkt_data + 12, 16, fast_sess->mask_key, hdr_iv, unmasked_hdr)) {
            if (std::memcmp(unmasked_hdr, &fast_sess->key_id_raw, 8) == 0 && std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                matched_sess = fast_sess;
            }
        }

        // Slow-path fallback: scan registered sessions if new connection or roaming
        if (!matched_sess) {
            // FIX Review Issue 5: Rate limit slow-path unmask scans to prevent CPU-DoS from unknown packet floods
            if (!check_roaming_rate_limit(ip_num, now)) {
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5);
                return;
            }
            std::lock_guard<std::mutex> lk(sessions_mu);
            for (auto& kv : sessions) {
                Session* s = kv.second;
                if (mask_unmask_header(pkt_data + 12, 16, s->mask_key, hdr_iv, unmasked_hdr)) {
                    if (std::memcmp(unmasked_hdr, &s->key_id_raw, 8) == 0 && std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                        matched_sess = s;
                        update_endpoint_cache(ep_key, s);
                        break;
                    }
                }
            }
        }

        if (!matched_sess) { record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 1.0); return; }

        Session* s = matched_sess;

        // Verify incoming port hopping compliance if multi-port listening is active
        if (ports.size() > 1 && s->v3_handshake_done) {
            auto pit = fd_to_port.find(fd);
            if (pit != fd_to_port.end() && !hopper.is_valid_port(s->session_keys.recv_key, pit->second)) {
                // Packet arrived on an invalid port for this session's hopping epoch
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5);
                return;
            }
        }

        uint16_t junk_len = (unmasked_hdr[8] << 8) | unmasked_hdr[9];
        size_t aead_offset = 12 + 16 + junk_len;
        if ((size_t)len < aead_offset + 12 + TAG_LEN) { record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5); return; }

        const uint8_t* aead_nonce = pkt_data + aead_offset;
        if (s->check_replay(aead_nonce)) return;

        const uint8_t* ct = pkt_data + aead_offset + 12;
        size_t ct_len = len - (aead_offset + 12);

        size_t dec_len = 0;
        uint8_t dec_key[32];
        {
            std::lock_guard<std::mutex> slk(s->mu);
            if (!s->v3_handshake_done) {
                record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5);
                return;
            }
            std::memcpy(dec_key, s->session_keys.recv_key, 32);
        }
        // FIX Blocker 3: Authenticate outer header (IV + masked header + junk) as AAD to prevent bit-flipping
        if (!chacha20_poly1305_decrypt(ct, ct_len, dec_key, aead_nonce, dec_buf.data(), dec_len, pkt_data, aead_offset)) {
            record_fail(fd, caddr, pkt_data, (size_t)len, ip_num, now, 0.5); return;
        }

        // Authentication passed! Securely update roaming endpoint & cache.
        {
            std::lock_guard<std::mutex> slk(s->mu);
            s->client_addr = caddr; 
            s->has_client = true;
            s->last_activity = now;
            s->last_server_fd = fd;
        }
        {
            std::lock_guard<std::mutex> lock(security_mu);
            failed_attempts.erase(ip_num);
        }

        if (unmasked_hdr[10] & 0x80) {
            std::cout << "[DEBUG] Received CHAFF packet from " << inet_ntoa(caddr.sin_addr) << "\n";
            return;
        }

        if (dec_len < 2) return;
        uint16_t plen = (dec_buf[0] << 8) | dec_buf[1];
        if (plen > 0 && plen <= dec_len - 2) {
            // FIX P0 TUN ACL: Verify inner packet source IP matches session's assigned IP
            // Prevents tunnel users from spoofing arbitrary source addresses
            const uint8_t* inner_pkt = dec_buf.data() + 2;
            if (plen >= 20) { // Minimum IPv4 header size
                uint8_t ip_version = (inner_pkt[0] >> 4) & 0xF;
                if (ip_version == 4) {
                    uint32_t inner_src_ip = (uint32_t(inner_pkt[12]) << 24) |
                                           (uint32_t(inner_pkt[13]) << 16) |
                                           (uint32_t(inner_pkt[14]) << 8)  |
                                            uint32_t(inner_pkt[15]);
                    if (s->assigned_ip != 0 && inner_src_ip != s->assigned_ip) {
                        return; // Drop: source IP spoofing attempt
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
        cleanup_maps(now, ip_pool);

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
                            ssize_t plen = msgvec[p].msg_len;
                            process_udp_packet(fd, slots[p].addr, slots[p].buf.data(), plen, now);
                        }
                    } else if (pkts < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                        // Socket drained
                    } else {
                        // Graceful fallback to recvfrom
                        struct sockaddr_in caddr {};
                        socklen_t clen = sizeof(caddr);
                        ssize_t len = recvfrom(fd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&caddr, &clen);
                        if (len >= 0) {
                            process_udp_packet(fd, caddr, buffer.data(), len, now);
                        }
                    }
                } else {
                    struct sockaddr_in caddr {};
                    socklen_t clen = sizeof(caddr);
                    ssize_t len = recvfrom(fd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&caddr, &clen);
                    if (len >= 0) {
                        process_udp_packet(fd, caddr, buffer.data(), len, now);
                    }
                }
#else
                struct sockaddr_in caddr {};
                socklen_t clen = sizeof(caddr);
                ssize_t len = recvfrom(fd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&caddr, &clen);
                if (len >= 0) {
                    process_udp_packet(fd, caddr, buffer.data(), len, now);
                }
#endif
            } else if (fd == tun_fd) {
                if (backpressure.should_pause_tun()) {
                    continue; // Egress congested: defer reading from TUN to trigger upstream TCP flow control
                }
                size_t max_batch = backpressure.max_tun_batch();
                for (size_t batch = 0; batch < max_batch; ++batch) {
                    ssize_t n = tun.read_packet(buffer.data(), buffer.size());
                    if (n < 0) {
                        break; // EAGAIN / EWOULDBLOCK
                    }
                    if (n < 20) continue; 

                    uint32_t dst_ip = (uint32_t(buffer[16]) << 24) | (uint32_t(buffer[17]) << 16)
                                    | (uint32_t(buffer[18]) << 8)  |  uint32_t(buffer[19]);

                    Session* s = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(sessions_mu);
                        auto ip_it = ip_to_session.find(dst_ip);
                        if (ip_it != ip_to_session.end()) s = ip_it->second;
                    }
                    if (!s) continue;

                    // FIX Client Isolation: Drop inter-client traffic when isolation enabled
                    // Source IP in TUN packet (bytes 12-15 in big-endian) — if it belongs to
                    // another VPN client, drop to prevent lateral movement between tenants
                    if (g_client_isolation && n >= 20) {
                        uint32_t src_ip = (uint32_t(buffer[12]) << 24) | (uint32_t(buffer[13]) << 16)
                                        | (uint32_t(buffer[14]) << 8)  |  uint32_t(buffer[15]);
                        if (src_ip != dst_ip) {
                            std::lock_guard<std::mutex> lk(sessions_mu);
                            if (ip_to_session.find(src_ip) != ip_to_session.end()) {
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

                    {
                        std::lock_guard<std::mutex> slk(s->mu);
                        if (!s->has_client || s->last_server_fd < 0 || !s->v3_handshake_done) continue;
                        s->last_activity = now;
                        client_addr = s->client_addr;
                        send_fd = s->last_server_fd;
                        s_key_id_raw = s->key_id_raw;
                        std::memcpy(s_mask_key, s->mask_key, 32);
                        std::memcpy(enc_key, s->session_keys.send_key, 32);
                        seq = ++(s->tx_seq);
                    }

                    size_t pad_len = shaper.semantic_pad((size_t)n);
                    size_t frame_len = FRAME_HDR + (size_t)n + pad_len;
                    if (frame_len + TAG_LEN > dec_buf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)n; }

                    uint16_t plen_be = htons((uint16_t)n);
                    std::memcpy(dec_buf.data(), &plen_be, 2);
                    std::memcpy(dec_buf.data() + 2, buffer.data(), (size_t)n);
                    if (pad_len > 0) TrafficShaper::fill_random_padding(dec_buf.data() + 2 + n, pad_len);

                    uint8_t aead_nonce[12] = {0};
                    std::memcpy(aead_nonce, &seq, sizeof(uint64_t));
                    RAND_bytes(aead_nonce + 8, 4);

                    uint16_t junk_len = generate_junk_len();

                    uint8_t hdr_plain[16];
                    std::memcpy(hdr_plain, &s_key_id_raw, 8);
                    hdr_plain[8] = (junk_len >> 8) & 0xFF;
                    hdr_plain[9] = junk_len & 0xFF;
                    hdr_plain[10] = 0; hdr_plain[11] = 0;
                    std::memcpy(hdr_plain + 12, VER_MAGIC.data(), 4);

                    uint8_t hdr_iv[12]; RAND_bytes(hdr_iv, 12);
                    uint8_t masked_hdr[16];
                    if (mask_unmask_header(hdr_plain, 16, s_mask_key, hdr_iv, masked_hdr)) {
                        size_t out_len = 0;
                        std::memcpy(out_buf.data(), hdr_iv, 12); out_len += 12;
                        std::memcpy(out_buf.data() + out_len, masked_hdr, 16); out_len += 16;
                        if (junk_len > 0) {
                            RAND_bytes(out_buf.data() + out_len, (int)junk_len);
                            out_len += junk_len;
                        }
                        size_t aead_offset = out_len;
                        std::memcpy(out_buf.data() + out_len, aead_nonce, 12); out_len += 12;

                        size_t enc_len = 0;
                        // FIX Blocker 3: Authenticate outer header as AAD in AEAD Poly1305
                        if (chacha20_poly1305_encrypt(dec_buf.data(), frame_len, enc_key, aead_nonce, enc_buf.data(), enc_len, out_buf.data(), aead_offset)) {
                            std::memcpy(out_buf.data() + out_len, enc_buf.data(), enc_len); out_len += enc_len;
                            ssize_t sret = sendto(send_fd, out_buf.data(), out_len, 0, (struct sockaddr*)&client_addr, sizeof(client_addr));
                            if (sret < 0) {
                                backpressure.record_egress_failure(errno);
                                break; // Stop draining TUN immediately when socket buffers are saturated
                            } else {
                                backpressure.record_egress_success();
                            }
                        }
                    }
                }
            }
        }
    }

    for (int sfd : server_fds) {
        close(sfd);
    }
    close(epoll_fd);
}

int main() {
    // Setup signal handling for clean shutdown
    struct sigaction sa {};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
    AegsConfig cfg = AegsConfig::from_env();
    g_client_isolation = cfg.client_isolation;
    sqlite3* db;
    if (sqlite3_open(cfg.db_path.c_str(), &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT aegis_key_id, aegis_token FROM users", -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Session* s = new Session();
                s->key_id_hex = (const char*)sqlite3_column_text(stmt, 0);
                s->key_id_raw = 0;
                for (int k = 0; k < 8; ++k) {
                    unsigned int b = 0;
                    std::sscanf(s->key_id_hex.c_str() + (k * 2), "%02x", &b);
                    ((uint8_t*)&s->key_id_raw)[k] = (uint8_t)b;
                }
                std::string token = (const char*)sqlite3_column_text(stmt, 1);
                if (!derive_master_key(token, s->key_id_hex, s->master_key) ||
                    !hkdf_expand(s->master_key, 32, "aegis-v2-header-mask", s->mask_key, 32)) {
                    std::cerr << "key derivation / HKDF failed for " << s->key_id_hex << "\n";
                    delete s;
                    continue;
                }
                sessions[s->key_id_hex] = s;
            }
            sqlite3_finalize(stmt);
        } else {
            std::cerr << "failed to prepare user query: " << sqlite3_errmsg(db) << "\n";
        }
        sqlite3_close(db);
    } else {
        std::cerr << "failed to open db at " << cfg.db_path << ": " << sqlite3_errmsg(db) << "\n";
        return 1;
    }

    if (sessions.empty()) {
        std::cerr << "no sessions loaded from db, nothing to serve\n";
        return 1;
    }
    
    std::unordered_map<uint64_t, std::string> user_map;
    // FIX CRIT-1: Build master_key_map so HandshakeServer can verify MAC
    // using user's MasterKey (secret), not the server's public key.
    std::unordered_map<uint64_t, std::vector<uint8_t>> master_key_map;
    for (auto& kv : sessions) {
        uint64_t kid = kv.second->key_id_raw;
        user_map[kid] = kv.first; 
        master_key_map[kid] = std::vector<uint8_t>(
            kv.second->master_key, kv.second->master_key + 32);
    }
    
    TunInterface tun(cfg.tun_name, cfg.tun_addr(), cfg.mtu);
    if (!tun.open()) {
        std::cerr << "[AEGS v3] Failed to create TUN interface aegs0\n";
        return 1;
    }
    std::cout << "[AEGS v3] TUN interface aegs0 (10.8.0.1/24) ready\n";

    std::string out_iface = NatManager::detect_outbound_iface();
    NatManager nat("aegs0", out_iface, "10.8.0.0/24");
    if (!nat.setup()) {
        std::cerr << "[AEGS v3] Warning: NAT setup failed (may need root)\n";
    } else {
        std::cout << "[AEGS v3] NAT/MASQUERADE active on " << out_iface << "\n";
    }

    IpPool ip_pool("10.8.0.0/24");
    HandshakeServer hs_server(user_map, master_key_map);
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

    std::cout << "[AEGS v4 Server] Port Hopping active on ports " << cfg.base_port << "-" << (cfg.base_port + cfg.port_count - 1)
              << " (" << cfg.port_count << " ports, " << cfg.hop_interval_sec << "s interval)\n";
    std::cout << "[AEGS v4 Server] Worker threads: " << num_workers
              << (num_workers > 1 ? " (SO_REUSEPORT active)" : "")
              << ", Batch size: " << cfg.recv_batch_size << "\n";

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

    std::cout << "[AEGS v4 Server] Shutting down...\n";
    nat.teardown();
    tun.close();

    {
        std::lock_guard<std::mutex> lk(sessions_mu);
        for (auto& kv : sessions) {
            delete kv.second;
        }
        sessions.clear();
        ip_to_session.clear();
    }

    std::cout << "[AEGS v4 Server] Clean shutdown complete.\n";
    return 0;
}
