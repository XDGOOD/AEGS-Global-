#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <queue>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "tun_interface.h"
#include "handshake.h"
#include "ip_pool.h"
#include "illusion_prebypass.h"
#include "chaff_engine.h"
#include "traffic_shaper.h"
#include "port_hopper.h"
#include "session_resumption.h"
#include "network_security.h"
#include "backpressure.h"
#include "crypto_utils.h"
#include <optional>
#include <memory>
#include <poll.h>


size_t secure_pad_len() {
    uint8_t b; RAND_bytes(&b, 1);
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

uint16_t generate_junk_len() {
    uint8_t b; RAND_bytes(&b, 1);
    if (b < 50) return 16 + (b % 49);
    return 0;
}

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0 << " <server_ip> <server_port> <token> [--no-tun] [--kill-switch] [--dns-protect]\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) { usage(argv[0]); return 1; }
    
    std::string s_host = argv[1];
    int s_port = std::stoi(argv[2]);
    std::string token = argv[3];
    bool use_tun = true;
    bool enable_kill_switch = (std::getenv("AEGS_KILL_SWITCH") != nullptr && std::string(std::getenv("AEGS_KILL_SWITCH")) == "1");
    bool enable_dns_protect = (std::getenv("AEGS_DNS_PROTECT") != nullptr && std::string(std::getenv("AEGS_DNS_PROTECT")) == "1");

    for (int i = 4; i < argc; ++i) {
        if (!strcmp(argv[i], "--no-tun")) use_tun = false;
        else if (!strcmp(argv[i], "--kill-switch")) enable_kill_switch = true;
        else if (!strcmp(argv[i], "--dns-protect")) enable_dns_protect = true;
    }

    uint8_t raw_kid[8];
    std::string kid_hex;
    compute_key_id(token, raw_kid, kid_hex);

    uint8_t master_key[32];
    if (!derive_master_key(token, kid_hex, master_key)) {
        std::cerr << "master key derivation failed\n";
        return 1;
    }

    uint8_t mask_key[32];
    if (!hkdf_expand(master_key, 32, "aegis-v2-header-mask", mask_key, 32)) {
        std::cerr << "HKDF expansion failed\n";
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int sock_buf_size = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));

    if (!use_tun) {
        struct sockaddr_in l_addr {};
        l_addr.sin_family = AF_INET; l_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); l_addr.sin_port = htons(51821);
        if (bind(fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) { perror("bind"); return 1; }
    }

    struct sockaddr_in s_addr {};
    s_addr.sin_family = AF_INET; s_addr.sin_port = htons(s_port);
    struct addrinfo hints {}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(s_host.c_str(), nullptr, &hints, &res) == 0 && res) {
        s_addr.sin_addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    } else if (inet_pton(AF_INET, s_host.c_str(), &s_addr.sin_addr) != 1) {
        std::cerr << "failed to resolve " << s_host << "\n";
        return 1;
    }

    // AEGS v3 Handshake with retry
    IllusionPreBypass::send_illusion_sequence(fd, s_addr, raw_kid);

    // FIX CRIT-4: No silent downgrade to PSK. An active MITM who can drop
    // packets will ALWAYS trigger any fallback that exists — losing PFS.
    // Instead, retry the handshake up to 3 times, then fail explicitly.
    const int HANDSHAKE_MAX_RETRIES = 3;
    SessionKeys session_keys;
    uint32_t assigned_ip = 0;
    uint32_t mtu = 1420;
    bool handshake_ok = false;

    for (int attempt = 0; attempt < HANDSHAKE_MAX_RETRIES && !handshake_ok; ++attempt) {
        // FIX CRIT-2: Pass master_key (secret) to HandshakeClient, not nullptr.
        // The old code passed nullptr as server_pubkey, causing UB (memcpy from NULL)
        // and a MAC computed on garbage → handshake would always fail or crash.
        HandshakeClient hc(raw_kid, master_key);
        std::vector<uint8_t> init_pkt = hc.build_init();
        if (init_pkt.empty()) {
            std::cerr << "[AEGS v3] Failed to build handshake init packet\n";
            close(fd);
            return 1;
        }
        sendto(fd, init_pkt.data(), init_pkt.size(), 0, (struct sockaddr*)&s_addr, sizeof(s_addr));

        struct pollfd pfd;
        pfd.fd = fd; pfd.events = POLLIN;
        if (poll(&pfd, 1, 5000) > 0) {
            struct sockaddr_in src; socklen_t slen = sizeof(src);
            std::vector<uint8_t> resp(BUFFER_SIZE);
            ssize_t len = recvfrom(fd, resp.data(), resp.size(), 0, (struct sockaddr*)&src, &slen);
            if (len > 0 && src.sin_addr.s_addr == s_addr.sin_addr.s_addr && hc.process_resp(resp.data(), len, session_keys)) {
                assigned_ip = session_keys.assigned_ip;
                mtu = session_keys.mtu;
                handshake_ok = true;
                std::cout << "[AEGS v3] Handshake successful. IP: " << IpPool::to_string(assigned_ip) << "\n";
            }
        }
        if (!handshake_ok && attempt < HANDSHAKE_MAX_RETRIES - 1) {
            std::cerr << "[AEGS v3] Handshake attempt " << (attempt + 1) << " failed, retrying...\n";
        }
    }

    if (!handshake_ok) {
        // FIX CRIT-4: Explicit failure instead of silent PSK fallback.
        // Falling back to pre-shared symmetric keys would:
        //   1. Lose Perfect Forward Secrecy (the whole point of ECDH handshake)
        //   2. Use the same key for send and recv (breaks context separation)
        //   3. Be trivially forced by any active attacker who drops HANDSHAKE_RESP
        std::cerr << "[AEGS v3] ERROR: Handshake failed after " << HANDSHAKE_MAX_RETRIES
                  << " attempts. Aborting — PSK fallback disabled (would lose PFS).\n";
        close(fd);
        return 1;
    }

    int port_count = 10;
    int hop_interval = 30;
    const char* pc_env = std::getenv("AEGS_PORT_COUNT");
    const char* hi_env = std::getenv("AEGS_HOP_INTERVAL");
    if (pc_env) port_count = std::atoi(pc_env);
    if (hi_env) hop_interval = std::atoi(hi_env);
    PortHopper hopper((uint16_t)s_port, port_count, (uint32_t)hop_interval);
    std::cout << "[AEGS v4] Port hopping active: base=" << s_port << " count=" << port_count << " interval=" << hop_interval << "s\n";

    ResumptionToken resumption_token;
    bool has_resumption_token = false;

    std::unique_ptr<TunInterface> tun;
    if (use_tun) {
        std::string ip_cidr = IpPool::to_string(assigned_ip) + "/24";
        tun = std::make_unique<TunInterface>("aegs0", ip_cidr, mtu);
        if (tun->open()) {
            // FIX: Removed tun->add_route("0.0.0.0/0"); 
            // Routing 0.0.0.0/0 into TUN without a bypass route for the server IP causes an infinite routing loop and BSOD!
            std::cout << "[AEGS v3] TUN interface ready: aegs0 = " << ip_cidr << "\n";
        } else {
            std::cerr << "Failed to open TUN interface.\n";
            return 1;
        }
    } else {
        std::cout << "[AEGS v2 Client] Obfuscated tunnel active. SOCKS/WG proxy on 127.0.0.1:51821\n";
    }

    struct sockaddr_in wg_addr {}; bool has_wg = false;
    AntiReplayFilter replay_filter;
    uint64_t client_tx_seq = 0;

    std::vector<uint8_t> buf(BUFFER_SIZE);
    std::vector<uint8_t> pbuf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> cbuf(INTERNAL_BUF_SIZE);

    std::vector<struct pollfd> pfds;
    struct pollfd pfd_udp; pfd_udp.fd = fd; pfd_udp.events = POLLIN; pfd_udp.revents = 0;
    pfds.push_back(pfd_udp);
    if (use_tun && tun) {
        struct pollfd pfd_tun; pfd_tun.fd = tun->fd(); pfd_tun.events = POLLIN; pfd_tun.revents = 0;
        pfds.push_back(pfd_tun);
    }

    ChaffEngine chaff_engine;
    TrafficShaper shaper(5, false);
    shaper.set_semantic_enabled(true);

    KillSwitch kill_switch;
    DnsLeakProtector dns_shield;
    TransportFailureDetector transport_detector;
    BackpressureController backpressure;

    if (enable_kill_switch) {
        kill_switch.enable(s_host, (uint16_t)s_port, port_count, "aegs0");
    }
    if (enable_dns_protect) {
        dns_shield.enable("aegs0", "10.8.0.1");
    }

    while (true) {
        int poll_ret = poll(pfds.data(), pfds.size(), 100);
        if (poll_ret < 0) break;

        if (chaff_engine.should_send_chaff()) {
            static thread_local uint8_t chaff_scratch[512];
            size_t chaff_len = chaff_engine.build_chaff_packet(raw_kid, mask_key, session_keys.send_key,
                                                               client_tx_seq, chaff_scratch, sizeof(chaff_scratch));
            if (chaff_len > 0) {
                s_addr.sin_port = htons(hopper.current_port(session_keys.send_key));
                sendto(fd, chaff_scratch, chaff_len, 0, (struct sockaddr*)&s_addr, sizeof(s_addr));
            }
        }

        if (poll_ret == 0) {
            transport_detector.record_timeout();
            if (transport_detector.should_fallback_to_tcp()) {
                static double last_warn = 0;
                double now_sec = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (now_sec - last_warn > 10.0) {
                    std::cerr << "[AEGS v4 ALERT] Severe UDP timeout / blackout detected ("
                              << transport_detector.consecutive_timeouts()
                              << " timeouts). Recommending automatic TCP/TLS 1.3 fallback!\n";
                    last_warn = now_sec;
                }
            }
            continue;
        }

        // UDP fd readable
        if (pfds[0].revents & POLLIN) {
            struct sockaddr_in src; socklen_t slen = sizeof(src);
            ssize_t len = recvfrom(fd, buf.data(), buf.size(), 0, (struct sockaddr*)&src, &slen);
            uint16_t src_port = ntohs(src.sin_port);
            bool port_ok = (src_port >= (uint16_t)s_port && src_port < (uint16_t)(s_port + port_count));
            if (len > 0 && src.sin_addr.s_addr == s_addr.sin_addr.s_addr && port_ok) {
                // Check for resumption token from server
                if (len >= 97 && buf[0] == 0x03) {
                    memcpy(&resumption_token, buf.data() + 1, 96);
                    has_resumption_token = true;
                    std::cout << "[AEGS v4] Resumption token received\n";
                    continue;
                }

                if (len < 56) continue;

                const uint8_t* hdr_iv = buf.data();
                uint8_t unmasked_hdr[16];
                if (!mask_unmask_header(buf.data() + 12, 16, mask_key, hdr_iv, unmasked_hdr)) continue;

                if (std::memcmp(unmasked_hdr, raw_kid, 8) != 0) continue;
                if (std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) != 0) continue;

                uint16_t junk_len = (unmasked_hdr[8] << 8) | unmasked_hdr[9];
                size_t aead_offset = 12 + 16 + junk_len;
                if (len < aead_offset + 12 + TAG_LEN) continue;

                const uint8_t* aead_nonce = buf.data() + aead_offset;
                uint64_t rx_seq = 0;
                std::memcpy(&rx_seq, aead_nonce, sizeof(uint64_t));
                if (replay_filter.check_and_update(rx_seq)) continue;

                const uint8_t* ct = buf.data() + aead_offset + 12;
                size_t ct_len = len - (aead_offset + 12);

                size_t dlen = 0;
                // FIX Blocker 3: Authenticate outer header as AAD in AEAD Poly1305
                if (chacha20_poly1305_decrypt(ct, ct_len, session_keys.recv_key, aead_nonce, pbuf.data(), dlen, buf.data(), aead_offset)) {
                    transport_detector.record_success();
                    if (dlen < 2) continue;
                    uint16_t plen = (pbuf[0] << 8) | pbuf[1];
                    if (plen > 0 && plen <= dlen - 2) {
                        if (use_tun) {
                            tun->write_packet(pbuf.data() + 2, plen);
                        } else if (has_wg) {
                            sendto(fd, pbuf.data() + 2, plen, 0, (struct sockaddr*)&wg_addr, sizeof(wg_addr));
                        }
                    }
                }
            } else if (len > 0 && !use_tun) {
                // Packet from local WireGuard
                wg_addr = src; has_wg = true;
                
                size_t pad_len = shaper.semantic_pad((size_t)len);
                size_t frame_len = FRAME_HDR + (size_t)len + pad_len;
                if (frame_len + TAG_LEN > pbuf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)len; }
                if (frame_len + TAG_LEN > pbuf.size()) continue;

                uint16_t plen_be = htons((uint16_t)len);
                std::memcpy(pbuf.data(), &plen_be, 2);
                std::memcpy(pbuf.data() + 2, buf.data(), len);
                if (pad_len > 0) TrafficShaper::fill_random_padding(pbuf.data() + 2 + len, pad_len);

                uint8_t aead_nonce[12] = {0};
                client_tx_seq++;
                std::memcpy(aead_nonce, &client_tx_seq, sizeof(uint64_t));
                RAND_bytes(aead_nonce + 8, 4);

                uint16_t junk_len = generate_junk_len();

                uint8_t hdr_plain[16];
                std::memcpy(hdr_plain, raw_kid, 8);
                hdr_plain[8] = (junk_len >> 8) & 0xFF;
                hdr_plain[9] = junk_len & 0xFF;
                hdr_plain[10] = 0; hdr_plain[11] = 0;
                std::memcpy(hdr_plain + 12, VER_MAGIC.data(), 4);

                uint8_t hdr_iv[12]; RAND_bytes(hdr_iv, 12);
                uint8_t masked_hdr[16];
                if (!mask_unmask_header(hdr_plain, 16, mask_key, hdr_iv, masked_hdr)) continue;

                static thread_local std::vector<uint8_t> out_buf(BUFFER_SIZE);
                size_t out_len = 0;
                std::memcpy(out_buf.data(), hdr_iv, 12); out_len += 12;
                std::memcpy(out_buf.data() + out_len, masked_hdr, 16); out_len += 16;
                if (junk_len > 0) { RAND_bytes(out_buf.data() + out_len, (int)junk_len); out_len += junk_len; }
                size_t aead_offset = out_len;
                std::memcpy(out_buf.data() + out_len, aead_nonce, 12); out_len += 12;

                size_t elen = 0;
                // FIX Blocker 3: Authenticate outer header as AAD in AEAD Poly1305
                if (!chacha20_poly1305_encrypt(pbuf.data(), frame_len, session_keys.send_key, aead_nonce, cbuf.data(), elen, out_buf.data(), aead_offset)) continue;
                std::memcpy(out_buf.data() + out_len, cbuf.data(), elen); out_len += elen;

                s_addr.sin_port = htons(hopper.current_port(session_keys.send_key));
                sendto(fd, out_buf.data(), out_len, 0, (struct sockaddr*)&s_addr, sizeof(s_addr));
                chaff_engine.mark_real_packet();
            }
        }

        // TUN fd readable
        if (use_tun && tun && (pfds[1].revents & POLLIN)) {
            if (!backpressure.should_pause_tun()) {
                ssize_t len = tun->read_packet(buf.data(), buf.size());
                if (len > 0) {
                    size_t pad_len = shaper.semantic_pad((size_t)len);
                    size_t frame_len = FRAME_HDR + (size_t)len + pad_len;
                    if (frame_len + TAG_LEN > pbuf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)len; }
                    if (frame_len + TAG_LEN > pbuf.size()) continue;

                    uint16_t plen_be = htons((uint16_t)len);
                    std::memcpy(pbuf.data(), &plen_be, 2);
                    std::memcpy(pbuf.data() + 2, buf.data(), len);
                    if (pad_len > 0) TrafficShaper::fill_random_padding(pbuf.data() + 2 + len, pad_len);

                    uint8_t aead_nonce[12] = {0};
                    client_tx_seq++;
                    std::memcpy(aead_nonce, &client_tx_seq, sizeof(uint64_t));
                    RAND_bytes(aead_nonce + 8, 4);

                    uint16_t junk_len = generate_junk_len();

                    uint8_t hdr_plain[16];
                    std::memcpy(hdr_plain, raw_kid, 8);
                    hdr_plain[8] = (junk_len >> 8) & 0xFF;
                    hdr_plain[9] = junk_len & 0xFF;
                    hdr_plain[10] = 0; hdr_plain[11] = 0;
                    std::memcpy(hdr_plain + 12, VER_MAGIC.data(), 4);

                    uint8_t hdr_iv[12]; RAND_bytes(hdr_iv, 12);
                    uint8_t masked_hdr[16];
                    if (!mask_unmask_header(hdr_plain, 16, mask_key, hdr_iv, masked_hdr)) continue;

                    static thread_local std::vector<uint8_t> out_buf(BUFFER_SIZE);
                    size_t out_len = 0;
                    std::memcpy(out_buf.data(), hdr_iv, 12); out_len += 12;
                    std::memcpy(out_buf.data() + out_len, masked_hdr, 16); out_len += 16;
                    if (junk_len > 0) { RAND_bytes(out_buf.data() + out_len, (int)junk_len); out_len += junk_len; }
                    size_t aead_offset = out_len;
                    std::memcpy(out_buf.data() + out_len, aead_nonce, 12); out_len += 12;

                    size_t elen = 0;
                    // FIX Blocker 3: Authenticate outer header as AAD in AEAD Poly1305
                    if (!chacha20_poly1305_encrypt(pbuf.data(), frame_len, session_keys.send_key, aead_nonce, cbuf.data(), elen, out_buf.data(), aead_offset)) continue;
                    std::memcpy(out_buf.data() + out_len, cbuf.data(), elen); out_len += elen;

                    s_addr.sin_port = htons(hopper.current_port(session_keys.send_key));
                    ssize_t sret = sendto(fd, out_buf.data(), out_len, 0, (struct sockaddr*)&s_addr, sizeof(s_addr));
                    if (sret < 0) {
                        backpressure.record_egress_failure(errno);
                    } else {
                        backpressure.record_egress_success();
                    }
                    chaff_engine.mark_real_packet();
                }
            }
        }
    }
}
