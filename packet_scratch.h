#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Zero-Allocation Scratchpad & TX Batching
// Pre-allocated TLS buffers eliminating heap churn and enabling sendmmsg() batching
// ==============================================================================
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>

struct PacketScratch {
    static constexpr size_t MAX_PKT_SIZE = 65535;
    static constexpr size_t MAX_BATCH    = 64;

    // Aligned scratchpad arenas
    alignas(64) uint8_t rx_buf[MAX_PKT_SIZE];
    alignas(64) uint8_t dec_buf[MAX_PKT_SIZE];
    alignas(64) uint8_t enc_buf[MAX_PKT_SIZE];
    alignas(64) uint8_t tx_buf[MAX_PKT_SIZE];

    // Batch TX slot
    struct TxSlot {
        alignas(16) uint8_t data[2048];
        size_t len = 0;
        struct sockaddr_in addr{};
        int fd = -1;
        struct iovec iov;
        struct mmsghdr msg;
    };

    std::array<TxSlot, MAX_BATCH> tx_slots;
    size_t tx_count = 0;

    void reset_tx() noexcept {
        tx_count = 0;
    }

    void queue_tx(int fd, const struct sockaddr_in& addr, const uint8_t* payload, size_t len) noexcept {
        if (tx_count >= MAX_BATCH || len > 2048) return;
        auto& slot = tx_slots[tx_count];
        slot.fd = fd;
        slot.addr = addr;
        slot.len = len;
        std::memcpy(slot.data, payload, len);
        slot.iov.iov_base = slot.data;
        slot.iov.iov_len = len;

        std::memset(&slot.msg, 0, sizeof(slot.msg));
        slot.msg.msg_hdr.msg_name = &slot.addr;
        slot.msg.msg_hdr.msg_namelen = sizeof(slot.addr);
        slot.msg.msg_hdr.msg_iov = &slot.iov;
        slot.msg.msg_hdr.msg_iovlen = 1;

        tx_count++;
    }

    // Flush queued packets using sendmmsg (Linux) or sendto
    // Retains unsent packet slots on partial sendmmsg or socket congestion (EAGAIN/ENOBUFS)
    size_t flush_tx() noexcept {
        if (tx_count == 0) return 0;
        size_t sent_total = 0;
        size_t cur = 0;

#ifdef __linux__
        while (cur < tx_count) {
            int cur_fd = tx_slots[cur].fd;
            size_t end = cur + 1;
            while (end < tx_count && tx_slots[end].fd == cur_fd) {
                end++;
            }
            unsigned int batch_len = static_cast<unsigned int>(end - cur);
            std::array<struct mmsghdr, MAX_BATCH> batch_msgs;
            for (size_t i = 0; i < batch_len; ++i) {
                batch_msgs[i] = tx_slots[cur + i].msg;
            }
            int sent = sendmmsg(cur_fd, batch_msgs.data(), batch_len, MSG_DONTWAIT);
            if (sent > 0) {
                sent_total += static_cast<size_t>(sent);
                cur += static_cast<size_t>(sent);
                if (static_cast<size_t>(sent) < batch_len) {
                    // Partial send due to full socket buffer; retain unsent suffix
                    break;
                }
            } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                // Socket buffer congested; stop and retain unsent packets
                break;
            } else {
                // Hard socket error on cur_fd; drop packet to avoid infinite stall
                cur++;
            }
        }
#else
        while (cur < tx_count) {
            ssize_t s = sendto(tx_slots[cur].fd, tx_slots[cur].data, tx_slots[cur].len, 0,
                               (struct sockaddr*)&tx_slots[cur].addr, sizeof(tx_slots[cur].addr));
            if (s >= 0) {
                sent_total++;
                cur++;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                break;
            } else {
                cur++;
            }
        }
#endif

        // Retain unsent pending packets [cur .. tx_count-1] for next flush
        if (cur < tx_count) {
            size_t unsent = tx_count - cur;
            if (cur > 0) {
                for (size_t i = 0; i < unsent; ++i) {
                    auto& dst = tx_slots[i];
                    const auto& src = tx_slots[cur + i];
                    dst.fd = src.fd;
                    dst.addr = src.addr;
                    dst.len = src.len;
                    std::memcpy(dst.data, src.data, src.len);
                    dst.iov.iov_base = dst.data;
                    dst.iov.iov_len = dst.len;
                    std::memset(&dst.msg, 0, sizeof(dst.msg));
                    dst.msg.msg_hdr.msg_name = &dst.addr;
                    dst.msg.msg_hdr.msg_namelen = sizeof(dst.addr);
                    dst.msg.msg_hdr.msg_iov = &dst.iov;
                    dst.msg.msg_hdr.msg_iovlen = 1;
                }
            }
            tx_count = unsent;
        } else {
            tx_count = 0;
        }

        return sent_total;
    }
};

inline PacketScratch& get_packet_scratch() noexcept {
    thread_local PacketScratch scratch;
    return scratch;
}
