#include "tun_interface.h"

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>

TunInterface::TunInterface(const std::string& iface_name, const std::string& ip_cidr, int mtu)
    : tun_fd_(-1), iface_name_(iface_name), ip_cidr_(ip_cidr), mtu_(mtu) {
    
    size_t slash_pos = ip_cidr.find('/');
    if (slash_pos != std::string::npos) {
        ip_ = ip_cidr.substr(0, slash_pos);
    } else {
        ip_ = ip_cidr;
    }
}

TunInterface::~TunInterface() {
    close();
}

bool TunInterface::open() {
    if ((tun_fd_ = ::open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, iface_name_.c_str(), IFNAMSIZ - 1);

    if (ioctl(tun_fd_, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close();
        return false;
    }

    // Set non-blocking
    int flags = fcntl(tun_fd_, F_GETFL, 0);
    if (flags == -1 || fcntl(tun_fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl O_NONBLOCK");
        close();
        return false;
    }

    if (!configure_interface()) {
        close();
        return false;
    }

    return true;
}

void TunInterface::close() {
    if (tun_fd_ >= 0) {
        ::close(tun_fd_);
        tun_fd_ = -1;
    }
}

int TunInterface::fd() const {
    return tun_fd_;
}

ssize_t TunInterface::read_packet(uint8_t* buf, size_t len) {
    if (tun_fd_ < 0) return -1;
    return ::read(tun_fd_, buf, len);
}

ssize_t TunInterface::write_packet(const uint8_t* buf, size_t len) {
    if (tun_fd_ < 0) return -1;
    return ::write(tun_fd_, buf, len);
}

static bool is_safe_identifier(const std::string& str) {
    if (str.empty() || str.length() > 64) return false;
    for (char c : str) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.' && c != '/') {
            return false;
        }
    }
    return true;
}

bool TunInterface::add_route(const std::string& cidr) {
    if (!is_safe_identifier(cidr) || !is_safe_identifier(iface_name_)) {
        std::cerr << "[TunInterface] Invalid CIDR or interface name\n";
        return false;
    }
    std::string cmd = "ip route add " + cidr + " dev " + iface_name_;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "Command failed: " << cmd << "\n";
        return false;
    }
    return true;
}

bool TunInterface::set_default_route() {
    if (!is_safe_identifier(iface_name_)) {
        std::cerr << "[TunInterface] Invalid interface name\n";
        return false;
    }
    std::string cmd1 = "ip route add 0.0.0.0/1 dev " + iface_name_;
    std::string cmd2 = "ip route add 128.0.0.0/1 dev " + iface_name_;
    int ret1 = system(cmd1.c_str());
    int ret2 = system(cmd2.c_str());
    if (ret1 != 0 || ret2 != 0) {
        std::cerr << "Failed to set default routes\n";
        return false;
    }
    return true;
}

std::string TunInterface::ip() const {
    return ip_;
}

void TunInterface::parse_cidr(const std::string& cidr, std::string& ip, std::string& netmask) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        ip = cidr;
        netmask = "255.255.255.255";
        return;
    }
    
    ip = cidr.substr(0, slash_pos);
    int prefix = 32;
    try {
        prefix = std::stoi(cidr.substr(slash_pos + 1));
    } catch (...) {
        prefix = 32;
    }
    if (prefix < 0) prefix = 0;
    if (prefix > 32) prefix = 32;
    
    // FIX Audit: Avoid undefined behavior (0xFFFFFFFF << 32) when prefix is 0
    uint32_t mask = (prefix == 0) ? 0u : (prefix == 32) ? 0xFFFFFFFFu : (~0u << (32 - prefix));
    struct in_addr addr;
    addr.s_addr = htonl(mask);
    netmask = inet_ntoa(addr);
}

bool TunInterface::configure_interface() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket AF_INET");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name_.c_str(), IFNAMSIZ - 1);

    std::string ip, netmask;
    parse_cidr(ip_cidr_, ip, netmask);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr->sin_addr);

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        ::close(sock);
        return false;
    }

    addr = (struct sockaddr_in*)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, netmask.c_str(), &addr->sin_addr);

    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        ::close(sock);
        return false;
    }

    ifr.ifr_mtu = mtu_;
    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl SIOCSIFMTU");
        ::close(sock);
        return false;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        ::close(sock);
        return false;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        ::close(sock);
        return false;
    }

    ::close(sock);
    return true;
}
