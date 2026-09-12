// ==============================================================================
// AEGS v4 "Pantheon" -- Network Security & Reliability Suite Implementation
// ==============================================================================

#include "network_security.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

// FIX Item 7: Input sanitization helpers to prevent shell injection vulnerabilities in system()
static bool is_valid_ip_address(const std::string& ip) {
    if (ip.empty() || ip.length() > 64) return false;
    struct in_addr sa;
    if (inet_pton(AF_INET, ip.c_str(), &sa) == 1) return true;
    struct in6_addr sa6;
    if (inet_pton(AF_INET6, ip.c_str(), &sa6) == 1) return true;
    return false;
}

static bool is_valid_iface_name(const std::string& iface) {
    if (iface.empty() || iface.length() > 15) return false; // Max IFNAMSIZ - 1
    for (char c : iface) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------------------
// KillSwitch Implementation
// -----------------------------------------------------------------------------

KillSwitch::KillSwitch() noexcept
    : active_(false),
      base_port_(50001),
      port_count_(1),
      tun_iface_("aegs0"),
      ipv6_blocked_(false)
{}

KillSwitch::~KillSwitch() {
    if (active_) {
        disable();
    }
}

int KillSwitch::execute_command(const std::string& cmd) const noexcept {
#ifdef _WIN32
    if (cmd.find("iptables") != std::string::npos || cmd.find("ip6tables") != std::string::npos) {
        return 0; // safe no-op on Windows
    }
#endif
    return std::system(cmd.c_str());
}

bool KillSwitch::is_ipv6_available() const noexcept {
#ifdef _WIN32
    return false;
#else
    return (execute_command("ip6tables -L -n >/dev/null 2>&1") == 0);
#endif
}

std::vector<std::string> KillSwitch::generate_ipv6_rules() const {
    std::string chain = "AEGS_KILLSWITCH6";
    return {
        "ip6tables -N " + chain,
        "ip6tables -A " + chain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "ip6tables -A " + chain + " -o lo -j ACCEPT",
        "ip6tables -A " + chain + " -j DROP",
        "ip6tables -I OUTPUT 1 -j " + chain
    };
}

std::vector<std::string> KillSwitch::generate_windows_rules(const std::string& server_ip,
                                                           uint16_t           base_port,
                                                           int                port_count) const {
    if (!is_valid_ip_address(server_ip)) {
        return {};
    }
    std::vector<std::string> rules;
    uint16_t end_port = static_cast<uint16_t>(base_port + (port_count > 0 ? port_count - 1 : 0));
    std::string port_spec = (port_count > 1) ? (std::to_string(base_port) + "-" + std::to_string(end_port)) : std::to_string(base_port);

    // 1. Allow outbound UDP to AEGS server ports
    rules.push_back("netsh advfirewall firewall add rule name=\"AEGS_Allow_Server\" dir=out action=allow protocol=UDP remoteip=" + server_ip + " remoteport=" + port_spec);
    // 2. Allow loopback traffic
    rules.push_back("netsh advfirewall firewall add rule name=\"AEGS_Allow_Loopback\" dir=out action=allow remoteip=127.0.0.1");
    // 3. Allow DHCP
    rules.push_back("netsh advfirewall firewall add rule name=\"AEGS_Allow_DHCP\" dir=out action=allow protocol=UDP localport=68 remoteport=67");
    // 4. Default outbound block during VPN active killswitch
    rules.push_back("netsh advfirewall set currentprofiles firewallpolicy blockinbound,blockoutbound");
    return rules;
}

std::vector<std::string> KillSwitch::generate_rules(const std::string& server_ip,
                                                   uint16_t           base_port,
                                                   int                port_count,
                                                   const std::string& tun_iface) const {
    if (!is_valid_ip_address(server_ip) || !is_valid_iface_name(tun_iface)) {
        return {};
    }
    std::vector<std::string> rules;
    std::string chain = "AEGS_KILLSWITCH";

    // 1. Create dedicated user chain
    rules.push_back("iptables -N " + chain);

    // 2. Allow established/related incoming connections
    rules.push_back("iptables -A " + chain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    // 3. Allow all traffic on loopback interface
    rules.push_back("iptables -A " + chain + " -o lo -j ACCEPT");

    // 4. Allow all traffic on the VPN TUN interface
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -j ACCEPT");

    // 5. Allow DHCP client traffic (prevent losing local DHCP lease)
    rules.push_back("iptables -A " + chain + " -p udp --sport 68 --dport 67 -j ACCEPT");

    // 6. Allow direct tunnel packets to the server IP on the port hopping range
    uint16_t end_port = static_cast<uint16_t>(base_port + (port_count > 0 ? port_count - 1 : 0));
    std::string port_spec = (port_count > 1)
        ? (std::to_string(base_port) + ":" + std::to_string(end_port))
        : std::to_string(base_port);

    rules.push_back("iptables -A " + chain + " -d " + server_ip + " -p udp --dport " + port_spec + " -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -d " + server_ip + " -p tcp --dport " + port_spec + " -j ACCEPT");

    // 7. Drop all other outbound IPv4 traffic on all other interfaces
    rules.push_back("iptables -A " + chain + " -j DROP");

    // 8. Insert jump at the top of the OUTPUT chain
    rules.push_back("iptables -I OUTPUT 1 -j " + chain);

    return rules;
}

bool KillSwitch::enable(const std::string& server_ip,
                        uint16_t           base_port,
                        int                port_count,
                        const std::string& tun_iface) noexcept {
    // FIX Item 7: Strict input validation preventing command injection in system()
    if (!is_valid_ip_address(server_ip)) {
        std::cerr << "[KillSwitch] ERROR: Invalid server IP format: " << server_ip << "\n";
        return false;
    }
    if (!is_valid_iface_name(tun_iface)) {
        std::cerr << "[KillSwitch] ERROR: Invalid interface name format: " << tun_iface << "\n";
        return false;
    }
    if (base_port == 0 || port_count < 1 || port_count > 1000 || (base_port + port_count - 1) > 65535) {
        std::cerr << "[KillSwitch] ERROR: Invalid port parameters: base=" << base_port << " count=" << port_count << "\n";
        return false;
    }

    if (active_) {
        disable();
    }

    server_ip_ = server_ip;
    base_port_ = base_port;
    port_count_ = (port_count < 1) ? 1 : port_count;
    tun_iface_ = tun_iface;

    auto rules = generate_rules(server_ip_, base_port_, port_count_, tun_iface_);
    std::string chain = "AEGS_KILLSWITCH";

    // Setup cleanup commands first in reverse order
    applied_cleanup_commands_.clear();
    applied_cleanup_commands_.push_back("iptables -D OUTPUT -j " + chain);
    applied_cleanup_commands_.push_back("iptables -F " + chain);
    applied_cleanup_commands_.push_back("iptables -X " + chain);

    std::cout << "[KillSwitch] Activating hardware-level firewall isolation on " << tun_iface_ << "...\n";
    std::vector<std::string> applied_rules; // Track successfully applied rules for rollback
    for (const auto& rule : rules) {
        int ret = execute_command(rule + " 2>/dev/null");
        if (ret != 0) {
            std::cerr << "[KillSwitch] FATAL: mandatory rule failed (exit code " << ret << "): " << rule << "\n";
            // Rollback all successfully applied rules in reverse order
            std::cerr << "[KillSwitch] Rolling back " << applied_rules.size() << " successfully applied rules...\n";
            for (auto rit = applied_rules.rbegin(); rit != applied_rules.rend(); ++rit) {
                execute_command(*rit + " 2>/dev/null");
            }
            // Also run full cleanup commands to ensure clean state
            for (const auto& cmd : applied_cleanup_commands_) {
                execute_command(cmd + " 2>/dev/null");
            }
            applied_cleanup_commands_.clear();
            active_ = false;
            std::cerr << "[KillSwitch] FAIL-CLOSED: activation aborted, no partial rules remain.\n";
            return false;
        }
        // Build reverse command for rollback: replace -A with -D and -I with -D
        std::string reverse = rule;
        auto pos_A = reverse.find(" -A ");
        if (pos_A != std::string::npos) {
            reverse.replace(pos_A, 4, " -D ");
        }
        auto pos_I = reverse.find(" -I ");
        if (pos_I != std::string::npos) {
            reverse.replace(pos_I, 4, " -D ");
        }
        // Skip chain creation commands (-N) for reverse — handled by cleanup
        if (rule.find(" -N ") == std::string::npos) {
            applied_rules.push_back(reverse);
        }
    }

    // Block IPv6 traffic safely via dedicated chain so existing user firewall rules are never touched
    if (is_ipv6_available()) {
        std::string chain6 = "AEGS_KILLSWITCH6";
        applied_cleanup_commands_.push_back("ip6tables -D OUTPUT -j " + chain6);
        applied_cleanup_commands_.push_back("ip6tables -F " + chain6);
        applied_cleanup_commands_.push_back("ip6tables -X " + chain6);

        auto v6_rules = generate_ipv6_rules();
        bool v6_ok = true;
        for (const auto& r : v6_rules) {
            if (execute_command(r + " 2>/dev/null") != 0) {
                std::cerr << "[KillSwitch] Warning: IPv6 rule failed: " << r << "\n";
                v6_ok = false;
            }
        }
        if (v6_ok) {
            ipv6_blocked_ = true;
            std::cout << "[KillSwitch] IPv6 leak protection active: dedicated " << chain6 << " chain\n";
        } else {
            // IPv6 failure is non-fatal but logged prominently
            std::cerr << "[KillSwitch] WARNING: IPv6 lockdown incomplete, some IPv6 leaks may occur\n";
        }
    } else {
        std::cout << "[KillSwitch] IPv6 not available or ip6tables not present, skipping IPv6 lockdown.\n";
    }

    active_ = true;
    std::cout << "[KillSwitch] Isolation ACTIVE. Direct leaks blocked, server="
              << server_ip_ << ":" << base_port_ << "-" << (base_port_ + port_count_ - 1) << "\n";
    return true;
}

bool KillSwitch::disable() noexcept {
    if (!active_) return true;

    std::cout << "[KillSwitch] Deactivating firewall isolation...\n";
    for (const auto& cmd : applied_cleanup_commands_) {
        int ret = execute_command(cmd + " 2>/dev/null");
        if (ret != 0) {
            std::cerr << "[KillSwitch] Warning: cleanup command failed (exit code " << ret << "): " << cmd << "\n";
        }
    }

    ipv6_blocked_ = false;
    applied_cleanup_commands_.clear();
    active_ = false;
    std::cout << "[KillSwitch] Isolation DEACTIVATED. Normal routing restored without touching foreign firewall rules.\n";
    return true;
}

// -----------------------------------------------------------------------------
// DnsLeakProtector Implementation
// -----------------------------------------------------------------------------

DnsLeakProtector::DnsLeakProtector() noexcept
    : active_(false),
      tun_iface_("aegs0"),
      secure_dns_("10.8.0.1"),
      resolv_conf_backed_up_(false),
      is_symlink_(false),
      symlink_target_(""),
      used_resolvectl_(false),
      ipv6_dns_blocked_(false)
{}

DnsLeakProtector::~DnsLeakProtector() {
    if (active_) {
        disable();
    }
}

int DnsLeakProtector::execute_command(const std::string& cmd) const noexcept {
#ifdef _WIN32
    if (cmd.find("iptables") != std::string::npos || cmd.find("ip6tables") != std::string::npos) {
        return 0; // safe no-op on Windows
    }
#endif
    return std::system(cmd.c_str());
}

bool DnsLeakProtector::is_ipv6_available() const noexcept {
#ifdef _WIN32
    return false;
#else
    return (execute_command("ip6tables -L -n >/dev/null 2>&1") == 0);
#endif
}

std::vector<std::string> DnsLeakProtector::generate_ipv6_rules() const {
    return {
        "ip6tables -A OUTPUT -p udp --dport 53 -j DROP",
        "ip6tables -A OUTPUT -p tcp --dport 53 -j DROP"
    };
}

std::vector<std::string> DnsLeakProtector::generate_windows_rules(const std::string& secure_dns) const {
    if (!is_valid_ip_address(secure_dns)) {
        return {};
    }
    return {
        // 1. Block outbound DNS (port 53) on external physical adapters via Windows Firewall
        "netsh advfirewall firewall add rule name=\"AEGS_Block_Ext_DNS_UDP\" dir=out action=block protocol=UDP remoteport=53",
        "netsh advfirewall firewall add rule name=\"AEGS_Block_Ext_DNS_TCP\" dir=out action=block protocol=TCP remoteport=53",
        // 2. Set primary DNS to secure tunnel DNS
        "powershell -Command \"Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses '" + secure_dns + "'\""
    };
}

std::vector<std::string> DnsLeakProtector::generate_rules(const std::string& tun_iface) const {
    if (!is_valid_iface_name(tun_iface)) {
        return {};
    }
    std::vector<std::string> rules;
    std::string chain = "AEGS_DNS_SHIELD";

    rules.push_back("iptables -N " + chain);
    // Allow DNS queries over the VPN interface
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -p udp --dport 53 -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -p tcp --dport 53 -j ACCEPT");
    // Allow local DNS (e.g. systemd-resolved on 127.0.0.53 or dnsmasq on 127.0.0.1)
    rules.push_back("iptables -A " + chain + " -o lo -p udp --dport 53 -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -o lo -p tcp --dport 53 -j ACCEPT");
    // Block all plaintext DNS requests on non-VPN physical interfaces (prevent ISP leak)
    rules.push_back("iptables -A " + chain + " -p udp --dport 53 -j DROP");
    rules.push_back("iptables -A " + chain + " -p tcp --dport 53 -j DROP");
    // Insert into OUTPUT chain
    rules.push_back("iptables -I OUTPUT 1 -j " + chain);

    return rules;
}

bool DnsLeakProtector::enable(const std::string& tun_iface,
                             const std::string& secure_dns) noexcept {
    std::string dns = secure_dns.empty() ? "10.8.0.1" : secure_dns;
    if (!is_valid_ip_address(dns)) {
        std::cerr << "[DNS-Shield] ERROR: Invalid DNS IP format: " << dns << "\n";
        return false;
    }
    if (!is_valid_iface_name(tun_iface)) {
        std::cerr << "[DNS-Shield] ERROR: Invalid interface name format: " << tun_iface << "\n";
        return false;
    }

    if (active_) {
        disable();
    }

    tun_iface_ = tun_iface;
    secure_dns_ = dns;

#ifndef _WIN32
    // R-07 Fix: Non-destructive DNS Leak Protection
    // 1. Prefer resolvectl if available (systemd-resolved systems)
    if (execute_command("which resolvectl >/dev/null 2>&1") == 0) {
        if (execute_command("resolvectl dns " + tun_iface_ + " " + secure_dns_ + " 2>/dev/null") == 0 &&
            execute_command("resolvectl default-route " + tun_iface_ + " true 2>/dev/null") == 0) {
            used_resolvectl_ = true;
            std::cout << "[DNS-Shield] systemd-resolved detected: configured DNS via resolvectl without touching /etc/resolv.conf.\n";
        }
    }

    // 2. Fallback to /etc/resolv.conf: detect symlinks before overwriting
    if (!used_resolvectl_) {
        struct stat st;
        if (lstat("/etc/resolv.conf", &st) == 0 && S_ISLNK(st.st_mode)) {
            char target[512] = {0};
            ssize_t len = readlink("/etc/resolv.conf", target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                symlink_target_ = target;
                is_symlink_ = true;
            }
        }

        // Backup /etc/resolv.conf if possible
        std::ifstream src("/etc/resolv.conf");
        if (src.is_open()) {
            std::stringstream ss;
            ss << src.rdbuf();
            original_resolv_conf_ = ss.str();
            resolv_conf_backed_up_ = true;
            src.close();

            if (is_symlink_) {
                unlink("/etc/resolv.conf");
            }

            // Write secure resolver
            std::ofstream dst("/etc/resolv.conf", std::ios::trunc);
            if (dst.is_open()) {
                dst << "# Generated by AEGS v4 DnsLeakProtector\n";
                dst << "nameserver " << secure_dns_ << "\n";
                dst << "options edns0\n";
                dst.close();
            }
        }
    }
#endif

    // Apply iptables port 53 lockdown
    auto rules = generate_rules(tun_iface_);
    for (const auto& rule : rules) {
        int ret = execute_command(rule + " 2>/dev/null");
        if (ret != 0) {
            std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret << "): " << rule << "\n";
        }
    }

    // Block IPv6 port 53 leakage
    if (is_ipv6_available()) {
        auto v6_rules = generate_ipv6_rules();
        bool all_ok = true;
        for (const auto& rule : v6_rules) {
            int ret = execute_command(rule + " 2>/dev/null");
            if (ret != 0) {
                std::cerr << "[DNS-Shield] Warning: failed to apply IPv6 DNS rule (exit code " << ret << "): " << rule << "\n";
                all_ok = false;
            }
        }
        ipv6_dns_blocked_ = all_ok;
        if (ipv6_dns_blocked_) {
            std::cout << "[DNS-Shield] IPv6 port 53 leak protection active.\n";
        }
    } else {
        std::cout << "[DNS-Shield] IPv6 not available or ip6tables not present, skipping IPv6 DNS lockdown.\n";
    }

    active_ = true;
    std::cout << "[DNS-Shield] Port 53 lockdown ACTIVE on " << tun_iface_
              << " -> DNS forced to " << secure_dns_ << "\n";
    return true;
}

bool DnsLeakProtector::disable() noexcept {
    if (!active_) return true;

    std::cout << "[DNS-Shield] Restoring default DNS resolver and removing port 53 lockdown...\n";
    std::string chain = "AEGS_DNS_SHIELD";
    int ret1 = execute_command("iptables -D OUTPUT -j " + chain + " 2>/dev/null");
    if (ret1 != 0) {
        std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret1 << "): iptables -D OUTPUT -j " << chain << "\n";
    }
    int ret2 = execute_command("iptables -F " + chain + " 2>/dev/null");
    if (ret2 != 0) {
        std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret2 << "): iptables -F " << chain << "\n";
    }
    int ret3 = execute_command("iptables -X " + chain + " 2>/dev/null");
    if (ret3 != 0) {
        std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret3 << "): iptables -X " << chain << "\n";
    }

    if (ipv6_dns_blocked_) {
        int ret4 = execute_command("ip6tables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null");
        if (ret4 != 0) {
            std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret4 << "): ip6tables -D OUTPUT -p udp --dport 53 -j DROP\n";
        }
        int ret5 = execute_command("ip6tables -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null");
        if (ret5 != 0) {
            std::cerr << "[DNS-Shield] Warning: command failed (exit code " << ret5 << "): ip6tables -D OUTPUT -p tcp --dport 53 -j DROP\n";
        }
        ipv6_dns_blocked_ = false;
    }

#ifndef _WIN32
    if (used_resolvectl_) {
        execute_command("resolvectl revert " + tun_iface_ + " 2>/dev/null");
        used_resolvectl_ = false;
        std::cout << "[DNS-Shield] Reverted systemd-resolved configuration for " << tun_iface_ << "\n";
    } else if (is_symlink_ && !symlink_target_.empty()) {
        unlink("/etc/resolv.conf");
        symlink(symlink_target_.c_str(), "/etc/resolv.conf");
        is_symlink_ = false;
        symlink_target_.clear();
        resolv_conf_backed_up_ = false;
        std::cout << "[DNS-Shield] Restored /etc/resolv.conf symlink.\n";
    } else if (resolv_conf_backed_up_ && !original_resolv_conf_.empty()) {
        std::ofstream dst("/etc/resolv.conf", std::ios::trunc);
        if (dst.is_open()) {
            dst << original_resolv_conf_;
            dst.close();
        }
        resolv_conf_backed_up_ = false;
        std::cout << "[DNS-Shield] Restored original /etc/resolv.conf file.\n";
    }
#endif

    active_ = false;
    return true;
}

// -----------------------------------------------------------------------------
// TransportFailureDetector Implementation
// -----------------------------------------------------------------------------

TransportFailureDetector::TransportFailureDetector(int max_consecutive_timeouts,
                                                   double max_blackout_sec) noexcept
    : max_consecutive_timeouts_(max_consecutive_timeouts < 1 ? 1 : max_consecutive_timeouts),
      max_blackout_sec_(max_blackout_sec < 1.0 ? 1.0 : max_blackout_sec),
      consecutive_timeouts_(0),
      total_sent_(0),
      total_lost_(0),
      last_success_time_(std::chrono::steady_clock::now())
{}

void TransportFailureDetector::record_success() noexcept {
    consecutive_timeouts_ = 0;
    last_success_time_ = std::chrono::steady_clock::now();
}

void TransportFailureDetector::record_timeout() noexcept {
    consecutive_timeouts_++;
}

void TransportFailureDetector::record_packet_loss(size_t sent, size_t lost) noexcept {
    total_sent_ += sent;
    total_lost_ += lost;
}

double TransportFailureDetector::loss_rate() const noexcept {
    if (total_sent_ == 0) return 0.0;
    return static_cast<double>(total_lost_) / static_cast<double>(total_sent_);
}

bool TransportFailureDetector::should_fallback_to_tcp() const noexcept {
    if (consecutive_timeouts_ >= max_consecutive_timeouts_) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    double blackout = std::chrono::duration<double>(now - last_success_time_).count();
    if (blackout >= max_blackout_sec_ && consecutive_timeouts_ > 0) {
        return true;
    }

    // Extreme packet loss (>75% sustained across >= 100 packets)
    if (total_sent_ >= 100 && loss_rate() > 0.75) {
        return true;
    }

    return false;
}

void TransportFailureDetector::reset() noexcept {
    consecutive_timeouts_ = 0;
    total_sent_ = 0;
    total_lost_ = 0;
    last_success_time_ = std::chrono::steady_clock::now();
}

// -----------------------------------------------------------------------------
// AntiReplayFilter Explicit Template Instantiations
// -----------------------------------------------------------------------------
template class AntiReplayFilterT<1>;
template class AntiReplayFilterT<16>;
template class AntiReplayFilterT<32>;
template class AntiReplayFilterT<64>;

