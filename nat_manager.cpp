#include "nat_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <cstdlib>

NatManager::NatManager(const std::string& tun_iface,
                       const std::string& out_iface,
                       const std::string& subnet)
    : tun_iface_(tun_iface), out_iface_(out_iface), subnet_(subnet) {}

static bool is_safe_shell_param(const std::string& str) {
    if (str.empty() || str.length() > 64) return false;
    for (char c : str) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.' && c != '/') {
            return false;
        }
    }
    return true;
}

int NatManager::run_cmd(const std::string& cmd) {
    std::cout << "Executing: " << cmd << std::endl;
    return std::system(cmd.c_str());
}

bool NatManager::setup() {
    if (!is_safe_shell_param(tun_iface_) || !is_safe_shell_param(out_iface_) || !is_safe_shell_param(subnet_)) {
        std::cerr << "[NatManager] ERROR: Dangerous characters detected in interface or subnet name\n";
        return false;
    }

    // 1. Enable IPv4 forwarding
    std::ofstream ip_forward("/proc/sys/net/ipv4/ip_forward");
    if (ip_forward.is_open()) {
        ip_forward << "1\n";
        ip_forward.close();
    } else {
        std::cerr << "Warning: Could not open /proc/sys/net/ipv4/ip_forward. (Might not be running on Linux or missing root)" << std::endl;
    }

    // 2 & 3. POSTROUTING MASQUERADE
    std::string rule_masq = "-t nat POSTROUTING -s " + subnet_ + " -o " + out_iface_ + " -j MASQUERADE";
    if (run_cmd("iptables -C " + rule_masq + " 2>/dev/null") != 0) {
        run_cmd("iptables -t nat -A POSTROUTING -s " + subnet_ + " -o " + out_iface_ + " -j MASQUERADE");
    }

    // 4. FORWARD ACCEPT in
    std::string rule_fwd_in = "FORWARD -i " + tun_iface_ + " -j ACCEPT";
    if (run_cmd("iptables -C " + rule_fwd_in + " 2>/dev/null") != 0) {
        run_cmd("iptables -A " + rule_fwd_in);
    }

    // 5. FORWARD ACCEPT out related,established
    std::string rule_fwd_out = "FORWARD -o " + tun_iface_ + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    if (run_cmd("iptables -C " + rule_fwd_out + " 2>/dev/null") != 0) {
        run_cmd("iptables -A " + rule_fwd_out);
    }

    active_ = true;
    return true;
}

void NatManager::teardown() {
    if (!active_) return;

    std::string rule_masq = "-t nat -D POSTROUTING -s " + subnet_ + " -o " + out_iface_ + " -j MASQUERADE";
    run_cmd("iptables " + rule_masq);

    std::string rule_fwd_in = "-D FORWARD -i " + tun_iface_ + " -j ACCEPT";
    run_cmd("iptables " + rule_fwd_in);

    std::string rule_fwd_out = "-D FORWARD -o " + tun_iface_ + " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    run_cmd("iptables " + rule_fwd_out);

    active_ = false;
}

std::string NatManager::detect_outbound_iface() {
    std::ifstream route_file("/proc/net/route");
    if (!route_file.is_open()) {
        return "eth0"; // fallback
    }

    std::string line;
    // Skip header
    std::getline(route_file, line);

    while (std::getline(route_file, line)) {
        std::istringstream iss(line);
        std::string iface;
        std::string dest;
        if (iss >> iface >> dest) {
            if (dest == "00000000") {
                return iface;
            }
        }
    }
    return "eth0"; // fallback
}
