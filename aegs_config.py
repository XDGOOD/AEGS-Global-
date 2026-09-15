# -*- coding: utf-8 -*-
"""
==============================================================================
AEGS Universal Configuration & Profile Manager (Amnezia-Style Architecture)
==============================================================================
Supports:
1. "Our Service" (Official AEGS High-Speed Stealth Network)
2. "Custom VPS / Servers" (User-provided VPS endpoints)
3. Cross-platform export: Windows, Linux, Android, iOS (aegs:// URI & WG-compatible configs)
4. Split-Tunneling & Domestic Service Bypass (Banks, Gosuslugi, Local Services)
"""

import os
import json
import base64
import urllib.parse
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

DEFAULT_CONFIG_PATH = os.path.expanduser(r"~/.aegs_profiles.json")

DEFAULT_BYPASS_DOMAINS = [
    "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru",
    "gosuslugi.ru", "ya.ru", "yandex.ru", "vk.com", "kinopoisk.ru",
    "ozon.ru", "wildberries.ru", "avito.ru", "nalog.gov.ru", "mos.ru"
]

@dataclass
class AegsProfile:
    name: str
    server_ip: str
    port: int = 50001
    port_count: int = 8
    token: str = "default_token_aegs_v6"
    key_id: str = "aegs_client_01"
    mimicry: bool = True               # RFC 9000 QUIC Camouflage
    split_tunnel: bool = True          # Smart Split-Tunneling for local services
    mode: str = "service"              # "service" (Our Cloud) or "custom" (User VPS)
    is_active: bool = False
    assigned_ip: str = "10.8.0.2"
    dns: str = "1.1.1.1, 8.8.8.8"
    bypass_domains: str = ", ".join(DEFAULT_BYPASS_DOMAINS)
    notes: str = ""

    def to_uri(self) -> str:
        """Generates an aegs:// URI string for 1-click import or QR codes."""
        data = {
            "v": 6,
            "name": self.name,
            "ip": self.server_ip,
            "p": self.port,
            "pc": self.port_count,
            "t": self.token,
            "k": self.key_id,
            "m": 1 if self.mimicry else 0,
            "st": 1 if self.split_tunnel else 0,
            "dns": self.dns
        }
        encoded = base64.urlsafe_b64encode(json.dumps(data).encode("utf-8")).decode("ascii").rstrip("=")
        return f"aegs://{encoded}"

    @classmethod
    def from_uri(cls, uri: str) -> "AegsProfile":
        """Parses an aegs:// URI string."""
        if not uri.startswith("aegs://"):
            raise ValueError("Invalid AEGS URI format (must start with aegs://)")
        raw = uri[7:]
        padded = raw + "=" * (-len(raw) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return cls(
            name=data.get("name", "Imported Server"),
            server_ip=data["ip"],
            port=data.get("p", 50001),
            port_count=data.get("pc", 8),
            token=data.get("t", ""),
            key_id=data.get("k", ""),
            mimicry=bool(data.get("m", 1)),
            split_tunnel=bool(data.get("st", 1)),
            mode="custom"
        )

    def to_mobile_conf(self) -> str:
        """Generates a client configuration profile compatible with mobile apps."""
        return f"""# AEGS v6 High-Speed Stealth Protocol Profile
# Compatible with AEGS Mobile & Amnezia Client
[Interface]
Name = {self.name}
AssignedIP = {self.assigned_ip}/24
DNS = {self.dns}
Mimicry = {"RFC9000_QUIC_INITIAL" if self.mimicry else "OFF"}
SplitTunneling = {"ENABLED" if self.split_tunnel else "DISABLED"}
BypassList = {self.bypass_domains}

[Server]
Endpoint = {self.server_ip}:{self.port}
PortRange = {self.port} - {self.port + self.port_count - 1}
Token = {self.token}
KeyID = {self.key_id}
Encryption = ChaCha20-Poly1305
AntiDDoS = StatelessCookies
"""

class ProfileStorage:
    def __init__(self, path: str = DEFAULT_CONFIG_PATH):
        self.path = path
        self.profiles: List[AegsProfile] = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    self.profiles = [AegsProfile(**p) for p in raw.get("profiles", [])]
                    return
            except Exception:
                pass
        # Default starter profiles
        self.profiles = [
            AegsProfile(
                name="AEGS Cloud — Быстрый сервер (Анти-Блокировка)",
                server_ip="185.196.8.10",
                port=50001,
                port_count=8,
                token="aegs_secure_token_titan_v6",
                key_id="user_key_01",
                mimicry=True,
                split_tunnel=True,
                mode="service",
                is_active=True,
                notes="Официальный высокоскоростной сервер AEGS с обходом ТСПУ/DPI"
            ),
            AegsProfile(
                name="Мой собственный VPS (Amnezia-style)",
                server_ip="198.51.100.1",
                port=50001,
                port_count=8,
                token="my_vps_secret_token",
                key_id="my_vps_key",
                mimicry=True,
                split_tunnel=True,
                mode="custom",
                is_active=False,
                notes="Пользовательский сервер (введите IP и токен своего VPS)"
            )
        ]
        self.save()

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"profiles": [asdict(p) for p in self.profiles]}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("Failed to save profiles:", e)

    def add_profile(self, profile: AegsProfile):
        self.profiles.append(profile)
        self.save()

    def delete_profile(self, idx: int):
        if 0 <= idx < len(self.profiles):
            del self.profiles[idx]
            self.save()

    def get_active(self) -> Optional[AegsProfile]:
        for p in self.profiles:
            if p.is_active:
                return p
        return self.profiles[0] if self.profiles else None

    def set_active(self, idx: int):
        for i, p in enumerate(self.profiles):
            p.is_active = (i == idx)
        self.save()
