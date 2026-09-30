"""Content-first and filename routing for network families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.network.iptables import looks_like_iptables

_FILTERLOG = re.compile(r"\bfilterlog\[", re.IGNORECASE)
_LINEPROTO = re.compile(r"%LINEPROTO-")
_SEC_ACL = re.compile(r"%SEC-6-IPACCESSLOG")
_OPENVPN = re.compile(r"\bopenvpn\[", re.IGNORECASE)
_NAMED = re.compile(r"\bnamed\[", re.IGNORECASE)
_DHCPD = re.compile(r"\bdhcpd\[", re.IGNORECASE)
_SQUID_HIER = re.compile(
    r"\bTCP_(?:MISS|DENIED|HIT|REFRESH_HIT|MEM_HIT|CLIENTREFRESH_MISS)/",
    re.IGNORECASE,
)
_NFDUMP_FLOW = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+\s+\S+\s+"
    r"\S+:\d+\s+->\s+\S+:\d+"
)
_HAPROXY = re.compile(r"\bhaproxy\[", re.IGNORECASE)
_ISE_PASS = re.compile(r"\bCISE_Passed_Authentications\b")
_ISE_FAIL = re.compile(r"\bCISE_Failed_Attempts\b")
_HOSTAPD = re.compile(r"\bhostapd\[", re.IGNORECASE)
_BGPD = re.compile(r"\bbgpd\[", re.IGNORECASE)

_BASENAME_SOURCES = {
    "pfsense.txt": "firewall",
    "pfsense.log": "firewall",
    "filterlog.log": "firewall",
    "filterlog.txt": "firewall",
    "firewall.log": "firewall",
    "ufw.log": "iptables",
    "ufw.txt": "iptables",
    "iptables.log": "iptables",
    "iptables.txt": "iptables",
    "device.txt": "network_device",
    "cisco.txt": "network_device",
    "cisco.log": "network_device",
    "vpn.txt": "vpn",
    "openvpn.log": "vpn",
    "openvpn.txt": "vpn",
    "dns.txt": "dns",
    "named.log": "dns",
    "named.txt": "dns",
    "dhcp.txt": "dhcp",
    "dhcpd.log": "dhcp",
    "dhcpd.txt": "dhcp",
    "proxy.txt": "proxy",
    "squid.log": "proxy",
    "squid.txt": "proxy",
    "netflow.txt": "netflow",
    "nfdump.txt": "netflow",
    "nfdump.log": "netflow",
    "load_balancer.txt": "load_balancer",
    "haproxy.log": "load_balancer",
    "haproxy.txt": "load_balancer",
    "nac.txt": "nac",
    "ise.log": "nac",
    "ise.txt": "nac",
    "wireless.txt": "wireless",
    "hostapd.log": "wireless",
    "hostapd.txt": "wireless",
    "bgp.txt": "bgp",
    "bgpd.log": "bgp",
    "bgpd.txt": "bgp",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("filterlog", "firewall"),
    ("pfsense", "firewall"),
    ("ufw.log", "iptables"),
    ("iptables", "iptables"),
    ("openvpn", "vpn"),
    ("named.log", "dns"),
    ("dhcpd", "dhcp"),
    ("squid", "proxy"),
    ("nfdump", "netflow"),
    ("netflow", "netflow"),
    ("haproxy", "load_balancer"),
    ("load_balancer", "load_balancer"),
    ("hostapd", "wireless"),
    ("bgpd", "bgp"),
    ("firewall.log", "firewall"),
    ("cisco", "network_device"),
    ("ise.log", "nac"),
    ("ise.txt", "nac"),
)


def detect_network_log_source_from_line(line: str) -> str | None:
    """Return a network source from strong content markers, else None."""
    if not line:
        return None
    if _FILTERLOG.search(line):
        return "firewall"
    if looks_like_iptables(line):
        return "iptables"
    if _LINEPROTO.search(line) or _SEC_ACL.search(line):
        return "network_device"
    if _OPENVPN.search(line):
        return "vpn"
    if _NAMED.search(line):
        return "dns"
    if _DHCPD.search(line):
        return "dhcp"
    if _SQUID_HIER.search(line):
        return "proxy"
    if _NFDUMP_FLOW.match(line.strip()):
        return "netflow"
    if _HAPROXY.search(line):
        return "load_balancer"
    if _ISE_PASS.search(line) or _ISE_FAIL.search(line):
        return "nac"
    if _HOSTAPD.search(line):
        return "wireless"
    if _BGPD.search(line):
        return "bgp"
    return None


def detect_network_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal firewall.txt (Windows)."""
    name = path.name.lower()
    if name == "firewall.txt":
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
