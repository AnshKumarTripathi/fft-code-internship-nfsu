"""Network infrastructure family extractors (Phase 23)."""

from src.ingestion.extractors.network.bgp import extract_bgp
from src.ingestion.extractors.network.device import extract_network_device
from src.ingestion.extractors.network.dhcp import extract_dhcp
from src.ingestion.extractors.network.dns import extract_dns
from src.ingestion.extractors.network.firewall import extract_firewall
from src.ingestion.extractors.network.iptables import extract_iptables
from src.ingestion.extractors.network.load_balancer import extract_load_balancer
from src.ingestion.extractors.network.nac import extract_nac
from src.ingestion.extractors.network.netflow import extract_netflow
from src.ingestion.extractors.network.proxy import extract_proxy
from src.ingestion.extractors.network.vpn import extract_vpn
from src.ingestion.extractors.network.wireless import extract_wireless
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

NETWORK_LOG_SOURCES = frozenset(
    {
        "firewall",
        "iptables",
        "network_device",
        "vpn",
        "dns",
        "dhcp",
        "proxy",
        "netflow",
        "load_balancer",
        "nac",
        "wireless",
        "bgp",
    }
)

_EXTRACTORS = {
    "firewall": extract_firewall,
    "iptables": extract_iptables,
    "network_device": extract_network_device,
    "vpn": extract_vpn,
    "dns": extract_dns,
    "dhcp": extract_dhcp,
    "proxy": extract_proxy,
    "netflow": extract_netflow,
    "load_balancer": extract_load_balancer,
    "nac": extract_nac,
    "wireless": extract_wireless,
    "bgp": extract_bgp,
}

__all__ = [
    "NETWORK_LOG_SOURCES",
    "extract_network_family",
]


def extract_network_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a network ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported network log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
