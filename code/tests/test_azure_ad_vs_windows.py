"""Azure AD JSON vs Windows Event Log isolation (Phase 27)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

AZURE = (
    '{"time":"2024-01-15T10:00:01.000Z","resourceId":"/tenants/0000/providers/Microsoft.aadiam",'
    '"operationName":"Sign-in activity","category":"SignInLogs",'
    '"properties":{"userPrincipalName":"alice@contoso.com","ipAddress":"10.0.0.8",'
    '"status":{"errorCode":0}}}'
)
WINDOWS = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)


def test_azure_ad_json_is_azure_ad() -> None:
    assert detect_log_source_from_line(AZURE) == "azure_ad"
    assert resolve_log_source(Path("security.txt"), AZURE) == "azure_ad"


def test_windows_event_stays_windows() -> None:
    assert detect_log_source_from_line(WINDOWS) == "windows_security"
    assert resolve_log_source(Path("azure_ad.json"), WINDOWS) == "windows_security"
