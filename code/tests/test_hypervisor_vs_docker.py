"""libvirt hypervisor vs Phase 28 docker isolation (Phase 32)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

LIBVIRT = "Jan 15 10:00:01 kvmhost libvirtd[1234]: Domain 'web01' started"
DOCKER = (
    'Jan 15 10:00:01 worker1 dockerd[1200]: time="2024-01-15T10:00:01Z" '
    'level=info msg="starting container"'
)


def test_libvirt_is_hypervisor() -> None:
    assert detect_log_source_from_line(LIBVIRT) == "hypervisor"
    assert resolve_log_source(Path("docker.log"), LIBVIRT) == "hypervisor"


def test_dockerd_stays_docker() -> None:
    assert detect_log_source_from_line(DOCKER) == "docker"
    assert resolve_log_source(Path("kvm.txt"), DOCKER) == "docker"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("kvm.txt")) == "hypervisor"
    assert detect_log_source(Path("docker.log")) == "docker"
