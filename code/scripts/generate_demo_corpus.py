"""Generate synthetic demo corpus for full pipeline + UI walkthrough.

From the ``code/`` directory::

    python scripts/generate_demo_corpus.py
    python -m src.pipeline run-all --config config/pipeline.yaml --require complete

Writes line-oriented raw logs under ``data/raw/demo_corpus/`` plus ``manifest.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

CODE_ROOT = Path(__file__).resolve().parents[1]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from tests.fixtures.synthetic_entities import (  # noqa: E402
    generate_periodic_counts,
    inject_rhythm_attack,
)

UTC = timezone.utc
BUCKET_SECONDS = 600
HOSTNAME = "demo-host"


@dataclass
class AttackWindow:
    name: str
    entity_id: str
    start: datetime
    end: datetime
    expected_detector: str
    notes: str = ""


@dataclass
class CorpusManifest:
    base_time: str
    days: int
    bucket_seconds: int
    entities: dict[str, dict[str, str]]
    attack_windows: list[dict[str, str]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    line_counts: dict[str, int] = field(default_factory=dict)


def _syslog_ts(ts: datetime) -> str:
    day = ts.day
    return ts.strftime(f"%b {day:2d} %H:%M:%S")


def _iso_ts(ts: datetime) -> str:
    return ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def bucket_start(base: datetime, index: int) -> datetime:
    return base + timedelta(seconds=BUCKET_SECONDS * index)


def spread_timestamps(
    start: datetime, count: int, *, bucket_seconds: int = BUCKET_SECONDS
) -> list[datetime]:
    if count <= 0:
        return []
    if count == 1:
        return [start]
    step = bucket_seconds / count
    return [start + timedelta(seconds=step * i) for i in range(count)]


def day_offset(base: datetime, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return base + timedelta(days=day - 1, hours=hour, minutes=minute)


def bucket_index(base: datetime, ts: datetime) -> int:
    return int((ts - base).total_seconds() // BUCKET_SECONDS)


# --- Log line formatters ---------------------------------------------------


def fmt_ssh_failed(user: str, src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"Failed password for {user} from {src_ip} port {52000 + pid % 1000} ssh2"
    )


def fmt_ssh_accepted(user: str, src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"Accepted password for {user} from {src_ip} port 22 ssh2"
    )


def fmt_ssh_no_ident(src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"Did not receive identification string from {src_ip}"
    )


def fmt_ssh_breakin(src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: reverse mapping checking "
        f"getaddrinfo for attacker.example.com [{src_ip}] failed - "
        f"POSSIBLE BREAK-IN ATTEMPT!"
    )


def fmt_ssh_disconnect(src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"Connection closed by {src_ip} [preauth]"
    )


def fmt_ssh_invalid_user(user: str, src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"Invalid user {user} from {src_ip} port 40000 ssh2"
    )


def fmt_ssh_refused(src_ip: str, ts: datetime, pid: int) -> str:
    return (
        f"{_syslog_ts(ts)} {HOSTNAME} sshd[{pid}]: "
        f"refused connect from {src_ip}"
    )


def fmt_app_runtime(
    ts: datetime,
    *,
    host: str = "",
    service: str = "",
    user: str = "",
    level: str = "info",
    msg: str = "request ok",
) -> str:
    payload: dict[str, str] = {"ts": _iso_ts(ts), "level": level, "msg": msg}
    if host:
        payload["host"] = host
    if service:
        payload["service"] = service
    if user:
        payload["user"] = user
    return json.dumps(payload, separators=(",", ":"))


def fmt_windows_security(
    ts: datetime,
    *,
    user: str,
    computer: str = "WIN-DC01",
    event_id: int = 4624,
    ip: str = "10.0.0.8",
) -> str:
    return (
        f"TimeCreated={_iso_ts(ts)} EventID={event_id} LogName=Security "
        f"Computer={computer} TargetUserName={user} IpAddress={ip} LogonType=3"
    )


def fmt_cloudtrail(ts: datetime, *, user: str, event_name: str = "ConsoleLogin") -> str:
    payload = {
        "eventVersion": "1.09",
        "eventTime": _iso_ts(ts),
        "eventSource": "iam.amazonaws.com",
        "eventName": event_name,
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
            "arn": f"arn:aws:iam::123456789012:user/{user}",
        },
        "sourceIPAddress": "10.0.0.8",
        "awsRegion": "us-east-1",
    }
    return json.dumps(payload, separators=(",", ":"))


def fmt_badge(ts: datetime, badge_id: str, door: str, result: str) -> str:
    return f"{_iso_ts(ts)},{badge_id},{door},{result}"


# --- Schedule builders -------------------------------------------------------


def build_peer_ssh_schedule(
    base: datetime,
    entity_id: str,
    *,
    days: int,
    daily_hours: tuple[int, ...] = (8, 12, 16, 20),
    events_per_slot: int = 2,
) -> list[str]:
    lines: list[str] = []
    pid_base = hash(entity_id) % 10000
    for day in range(1, days + 1):
        for hour in daily_hours:
            slot = day_offset(base, day, hour)
            for i, ts in enumerate(spread_timestamps(slot, events_per_slot)):
                pid = pid_base + day * 10 + hour + i
                lines.append(
                    fmt_ssh_accepted(entity_id, "192.168.1.10", ts, pid)
                    if i % 2 == 0
                    else fmt_ssh_failed(entity_id, "192.168.1.10", ts, pid)
                )
    return lines


def build_outlier_ssh_schedule(base: datetime, *, days: int) -> list[str]:
    """8-hour rhythm: events every 8 hours (cluster outlier vs 24h peers)."""
    lines: list[str] = []
    for day in range(1, days + 1):
        for hour in (0, 8, 16):
            slot = day_offset(base, day, hour)
            for i, ts in enumerate(spread_timestamps(slot, 2)):
                pid = 9000 + day * 10 + hour + i
                lines.append(fmt_ssh_accepted("outlier-01", "10.0.0.5", ts, pid))
    return lines


def build_charlie_ssh_schedule(base: datetime, *, days: int) -> list[str]:
    lines: list[str] = []
    for day in range(1, days + 1):
        ts = day_offset(base, day, 9, 0)
        lines.append(fmt_ssh_accepted("charlie", "172.16.0.2", ts, 7000 + day))
    return lines


def build_alice_ssh_schedule(
    base: datetime,
    *,
    days: int,
    burst_day: int,
    burst_hour: int,
    attacker_ip: str,
) -> list[str]:
    lines: list[str] = []
    for day in range(1, days + 1):
        if day == burst_day:
            continue
        ts = day_offset(base, day, 10, 0)
        lines.append(fmt_ssh_accepted("alice", "192.168.1.10", ts, 1000 + day))

    burst_start = day_offset(base, burst_day, burst_hour)
    for i, ts in enumerate(spread_timestamps(burst_start, 420, bucket_seconds=3600)):
        lines.append(fmt_ssh_failed("alice", attacker_ip, ts, 2000 + i))

    link_day = burst_day + 5
    if link_day <= days:
        for i, ts in enumerate(spread_timestamps(day_offset(base, link_day, 11), 15)):
            lines.append(fmt_ssh_no_ident(attacker_ip, ts, 3000 + i))

    return lines


def build_bob_ssh_schedule(
    base: datetime,
    *,
    days: int,
    anomaly_day: int,
    anomaly_hour: int,
) -> list[str]:
    lines: list[str] = []
    rare_fns = (
        fmt_ssh_no_ident,
        fmt_ssh_breakin,
        fmt_ssh_disconnect,
        fmt_ssh_invalid_user,
        fmt_ssh_refused,
    )
    for day in range(1, days + 1):
        hour_start = day_offset(base, day, anomaly_hour if day == anomaly_day else 10)
        if day == anomaly_day:
            for i, ts in enumerate(spread_timestamps(hour_start, 35)):
                fn = rare_fns[i % len(rare_fns)]
                if fn is fmt_ssh_invalid_user:
                    lines.append(fn("scanner", "203.0.113.50", ts, 4000 + i))
                else:
                    lines.append(fn("203.0.113.50", ts, 4000 + i))
        else:
            for i, ts in enumerate(spread_timestamps(hour_start, 6)):
                pid = 5000 + day * 10 + i
                if i % 2 == 0:
                    lines.append(fmt_ssh_accepted("bob", "10.0.0.9", ts, pid))
                else:
                    lines.append(fmt_ssh_failed("bob", "10.0.0.9", ts, pid))
    return lines


def build_web01_app_schedule(
    base: datetime,
    n_buckets: int,
    counts: np.ndarray,
    *,
    rhythm_start_day: int,
    rhythm_hours: int,
    energy_start_day: int,
    energy_buckets: int,
    multi_burst_day: int,
) -> list[str]:
    lines: list[str] = []
    rhythm_start_idx = (rhythm_start_day - 1) * 24 * (3600 // BUCKET_SECONDS)
    energy_start_idx = (energy_start_day - 1) * 24 * (3600 // BUCKET_SECONDS)
    multi_idx = (multi_burst_day - 1) * 24 * (3600 // BUCKET_SECONDS) + 14 * (
        3600 // BUCKET_SECONDS
    )

    for idx in range(n_buckets):
        count = int(max(0, round(float(counts[idx]))))
        if idx == multi_idx:
            count = max(count, 200)
        if energy_start_idx <= idx < energy_start_idx + energy_buckets:
            count = max(count, int(100 * (0.5 + 0.5 * np.sin(idx))))

        if count <= 0:
            continue

        b_start = bucket_start(base, idx)
        for i, ts in enumerate(spread_timestamps(b_start, min(count, 50))):
            if rhythm_start_idx <= idx < rhythm_start_idx + rhythm_hours * (
                3600 // BUCKET_SECONDS
            ):
                msg = "rhythm segment workload"
            elif idx == multi_idx:
                msg = "critical burst request"
            elif idx >= energy_start_idx:
                msg = "energy burst load"
            else:
                msg = "health ok" if i % 3 else "request ok"
            lines.append(
                fmt_app_runtime(
                    ts,
                    host="web-01",
                    level="info" if i % 5 else "warn",
                    msg=msg,
                )
            )
    return lines


def build_svc_api_schedule(base: datetime, *, days: int) -> list[str]:
    lines: list[str] = []
    for day in range(1, days + 1, 3):
        for hour in (6, 18):
            ts = day_offset(base, day, hour)
            lines.append(
                fmt_app_runtime(
                    ts,
                    service="svc-api",
                    level="info",
                    msg="service heartbeat",
                )
            )
    return lines


def build_eve_windows_schedule(base: datetime, *, days: int, burst_day: int) -> list[str]:
    lines: list[str] = []
    for day in range(1, days + 1):
        n = 3 if day != burst_day else 40
        start = day_offset(base, day, 13)
        for i, ts in enumerate(spread_timestamps(start, n, bucket_seconds=3600)):
            lines.append(
                fmt_windows_security(
                    ts,
                    user="eve",
                    computer="web-01",
                    event_id=4624 if i % 2 == 0 else 4625,
                )
            )
    return lines


def build_cloudtrail_schedule(base: datetime, *, days: int) -> list[str]:
    lines: list[str] = []
    events = ("ConsoleLogin", "GetObject", "AssumeRole", "CreateUser")
    for day in range(1, days + 1, 2):
        ts = day_offset(base, day, 11, 30)
        lines.append(
            fmt_cloudtrail(ts, user="alice", event_name=events[day % len(events)])
        )
    return lines


def build_badge_schedule(base: datetime, *, days: int) -> list[str]:
    lines: list[str] = []
    badges = ("B-1001", "B-1002", "B-1003", "B-1004")
    doors = ("door-lobby", "door-lab", "door-server")
    for day in range(1, min(days, 15) + 1):
        ts = day_offset(base, day, 8, 15)
        lines.append(
            fmt_badge(ts, badges[day % len(badges)], doors[day % len(doors)], "allow")
        )
    return lines


def build_entity_counts(
    base: datetime,
    *,
    n_buckets: int,
    period_buckets: int,
    amplitude: float = 3.0,
) -> tuple[list[datetime], np.ndarray]:
    return generate_periodic_counts(
        n_buckets=n_buckets,
        period_buckets=period_buckets,
        amplitude=amplitude,
        bucket_seconds=BUCKET_SECONDS,
        base_time=base,
    )


def build_attack_windows(base: datetime, *, days: int) -> list[AttackWindow]:
    burst_day = 29
    rhythm_day = 30
    ml_day = 31
    cluster_day = 32
    multi_day = 33
    ip_link_day = 34
    energy_day = 35
    return [
        AttackWindow(
            name="alice_bruteforce",
            entity_id="alice",
            start=day_offset(base, burst_day, 14),
            end=day_offset(base, burst_day, 15),
            expected_detector="statistical",
            notes="400+ failed SSH attempts in one hour",
        ),
        AttackWindow(
            name="web01_rhythm_change",
            entity_id="web-01",
            start=day_offset(base, rhythm_day, 0),
            end=day_offset(base, rhythm_day, 0) + timedelta(hours=72),
            expected_detector="spectral",
            notes="shape_js_z via 4h rhythm segment",
        ),
        AttackWindow(
            name="bob_template_anomaly",
            entity_id="bob",
            start=day_offset(base, ml_day, 10),
            end=day_offset(base, ml_day, 11),
            expected_detector="ml",
            notes="Rare SSH templates in one hour",
        ),
        AttackWindow(
            name="outlier_cluster",
            entity_id="outlier-01",
            start=day_offset(base, cluster_day, 0),
            end=day_offset(base, days, 0),
            expected_detector="cluster_outlier",
            notes="8h rhythm vs 24h peer baseline",
        ),
        AttackWindow(
            name="web01_multi_detector",
            entity_id="web-01",
            start=day_offset(base, multi_day, 14),
            end=day_offset(base, multi_day, 16),
            expected_detector="statistical+spectral",
            notes="Rate burst + rhythm overlap -> critical severity",
        ),
        AttackWindow(
            name="alice_ip_link",
            entity_id="alice",
            start=day_offset(base, ip_link_day, 11),
            end=day_offset(base, ip_link_day, 12),
            expected_detector="correlation",
            notes="same_ip link with 198.51.100.99",
        ),
        AttackWindow(
            name="web01_energy_burst",
            entity_id="web-01",
            start=day_offset(base, energy_day, 0),
            end=day_offset(base, energy_day, 0) + timedelta(hours=50 * BUCKET_SECONDS / 3600),
            expected_detector="spectral",
            notes="energy_z via 50-bucket volume burst",
        ),
    ]


def write_lines(path: Path, lines: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")
    return len(lines)


def generate_corpus(
    output_dir: Path,
    *,
    base_date: datetime,
    days: int,
    seed: int,
) -> CorpusManifest:
    del seed  # schedules are deterministic from calendar constants
    n_buckets = days * 24 * (3600 // BUCKET_SECONDS)
    period_buckets = (24 * 3600) // BUCKET_SECONDS

    _, web_counts = build_entity_counts(base_date, n_buckets=n_buckets, period_buckets=period_buckets)
    rhythm_start_bucket = (30 - 1) * period_buckets
    web_counts = inject_rhythm_attack(
        web_counts,
        start=rhythm_start_bucket,
        length=72 * (3600 // BUCKET_SECONDS),
        new_period_buckets=24,
    )

    attack_windows = build_attack_windows(base_date, days=days)

    file_specs: dict[str, list[str]] = {
        "demo_ssh_peers.log": [],
        "demo_ssh_alice.log": build_alice_ssh_schedule(
            base_date,
            days=days,
            burst_day=29,
            burst_hour=14,
            attacker_ip="198.51.100.99",
        ),
        "demo_ssh_bob.log": build_bob_ssh_schedule(
            base_date,
            days=days,
            anomaly_day=31,
            anomaly_hour=10,
        ),
        "demo_ssh_outlier.log": build_outlier_ssh_schedule(base_date, days=days),
        "demo_app_runtime.jsonl": build_web01_app_schedule(
            base_date,
            n_buckets,
            web_counts,
            rhythm_start_day=30,
            rhythm_hours=72,
            energy_start_day=35,
            energy_buckets=50,
            multi_burst_day=33,
        ),
        "demo_windows_security.txt": build_eve_windows_schedule(
            base_date, days=days, burst_day=33
        ),
        "demo_cloudtrail.jsonl": build_cloudtrail_schedule(base_date, days=days),
        "demo_badge.csv": ["ts,badge_id,door,result"]
        + build_badge_schedule(base_date, days=days),
    }

    for i in range(1, 21):
        peer_id = f"peer-{i:02d}"
        file_specs["demo_ssh_peers.log"].extend(
            build_peer_ssh_schedule(base_date, peer_id, days=days)
        )
    file_specs["demo_ssh_peers.log"].extend(
        build_charlie_ssh_schedule(base_date, days=days)
    )
    file_specs["demo_app_runtime.jsonl"].extend(
        build_svc_api_schedule(base_date, days=days)
    )

    manifest = CorpusManifest(
        base_time=_iso_ts(base_date),
        days=days,
        bucket_seconds=BUCKET_SECONDS,
        entities={
            "alice": {"type": "user", "role": "statistical rate burst"},
            "web-01": {"type": "host", "role": "spectral shape + energy + critical"},
            "bob": {"type": "user", "role": "ml template anomaly"},
            "outlier-01": {"type": "user", "role": "cluster outlier (8h rhythm)"},
            **{f"peer-{i:02d}": {"type": "user", "role": "cluster peer"} for i in range(1, 21)},
            "charlie": {"type": "user", "role": "benign negative control"},
            "198.51.100.99": {"type": "ip", "role": "same_ip correlation"},
            "eve": {"type": "user", "role": "windows + multi-detector context"},
            "svc-api": {"type": "service", "role": "log source diversity"},
        },
        attack_windows=[
            {
                "name": w.name,
                "entity_id": w.entity_id,
                "start": _iso_ts(w.start),
                "end": _iso_ts(w.end),
                "expected_detector": w.expected_detector,
                "notes": w.notes,
            }
            for w in attack_windows
        ],
    )

    total = 0
    for name, lines in file_specs.items():
        out_path = output_dir / name
        count = write_lines(out_path, lines)
        manifest.files.append(name)
        manifest.line_counts[name] = count
        total += count
        print(f"  wrote {count:6d} lines -> {out_path}")

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "base_time": manifest.base_time,
                "days": manifest.days,
                "bucket_seconds": manifest.bucket_seconds,
                "total_lines": total,
                "entities": manifest.entities,
                "attack_windows": manifest.attack_windows,
                "files": manifest.files,
                "line_counts": manifest.line_counts,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  wrote manifest -> {manifest_path}")
    print(f"  total: {total} lines across {len(manifest.files)} files")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=CODE_ROOT / "data" / "raw" / "demo_corpus",
        help="Directory for generated raw logs (default: data/raw/demo_corpus/)",
    )
    parser.add_argument(
        "--base-date",
        type=str,
        default="2024-01-01T00:00:00Z",
        help="UTC start timestamp (ISO-8601)",
    )
    parser.add_argument("--days", type=int, default=35, help="Corpus duration in days")
    parser.add_argument("--seed", type=int, default=42, help="Reserved for future use")
    args = parser.parse_args(argv)

    base_date = datetime.fromisoformat(args.base_date.replace("Z", "+00:00"))
    if base_date.tzinfo is None:
        base_date = base_date.replace(tzinfo=UTC)

    print(f"Generating {args.days}-day demo corpus -> {args.output_dir}")
    generate_corpus(
        args.output_dir.resolve(),
        base_date=base_date,
        days=args.days,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
