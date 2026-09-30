"""Tests for Drain3Miner wrapper: template stability across state reload."""

from __future__ import annotations

from pathlib import Path

from src.parsing.drain3_wrapper import Drain3Miner, drain3_state_path

CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"

LINE_A1 = (
    "Jan 15 10:00:01 hostname sshd[1234]: Failed password for alice "
    "from 192.168.1.10 port 51234 ssh2"
)
LINE_A2 = (
    "Jan 15 10:00:02 hostname sshd[1235]: Failed password for bob "
    "from 10.0.0.5 port 40000 ssh2"
)
LINE_B = "May  5 09:30:00 hostname CRON[99]: (root) CMD (/usr/bin/true)"


def test_structurally_similar_lines_share_template(tmp_path: Path) -> None:
    miner = Drain3Miner(baseline_dir=tmp_path / "baselines", drain3_ini_path=DRAIN3_INI)
    tid1, tmpl1 = miner.add_log_message(LINE_A1)
    tid2, tmpl2 = miner.add_log_message(LINE_A2)
    tid3, _ = miner.add_log_message(LINE_B)

    assert tid1 == tid2
    assert tmpl1 or tmpl2  # template string present
    assert tid3 != tid1
    miner.flush()
    assert drain3_state_path(tmp_path / "baselines").is_file()


def test_state_reload_keeps_template_ids(tmp_path: Path) -> None:
    baseline = tmp_path / "baselines"
    miner1 = Drain3Miner(baseline_dir=baseline, drain3_ini_path=DRAIN3_INI)
    tid_a, _ = miner1.add_log_message(LINE_A1)
    tid_b, _ = miner1.add_log_message(LINE_B)
    miner1.flush()

    miner2 = Drain3Miner(baseline_dir=baseline, drain3_ini_path=DRAIN3_INI)
    tid_a2, _ = miner2.add_log_message(LINE_A2)
    tid_b2, _ = miner2.add_log_message(LINE_B)

    assert tid_a2 == tid_a
    assert tid_b2 == tid_b
