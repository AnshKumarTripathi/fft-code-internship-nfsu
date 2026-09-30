"""Thin wrapper around drain3.TemplateMiner (template mining only).

Field / entity / timestamp extraction stays in ``src.ingestion`` — this module
only mines ``template_id`` + ``template_string`` and persists miner state.
"""

from __future__ import annotations

import logging
from pathlib import Path

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

logger = logging.getLogger(__name__)

DRAIN3_STATE_FILENAME = "drain3_state.bin"
DEFAULT_DRAIN3_INI = Path("config") / "drain3.ini"


def resolve_drain3_ini(config_path: str | Path | None = None) -> Path:
    """Resolve drain3.ini next to pipeline.yaml, else ``config/drain3.ini``."""
    if config_path is not None:
        sibling = Path(config_path).resolve().parent / "drain3.ini"
        if sibling.is_file():
            return sibling
    cwd_candidate = DEFAULT_DRAIN3_INI.resolve()
    if cwd_candidate.is_file():
        return cwd_candidate
    raise FileNotFoundError(
        f"drain3.ini not found (looked for sibling of {config_path!r} "
        f"and {DEFAULT_DRAIN3_INI})"
    )


def drain3_state_path(baseline_dir: str | Path) -> Path:
    return Path(baseline_dir) / DRAIN3_STATE_FILENAME


class Drain3Miner:
    """Wrap TemplateMiner with FilePersistence under ``baseline_dir``."""

    def __init__(
        self,
        baseline_dir: str | Path,
        drain3_ini_path: str | Path,
    ) -> None:
        baseline = Path(baseline_dir)
        baseline.mkdir(parents=True, exist_ok=True)
        state_path = drain3_state_path(baseline)

        miner_config = TemplateMinerConfig()
        miner_config.load(str(Path(drain3_ini_path)))

        persistence = FilePersistence(str(state_path))
        self._miner = TemplateMiner(persistence, miner_config)
        self.state_path = state_path
        logger.info(
            "Drain3 miner ready (state=%s, clusters=%s)",
            state_path,
            len(self._miner.drain.clusters),
        )

    def add_log_message(self, raw_line: str) -> tuple[str, str]:
        """Mine one line; return ``(template_id, template_string)``."""
        result = self._miner.add_log_message(raw_line)
        template_id = str(result["cluster_id"])
        template_string = str(result["template_mined"])
        return template_id, template_string

    def flush(self) -> None:
        """Force-persist miner state after a successful parse run."""
        if self._miner.persistence_handler is None:
            return
        self._miner.save_state("parse_complete")
