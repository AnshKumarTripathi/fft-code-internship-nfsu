"""Line-safe large-corpus sharding (Phase 88–91)."""

from src.ingestion.sharding.manifest import (
    ShardManifestRecord,
    read_manifest,
    write_manifest,
)
from src.ingestion.sharding.orchestrate import (
    POST_MERGE_STAGES,
    ShardCancelled,
    ShardedIngestParseResult,
    assert_shards_ready_for_detect,
    corpus_digest_from_shards,
    run_sharded_pipeline,
    run_sharded_post_merge_detect,
    run_sharded_through_parse,
)
from src.ingestion.sharding.split import (
    ShardError,
    ShardSplitResult,
    split_log_file,
)

__all__ = [
    "POST_MERGE_STAGES",
    "ShardCancelled",
    "ShardError",
    "ShardManifestRecord",
    "ShardSplitResult",
    "ShardedIngestParseResult",
    "assert_shards_ready_for_detect",
    "corpus_digest_from_shards",
    "read_manifest",
    "run_sharded_pipeline",
    "run_sharded_post_merge_detect",
    "run_sharded_through_parse",
    "split_log_file",
    "write_manifest",
]
