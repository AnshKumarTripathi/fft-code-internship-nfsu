"""v1 pipeline job control + uploads (Phases 56–57, 65, 91)."""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from src.api.analyses import (
    create_analysis,
    default_analysis_label,
    get_analysis,
    corpus_digest_from_uploads,
    normalize_analysis_label,
    normalize_analysis_notes,
)
from src.api.deps import load_app_config, resolve_config_path
from src.api.lab_reset import LabResetError, reset_lab_data
from src.api.pipeline_jobs import (
    JobBusyError,
    JobPathError,
    corpus_digest_for_path,
    get_job_store,
    resolve_sharded_input_path,
)
from src.api.pipeline_uploads import (
    UploadError,
    assert_allowed_suffix,
    copy_demo_corpus,
    delete_staged_upload,
    iter_upload_file_chunks,
    list_existing_raw_top_level,
    list_staged_uploads,
    raw_dir_from_config,
    sanitize_upload_basename,
    save_upload_stream,
    unique_destination,
    upload_dir_from_config,
)
from src.api.schemas import (
    PipelineCorpusListResponse,
    PipelineJobCreate,
    PipelineJobStatus,
    PipelineLabResetRequest,
    PipelineLabResetResponse,
    PipelineShardingSettings,
    PipelineUploadFileItem,
    PipelineUploadListResponse,
)
from src.config import (
    effective_upload_allowed_suffixes,
    pipeline_ui_settings,
    sharding_settings,
)
from src.db.connection import get_connection
from src.db.writer_lock import WarehouseBusyError
from src.pipeline import STAGE_ORDER, resolve_stage_list

router = APIRouter(prefix="/pipeline", tags=["v1-pipeline"])


def _to_status(payload: dict) -> PipelineJobStatus:
    return PipelineJobStatus.model_validate(payload)


def _upload_http(exc: UploadError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=str(exc))


def _resolve_analysis_for_job(
    request: Request,
    payload: PipelineJobCreate,
    *,
    corpus_digest: str,
    file_count: int,
) -> str:
    """Ensure an analysis exists; return analysis_id."""
    config = load_app_config(request)

    try:
        connection = get_connection(config)
    except WarehouseBusyError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Warehouse is busy or missing. If a batch job is running, "
                "wait for it to finish."
            ),
        ) from exc
    try:
        analysis_id = (payload.analysis_id or "").strip() or None
        if analysis_id:
            existing = get_analysis(connection, analysis_id)
            if existing is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Analysis not found: {analysis_id}",
                )
            return analysis_id

        try:
            if payload.label is not None and str(payload.label).strip():
                label = normalize_analysis_label(payload.label)
            else:
                label = default_analysis_label()
            notes = normalize_analysis_notes(payload.notes)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        created = create_analysis(
            connection, label=label, notes=notes, status="draft"
        )
        return created.analysis_id
    finally:
        connection.close()


def _resolve_sharded_source(
    request: Request,
    payload: PipelineJobCreate,
) -> tuple[str, str, int]:
    """Return (input_path, corpus_digest, file_count) for a sharded start."""
    config = load_app_config(request)
    upload_dir = upload_dir_from_config(config)
    staged = list_staged_uploads(upload_dir)

    explicit = (payload.input_path or "").strip() or None
    if explicit and payload.use_staged_uploads:
        raise HTTPException(
            status_code=422,
            detail="Provide either input_path or use_staged_uploads, not both",
        )

    if payload.use_staged_uploads:
        if not staged:
            raise HTTPException(
                status_code=422,
                detail=(
                    "use_staged_uploads requires exactly one staged file "
                    "(small multipart stays ≤50 MiB; prefer a server path for huge logs)"
                ),
            )
        if len(staged) != 1:
            raise HTTPException(
                status_code=422,
                detail=(
                    "use_staged_uploads requires exactly one staged file; "
                    f"found {len(staged)}. Leave one file or set input_path."
                ),
            )
        path = upload_dir / str(staged[0]["name"])
        resolved = resolve_sharded_input_path(config, path)
        digest, count = corpus_digest_from_uploads(staged)
        return str(resolved), digest, count

    if not explicit:
        raise HTTPException(
            status_code=422,
            detail=(
                "run_sharded requires input_path under raw_log_dir "
                "or use_staged_uploads=true with one staged file"
            ),
        )

    try:
        resolved = resolve_sharded_input_path(config, explicit)
    except JobPathError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    digest, count = corpus_digest_for_path(resolved)
    return str(resolved), digest, count


@router.get("/sharding", response_model=PipelineShardingSettings)
def v1_pipeline_sharding_settings(request: Request) -> PipelineShardingSettings:
    """Expose whether large-corpus UI should appear (does not raise upload caps)."""
    config = load_app_config(request)
    shard = sharding_settings(config)
    ui = pipeline_ui_settings(config)
    window = shard.get("analysis_window") or {}
    return PipelineShardingSettings(
        enabled=bool(shard["enabled"]),
        prefer_server_path=bool(shard["prefer_server_path"]),
        target_shard_bytes=shard.get("target_shard_bytes"),
        target_shard_lines=shard.get("target_shard_lines"),
        max_shards=int(shard["max_shards"]),
        output_dir=str(shard["output_dir"]),
        raw_log_dir=str(config["paths"]["raw_log_dir"]),
        max_upload_bytes=int(ui["max_upload_bytes"]),
        analysis_window_enabled=bool(window.get("enabled", False)),
        analysis_window_last_days=int(window.get("last_days", 30)),
        analysis_window_start_utc=window.get("start_utc"),
        analysis_window_end_utc=window.get("end_utc"),
    )


@router.post("/jobs", response_model=PipelineJobStatus, status_code=202)
def v1_create_pipeline_job(
    payload: PipelineJobCreate,
    request: Request,
) -> PipelineJobStatus:
    mode = (payload.mode or "run_all").strip().lower()
    if mode not in {"run_all", "run_sharded"}:
        raise HTTPException(
            status_code=422,
            detail="mode must be 'run_all' or 'run_sharded'",
        )

    input_path: str | None = None
    if mode == "run_sharded":
        if payload.stages is not None:
            raise HTTPException(
                status_code=422,
                detail="stages is not supported for run_sharded",
            )
        try:
            input_path, corpus_digest, file_count = _resolve_sharded_source(
                request, payload
            )
        except JobPathError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        analysis_id = _resolve_analysis_for_job(
            request,
            payload,
            corpus_digest=corpus_digest,
            file_count=file_count,
        )
    else:
        if payload.input_path or payload.use_staged_uploads:
            raise HTTPException(
                status_code=422,
                detail="input_path / use_staged_uploads require mode=run_sharded",
            )
        if payload.stages is not None:
            try:
                resolve_stage_list(payload.stages)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if not payload.stages:
                raise HTTPException(
                    status_code=422,
                    detail="stages must be a non-empty subset of STAGE_ORDER "
                    f"({', '.join(STAGE_ORDER)})",
                )
        config = load_app_config(request)
        upload_dir = upload_dir_from_config(config)
        files = list_staged_uploads(upload_dir)
        corpus_digest, file_count = corpus_digest_from_uploads(files)
        analysis_id = _resolve_analysis_for_job(
            request,
            payload,
            corpus_digest=corpus_digest,
            file_count=file_count,
        )

    store = get_job_store()
    config_path = resolve_config_path(request)
    try:
        job = store.try_start(
            config_path=config_path,
            mode=mode,
            require_complete=bool(payload.require_complete),
            stages=payload.stages,
            analysis_id=analysis_id,
            corpus_digest=corpus_digest,
            file_count=file_count,
            ml_ensemble_enabled=payload.ml_ensemble_enabled,
            input_path=input_path,
        )
    except JobBusyError as exc:
        detail: dict[str, str] = {"message": str(exc)}
        if exc.job_id:
            detail["job_id"] = exc.job_id
        raise HTTPException(status_code=409, detail=detail) from exc
    except JobPathError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface config / start errors
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return _to_status(job.to_dict())


@router.post("/jobs/{job_id}/cancel", response_model=PipelineJobStatus)
def v1_cancel_pipeline_job(job_id: str) -> PipelineJobStatus:
    """Cancel between shards (MVP). Current shard may finish; detect will not start."""
    store = get_job_store()
    try:
        job = store.request_cancel(job_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Pipeline job not found: {job_id}",
        ) from exc
    except JobPathError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_status(job.to_dict())


@router.get("/jobs", response_model=PipelineJobStatus)
def v1_latest_pipeline_job() -> PipelineJobStatus:
    job = get_job_store().latest()
    if job is None:
        raise HTTPException(status_code=404, detail="No pipeline jobs yet")
    return _to_status(job.to_dict())


@router.get("/jobs/{job_id}", response_model=PipelineJobStatus)
def v1_get_pipeline_job(job_id: str) -> PipelineJobStatus:
    job = get_job_store().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Pipeline job not found: {job_id}")
    return _to_status(job.to_dict())


@router.get("/uploads", response_model=PipelineUploadListResponse)
def v1_list_pipeline_uploads(request: Request) -> PipelineUploadListResponse:
    config = load_app_config(request)
    upload_dir = upload_dir_from_config(config)
    files = [
        PipelineUploadFileItem.model_validate(item)
        for item in list_staged_uploads(upload_dir)
    ]
    return PipelineUploadListResponse(files=files, upload_dir=str(upload_dir))


@router.post("/uploads", response_model=PipelineUploadListResponse, status_code=201)
async def v1_create_pipeline_uploads(
    request: Request,
    files: list[UploadFile] = File(...),
) -> PipelineUploadListResponse:
    config = load_app_config(request)
    settings = pipeline_ui_settings(config)
    upload_dir = upload_dir_from_config(config)
    max_files = int(settings["max_files_per_request"])
    max_bytes = int(settings["max_upload_bytes"])
    allowed = effective_upload_allowed_suffixes(config)

    if not files:
        raise HTTPException(status_code=422, detail="at least one file is required")
    if len(files) > max_files:
        raise HTTPException(
            status_code=400,
            detail=f"at most {max_files} files per request",
        )

    saved: list[PipelineUploadFileItem] = []
    try:
        for upload in files:
            try:
                basename = sanitize_upload_basename(upload.filename)
                assert_allowed_suffix(basename, allowed)
                destination = unique_destination(upload_dir, basename)
                digest = save_upload_stream(
                    destination,
                    iter_upload_file_chunks(upload),
                    max_bytes=max_bytes,
                )
                saved.append(
                    PipelineUploadFileItem(
                        name=destination.name,
                        size_bytes=digest.size_bytes,
                        sha256=digest.sha256,
                        modified_at=digest.mtime_utc.isoformat(),
                    )
                )
            except UploadError as exc:
                raise _upload_http(exc) from exc
            finally:
                await upload.close()
    except HTTPException:
        raise

    return PipelineUploadListResponse(files=saved, upload_dir=str(upload_dir))


@router.delete("/uploads/{name}", status_code=204)
def v1_delete_pipeline_upload(name: str, request: Request) -> None:
    config = load_app_config(request)
    upload_dir = upload_dir_from_config(config)
    try:
        delete_staged_upload(upload_dir, name)
    except UploadError as exc:
        raise _upload_http(exc) from exc


@router.get("/corpus/raw", response_model=PipelineCorpusListResponse)
def v1_list_existing_raw(request: Request) -> PipelineCorpusListResponse:
    """Read-only top-level listing under ``paths.raw_log_dir``."""
    config = load_app_config(request)
    raw_dir = raw_dir_from_config(config)
    files = [
        PipelineUploadFileItem.model_validate(item)
        for item in list_existing_raw_top_level(raw_dir)
    ]
    return PipelineCorpusListResponse(
        files=files,
        raw_log_dir=str(raw_dir),
        mode="existing_raw",
    )


@router.post("/corpus/demo", response_model=PipelineUploadListResponse, status_code=201)
def v1_seed_demo_corpus(request: Request) -> PipelineUploadListResponse:
    """Copy mixed_v3 fixture logs into the upload directory."""
    config = load_app_config(request)
    upload_dir = upload_dir_from_config(config)
    try:
        copied = copy_demo_corpus(upload_dir)
    except UploadError as exc:
        raise _upload_http(exc) from exc
    return PipelineUploadListResponse(
        files=[PipelineUploadFileItem.model_validate(item) for item in copied],
        upload_dir=str(upload_dir),
    )


@router.post("/lab-reset", response_model=PipelineLabResetResponse)
def v1_lab_reset(
    payload: PipelineLabResetRequest,
    request: Request,
) -> PipelineLabResetResponse:
    """Clear regenerable lab outputs so the next run starts clean.

    Deletes warehouse, analyses snapshots, reports, scores, timeseries, parsed,
    baselines, and (by default) staged uploads. Does not delete config, fixtures,
    or source. Blocked while a pipeline job holds the writer.
    """
    if (payload.confirm or "").strip() != "CLEAR":
        raise HTTPException(
            status_code=422,
            detail="confirm must be exactly CLEAR",
        )
    config = load_app_config(request)
    try:
        result = reset_lab_data(
            config,
            clear_uploads=payload.clear_uploads,
            clear_raw_non_upload=payload.clear_raw_non_upload,
        )
    except LabResetError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return PipelineLabResetResponse.model_validate(result)
