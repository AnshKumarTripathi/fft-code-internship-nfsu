"""aws_cloudtrail extractor tests (Phase 27)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

LINE = (
    '{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:01Z",'
    '"eventSource":"iam.amazonaws.com","eventName":"ConsoleLogin",'
    '"userIdentity":{"type":"IAMUser","userName":"alice",'
    '"arn":"arn:aws:iam::123456789012:user/alice"},'
    '"sourceIPAddress":"10.0.0.8","awsRegion":"us-east-1"}'
)
WRAPPED = (
    '{"Records":[{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:11Z",'
    '"eventSource":"s3.amazonaws.com","eventName":"ListBuckets",'
    '"userIdentity":{"type":"IAMUser","userName":"alice",'
    '"arn":"arn:aws:iam::123456789012:user/alice"},'
    '"sourceIPAddress":"10.0.0.8"}]}'
)
ROLE = (
    '{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:05Z",'
    '"eventSource":"ec2.amazonaws.com","eventName":"RunInstances",'
    '"userIdentity":{"type":"AssumedRole",'
    '"arn":"arn:aws:sts::123456789012:assumed-role/AdminRole/session",'
    '"principalId":"AROASAMPLE:session"},'
    '"sourceIPAddress":"10.0.0.11"}'
)


def test_cloudtrail_extracts_user_and_src_ip() -> None:
    assert resolve_log_source(Path("server1.log"), LINE) == "aws_cloudtrail"
    result = extract_entity_and_timestamp(LINE, "aws_cloudtrail", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["event_name"] == "ConsoleLogin"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_cloudtrail_unwraps_records_wrapper() -> None:
    assert resolve_log_source(Path("cloudtrail.json"), WRAPPED) == "aws_cloudtrail"
    result = extract_entity_and_timestamp(WRAPPED, "aws_cloudtrail", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["src_ip"] == "10.0.0.8"


def test_assumed_role_uses_service_entity() -> None:
    result = extract_entity_and_timestamp(ROLE, "aws_cloudtrail", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_type == "service"
    assert result.entity_id == "session"
    assert result.raw_fields["src_ip"] == "10.0.0.11"
