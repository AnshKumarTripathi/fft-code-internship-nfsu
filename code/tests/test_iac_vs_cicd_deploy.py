"""Terraform iac vs Phase 30 cicd_deploy isolation (Phase 32)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

TERRAFORM = (
    "2024-01-15T10:00:03Z Apply complete! Resources: 1 added, 0 changed, 0 destroyed. "
    "user=alice host=ci01"
)
TERRAFORM_JSON = (
    '{"@level":"info","@message":"Apply complete! Resources: 1 added, 0 changed, '
    '0 destroyed.","@module":"terraform.ui","@timestamp":"2024-01-15T10:00:01Z",'
    '"type":"apply_complete","user":"alice"}'
)
DEPLOY = (
    '{"event":"deploy","service":"web","user":"alice",'
    '"environment":"prod","ts":"2024-01-15T10:00:01Z"}'
)
ANSIBLE = "2024-01-15T10:00:07Z PLAY RECAP *********************************************************************"


def test_terraform_text_is_iac() -> None:
    assert detect_log_source_from_line(TERRAFORM) == "iac"
    assert resolve_log_source(Path("deploy.json"), TERRAFORM) == "iac"
    result = extract_entity_and_timestamp(TERRAFORM, "iac", default_year=1999)
    assert result.extraction_ok is True


def test_terraform_json_is_iac() -> None:
    assert detect_log_source_from_line(TERRAFORM_JSON) == "iac"
    assert resolve_log_source(Path("deploy.json"), TERRAFORM_JSON) == "iac"


def test_deploy_json_stays_cicd_deploy() -> None:
    assert detect_log_source_from_line(DEPLOY) == "cicd_deploy"
    assert resolve_log_source(Path("terraform.json"), DEPLOY) == "cicd_deploy"


def test_ansible_recap_is_config_mgmt_not_deploy() -> None:
    assert detect_log_source_from_line(ANSIBLE) == "config_mgmt"
    assert resolve_log_source(Path("deploy.txt"), ANSIBLE) == "config_mgmt"
