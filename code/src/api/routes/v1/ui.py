"""v1 UI honesty policy (R8 display cutoffs; does not change flagging)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from src.api.deps import load_app_config
from src.api.schemas import UiHonestyPolicy
from src.config import ui_honesty_settings

router = APIRouter(tags=["v1-ui"])


@router.get("/ui-policy", response_model=UiHonestyPolicy)
def v1_ui_policy(request: Request) -> UiHonestyPolicy:
    return UiHonestyPolicy.model_validate(ui_honesty_settings(load_app_config(request)))
