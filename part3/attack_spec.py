from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AttackSpec(BaseModel):
    """A proposal. The injector applies it to a copy of a window."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(min_length=1)
    family: Literal["freeze"]
    target_can_id: str = Field(min_length=1)
    start_offset_ms: float = Field(ge=0)
    duration_ms: float = Field(gt=0)
    reasoning: str = ""