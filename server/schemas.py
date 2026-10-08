from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field

MAX_EVENTS_PER_BATCH = 500


class AgentInfo(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    hostname: str = Field(default="", max_length=255)
    os_info: str = Field(default="", max_length=255)
    ip_address: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=32)


class EventBatch(AgentInfo):
    sent_at: str = ""
    events: List[Dict[str, Any]] = Field(default_factory=list, max_length=MAX_EVENTS_PER_BATCH)
