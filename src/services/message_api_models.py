from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class MessageSendRequest(BaseModel):
    recipient_id: int
    message: bytes

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    message: bytes | None
    timestamp: datetime
    is_delivered: bool

class PollingResponse(BaseModel):
    has_messages: bool
    messages: list[MessageResponse] | None = []
    last_message_id: int | None = None

class AckRequest(BaseModel):
    message_ids: list[int]