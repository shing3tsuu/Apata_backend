from pydantic import BaseModel, constr, validator
from datetime import datetime
from typing import List

class UserDTO(BaseModel):
    id: int
    name: str = constr(min_length=1, max_length=50)
    ecdsa_public_key: str | None = None
    ecdh_public_key: str | None = None

class ContactRequestDTO(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    status: str
    created_at: datetime

class UserWithContactStatusDTO(UserDTO):
    status: str  # status: 'accepted', 'pending', 'rejected', 'none'

class MessageDTO(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    message: bytes
    timestamp: datetime
    is_delivered: bool
