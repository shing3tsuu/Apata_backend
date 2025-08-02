from pydantic import BaseModel, constr
from datetime import datetime
from typing import List
from .database import User, Contact, Message

class UserDomain(BaseModel):
    id: int
    name: constr(min_length=1, max_length=50)
    hashed_password: str
    public_key: str | None = None

class ContactDomain(BaseModel):
    id: int
    owner_id: int
    contact_id: int

class MessageDomain(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    message: bytes
    timestamp: datetime
    is_delivered: bool
    encryption_version: int