from pydantic import BaseModel, constr, Field, validator
from datetime import datetime
import enum


class UserContactResponse(BaseModel):
    name: str
    ecdsa_public_key: str | None = None
    ecdh_public_key: str | None = None

class SentContactRequest(BaseModel):
    sender_id: int
    receiver_id: int

class ContactRequestResponse(BaseModel):
    sender_id: int
    receiver_id: int
    status: str
    created_at: datetime

class GetUserContactsRequests(BaseModel):
    receiver_id: int
    status: str
