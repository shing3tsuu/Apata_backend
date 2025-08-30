from pydantic import BaseModel, constr, Field
from typing import Optional

class UserCreateDTO(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")

class PublicKeyUpdateDTO(BaseModel):
    """
    # Development notes: keys are not changing yet, in future PFS (perfect forward secrecy) needs to be implemented
    # Development notes: add validation for keys
    """
    ecdsa_public_key: str
    ecdh_public_key: str | None = None

class EncryptedMessageDTO(BaseModel):
    recipient_id: int
    encrypted_data: str
    iv: str
    auth_tag: str
    encryption_version: int = 1

class ContactCreateDTO(BaseModel):
    contact_username: str

class UserRegisterRequest(UserCreateDTO):
    ecdsa_public_key: str
    ecdh_public_key: str | None = None

class UserRegisterResponse(BaseModel):
    id: int
    username: str

class PublicKeyResponse(BaseModel):
    user_id: int
    ecdsa_public_key: str
    ecdh_public_key: str | None = None

class ChallengeRequest(BaseModel):
    username: str

class ChallengeLoginRequest(BaseModel):
    username: str
    signature: str  # Base64-encoded signature

class UserDomain(BaseModel):
    id: int
    name: str
    ecdsa_public_key: str | None = None
    ecdh_public_key: str | None = None

class UserResponse(BaseModel):
    id: int
    name: str
    ecdsa_public_key: str | None = None
    ecdh_public_key: str | None = None # Base64-encoded public key

    class Config:

        from_attributes = True
