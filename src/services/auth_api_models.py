from pydantic import BaseModel, constr, Field
from typing import Optional

class UserCreateDTO(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")

class PublicKeyUpdateDTO(BaseModel):
    public_key: str = Field(..., min_length=100, pattern="^-----BEGIN PUBLIC KEY-----")

class EncryptedMessageDTO(BaseModel):
    recipient_id: int
    encrypted_data: str
    iv: str
    auth_tag: str
    encryption_version: int = 1

class ContactCreateDTO(BaseModel):
    contact_username: str

class UserRegisterRequest(UserCreateDTO):
    public_key: str = Field(..., min_length=100, pattern="^-----BEGIN PUBLIC KEY-----")

class UserRegisterResponse(BaseModel):
    id: int
    username: str

class PublicKeyResponse(BaseModel):
    user_id: int
    public_key: str = Field(..., min_length=100, pattern="^-----BEGIN PUBLIC KEY-----")

class ChallengeRequest(BaseModel):
    username: str

class ChallengeLoginRequest(BaseModel):
    username: str
    signature: str  # Base64-encoded signature

class UserDomain(BaseModel):
    id: int
    name: str
    public_key: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    name: str
    public_key: Optional[str] # Base64-encoded public key

    class Config:

        from_attributes = True
