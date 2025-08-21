from pydantic import BaseModel, constr
from typing import Optional

class UserCreateDTO(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=8)

class UserLoginDTO(BaseModel):
    username: str
    password: str

class PublicKeyUpdateDTO(BaseModel):
    public_key: str

class EncryptedMessageDTO(BaseModel):
    recipient_id: int
    encrypted_data: str
    iv: str
    auth_tag: str
    encryption_version: int = 1

class ContactCreateDTO(BaseModel):
    contact_username: str

# Добавлено поле public_key
class UserRegisterRequest(UserCreateDTO):
    public_key: str

class UserRegisterResponse(BaseModel):
    id: int
    username: str

class PublicKeyResponse(BaseModel):
    user_id: int
    public_key: str

class UserDomain(BaseModel):
    id: int
    name: str
    hashed_password: str

    public_key: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    name: str
    public_key: Optional[str] = None

    class Config:
        from_attributes = True
