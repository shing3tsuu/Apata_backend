from pydantic import BaseModel


class UserRegistration(BaseModel):
    username: str
    password: str
    public_key: str

class UserLogin(BaseModel):
    username: str
    password: str

class GetMessagesRequest(BaseModel):
    user_id: int

class AddContactRequest(BaseModel):
    contact_username: str

class SendMessageRequest(BaseModel):
    recipient_id: int
    message: str

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    message: str
    timestamp: str

class GetMessagesResponse(BaseModel):
    messages: list[MessageResponse]