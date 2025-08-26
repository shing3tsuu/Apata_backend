from sqlalchemy import ForeignKey, String, Text, DateTime, Boolean, Index, BigInteger, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from typing import List, Optional

class Base(DeclarativeBase):
    """
    backend (fastapi)
    """
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(100), nullable=False)
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    message: Mapped[bytes] = mapped_column(LargeBinary)  # Encrypted message data
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    is_delivered: Mapped[bool] = mapped_column(default=False)
    encryption_version: Mapped[int] = mapped_column(default=1)
