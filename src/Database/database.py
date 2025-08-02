from sqlalchemy import ForeignKey, String, Text, DateTime, Boolean, Index, BigInteger, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from typing import List, Optional

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(100), nullable=False)
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    sent_messages: Mapped[List["Message"]] = relationship(
        back_populates="sender",
        foreign_keys="Message.sender_id"
    )
    received_messages: Mapped[List["Message"]] = relationship(
        back_populates="recipient",
        foreign_keys="Message.recipient_id"
    )
    owner_contacts: Mapped[List["Contact"]] = relationship(
        back_populates="owner",
        foreign_keys="Contact.owner_id"
    )
    contact_in: Mapped[List["Contact"]] = relationship(
        back_populates="contact_user",
        foreign_keys="Contact.contact_id"
    )

class Contact(Base):
    __tablename__ = "contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    contact_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    owner: Mapped["User"] = relationship(
        back_populates="owner_contacts",
        foreign_keys=[owner_id]
    )
    contact_user: Mapped[User] = relationship(
        back_populates="contact_in",
        foreign_keys=[contact_id]
    )

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    message: Mapped[bytes] = mapped_column(LargeBinary)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    is_delivered: Mapped[bool] = mapped_column(default=False)
    encryption_version: Mapped[int] = mapped_column(default=1)

    sender: Mapped["User"] = relationship(
        back_populates="sent_messages",
        foreign_keys=[sender_id]
    )
    recipient: Mapped["User"] = relationship(
        back_populates="received_messages",
        foreign_keys=[recipient_id]
    )

    # Правильные индексы
    __table_args__ = (
        Index('idx_message_sender', 'sender_id'),
        Index('idx_message_recipient', 'recipient_id'),
        Index('idx_message_timestamp', 'timestamp'),
    )

