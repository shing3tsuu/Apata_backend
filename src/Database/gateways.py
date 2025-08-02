from typing import Awaitable, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, date, time

from sqlalchemy import select, insert, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from abc import ABC
from functools import wraps
from typing import Callable, Optional
import logging

from src.Database.database import User, Message, Contact
from src.Database.DAO import BaseUserGateway
from src.Database.DTO import UserDomain, MessageDomain
from src.Encryption.password_hash import PasswordHash
from src.Config.config import load_config
from src.Database.db_manager import DatabaseManager

class UserGateway(BaseUserGateway):
    __slots__ = "db_manager"

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger(__name__)

    async def create_user(self, name: str, hashed_password: str, public_key: str) -> UserDomain:
        async with self.db_manager.session() as session:
            try:
                stmt = insert(User).values(
                    name=name,
                    hashed_password=hashed_password,
                    public_key=public_key
                ).returning(User)
                result = await session.execute(stmt)
                user = result.scalars().first()
                return UserDomain(
                    id=user.id,
                    name=user.name,
                    hashed_password=user.hashed_password,
                    public_key=user.public_key
                )
            except Exception as e:
                self.logger.error(f"Error creating user: {e}")
                raise

    async def get_user_by_name(self, name: str) -> UserDomain | None:
        async with self.db_manager.session() as session:
            try:
                stmt = select(User).where(User.name == name)
                result = await session.execute(stmt)
                user = result.scalars().first()
                if user:
                    return UserDomain(
                        id=user.id,
                        name=user.name,
                        hashed_password=user.hashed_password,
                        public_key=user.public_key
                        )
                else:
                    return None
            except Exception as e:
                self.logger.error("Error getting user by name: %s", e)
                return None

    async def update_public_key(self, user_id: int, public_key: str) -> bool:
        async with self.db_manager.session() as session:
            try:
                stmt = update(User).where(
                    User.id == user_id
                ).values(public_key=public_key)
                await session.execute(stmt)
                return True
            except Exception as e:
                self.logger.error("Error updating public key: %s", e)
                return False

class ContactGateway(BaseContactGateway):
    __slots__ = "db_manager"

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger(__name__)

    async def create_contact(self, owner_id: int, contact_id: int) -> ContactDomain:
        async with self.db_manager.session() as session:
            try:
                stmt = insert(Contact).values(
                    owner_id=owner_id,
                    contact_id=contact_id
                ).returning(Contact)
                result = await session.execute(stmt)
                contact = result.scalars().first()
                return ContactDomain(
                    id=contact.id,
                    owner_id=contact.owner_id,
                    contact_id=contact.contact_id
                )
            except Exception as e:
                self.logger.error("Error creating contact: %s", e)
                raise

    async def delete_contact(self, contact_id: int) -> bool:
        async with self.db_manager.session() as session:
            try:
                stmt = delete(Contact).where(Contact.id == contact_id)
                await session.execute(stmt)
                return True
            except Exception as e:
                self.logger.error("Error deleting contact: %s", e)
                return False

    async def get_contacts(self, owner_id: int) -> list[ContactDomain]:
        async with self.db_manager.session() as session:
            try:
                stmt = select(Contact).where(Contact.owner_id == owner_id)
                result = await session.execute(stmt)
                contacts = result.scalars().all()
                return [
                    ContactDomain(
                        id=c.id,
                        owner_id=c.owner_id,
                        contact_id=c.contact_id
                    ) for c in contacts
                ]
            except Exception as e:
                self.logger.error("Error getting contacts: %s", e)
                return []

class MessageGateway(BaseMessageGateway):
    __slots__ = "db_manager"

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger(__name__)

    async def create_message(
            self,
            sender_id: int,
            recipient_id: int,
            message: bytes,
            encryption_version: int
            ) -> MessageDomain:
        async with self.db_manager.session() as session:
            try:
                stmt = insert(Message).values(
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    message=message,
                    encryption_version=encryption_version
                ).returning(Message)
                result = await session.execute(stmt)
                msg = result.scalars().first()
                return MessageDomain(
                    id=msg.id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    message=msg.message,
                    timestamp=msg.timestamp,
                    is_delivered=msg.is_delivered,
                    encryption_version=msg.encryption_version
                )
            except Exception as e:
                self.logger.error("Error creating message: %s", e)
                raise

    async def get_undelivered_messages(self, recipient_id: int) -> list[MessageDomain]:
        async with self.db_manager.session() as session:
            try:
                stmt = select(Message).where(
                    Message.recipient_id == recipient_id,
                    Message.is_delivered == False
                )
                result = await session.execute(stmt)
                messages = result.scalars().all()
                return [
                    MessageDomain(
                        id=m.id,
                        sender_id=m.sender_id,
                        recipient_id=m.recipient_id,
                        message=m.message,
                        timestamp=m.timestamp,
                        is_delivered=m.is_delivered,
                        encryption_version=m.encryption_version
                    ) for m in messages
                ]
            except Exception as e:
                self.logger.error("Error getting messages: %s", e)
                return []

    async def mark_as_delivered(self, message_id: int) -> bool:
        async with self.db_manager.session() as session:
            try:
                stmt = update(Message).where(
                    Message.id == message_id
                ).values(is_delivered=True)
                await session.execute(stmt)
                return True
            except Exception as e:
                self.logger.error("Error marking message delivered: %s", e)
                return False

    async def get_message_by_id(self, message_id: int) -> MessageDomain | None:
        async with self.db_manager.session() as session:
            try:
                stmt = select(Message).where(Message.id == message_id)
                result = await session.execute(stmt)
                msg = result.scalars().first()
                if msg:
                    return MessageDomain(
                        id=msg.id,
                        sender_id=msg.sender_id,
                        recipient_id=msg.recipient_id,
                        message=msg.message,
                        timestamp=msg.timestamp,
                        is_delivered=msg.is_delivered,
                        encryption_version=msg.encryption_version
                    )
                return None
            except Exception as e:
                self.logger.error(f"Error getting message by ID: {e}")
                return None

    async def get_conversation_history(
            self,
            user1_id: int,
            user2_id: int,
            limit: int = 100
    ) -> list[MessageDomain]:
        async with self.db_manager.session() as session:
            try:
                stmt = select(Message).where(
                    ((Message.sender_id == user1_id) & (Message.recipient_id == user2_id)) |
                    ((Message.sender_id == user2_id) & (Message.recipient_id == user1_id))
                ).order_by(Message.timestamp.desc()).limit(limit)

                result = await session.execute(stmt)
                messages = result.scalars().all()
                return [
                    MessageDomain(
                        id=m.id,
                        sender_id=m.sender_id,
                        recipient_id=m.recipient_id,
                        message=m.message,
                        timestamp=m.timestamp,
                        is_delivered=m.is_delivered,
                        encryption_version=m.encryption_version
                    ) for m in messages
                ]
            except Exception as e:
                self.logger.error(f"Error getting conversation history: {e}")
                return []

class KeyExchangeGateway(BaseKeyExchangeGateway):
    __slots__ = "db_manager"

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger(__name__)

    async def get_public_key(self, user_id: int) -> str | None:
        async with self.db_manager.session() as session:
            try:
                stmt = select(User.public_key).where(User.id == user_id)
                result = await session.execute(stmt)
                return result.scalar_one_or_none()
            except Exception as e:
                self.logger.error(f"Error getting public key: {e}")
                return None

    async def update_public_key(self, user_id: int, public_key: str) -> bool:
        async with self.db_manager.session() as session:
            try:
                stmt = update(User).where(
                    User.id == user_id
                ).values(public_key=public_key)
                await session.execute(stmt)
                return True
            except Exception as e:
                self.logger.error(f"Error updating public key: {e}")
                return False