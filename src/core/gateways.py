from typing import Awaitable, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, date, time

from sqlalchemy import select, insert, update, delete, Integer, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from abc import ABC
from functools import wraps
from typing import Callable, Optional
import logging

from .database import User, ContactRequest, Message
from .interfaces import UserInterface, MessageInterface
from .dto import UserDTO, ContactRequestDTO, UserWithContactStatusDTO, MessageDTO
from src.config import load_config
from .db_manager import DatabaseManager

class UserGateway(UserInterface):
    __slots__ = ("_db_manager", "_logger")

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self._db_manager = db_manager
        self._logger = logger or logging.getLogger(__name__)

    async def create_user(self, name: str, ecdsa_public_key: str, ecdh_public_key: str) -> UserDTO:
        async with self._db_manager.session() as session:
            try:
                stmt = insert(User).values(
                    name=name,
                    ecdsa_public_key=ecdsa_public_key,
                    ecdh_public_key=ecdh_public_key
                ).returning(User)
                result = await session.execute(stmt)
                user = result.scalars().first()
                return UserDTO(
                    id=user.id,
                    name=user.name,
                    ecdsa_public_key=user.ecdsa_public_key,
                    ecdh_public_key=user.ecdh_public_key
                )
            except Exception as e:
                self._logger.error(f"Error creating user in database: {e}")
                raise

    async def get_user_by_id(self, user_id: int) -> UserDTO | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(User).where(User.id == user_id)
                result = await session.execute(stmt)
                user = result.scalars().first()
                if user:
                    return UserDTO(
                        id=user.id,
                        name=user.name,
                        ecdsa_public_key=user.ecdsa_public_key,
                        ecdh_public_key=user.ecdh_public_key
                    )
                else:
                    return None
            except Exception as e:
                self._logger.error(f"Error getting user by id in database: %s", e)
                return None

    async def get_users_by_ids(self, user_ids: list[int]) -> list[UserDTO]:
        async with self._db_manager.session() as session:
            try:
                if not user_ids:
                    return []

                stmt = select(User).where(User.id.in_(user_ids))
                result = await session.execute(stmt)
                users = result.scalars().all()

                return [
                    UserDTO(
                        id=user.id,
                        name=user.name,
                        ecdsa_public_key=user.ecdsa_public_key,
                        ecdh_public_key=user.ecdh_public_key
                    )
                    for user in users
                ]
            except Exception as e:
                self._logger.error(f"Error getting users by ids in database: %s", e)
                return []

    async def get_user_by_name(self, name: str) -> UserDTO | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(User).where(User.name == name)
                result = await session.execute(stmt)
                user = result.scalars().first()
                if user:
                    return UserDTO(
                        id=user.id,
                        name=user.name,
                        ecdsa_public_key=user.ecdsa_public_key,
                        ecdh_public_key=user.ecdh_public_key
                        )
                else:
                    return None
            except Exception as e:
                self._logger.error("Error getting user by name in database: %s", e)
                return None

    async def get_users_by_name(self, name: str) -> list[UserDTO] | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(User).where(
                        User.name.ilike(f"%{name}%"),
                ).limit(10)
                result = await session.execute(stmt)
                users = result.scalars().all()
                if not users:
                    return None
                else:
                    return [
                        UserDTO(
                            id=user.id,
                            name=user.name,
                            ecdsa_public_key=user.ecdsa_public_key,
                            ecdh_public_key=user.ecdh_public_key
                            ) for user in users
                    ]
            except Exception as e:
                self._logger.error("Error getting users by name in database: %s", e)
                return None

    async def get_contacts_by_user_id(self, user_id: int) -> list[ContactRequestDTO]:
        async with self._db_manager.session() as session:
            try:
                stmt = select(ContactRequest).where(
                    or_(
                        and_(
                            ContactRequest.sender_id == user_id,
                        ),
                        and_(
                            ContactRequest.receiver_id == user_id
                        )
                    )
                )
                result = await session.execute(stmt)
                contacts = result.scalars().all()

                return [
                    ContactRequestDTO(
                        id=contact.id,
                        sender_id=contact.sender_id,
                        receiver_id=contact.receiver_id,
                        status=contact.status,
                        created_at=contact.created_at
                    ) for contact in contacts
                ]
            except Exception as e:
                self._logger.error(f"Error getting contacts by user id in database: {e}")
                return []

    async def get_users_with_contact_status_by_ids(
            self,
            current_user_id: int,
            user_ids: list[int]
    ) -> list[UserWithContactStatusDTO]:
        async with self._db_manager.session() as session:
            try:
                if not user_ids:
                    return []

                stmt = select(User).where(User.id.in_(user_ids))
                result = await session.execute(stmt)
                users = result.scalars().all()

                contact_stmt = select(ContactRequest).where(
                    or_(
                        and_(
                            ContactRequest.sender_id == current_user_id,
                            ContactRequest.receiver_id.in_(user_ids)
                        ),
                        and_(
                            ContactRequest.sender_id.in_(user_ids),
                            ContactRequest.receiver_id == current_user_id
                        )
                    )
                )
                contact_result = await session.execute(contact_stmt)
                contacts = contact_result.scalars().all()

                contact_dict = {}
                for contact in contacts:
                    if contact.sender_id == current_user_id:
                        contact_dict[contact.receiver_id] = contact.status
                    else:
                        contact_dict[contact.sender_id] = contact.status

                result_users = []
                for user in users:
                    status = contact_dict.get(user.id, 'none')
                    result_users.append(
                        UserWithContactStatusDTO(
                            id=user.id,
                            name=user.name,
                            ecdsa_public_key=user.ecdsa_public_key,
                            ecdh_public_key=user.ecdh_public_key,
                            status=status
                        )
                    )

                return result_users

            except Exception as e:
                self._logger.error(f"Error getting users with contact status by ids in database: {e}")
                return []

    async def add_contact_request(self, sender_id: int, receiver_id: int, status: str) -> ContactRequestDTO:
        async with self._db_manager.session() as session:
            try:
                stmt = insert(ContactRequest).values(
                    sender_id=sender_id,
                    receiver_id=receiver_id,
                    status=status
                ).returning(ContactRequest)

                result = await session.execute(stmt)
                contact = result.scalars().first()

                return ContactRequestDTO(
                    id=contact.id,
                    sender_id=contact.sender_id,
                    receiver_id=contact.receiver_id,
                    status=contact.status,
                    created_at=contact.created_at
                )

            except Exception as e:
                self._logger.error(f"Error adding contact in database: {e}")
                raise

    async def get_contact_request(self, sender_id: int, receiver_id: int) -> ContactRequestDTO | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(ContactRequest).where(
                    ContactRequest.sender_id == sender_id,
                    ContactRequest.receiver_id == receiver_id
                )
                result = await session.execute(stmt)
                contact = result.scalars().first()

                if contact is None:
                    return None

                return ContactRequestDTO(
                    id=contact.id,
                    sender_id=contact.sender_id,
                    receiver_id=contact.receiver_id,
                    status=contact.status,
                    created_at=contact.created_at
                    )

            except Exception as e:
                self._logger.error(f"Error getting contact requests in database: {e}")
                return None

    async def get_contact_requests(self, receiver_id: int, status: str) -> list[ContactRequestDTO] | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(ContactRequest).where(
                    ContactRequest.receiver_id == receiver_id,
                    ContactRequest.status == status
                )
                result = await session.execute(stmt)
                contacts = result.scalars().all()

                if not contacts:
                    return []

                else:
                    return [
                        ContactRequestDTO(
                        id=contact.id,
                        sender_id=contact.sender_id,
                        receiver_id=contact.receiver_id,
                        status=contact.status,
                        created_at=contact.created_at
                        ) for contact in contacts
                    ]

            except Exception as e:
                self._logger.error(f"Error getting contact requests in database: {e}")
                return None

    async def update_contact_request(self, sender_id: int, receiver_id: int, status: str) -> bool:
        async with self._db_manager.session() as session:
            try:
                stmt = update(ContactRequest).where(
                    ContactRequest.sender_id == sender_id,
                    ContactRequest.receiver_id == receiver_id
                ).values(status=status)

                await session.execute(stmt)
                return True

            except Exception as e:
                self._logger.error(f"Error accepting contact request in database: {e}")
                return False

    async def get_ecdsa_public_key(self, user_id: int) -> str | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(User.ecdsa_public_key).where(User.id == user_id)
                result = await session.execute(stmt)
                return result.scalar_one_or_none()

            except Exception as e:
                self._logger.error(f"Error getting ecdsa public key in database: {e}")
                return None

    async def update_ecdsa_public_key(self, user_id: int, ecdsa_public_key: str) -> bool:
        async with self._db_manager.session() as session:
            try:
                stmt = update(User).where(
                    User.id == user_id
                ).values(ecdsa_public_key=ecdsa_public_key)
                await session.execute(stmt)

                return True

            except Exception as e:
                self._logger.error(f"Error updating ecdsa public key in database: {e}")
                return False

    async def get_ecdh_public_key(self, user_id: int) -> str | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(User.ecdh_public_key).where(User.id == user_id)
                result = await session.execute(stmt)

                return result.scalar_one_or_none()

            except Exception as e:
                self._logger.error(f"Error getting ecdh public key in database: {e}")
                return None

    async def update_ecdh_public_key(self, user_id: int, ecdh_public_key: str) -> bool:
        async with self._db_manager.session() as session:
            try:
                stmt = update(User).where(
                    User.id == user_id
                ).values(ecdh_public_key=ecdh_public_key)
                await session.execute(stmt)

                return True

            except Exception as e:
                self._logger.error(f"Error updating ecdh public key in database: {e}")
                return False

class MessageGateway(MessageInterface):
    __slots__ = ("_db_manager", "_logger")

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger):
        self._db_manager = db_manager
        self._logger = logger

    async def wait_for_undelivered_messages(self, user_id: int, timeout: int = 30) -> list[MessageDTO]:
        # First we check if there are any messages without waiting
        messages = await self.get_undelivered_messages(user_id)
        if messages:
            return messages

        # Waiting for notification from PostgreSQL
        notified = await self._db_manager.wait_for_user_notification(user_id, timeout)
        if notified:
            # After notification, check messages again
            return await self.get_undelivered_messages(user_id)

        return []

    async def create_message_and_notify(self, sender_id: int, recipient_id: int, message: bytes) -> MessageDTO:
        async with self._db_manager.session() as session:
            try:
                # Create a message
                stmt = insert(Message).values(
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    message=message
                ).returning(Message)
                result = await session.execute(stmt)
                msg = result.scalars().first()

                # Notify the recipient
                await self._db_manager.notify_user(recipient_id)

                return MessageDTO(
                    id=msg.id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    message=msg.message,
                    timestamp=msg.timestamp,
                    is_delivered=msg.is_delivered
                )

            except Exception as e:
                self._logger.error("Error creating message and notifying: %s", e)
                raise

    async def create_message(self, sender_id: int, recipient_id: int, message: bytes)\
            -> MessageDTO:
        async with self._db_manager.session() as session:
            try:
                stmt = insert(Message).values(
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    message=message
                ).returning(Message)
                result = await session.execute(stmt)
                msg = result.scalars().first()

                return MessageDTO(
                    id=msg.id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    message=msg.message,
                    timestamp=msg.timestamp,
                    is_delivered=msg.is_delivered
                )

            except Exception as e:
                self._logger.error("Error creating message in database: %s", e)
                raise

    async def get_undelivered_messages(self, recipient_id: int) -> list[MessageDTO]:
        async with self._db_manager.session() as session:
            try:
                stmt = select(Message).where(
                    Message.recipient_id == recipient_id,
                    Message.is_delivered == False
                )
                result = await session.execute(stmt)
                messages = result.scalars().all()

                return [
                    MessageDTO(
                        id=m.id,
                        sender_id=m.sender_id,
                        recipient_id=m.recipient_id,
                        message=m.message,
                        timestamp=m.timestamp,
                        is_delivered=m.is_delivered
                    ) for m in messages
                ]

            except Exception as e:
                self._logger.error("Error getting messages in database: %s", e)
                return []

    async def mark_as_delivered(self, message_id: int) -> bool:
        async with self._db_manager.session() as session:
            try:
                stmt = update(Message).where(
                    Message.id == message_id
                ).values(is_delivered=True)
                await session.execute(stmt)

                return True

            except Exception as e:
                self._logger.error("Error marking message delivered in database: %s", e)
                return False

    async def get_message_by_id(self, message_id: int) -> MessageDTO | None:
        async with self._db_manager.session() as session:
            try:
                stmt = select(Message).where(Message.id == message_id)
                result = await session.execute(stmt)
                msg = result.scalars().first()

                if msg:
                    return MessageDTO(
                        id=msg.id,
                        sender_id=msg.sender_id,
                        recipient_id=msg.recipient_id,
                        message=msg.message,
                        timestamp=msg.timestamp,
                        is_delivered=msg.is_delivered
                    )
                return None

            except Exception as e:
                self._logger.error(f"Error getting message by ID in database: {e}")
                return None
