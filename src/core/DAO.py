from typing import Awaitable, Optional
from abc import ABC, abstractmethod

from .DTO import *

class BaseUserGateway(ABC):
    @abstractmethod
    async def create_user(
            self,
            name: str,
            hashed_password: str,
            public_key: str | None
    ) -> UserDomain:
        """
        Creates a new user in the database.
        :param name:
        :param hashed_password:
        :param public_key:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_user_by_name(
            self,
            name: str
    ) -> UserDomain | None:
        raise NotImplementedError()


class BaseContactGateway(ABC):
    @abstractmethod
    async def create_contact(
            self, owner_id: int,
            contact_id: int
    ) -> ContactDomain:
        """
        Creates a new contact in the database.
        :param owner_id:
        :param contact_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def delete_contact(
            self,
            contact_id: int
    ) -> bool:
        """
        Deletes a contact from the database.
        :param contact_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_contacts(
            self,
            owner_id: int
    ) -> list[ContactDomain]:
        """
        Gets all contacts for a user.
        :param owner_id:
        :return:
        """
        raise NotImplementedError()


class BaseMessageGateway(ABC):
    @abstractmethod
    async def create_message(
            self,
            sender_id: int,
            recipient_id: int,
            message: bytes,
            encryption_version: int
    ) -> MessageDomain:
        """
        Creates a new message in the database.
        :param sender_id:
        :param recipient_id:
        :param message:
        :param encryption_version:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_undelivered_messages(
            self,
            recipient_id: int
    ) -> list[MessageDomain]:
        """
        Gets all undelivered messages for a user.
        :param recipient_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def mark_as_delivered(
            self,
            message_id: int
    ) -> bool:
        """
        Marks a message as delivered.
        :param message_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_message_by_id(
            self,
            message_id: int
    ) -> MessageDomain | None:
        """
        Gets a message by ID.
        :param message_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_conversation_history(
            self,
            user1_id: int,
            user2_id: int,
            limit: int = 100
    ) -> list[MessageDomain]:
        """
        Gets the conversation history between two users.
        :param user1_id:
        :param user2_id:
        :param limit:
        :return:
        """
        raise NotImplementedError()

class BaseKeyExchangeGateway(ABC):
    @abstractmethod
    async def get_public_key(
            self,
            user_id: int
    ) -> str | None:
        """
        Gets the public key for a user.
        :param user_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def update_public_key(
            self,
            user_id: int,
            public_key: str
    ) -> bool:
        """
        Updates the public key for a user.
        :param user_id:
        :param public_key:
        :return:
        """
        raise NotImplementedError()