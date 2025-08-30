from typing import Awaitable, Optional
from abc import ABC, abstractmethod

from .dto import *

class BaseUserGateway(ABC):
    @abstractmethod
    async def create_user(
            self,
            name: str,
            ecdsa_public_key: str | None,
            ecdh_public_key: str | None
    ) -> UserDTO:
        """
        Creates a new user in the database.
        :param name:
        :param ecdsa_public_key:
        :param ecdh_public_key
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_user_by_id(
            self,
            user_id: int
    ) -> UserDTO | None:
        """
        Get user by user.id
        :param user_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_user_by_name(
            self,
            name: str
    ) -> UserDTO | None:
        """
        Get user by User.name
        :param name:
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
    ) -> MessageDTO:
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
    ) -> list[MessageDTO]:
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
    ) -> MessageDTO | None:
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
    ) -> list[MessageDTO]:
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
    async def get_ecdsa_public_key(
            self,
            user_id: int
    ) -> str | None:
        """
        Gets the ecdsa public key for a user.
        :param user_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def update_ecdsa_public_key(
            self,
            user_id: int,
            ecdsa_public_key: str
    ) -> bool:
        """
        Updates the ecdsa public key for a user.
        :param user_id:
        :param ecdsa_public_key:
        :return:
        """

        raise NotImplementedError()
