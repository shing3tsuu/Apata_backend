from typing import Awaitable, Optional
from abc import ABC, abstractmethod

from .dto import *

class UserInterface(ABC):
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

    @abstractmethod
    async def get_users_by_name(
            self,
            name: str
    ) -> list[UserDTO]:
        """
        Get users by User.name (first 10 results)
        :param name:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def add_contact_request(
            self,
            sender_id: int,
            receiver_id: int,
            status: str
    ) -> ContactRequestDTO:
        """
        Adds a contact to the database.
        :param sender_id:
        :param receiver_id:
        :param status:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_contact_request(
            self,
            sender_id: int,
            receiver_id: int
    ) -> ContactRequestDTO:
        """
        Gets one contact requests from current user to another.
        :param sender_id:
        :param receiver_id:
        :return:
        """

    @abstractmethod
    async def get_contact_requests(
            self,
            receiver_id: int,
            status: str
    ) -> list[ContactRequestDTO]:
        """
        Gets all waiting contact requests for a user.
        :param receiver_id:
        :param status:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def update_contact_request(
            self,
            sender_id: int,
            receiver_id: int,
            status: str
    ) -> bool:
        """
        Accepts a contact request.
        :param sender_id:
        :param receiver_id:
        :param status:
        :return:
        """
        raise NotImplementedError()

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

    @abstractmethod
    async def get_ecdh_public_key(
            self,
            user_id: int
    ) -> str | None:
        """
        Gets the ecdh public key for a user.
        :param user_id:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def update_ecdh_public_key(
            self,
            user_id: int,
            ecdh_public_key: str
    ) -> bool:
        """
        Updates the ecdh public key for a user.
        :param user_id:
        :param ecdh_public_key:
        :return:
        """
        raise NotImplementedError()


class MessageInterface(ABC):
    @abstractmethod
    async def create_message(
            self,
            sender_id: int,
            recipient_id: int,
            message: bytes
    ) -> MessageDTO:
        """
        Creates a new message in the database.
        :param sender_id:
        :param recipient_id:
        :param message:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def get_messages_after(
            self,
            recipient_id: int,
            last_message_id: int = 0,
            limit: int = 100
    ) -> list[MessageDTO]:
        """
        Gets messages after a certain ID.
        :param recipient_id:
        :param last_message_id:
        :param limit:
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