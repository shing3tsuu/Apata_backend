from fastapi import APIRouter, HTTPException, status, Depends
from dishka.integrations.fastapi import inject
from dishka import FromDishka
import logging
import asyncio
from typing import List, Optional

from .message_api_models import *
from src.core.gateways import MessageGateway
from src.services.auth_api import AuthAPI


class MessageAPI:
    """
    Main class for message-related API endpoints.

    Handles message sending, polling, delivery acknowledgment, and history retrieval.
    Integrates with authentication and message persistence layers.

    Attributes:
        logger: Logger instance for tracking operations
        auth_api: Authentication API instance for user validation
        message_router: FastAPI router containing message endpoints
        polling_interval: Time interval for checking new messages during polling
    """

    def __init__(
            self,
            logger: logging.Logger,
            auth_api: AuthAPI
    ):

        self.logger = logger
        self.auth_api = auth_api
        self._message_router = APIRouter(tags=["Messages"])
        self._register_endpoints()
        self.polling_interval = 3  # seconds

    @property
    def message_router(self) -> APIRouter:
        return self._message_router

    def get_router(self) -> APIRouter:
        return self._message_router

    def _register_endpoints(self):
        @self.message_router.post("/send", status_code=status.HTTP_201_CREATED)
        @inject
        async def send_message(
                message_data: MessageSendRequest,
                message_gateway: FromDishka[MessageGateway],
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Send a new message to a recipient.

            Args:
                message_data: Contains recipient ID and message content
                message_gateway: Message persistence interface
                token: JWT authentication token

            Returns:
                Dictionary with message ID and status

            Raises:
                HTTPException: If authentication fails or message delivery fails
            """
            sender_id = await self.auth_api.get_current_user(token)

            new_message = await message_gateway.create_message(
                sender_id=sender_id,
                recipient_id=message_data.recipient_id,
                message=message_data.message
            )

            return {"id": new_message.id, "status": "sent"}

        @self.message_router.get("/poll", response_model=PollingResponse)
        @inject
        async def poll_messages(
                message_gateway: FromDishka[MessageGateway],
                last_message_id: int = 0,
                timeout: int = 30, # seconds
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Poll for new messages using long-polling technique.

            Checks for new messages immediately and waits for new messages if none are found,
            up to the specified timeout duration.

            Args:
                message_gateway: Message persistence interface
                last_message_id: ID of last received message (default 0)
                timeout: Maximum time to wait for new messages in seconds
                token: JWT authentication token

            Returns:
                PollingResponse containing new messages if available, or empty response
            """
            user_id = await self.auth_api.get_current_user(token)
            start_time = asyncio.get_event_loop().time()

            new_messages = await message_gateway.get_messages_after(
                user_id, last_message_id
            )

            # Convert MessageDTO to MessageResponse
            message_responses = [
                MessageResponse(
                    id=msg.id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    message=msg.message,
                    timestamp=msg.timestamp,
                    is_delivered=msg.is_delivered
                ) for msg in new_messages
            ]

            if message_responses:
                last_id = max(m.id for m in message_responses)
                return PollingResponse(
                    has_messages=True,
                    messages=message_responses,
                    last_message_id=last_id
                )

            while (asyncio.get_event_loop().time() - start_time) < timeout:
                await asyncio.sleep(self.polling_interval)

                new_messages = await message_gateway.get_messages_after(
                    user_id, last_message_id
                )

                # Convert MessageDTO to MessageResponse
                message_responses = [
                    MessageResponse(
                        id=msg.id,
                        sender_id=msg.sender_id,
                        recipient_id=msg.recipient_id,
                        message=msg.message,
                        timestamp=msg.timestamp,
                        is_delivered=msg.is_delivered
                    ) for msg in new_messages
                ]

                if message_responses:
                    last_id = max(m.id for m in message_responses)
                    return PollingResponse(
                        has_messages=True,
                        messages=message_responses,
                        last_message_id=last_id
                    )

            return PollingResponse(
                has_messages=False,
                last_message_id=last_message_id
            )

        @self.message_router.post("/ack")
        @inject
        async def ack_messages(
                ack_data: AckRequest,
                message_gateway: FromDishka[MessageGateway],
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Acknowledge delivery of messages.

            Marks specified messages as delivered after verifying ownership.

            Args:
                ack_data: Contains list of message IDs to acknowledge
                message_gateway: Message persistence interface
                token: JWT authentication token

            Returns:
                Status confirmation

            Raises:
                HTTPException: If user doesn't own specified messages
            """
            user_id = await self.auth_api.get_current_user(token)

            for msg_id in ack_data.message_ids:
                message = await message_gateway.get_message_by_id(msg_id)
                if message and message.recipient_id != user_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Message {msg_id} does not belong to user {user_id}"
                    )

            for msg_id in ack_data.message_ids:
                success = await message_gateway.mark_as_delivered(msg_id)
                if not success:
                    self.logger.warning(f"Failed to mark message {msg_id} as delivered")

            return {"status": "acknowledged"}

        @self.message_router.get("/history/{other_user_id}", response_model=List[MessageResponse])
        @inject
        async def get_conversation_history(
                message_gateway: FromDishka[MessageGateway],
                other_user_id: int,
                limit: int = 100,
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Retrieve conversation history with another user.

            Args:
                message_gateway: Message persistence interface
                other_user_id: ID of the other conversation participant
                limit: Maximum number of messages to retrieve (default 100)
                token: JWT authentication token

            Returns:
                List of historical messages with the specified user
            """
            user_id = await self.auth_api.get_current_user(token)

            history = await message_gateway.get_conversation_history(
                user_id, other_user_id, limit
            )

            # Convert MessageDTO to MessageResponse
            return [
                MessageResponse(
                    id=msg.id,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    message=msg.message,
                    timestamp=msg.timestamp,
                    is_delivered=msg.is_delivered
                ) for msg in history
            ]