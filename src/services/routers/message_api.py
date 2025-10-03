from fastapi import APIRouter, HTTPException, status, Depends
from dishka.integrations.fastapi import inject
from dishka import FromDishka
import logging
from typing import List
from datetime import datetime

from ..models.message_api_models import *
from src.core.gateways import MessageGateway
from .auth_api import AuthAPI


class MessageAPI:
    """
    Simplified message API handler for direct database operations.

    Provides endpoints for sending messages, polling for new messages,
    acknowledging delivery, and retrieving conversation history.
    All operations work directly with the database without Redis caching.

    Attributes:
        logger: Logger instance for tracking operations
        auth_api: Authentication API instance for user validation
        message_router: FastAPI router containing message endpoints
        polling_interval: Time interval between polling checks (seconds)
    """

    def __init__(
            self,
            logger: logging.Logger,
            auth_api: AuthAPI,
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
            sender_id = await self.auth_api.get_current_user(token)

            # Save the message and notify the recipient
            message = await message_gateway.create_message_and_notify(
                sender_id=sender_id,
                recipient_id=message_data.recipient_id,
                message=message_data.message
            )

            return {"id": message.id, "status": "sent"}

        @self.message_router.get("/poll", response_model=PollingResponse)
        @inject
        async def real_long_polling(
                message_gateway: FromDishka[MessageGateway],
                timeout: int = 30,
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            user_id = await self.auth_api.get_current_user(token)

            # Waiting for messages
            messages = await message_gateway.wait_for_undelivered_messages(user_id, timeout)

            if messages:
                message_responses = [
                    MessageResponse(
                        id=msg.id,
                        sender_id=msg.sender_id,
                        recipient_id=msg.recipient_id,
                        message=msg.message,
                        timestamp=msg.timestamp,
                        is_delivered=msg.is_delivered
                    ) for msg in messages
                ]
                return PollingResponse(
                    has_messages=True,
                    messages=message_responses,
                    last_message_id=max(m.id for m in messages) if messages else None
                )

            return PollingResponse(has_messages=False)

        @self.message_router.post("/ack")
        @inject
        async def ack_messages(
                ack_data: AckRequest,
                message_gateway: FromDishka[MessageGateway],
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            user_id = await self.auth_api.get_current_user(token)

            for msg_id in ack_data.message_ids:
                # Verify message exists and user has permission to acknowledge it
                message = await message_gateway.get_message_by_id(msg_id)
                if not message:
                    continue

                # Check authorization - only recipient can acknowledge delivery
                if message.recipient_id != user_id:
                    raise HTTPException(status_code=403, detail="Not authorized")

                # Mark message as delivered in database
                await message_gateway.mark_as_delivered(msg_id)

            return {"status": "acknowledged"}
