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
        """Get the FastAPI router with registered message endpoints."""
        return self._message_router

    def get_router(self) -> APIRouter:
        """Get the FastAPI router (alias for message_router property)."""
        return self._message_router

    def _register_endpoints(self):
        """Register all message-related API endpoints."""
        
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
                message_data: Message content and recipient information
                message_gateway: Database gateway for message operations
                token: JWT authentication token
                
            Returns:
                dict: Message ID and status confirmation
                
            Raises:
                HTTPException: If authentication fails
            """
            sender_id = await self.auth_api.get_current_user(token)

            # Save message directly to database
            message = await message_gateway.create_message(
                sender_id=sender_id,
                recipient_id=message_data.recipient_id,
                message=message_data.message
            )

            return {"id": message.id, "status": "sent"}

        @self.message_router.get("/poll", response_model=PollingResponse)
        @inject
        async def poll_messages(
                message_gateway: FromDishka[MessageGateway],
                last_message_id: int = 0,
                timeout: int = 30,
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Poll for new messages using long-polling approach.
            
            Checks for new messages at regular intervals until timeout is reached
            or new messages are found.
            
            Args:
                message_gateway: Database gateway for message operations
                last_message_id: ID of the last received message (for delta polling)
                timeout: Maximum time to wait for new messages (seconds)
                token: JWT authentication token
                
            Returns:
                PollingResponse: New messages and polling status
                
            Notes:
                - Uses long-polling to reduce empty responses
                - Returns immediately when new messages are available
                - Returns empty response after timeout if no new messages
            """
            user_id = await self.auth_api.get_current_user(token)
            start_time = datetime.utcnow()

            # Poll for new messages until timeout
            while (datetime.utcnow() - start_time).total_seconds() < timeout:
                # Check database for new messages since last_message_id
                new_messages = await message_gateway.get_messages_after(user_id, last_message_id)
                
                if new_messages:
                    # Convert database models to response models
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
                    
                    return PollingResponse(
                        has_messages=True,
                        messages=message_responses,
                        last_message_id=max(m.id for m in message_responses)
                    )

                # Wait before next polling check
                import asyncio
                await asyncio.sleep(self.polling_interval)

            # Return empty response if timeout reached
            return PollingResponse(has_messages=False)

        @self.message_router.post("/ack")
        @inject
        async def ack_messages(
                ack_data: AckRequest,
                message_gateway: FromDishka[MessageGateway],
                token: str = Depends(self.auth_api.oauth2_scheme)
        ):
            """
            Acknowledge delivery of messages.
            
            Marks specified messages as delivered in the database.
            
            Args:
                ack_data: List of message IDs to acknowledge
                message_gateway: Database gateway for message operations
                token: JWT authentication token
                
            Returns:
                dict: Acknowledgment status
                
            Raises:
                HTTPException: If user is not authorized to acknowledge messages
            """
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
                message_gateway: Database gateway for message operations
                other_user_id: ID of the conversation partner
                limit: Maximum number of messages to return
                token: JWT authentication token
                
            Returns:
                List[MessageResponse]: Conversation history messages, sorted by timestamp
                
            Notes:
                - Returns most recent messages up to the specified limit
                - Includes messages in both directions of the conversation
            """
            user_id = await self.auth_api.get_current_user(token)

            # Retrieve conversation history from database
            history = await message_gateway.get_conversation_history(
                user_id, other_user_id, limit
            )

            return history
