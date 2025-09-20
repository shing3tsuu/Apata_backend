from fastapi import APIRouter, HTTPException, status, Depends
from dishka.integrations.fastapi import inject
from dishka import FromDishka
import logging
import asyncio
from typing import List, Optional
from datetime import datetime, timedelta
import json
import redis

from ..models.message_api_models import *
from src.core.gateways import MessageGateway
from .auth_api import AuthAPI


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
        MESSAGE_CACHE_TTL: Time-to-live for messages in Redis cache (seconds)
        _background_tasks: Set of background tasks for message management
    """

    def __init__(
            self,
            logger: logging.Logger,
            auth_api: AuthAPI,
            redis: redis.Redis
    ):
        self.logger = logger
        self.auth_api = auth_api
        self.redis = redis

        self._message_router = APIRouter(tags=["Messages"])
        self._register_endpoints()

        self.polling_interval = 3 # seconds
        self.MESSAGE_CACHE_TTL = 60  # seconds

    @property
    def message_router(self) -> APIRouter:
        return self._message_router

    def get_router(self) -> APIRouter:
        return self._message_router

    async def _cache_message_in_redis(
            self,
            sender_id: int,
            recipient_id: int,
            message: bytes,
    ) -> int:
        """
        Store message in Redis cache with automatic expiration.

        Args:
            sender_id: ID of the message sender
            recipient_id: ID of the message recipient
            message: Encrypted message content

        Returns:
            int: Generated message ID

        Notes:
            - Uses Redis pipeline for atomic operations
            - Messages are stored with TTL for automatic cleanup
            - Message IDs are added to recipient's message list
        """
        message_id = self.redis.incr("global:message_id")

        message_data = {
            "id": message_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "message": message.decode('utf-8'),
            "timestamp": datetime.utcnow().isoformat(),
            "is_delivered": False
        }

        pipe = self.redis.pipeline()
        pipe.setex(
            f"message:{message_id}",
            timedelta(seconds=self.MESSAGE_CACHE_TTL),
            json.dumps(message_data)
        )
        pipe.lpush(f"user:{recipient_id}:messages", message_id)
        pipe.execute()

        return message_id

    async def _persist_message_to_db(
            self,
            message_gateway: MessageGateway,
            sender_id: int,
            recipient_id: int,
            message: bytes,
            message_id: int,
    ) -> None:
        """
        Persist message from Redis to database storage.

        Args:
            message_gateway: Database gateway for message operations
            sender_id: ID of the message sender
            recipient_id: ID of the message recipient
            message: Encrypted message content
            message_id: Unique message identifier

        Notes:
            - Checks for duplicate messages before insertion
            - Removes message from Redis after successful persistence
            - Logs errors if database operation fails
        """
        try:
            # Check if message already exists in DB to avoid duplicates
            existing_message = await message_gateway.get_message_by_id(message_id)
            if not existing_message:
                await message_gateway.create_message(
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    message=message
                )
            self.redis.delete(f"message:{message_id}")
            self.redis.lrem(f"user:{recipient_id}:messages", 1, message_id)
        except Exception as e:
            self.logger.error(f"Failed to persist message to DB: {e}")

    async def _get_messages_from_redis(
            self,
            user_id: int,
    ) -> list[MessageResponse]:
        """
        Retrieve user's messages from Redis cache.

        Args:
            user_id: ID of the user whose messages to retrieve

        Returns:
            list[MessageResponse]: List of messages from Redis cache

        Notes:
            - Retrieves messages from user's message list
            - Converts JSON data to MessageResponse objects
            - Only returns messages that still exist in cache
        """
        message_ids = self.redis.lrange(f"user:{user_id}:messages", 0, -1)
        messages = []

        for msg_id in message_ids:
            msg_data = self.redis.get(f"message:{msg_id}")
            if msg_data:
                msg_dict = json.loads(msg_data)
                messages.append(MessageResponse(
                    id=msg_dict['id'],
                    sender_id=msg_dict['sender_id'],
                    recipient_id=msg_dict['recipient_id'],
                    message=msg_dict['message'].encode('utf-8'),
                    timestamp=datetime.fromisoformat(msg_dict['timestamp']),
                    is_delivered=msg_dict['is_delivered']
                ))

        return messages

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
                message_data: Message content and recipient information
                message_gateway: Database gateway for message operations
                token: JWT authentication token

            Returns:
                dict: Message ID and status

            Flow:
                1. Authenticate sender using JWT token
                2. Cache message in Redis with automatic expiration
                3. Initiate async persistence to database
            """
            sender_id = await self.auth_api.get_current_user(token)

            # First, save to Redis
            message_id = await self._cache_message_in_redis(
                sender_id,
                message_data.recipient_id,
                message_data.message
            )

            # Then we save it to the database asynchronously
            asyncio.create_task(
                self._persist_message_to_db(
                    message_gateway,
                    sender_id,
                    message_data.recipient_id,
                    message_data.message,
                    message_id
                )
            )

            return {"id": message_id, "status": "sent"}

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

            Args:
                message_gateway: Database gateway for message operations
                last_message_id: ID of the last received message (for delta polling)
                timeout: Maximum time to wait for new messages (seconds)
                token: JWT authentication token

            Returns:
                PollingResponse: New messages and polling status

            Notes:
                - Checks both Redis cache and database for new messages
                - Implements long-polling to reduce empty responses
                - Returns immediately if new messages are available
            """
            user_id = await self.auth_api.get_current_user(token)
            start_time = asyncio.get_event_loop().time()

            while (asyncio.get_event_loop().time() - start_time) < timeout:
                # Check Redis for new messages
                redis_messages = await self._get_messages_from_redis(user_id)
                # Filter to only include messages with ID > last_message_id
                new_redis_messages = [m for m in redis_messages if m.id > last_message_id]

                if new_redis_messages:
                    return PollingResponse(
                        has_messages=True,
                        messages=new_redis_messages,
                        last_message_id=max(m.id for m in new_redis_messages)
                    )

                # Check database for new messages
                db_messages = await message_gateway.get_messages_after(user_id, last_message_id)
                if db_messages:
                    message_responses = [
                        MessageResponse(
                            id=msg.id,
                            sender_id=msg.sender_id,
                            recipient_id=msg.recipient_id,
                            message=msg.message,
                            timestamp=msg.timestamp,
                            is_delivered=msg.is_delivered
                        ) for msg in db_messages
                    ]
                    return PollingResponse(
                        has_messages=True,
                        messages=message_responses,
                        last_message_id=max(m.id for m in message_responses)
                    )

                await asyncio.sleep(self.polling_interval)

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

            Args:
                ack_data: List of message IDs to acknowledge
                message_gateway: Database gateway for message operations
                token: JWT authentication token

            Returns:
                dict: Acknowledgment status

            Notes:
                - Updates both Redis cache and database records
                - Verifies user authorization for each message
                - Marks messages as delivered in both storage systems
            """
            user_id = await self.auth_api.get_current_user(token)

            for msg_id in ack_data.message_ids:
                # Check both Redis and database for the message
                msg_data = self.redis.get(f"message:{msg_id}")
                if msg_data:
                    msg_dict = json.loads(msg_data)
                    if msg_dict['recipient_id'] != user_id:
                        raise HTTPException(status_code=403, detail="Not authorized")
                    # Mark as delivered in Redis
                    msg_dict['is_delivered'] = True
                    self.redis.setex(f"message:{msg_id}", self.MESSAGE_CACHE_TTL, json.dumps(msg_dict))
                else:
                    # Check database
                    message = await message_gateway.get_message_by_id(msg_id)
                    if message and message.recipient_id != user_id:
                        raise HTTPException(status_code=403, detail="Not authorized")
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
                List[MessageResponse]: Conversation history messages

            Notes:
                - Combines messages from both database and Redis cache
                - Returns messages sorted by timestamp
                - Respects authorization rules for message access
            """
            user_id = await self.auth_api.get_current_user(token)

            # Get history from database
            db_history = await message_gateway.get_conversation_history(
                user_id, other_user_id, limit
            )

            # Get messages from Redis for both directions of the conversation
            redis_messages_user = await self._get_messages_from_redis(user_id)
            redis_messages_other = await self._get_messages_from_redis(other_user_id)

            # Filter Redis messages to only include relevant conversation
            relevant_redis_messages = [
                msg for msg in redis_messages_user + redis_messages_other
                if (msg.sender_id == user_id and msg.recipient_id == other_user_id) or
                               (msg.sender_id == other_user_id and msg.recipient_id == user_id)
            ]

            # Combine and sort all messages
            all_messages = db_history + relevant_redis_messages
            all_messages.sort(key=lambda x: x.timestamp)

            # Return the most recent messages up to the limit
            return all_messages[-limit:]
