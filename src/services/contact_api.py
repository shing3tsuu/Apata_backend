from fastapi import FastAPI, status, HTTPException, Depends, APIRouter

from dishka import FromDishka
from dishka.integrations.fastapi import inject

import logging
import base64
import asyncio
import secrets
import json
import redis
from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from src.core.gateways import UserGateway
from src.core.db_manager import DatabaseManager

from .contact_api_models import *

class ContactAPI:
    """
    Main class for contact-related API endpoints.

    Handles user discovery, contact requests, and contact management.
    Integrates with user persistence and Redis for efficient operations.

    Attributes:
        redis: Redis client for caching and temporary storage
        logger: Logger instance for tracking operations
        contact_router: FastAPI router containing contact endpoints
    """
    def __init__(
            self,
            redis: redis.Redis,
            logger: logging.Logger
    ):
        self.redis = redis
        self.logger = logger

        self._contact_router = APIRouter(tags=["Contacts"])

        self._register_endpoints()

    @property
    def contact_router(self) -> APIRouter:
        return self._contact_router

    def get_router(self) -> APIRouter:
        return self._contact_router

    def _register_endpoints(self):
        @self.contact_router.get("/get-users", response_model=list[UserContactResponse])
        @inject
        async def get_users(username: str, user_gateway: FromDishka[UserGateway]):
            """
            Search for users by username.

            Args:
                username: Partial or complete username to search for
                user_gateway: User persistence interface

            Returns:
                List of users matching the search criteria

            Raises:
                HTTPException: If no users are found
            """
            users = await user_gateway.get_users_by_name(username)
            if not users:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            return [
                UserContactResponse(
                    id=user.id,
                    name=user.name,
                    ecdsa_public_key=user.ecdsa_public_key,
                    ecdh_public_key=user.ecdh_public_key
                ) for user in users
            ]

        @self.contact_router.post("/send-contact-request", status_code=status.HTTP_201_CREATED)
        @inject
        async def send_contact_request(request_data: SentContactRequest, user_gateway: FromDishka[UserGateway]):
            """
            Send a contact request to another user.

            Args:
                request_data: Contains sender and receiver IDs
                user_gateway: User persistence interface

            Returns:
                Status confirmation of the operation

            Raises:
                HTTPException: If users not found, self-request, or duplicate request
            """
            sender = await user_gateway.get_user_by_id(request_data.sender_id)
            receiver = await user_gateway.get_user_by_id(request_data.receiver_id)

            if not sender:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Sender user not found"
                )
            if not receiver:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Receiver user not found"
                )

            if sender.id == receiver.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot send contact request to yourself"
                )

            check_contact = await user_gateway.get_contact_request(
                request_data.sender_id,
                request_data.receiver_id
            )

            if check_contact is not None:
                if check_contact.status in ['pending', 'accepted']:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="This contact request already exists"
                    )
                else:
                    success = await user_gateway.update_contact_request(
                        request_data.sender_id,
                        request_data.receiver_id,
                        "pending"
                    )
                    if not success:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to update contact request"
                        )
                    return {"status": "contact request updated to pending"}

            contact = await user_gateway.add_contact_request(
                request_data.sender_id,
                request_data.receiver_id,
                "pending"
            )

            if not contact:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to add contact request"
                )

            return {"status": "success add contact request",}

        @self.contact_router.get("/get-contact-requests", response_model=list[ContactRequestResponse])
        @inject
        async def get_contact_requests(user_id: int, user_gateway: FromDishka[UserGateway]):
            """
            Retrieve pending contact requests for a user.

            Args:
                user_id: ID of the user to retrieve requests for
                user_gateway: User persistence interface

            Returns:
                List of pending contact requests
            """
            contacts = await user_gateway.get_contact_requests(user_id, "pending")

            if not contacts:
                return []

            else:
                return [
                    ContactRequestResponse(
                        sender_id=contact.sender_id,
                        receiver_id=contact.receiver_id,
                        status=contact.status,
                        created_at=contact.created_at
                    ) for contact in contacts
                ]

        @self.contact_router.put("/accept-contact-request", status_code=status.HTTP_200_OK)
        @inject
        async def accept_contact_request(request_data: SentContactRequest, user_gateway: FromDishka[UserGateway]):
            """
            Accept a pending contact request.

            Args:
                request_data: Contains sender and receiver IDs
                user_gateway: User persistence interface

            Returns:
                Status confirmation of acceptance

            Raises:
                HTTPException: If request not found or already processed
            """
            check_contact = await user_gateway.get_contact_request(
                request_data.sender_id,
                request_data.receiver_id
            )

            if check_contact is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Contact request not found"
                )

            if check_contact.status != "pending":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Contact request is already {check_contact.status}"
                )

            contact = await user_gateway.update_contact_request(
                request_data.sender_id,
                request_data.receiver_id,
                "accepted"
            )

            if not contact:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to accept contact request"
                )

            return {"status": "success accept contact request",}

        @self.contact_router.put("/reject-contact-request", status_code=status.HTTP_200_OK)
        @inject
        async def reject_contact_request(request_data: SentContactRequest, user_gateway: FromDishka[UserGateway]):
            """
            Reject a pending contact request.

            Args:
                request_data: Contains sender and receiver IDs
                user_gateway: User persistence interface

            Returns:
                Status confirmation of rejection

            Raises:
                HTTPException: If request not found or already processed
            """
            check_contact = await user_gateway.get_contact_request(
                request_data.sender_id,
                request_data.receiver_id
            )

            if check_contact is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Contact request not found"
                )

            if check_contact.status != "pending":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Contact request is already {check_contact.status}"
                )

            contact = await user_gateway.update_contact_request(
                request_data.sender_id,
                request_data.receiver_id,
                "rejected"
                )

            if not contact:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to reject contact request"
                )

            return {"status": "success reject contact request",}