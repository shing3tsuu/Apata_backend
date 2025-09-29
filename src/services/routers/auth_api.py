from fastapi import FastAPI, status, HTTPException, Depends, APIRouter, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from dishka import FromDishka
from dishka.integrations.fastapi import inject

import logging
import base64
import asyncio
import secrets
import json
import redis

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from src.core.gateways import UserGateway
from ..models.auth_api_models import *


class AuthAPI:
    """
    Authentication API service that handles user authentication and authorization.
    This class provides cryptographic authentication using ECDSA signatures,
    JWT token generation/validation, and user public key management.
    Attributes:
        SECRET_KEY (str): Secret key for JWT token signing
        ALGORITHM (str): JWT signing algorithm (HS256)
        ACCESS_TOKEN_EXPIRE_MINUTES (int): JWT token expiration time in minutes
        CHALLENGE_EXPIRE_MINUTES (int): Challenge expiration time in minutes
        redis (redis.Redis): Redis client for challenge storage
        logger (logging.Logger): Logger instance
        oauth2_scheme (OAuth2PasswordBearer): OAuth2 password bearer scheme
        _auth_router (APIRouter): FastAPI router for authentication endpoints
    """
    def __init__(
            self,
            secret_key: str,
            redis: redis.Redis,
            logger: logging.Logger
    ):
        """
        Initialize AuthAPI with configuration and dependencies.
        Args:
            secret_key: Secret key for JWT token signing
            redis: Redis instance for challenge storage
            logger: Logger instance for logging
        """
        self.SECRET_KEY = secret_key
        self.ALGORITHM = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = 480 # 8 hours
        self.CHALLENGE_EXPIRE_MINUTES: int = 5
        self.redis = redis
        self.logger = logger
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
        self._auth_router = APIRouter(tags=["Authentication"])
        self._register_endpoints()

    @property
    def auth_router(self) -> APIRouter:
        return self._auth_router

    def get_router(self) -> APIRouter:
        return self._auth_router

    def create_access_token(self, user_id: int) -> str:
        """
        Create JWT access token for authenticated user.
        Args:
            user_id: User ID to include in the token payload
        Returns:
            str: Encoded JWT access token
        Raises:
            Exception: If token creation fails
        """
        try:
            expires_delta = timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
            expire = datetime.now(timezone.utc) + expires_delta

            payload = {
                "sub": str(user_id),
                "exp": expire,
                "type": "access",
                "iat": datetime.now(timezone.utc)
            }
            return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)
        except Exception as e:
            self.logger.error("Error creating access token: %s", str(e), exc_info=True)
            raise

    async def get_current_user(self, token: str) -> int:
        """
        Validate JWT token and extract user ID.
        Args:
            token: JWT token string
        Returns:
            int: User ID extracted from token
        Raises:
            HTTPException: If token is invalid, expired, or has wrong type
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])

            # Check token type
            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )

            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                )
            return int(user_id)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        except (JWTError, ValueError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            ) from e
        except Exception as e:
            self.logger.critical("Error validating token: %s", str(e), exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    async def verify_signature(self, public_key_pem: str, challenge: str, signature: str) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._verify_signature, public_key_pem, challenge, signature)

    def _verify_signature(self, public_key_pem: str, challenge: str, signature: str) -> bool:
        """
        Synchronously verify ECDSA signature using user's public key.
        Args:
            public_key_pem: PEM-formatted ECDSA public key
            challenge: Original challenge string that was signed
            signature: Base64-encoded signature to verify
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            ecdsa_public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            # Decode signature from base64
            signature_bytes = base64.b64decode(signature)

            # Verify signature using ECDSA with SHA384
            ecdsa_public_key.verify(
                signature_bytes,
                challenge.encode(),
                ec.ECDSA(hashes.SHA384())
            )
            return True
        except (InvalidSignature, ValueError):
            return False
        except Exception as e:
            self.logger.error("Error verifying signature: %s", str(e), exc_info=True)
            return False

    def _validate_public_key_format(self, key: str) -> bool:
        """
        Basic validation of PEM key format.
        Args:
            key: Public key string to validate
        Returns:
            bool: True if key appears to be in valid PEM format, False otherwise
        """
        if not key or not isinstance(key, str):
            return False
        return key.startswith('-----BEGIN') and 'KEY-----' in key

    def _register_endpoints(self):
        """
        Register all authentication endpoints with the FastAPI router.

        This method sets up the following endpoints:
        - GET /health: Health check
        - POST /register: User registration
        - GET /challenge/{username}: Get authentication challenge
        - POST /login: User login with signed challenge
        - POST /logout: User logout
        - GET /public-keys/{user_id}: Get user's public keys
        - PUT /ecdsa-update-key: Update ECDSA public key
        - PUT /ecdh-update-key: Update ECDH public key
        - GET /me: Get current user information
        """
        @self.auth_router.get("/health")
        async def health_check():
            """
            Health check endpoint to verify service status and Redis connectivity.
            Returns:
                dict: Health status with timestamp and service information
            Raises:
                HTTPException: If Redis is unavailable or service is unhealthy
            """
            try:
                # Check Redis connection
                self.redis.ping()
                return {
                    "status": "healthy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "service": "auth",
                    "redis": "connected"
                }
            except Exception as e:
                self.logger.error("Health check failed: %s", str(e))
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Service unavailable"
                )

        @self.auth_router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserRegisterResponse)
        @inject
        async def register(
                user_data: UserRegisterRequest,
                user_gateway: FromDishka[UserGateway]
        ):
            """
            Register new user with ECDSA and ECDH public keys.
            Args:
                user_data: User registration data including username and public keys
                user_gateway: User gateway for database operations
            Returns:
                UserRegisterResponse: Created user information
            Raises:
                HTTPException: If public keys are invalid or username already exists
            """
            # Validate public keys format
            if not self._validate_public_key_format(user_data.ecdsa_public_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid ECDSA public key format"
                )

            if user_data.ecdh_public_key and not self._validate_public_key_format(user_data.ecdh_public_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid ECDH public key format"
                )

            existing_user = await user_gateway.get_user_by_name(user_data.username)
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists"
                )

            user = await user_gateway.create_user(
                name=user_data.username,
                ecdsa_public_key=user_data.ecdsa_public_key,
                ecdh_public_key=user_data.ecdh_public_key
            )

            self.logger.info("New user registered: %s (ID: %s)", user_data.username, user.id)
            return UserRegisterResponse(id=user.id, username=user.name)

        @self.auth_router.get("/challenge/{username}")
        @inject
        async def get_challenge(
                username: str,
                user_gateway: FromDishka[UserGateway]
        ):
            """
            Request authentication challenge for user.
            Generates a random challenge and stores it in Redis for verification during login.
            Args:
                username: Username to generate challenge for
                user_gateway: User gateway for database operations
            Returns:
                dict: Challenge string and expiration timestamp
            Raises:
                HTTPException: If user is not found
            """
            user = await user_gateway.get_user_by_name(username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Generate random challenge
            challenge = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(minutes=self.CHALLENGE_EXPIRE_MINUTES)

            # Store challenge in Redis
            challenge_data = {
                "challenge": challenge,
                "expires": expires.isoformat(),
                "user_id": user.id
            }
            self.redis.setex(
                f"challenge:{username}",
                timedelta(minutes=self.CHALLENGE_EXPIRE_MINUTES),
                json.dumps(challenge_data)
            )

            self.logger.debug("Generated challenge for user: %s", username)
            return {"challenge": challenge, "expires": expires.isoformat()}

        @self.auth_router.post("/login", response_model=Dict[str, Any])
        @inject
        async def login(
                login_data: ChallengeLoginRequest,
                user_gateway: FromDishka[UserGateway]
        ):
            """
            Authenticate user using signed challenge response.
            Verifies the cryptographic signature of the challenge using the user's ECDSA public key.
            Args:
                login_data: Login data containing username and signature
                user_gateway: User gateway for database operations
            Returns:
                dict: JWT access token and token information
            Raises:
                HTTPException: If challenge is invalid, expired, or signature verification fails
            """
            # Check if challenge exists in Redis
            challenge_key = f"challenge:{login_data.username}"
            challenge_data_json = self.redis.get(challenge_key)
            if not challenge_data_json:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Challenge not found or expired"
                )

            challenge_data = json.loads(challenge_data_json)

            # Check challenge expiration
            expires = datetime.fromisoformat(challenge_data["expires"].replace('Z', '+00:00'))
            if datetime.now(timezone.utc) > expires:
                self.redis.delete(challenge_key)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Challenge expired"
                )

            # Get user and public key
            user = await user_gateway.get_user_by_name(login_data.username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Verify signature
            is_valid = await self.verify_signature(
                user.ecdsa_public_key,
                challenge_data["challenge"],
                login_data.signature
            )

            if not is_valid:
                self.logger.warning("Invalid signature for user: %s", login_data.username)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid signature"
                )

            # Remove used challenge from Redis
            self.redis.delete(challenge_key)

            # Create access token
            access_token = self.create_access_token(user.id)

            self.logger.info("User logged in: %s (ID: %s)", login_data.username, user.id)
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": self.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }

        @self.auth_router.post("/logout")
        async def logout():
            """
            Logout user (client-side token invalidation).
            Note: This is a stateless logout since JWT tokens are client-side.
            Actual token invalidation should be handled client-side.
            Returns:
                dict: Success status message
            """
            self.logger.debug("User logged out")
            return {"status": "success", "message": "Logged out successfully"}

        @self.auth_router.get("/public-keys/{user_id}", response_model=PublicKeyResponse)
        @inject
        async def get_public_keys(user_id: int, user_gateway: FromDishka[UserGateway]):
            """
            Retrieve public keys for specified user.
            Args:
                user_id: User ID to retrieve keys for
                user_gateway: User gateway for database operations
            Returns:
                PublicKeyResponse: User's ECDSA and ECDH public keys
            Raises:
                HTTPException: If user or public keys are not found
            """
            ecdsa_public_key = await user_gateway.get_ecdsa_public_key(user_id)
            ecdh_public_key = await user_gateway.get_ecdh_public_key(user_id)

            if not ecdsa_public_key or not ecdh_public_key:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Public keys not found"
                )

            return PublicKeyResponse(
                user_id=user_id,
                ecdsa_public_key=ecdsa_public_key,
                ecdh_public_key=ecdh_public_key
            )

        @self.auth_router.put("/ecdsa-update-key", status_code=status.HTTP_200_OK)
        @inject
        async def update_ecdsa_public_key(
                key_data: PublicKeyUpdateDTO,
                user_gateway: FromDishka[UserGateway],
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Update authenticated user's ECDSA public key.
            Args:
                key_data: New ECDSA public key data
                user_gateway: User gateway for database operations
                token: JWT token for authentication
            Returns:
                dict: Success status message
            Raises:
                HTTPException: If key format is invalid or update fails
            """
            if not key_data.ecdsa_public_key or not self._validate_public_key_format(key_data.ecdsa_public_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid ECDSA public key format"
                )

            user_id = await self.get_current_user(token)
            success = await user_gateway.update_ecdsa_public_key(user_id, key_data.ecdsa_public_key)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update public key"
                )

            self.logger.info("ECDSA public key updated for user: %s", user_id)
            return {"status": "ecdsa public key updated"}

        @self.auth_router.put("/ecdh-update-key", status_code=status.HTTP_200_OK)
        @inject
        async def update_ecdh_public_key(
                key_data: PublicKeyUpdateDTO,
                user_gateway: FromDishka[UserGateway],
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Update authenticated user's ECDH public key.
            Args:
                key_data: New ECDH public key data
                user_gateway: User gateway for database operations
                token: JWT token for authentication
            Returns:
                dict: Success status message
            Raises:
                HTTPException: If key format is invalid or update fails
            """
            if not key_data.ecdh_public_key or not self._validate_public_key_format(key_data.ecdh_public_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid ECDH public key format"
                )

            user_id = await self.get_current_user(token)
            success = await user_gateway.update_ecdh_public_key(user_id, key_data.ecdh_public_key)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update public key"
                )

            self.logger.info("ECDH public key updated for user: %s", user_id)
            return {"status": "ecdh public key updated"}

        @self.auth_router.get("/me", response_model=UserResponse)
        @inject
        async def get_current_user_info(
                user_gateway: FromDishka[UserGateway],
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Get current authenticated user's information.
            Args:
                user_gateway: User gateway for database operations
                token: JWT token for authentication   
            Returns:
                UserResponse: Current user's information including public keys     
            Raises:
                HTTPException: If user is not found
            """
            user_id = await self.get_current_user(token)
            user = await user_gateway.get_user_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return UserResponse(
                id=user.id,
                name=user.name,
                ecdsa_public_key=user.ecdsa_public_key,
                ecdh_public_key=user.ecdh_public_key
            )
