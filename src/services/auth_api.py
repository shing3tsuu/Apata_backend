from fastapi import FastAPI, status, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import logging
import base64
import asyncio
import secrets
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from src.core.gateways import UserGateway, KeyExchangeGateway
from src.core.db_manager import DatabaseManager

from .auth_api_models import *


class AuthAPI:
    """
    Main authentication API class handling user registration, authentication, and key management like WebAuthn.
    """
    def __init__(
            self,
            secret_key: str,
            db_manager: DatabaseManager | None = None,
            redis = None,
            logger: logging.Logger | None = None
    ):
        """
        Initialize AuthAPI with configuration and dependencies
        Args:
            secret_key: Secret key for JWT token signing
            db_manager: Database manager instance (optional)
            redis: Redis instance for challenge storage
            logger: Custom logger instance (optional)
        """
        self.SECRET_KEY = secret_key
        self.ALGORITHM= "HS256" # could replace on RS256

        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
        self.CHALLENGE_EXPIRE_MINUTES: int = 5

        self.db_manager = db_manager or DatabaseManager()
        self.redis = redis

        self.logger = logger or logging.getLogger(__name__)

        self.user_gateway = UserGateway(self.db_manager)
        self.key_gateway = KeyExchangeGateway(self.db_manager)

        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

        self._auth_router = APIRouter(tags=["Authentication"])
        self._register_endpoints()

    @property
    def auth_router(self) -> APIRouter:
        """
        Get the authentication router instance
        """
        return self._auth_router

    def get_router(self) -> APIRouter:
        """
        Get the authentication router instance (alias for auth_router)
        """
        return self._auth_router

    def create_access_token(self, user_id: int) -> str:
        """
        Create JWT access token for authenticated user
        Args: user_id: User identifier to include in token
        Returns: str: Encoded JWT token
        """
        try:
            expires_delta = timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
            expire = datetime.utcnow() + expires_delta

            payload = {"sub": str(user_id),"exp": expire}
            return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)
        except Exception as e:
            self.logger.error("Error creating access token: %s", str(e), exc_info=True)
            raise

    async def get_current_user(self, token: str) -> int:
        """
        Validate JWT token and extract user ID
        Args: token: JWT token from authorization header
        Returns: int: User ID extracted from token
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                )
            return int(user_id)
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
        Verify ECDSA signature using user's ecdsa public key
        Args:
            ecdsa_public_key_pem: PEM-formatted ecdsa public key
            challenge: Original challenge string that was signed
            signature: Base64-encoded signature to verify
        Returns: bool: True if signature is valid, False otherwise
        """
        try:
            ecdsa_public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            # Decode signature from base64
            signature_bytes = base64.b64decode(signature)

            # Verify signature using ECDSA with SHA256
            ecdsa_public_key.verify(
                signature_bytes,
                challenge.encode(),
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except (InvalidSignature, ValueError):
            return False
        except Exception as e:
            self.logger.critical("Error verifying signature: %s", str(e), exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    def _register_endpoints(self):
        """
        Register all authentication endpoints with the router
        # Development notes: add work with ecdh public key
        """
        @self.auth_router.post("/register", status_code=status.HTTP_201_CREATED)
        async def register(user_data: UserRegisterRequest):
            """
            Register new user with public keys (ecdsa and ecdh)
            Args: user_data: User registration data containing username and public keys
            Returns: dict: Created user's ID and username
            """
            if await self.user_gateway.get_user_by_name(user_data.username):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists"
                )

            user = await self.user_gateway.create_user(
                name=user_data.username,
                ecdsa_public_key=user_data.ecdsa_public_key,
                ecdh_public_key=user_data.ecdh_public_key
            )

            return {"id": user.id, "username": user.name}

        @self.auth_router.get("/challenge/{username}")
        async def get_challenge(username: str):
            """
            Request authentication challenge for user
            Args: username: Username to generate challenge for
            Returns: dict: Generated challenge and expiration time
            """
            user = await self.user_gateway.get_user_by_name(username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Generate random challenge
            challenge = secrets.token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(minutes=self.CHALLENGE_EXPIRE_MINUTES)

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

            return {"challenge": challenge, "expires": expires.isoformat()}

        @self.auth_router.post("/login", response_model=dict)
        async def login(login_data: ChallengeLoginRequest):
            """
            Authenticate user using signed challenge
            Args: login_data: Login request containing username and signature
            Returns: dict: JWT access token
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
            if datetime.utcnow() > datetime.fromisoformat(challenge_data["expires"]):
                self.redis.delete(challenge_key)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Challenge expired"
                )

            # Get user and public key
            user = await self.user_gateway.get_user_by_name(login_data.username)
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
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid signature"
                )

            # Remove used challenge from Redis
            self.redis.delete(challenge_key)

            # Create JWT token
            access_token = self.create_access_token(user.id)
            return {"access_token": access_token, "token_type": "bearer"}

        @self.auth_router.get("/public-keys/{user_id}", response_model=PublicKeyResponse)
        async def get_ecdsa_public_key(user_id: int):
            """
            Retrieve ecdsa public keys for specified user
            Args: user_id: ID of user to get public keys for
            Returns: PublicKeyResponse: User ID and public keys
            """
            ecdsa_public_key = await self.key_gateway.get_ecdsa_public_key(user_id)
            ecdh_public_key = await self.key_gateway.get_ecdh_public_key(user_id)
            if not ecdsa_public_key or not ecdh_public_key:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Public key not found"
                )
            return PublicKeyResponse(user_id=user_id, ecdsa_public_key=ecdsa_public_key, ecdh_public_key=ecdh_public_key)

        @self.auth_router.put("/ecdsa-update-key", status_code=status.HTTP_200_OK)
        async def update_ecdsa_public_key(
                key_data: PublicKeyUpdateDTO,
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Update authenticated user's ecdsa public key
            Args:
                key_data: New ecdsa public key data
                token: JWT authentication token
            Returns: dict: Success status
            Development note:
                In the current implementation of the flet client, this method is not used for its intended purpose.
            """
            user_id = await self.get_current_user(token)
            success = await self.key_gateway.update_ecdsa_public_key(user_id, key_data.ecdsa_public_key)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update public key"
                )
            return {"status": "ecdsa public key updated"}

        @self.auth_router.put("/ecdh-update-key", status_code=status.HTTP_200_OK)
        async def update_ecdh_public_key(
                key_data: PublicKeyUpdateDTO,
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Update authenticated user's ecdh public key
            Args:
                key_data: New ecdh public key data (Perfect Forward Secrecy)
                token: JWT authentication token
            Returns: dict: Success status
            Development note:
                In the current implementation of the flet client, this method is not used for its intended purpose.
            """
            user_id = await self.get_current_user(token)
            success = await self.key_gateway.update_ecdh_public_key(user_id, key_data.ecdh_public_key)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update public key"
                )
            return {"status": "ecdh public key updated"}

        @self.auth_router.get("/me", response_model=UserResponse)
        async def get_current_user_info(
                token: str = Depends(self.oauth2_scheme)
        ):
            """
            Get current authenticated user's information
            Args: token: JWT authentication token
            Returns: UserResponse: User information
            """
            user_id = await self.get_current_user(token)
            user = await self.user_gateway.get_user_by_id(user_id)
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
