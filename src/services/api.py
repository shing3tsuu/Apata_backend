from fastapi import FastAPI, status, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
import logging
import base64
from abc import ABC, abstractmethod

from src.core.gateways import UserGateway, KeyExchangeGateway
from src.core.db_manager import DatabaseManager

from .api_models import *


class BaseAuthAPI(ABC):
    @property
    @abstractmethod
    def auth_router(
            self
    ) -> APIRouter:
        """
        router for authentication
        :return:
        """
        raise NotImplementedError

    @abstractmethod
    def get_router(
            self
    ) -> APIRouter:
        """
        get router
        :return:
        """
        raise NotImplementedError

    @abstractmethod
    def create_access_token(
            self,
            user_id: int
    ) -> str:
        """
        create access token
        :param user_id:
        :return:
        """
        raise NotImplementedError

    @abstractmethod
    async def get_current_user(
            self,
            token: str
    ) -> int:
        """
        get current user
        :param token:
        :return:
        """
        raise NotImplementedError


class AuthAPI(BaseAuthAPI):
    def __init__(
            self,
            secret_key: str,
            db_manager: DatabaseManager | None = None,
    ):
        self.SECRET_KEY = secret_key
        self.ALGORITHM: str = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

        self.db_manager = db_manager or DatabaseManager()
        self.user_gateway = UserGateway(self.db_manager)
        self.key_gateway = KeyExchangeGateway(self.db_manager)

        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

        self._auth_router = APIRouter(tags=["Authentication"])
        self._register_endpoints()

    @property
    def auth_router(self) -> APIRouter:
        return self._auth_router

    def get_router(self) -> APIRouter:
        return self._auth_router

    def create_access_token(self, user_id: int) -> str:
        expires_delta = timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
        expire = datetime.utcnow() + expires_delta

        payload = {
            "sub": str(user_id),
            "exp": expire
        }
        return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

    async def get_current_user(self, token: str) -> int:
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

    def _register_endpoints(self):
        @self.auth_router.post("/register", status_code=status.HTTP_201_CREATED)
        async def register(user_data: UserRegisterRequest):
            if await self.user_gateway.get_user_by_name(user_data.username):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists"
                )

            user = await self.user_gateway.create_user(
                name=user_data.username,
                hashed_password=user_data.password,
                public_key=user_data.public_key
            )

            return {"id": user.id, "username": user.name}

        @self.auth_router.post("/login", response_model=dict)
        async def login(form_data: OAuth2PasswordRequestForm = Depends()):
            user = await self.user_gateway.get_user_by_name(form_data.username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )

            if not await self.password_manager.compare(form_data.password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )

            access_token = self.create_access_token(user.id)

            return {"access_token": access_token, "token_type": "bearer"}

        @self.auth_router.get("/public-key/{user_id}", response_model=PublicKeyResponse)
        async def get_public_key(user_id: int):
            public_key = await self.key_gateway.get_public_key(user_id)
            if not public_key:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Public key not found"
                )
            return PublicKeyResponse(user_id=user_id, public_key=public_key)

        @self.auth_router.put("/update-key", status_code=status.HTTP_200_OK)
        async def update_public_key(
                key_data: PublicKeyUpdateDTO,
                token: str = Depends(self.oauth2_scheme)
        ):
            user_id = await self.get_current_user(token)
            success = await self.key_gateway.update_public_key(user_id, key_data.public_key)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to update public key"
                )
            return {"status": "public key updated"}

        @self.auth_router.get("/me", response_model=UserDomain)
        async def get_current_user_info(
                token: str = Depends(self.oauth2_scheme)
        ):
            user_id = await self.get_current_user(token)
            user = await self.user_gateway.get_user_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            return user