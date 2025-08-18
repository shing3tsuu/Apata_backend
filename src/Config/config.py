from dataclasses import dataclass
from environs import Env
from typing import Optional

@dataclass
class JWTConfig:
    secret_key: str

@dataclass
class DBConfig:
    """ PostgreSQL """
    host: str | None = None
    port: int | None = None
    name: str | None = None
    user: str | None = None
    password: str | None = None

    """ SQLite """
    path: str | None = None

@dataclass
class Config:
    """ Config """
    jwt: JWTConfig
    db: DBConfig

def load_config(path: str | None) -> Config:
    env = Env()
    env.read_env(path)

    return Config(
        jwt=JWTConfig(
            secret_key=env('SECRET_KEY'),
        ),
        db=DBConfig(
            host=env('DB_HOST', None),
            port=env.int('DB_PORT', None),
            name=env('DB_NAME', None),
            user=env('DB_USER', None),
            password=env('DB_PASSWORD', None),
            path=env('DB_PATH', 'data/bot.db')
        )
    )