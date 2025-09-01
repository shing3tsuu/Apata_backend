import redis

class RedisManager:
    def __init__(self, host: str | None = None, port: int | None = None):
        self.host = host or 'localhost'
        self.port = port or 6379

    def get_redis(self):
        return redis.Redis(host=self.host, port=self.port, db=0)