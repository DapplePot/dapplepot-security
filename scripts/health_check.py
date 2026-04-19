"""
Health check for dapplepot-security.
Exits 0 if Postgres and Redis are reachable, 1 otherwise.

Usage:
    uv run python scripts/health_check.py
"""
import sys
import asyncio

from core.config import settings


async def _check_postgres() -> bool:
    try:
        import asyncpg
        conn = await asyncpg.connect(settings.postgres_dsn)
        await conn.execute('SELECT 1')
        await conn.close()
        return True
    except Exception as exc:
        print(f'ERROR: Postgres unreachable — {exc}', file=sys.stderr)
        return False


async def _check_redis() -> bool:
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        return True
    except Exception as exc:
        print(f'ERROR: Redis unreachable — {exc}', file=sys.stderr)
        return False


async def main() -> int:
    results = await asyncio.gather(_check_postgres(), _check_redis())
    if all(results):
        print('OK: all services healthy')
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
