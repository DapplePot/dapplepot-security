"""Run Postgres migrations in order."""
import asyncio
import os
import asyncpg
from pathlib import Path
from core.config import settings

MIGRATIONS_DIR = Path(__file__).parent.parent / "db" / "postgres"


async def run() -> None:
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
            print(f"Running {sql_file.name}...")
            sql = sql_file.read_text()
            await conn.execute(sql)
            print(f"  OK")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(run())
