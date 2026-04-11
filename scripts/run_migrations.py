"""Run Postgres migrations in order, skipping already-applied files."""
import asyncio
import asyncpg
from pathlib import Path
from core.config import settings

MIGRATIONS_DIR = Path(__file__).parent.parent / "db" / "postgres"


async def run() -> None:
    conn = await asyncpg.connect(settings.postgres_dsn)
    try:
        # Create tracking table if it doesn't exist
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS _migrations (
                filename   TEXT        NOT NULL PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        applied = {
            row["filename"]
            for row in await conn.fetch("SELECT filename FROM _migrations")
        }

        for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if sql_file.name in applied:
                print(f"skip  {sql_file.name}")
                continue
            print(f"apply {sql_file.name}...")
            sql = sql_file.read_text()
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO _migrations (filename) VALUES ($1)", sql_file.name
                )
            print(f"  OK")

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(run())
