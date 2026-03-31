"""Run Postgres migrations in order."""
import asyncio
import os
import asyncpg
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent.parent / "db" / "postgres"


async def run() -> None:
    dsn = os.environ.get(
        "POSTGRES_DSN",
        "postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline",
    )
    conn = await asyncpg.connect(dsn)
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
