"""Drop the user table so SQLModel can recreate it with the current schema (UUID id)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text

from server.database.core import engine, create_db_and_tables
from server.users.models import User  # noqa: F401 — register table in metadata


async def main() -> None:
    async with engine.begin() as conn:
        await conn.execute(text('DROP TABLE IF EXISTS "user" CASCADE'))
    await create_db_and_tables()
    print('Reset complete: "user" table recreated with UUID id.')


if __name__ == "__main__":
    asyncio.run(main())
