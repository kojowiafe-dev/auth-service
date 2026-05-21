import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlmodel import SQLModel
from contextlib import asynccontextmanager
from fastapi import Depends
from typing import Annotated


load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=False,
    future=True
)


async def get_session():
    async with AsyncSession(engine) as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)] 

async def create_db_and_tables():
    import server.users.models  # noqa: F401 — register SQLModel tables

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)