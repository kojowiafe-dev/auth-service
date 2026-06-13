import pytest
import pytest_asyncio
import asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlmodel import SQLModel
from httpx import AsyncClient, ASGITransport

from server.main import app
from server.database.core import get_session
from server.auth.token_access import token_access

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture(name="session")
async def session_fixture() -> AsyncGenerator[AsyncSession, None]:
    # Set up memory db engine
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    # Import all models to ensure they register on SQLModel.metadata
    import server.users.models  # noqa: F401
    import server.wallet.models  # noqa: F401
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        
    async with AsyncSession(engine) as session:
        yield session
        
    # Drop tables
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        
    await engine.dispose()

@pytest_asyncio.fixture
async def client(session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    # Override FastAPI DB session dependency
    async def _override_get_session():
        yield session
        
    app.dependency_overrides[get_session] = _override_get_session
    
    # Use standard AsyncClient
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as ac:
        yield ac
        
    app.dependency_overrides.clear()

@pytest.fixture
def get_auth_headers():
    """
    Returns a function that generates Authorization headers for a given email address.
    """
    def _headers(email_address: str) -> dict:
        token = token_access.create_access_token({"sub": email_address})
        return {"Authorization": f"Bearer {token}"}
    return _headers
