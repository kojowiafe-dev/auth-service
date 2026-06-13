import errx
from errx import DisplayStyle
errx.bootstrap()
ERRX_AVAILABLE = True


from fastapi import FastAPI, Request, HTTPException
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from server.database.core import create_db_and_tables
from server.api import register_routes




@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        import server.users.models  # noqa: F401 — registers User, RefreshToken, OtpCode,
        # LoginAudit, KnownDevice with SQLModel.metadata so create_all sees them.
        import server.wallet.models  # noqa: F401 — registers Wallet, Transaction, LedgerEntry, WalletAuditLog
        await create_db_and_tables()
        logger.info("Database and tables verified")
        yield
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        logger.info("Application shutting down")



app = FastAPI(
    title="Auth Service",
    description="Authentication service",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
        
errx.install(app)



@app.get("/health")
async def health():
    return {"status": "ok"}


register_routes(app)