from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api import auth, admin, scanner, subdomain, proxy, repeater, decoder, dashboard, xss, sqli
from app.database import init_db

app = FastAPI(
    title="Shadow Spike API",
    version=settings.APP_VERSION,
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(scanner.router, prefix="/api/v1")
app.include_router(subdomain.router, prefix="/api/v1")
app.include_router(proxy.router, prefix="/api/v1")
app.include_router(repeater.router, prefix="/api/v1")
app.include_router(decoder.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(xss.router, prefix="/api/v1")
app.include_router(sqli.router, prefix="/api/v1")

@app.on_event("startup")
async def on_startup():
    await init_db()


@app.get("/")
async def root():
    return {"app": "Shadow Spike", "status": "online"}

@app.get("/health")
async def health():
    return {"status": "healthy"}