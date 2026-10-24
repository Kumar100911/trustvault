from fastapi import FastAPI

from app.routes import admin, auth_routes, documents, grants, suggestions

app = FastAPI(title="TrustVault")


@app.middleware("http")
async def security_headers(request, call_next):
    """Defaults for every response. Private data must not sit in browser caches."""
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


app.include_router(auth_routes.router)
app.include_router(documents.router)
app.include_router(grants.router)
app.include_router(suggestions.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok"}