from fastapi import FastAPI

from app.routes import admin, auth_routes, documents, grants, suggestions

app = FastAPI(title="TrustVault")
app.include_router(auth_routes.router)
app.include_router(documents.router)
app.include_router(grants.router)
app.include_router(suggestions.router)
app.include_router(admin.router)


@app.get("/health")
def health():
    return {"status": "ok"}