from fastapi import FastAPI

from app.routes import auth_routes

app = FastAPI(title="TrustVault")
app.include_router(auth_routes.router)


@app.get("/health")
def health():
    return {"status": "ok"}