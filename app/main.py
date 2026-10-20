from fastapi import FastAPI

app = FastAPI(title="TrustVault")

@app.get("/health")
def health():
    return {"status": "ok"}