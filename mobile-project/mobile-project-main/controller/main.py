from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from listener import router as webhook_router
from auth import verify_admin_key
import httpx, os
from config import INTERNAL_SERVICES

app = FastAPI(title="MobSecOps Controller", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Route publique — seul chemin d'entrée autorisé
app.include_router(webhook_router)

# Routes admin (protégées par API key)
@app.get("/admin/status", dependencies=[Depends(verify_admin_key)])
async def admin_status():
    """Vérifie l'état de tous les services internes."""
    results = {}
    async with httpx.AsyncClient(timeout=5) as client:
        for name, url in INTERNAL_SERVICES.items():
            try:
                r = await client.get(f"{url}/health")
                results[name] = {"status": "ok", "code": r.status_code}
            except Exception as e:
                results[name] = {"status": "down", "error": str(e)}
    return results

@app.get("/admin/pipelines", dependencies=[Depends(verify_admin_key)])
async def admin_pipelines():
    """Retourne les N derniers pipelines exécutés (depuis la mémoire)."""
    from pipeline import pipeline_history
    return {"pipelines": pipeline_history[-20:]}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "controller"}

# Bloquer tout accès direct aux services internes
@app.api_route("/{full_path:path}", methods=["GET","POST","PUT","DELETE"])
async def block_direct_access(full_path: str):
    from fastapi import HTTPException
    raise HTTPException(403, f"Accès direct interdit. Utilise /webhook/github")
