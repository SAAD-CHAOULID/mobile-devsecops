"""
service_virustotal — :8005
Soumet l'APK à VirusTotal et récupère le rapport de détection malware.
"""
import os, time, logging, hashlib
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")
VT_API_KEY     = os.getenv("VT_API_KEY", "")
VT_BASE        = "https://www.virustotal.com/api/v3"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service VirusTotal", version="1.0.0")


class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanResult(BaseModel):
    service: str = "virustotal"
    status: str
    apk_filename: str
    file_hash: str | None = None
    findings: list[dict]
    summary: dict
    duration_seconds: float
    message: str


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


async def _check_existing(file_hash: str, headers: dict) -> dict | None:
    """Vérifie si le fichier est déjà connu de VT via son hash."""
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"{VT_BASE}/files/{file_hash}", headers=headers)
        if r.status_code == 200:
            return r.json()
        return None


async def _upload_file(apk_path: str, headers: dict) -> str:
    """Uploade l'APK et retourne l'analysis ID."""
    async with httpx.AsyncClient(timeout=120) as c:
        with open(apk_path, 'rb') as f:
            files = {"file": (os.path.basename(apk_path), f, "application/octet-stream")}
            r = await c.post(f"{VT_BASE}/files", headers=headers, files=files)
            r.raise_for_status()
            return r.json()["data"]["id"]


async def _wait_for_analysis(analysis_id: str, headers: dict, max_wait: int = 120) -> dict:
    """Attend la fin de l'analyse VT (polling)."""
    async with httpx.AsyncClient(timeout=30) as c:
        for _ in range(max_wait // 10):
            r = await c.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
            data = r.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
            time.sleep(10)
    raise RuntimeError("Timeout VirusTotal — analyse trop longue")


def _parse_results(vt_data: dict) -> tuple[list[dict], dict]:
    """Parse le rapport VT et retourne findings + summary."""
    attrs = vt_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", attrs.get("stats", {}))
    results = attrs.get("last_analysis_results", attrs.get("results", {}))

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) if stats else 0

    findings = []
    for engine, result in results.items():
        category = result.get("category", "")
        if category in ("malicious", "suspicious"):
            findings.append({
                "engine":   engine,
                "severity": "critical" if category == "malicious" else "high",
                "category": category,
                "result":   result.get("result", ""),
                "version":  result.get("engine_version", ""),
            })

    severity = "clean"
    if malicious > 5:   severity = "critical"
    elif malicious > 0: severity = "high"
    elif suspicious > 0: severity = "medium"

    summary = {
        "malicious":  malicious,
        "suspicious": suspicious,
        "clean":      stats.get("undetected", 0),
        "total":      total,
        "severity":   severity,
        "score":      max(0, 100 - malicious * 15 - suspicious * 5),
    }
    return findings, summary


async def _notify_aggregator(payload):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(AGGREGATOR_URL, json=payload)
    except Exception as e:
        log.warning(f"Aggregator: {e}")


@app.get("/health")
def health():
    configured = bool(VT_API_KEY)
    return {"status": "ok", "service": "virustotal", "port": 8005, "api_key_configured": configured}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    if not VT_API_KEY:
        raise HTTPException(503, "VT_API_KEY non configurée dans .env")

    apk_path = os.path.join(APK_STORAGE, req.apk_filename)
    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    headers = {"x-apikey": VT_API_KEY}
    file_hash = _sha256(apk_path)
    log.info(f"SHA256: {file_hash}")

    try:
        # 1. Vérifier si déjà connu de VT
        vt_data = await _check_existing(file_hash, headers)

        if vt_data:
            log.info("Fichier déjà connu de VT — récupération rapport existant")
        else:
            log.info("Fichier inconnu — upload vers VT")
            analysis_id = await _upload_file(apk_path, headers)
            vt_data = await _wait_for_analysis(analysis_id, headers)

        findings, summary = _parse_results(vt_data)

    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"Erreur API VirusTotal : {e.response.status_code}")
    except RuntimeError as e:
        raise HTTPException(504, str(e))

    duration = round(time.time() - t0, 2)
    result = ScanResult(
        status="success",
        apk_filename=req.apk_filename,
        file_hash=file_hash,
        findings=findings,
        summary=summary,
        duration_seconds=duration,
        message=f"{summary['malicious']}/{summary['total']} moteurs détectent un malware — score {summary['score']}/100"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(), "repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
