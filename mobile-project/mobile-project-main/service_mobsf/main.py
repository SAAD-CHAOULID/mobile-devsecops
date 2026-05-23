"""
service_mobsf — :8001
Reçoit un chemin APK, le scanne avec MobSF, retourne un rapport JSON normalisé.
Contrat : POST /scan { apk_filename } → ScanResult
"""
import os
import time
import logging
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

from config import APK_STORAGE_PATH, MOBSF_URL, MOBSF_API_KEY, AGGREGATOR_URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Service MobSF Scanner", version="1.0.0")


# ── Schémas ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    score: int | None = None

class ScanResult(BaseModel):
    service: str = "mobsf"
    status: str
    apk_filename: str
    findings: list[dict] | None = None
    summary: ScanSummary
    duration_seconds: float
    message: str


# ── Helpers MobSF ──────────────────────────────────────────────────────────────
def _headers() -> dict:
    return {"Authorization": MOBSF_API_KEY}


async def _upload(apk_path: str, client: httpx.AsyncClient) -> str:
    with open(apk_path, "rb") as f:
        r = await client.post(
            f"{MOBSF_URL}/api/v1/upload",
            files={"file": (Path(apk_path).name, f, "application/octet-stream")},
            headers=_headers(), timeout=120
        )
    r.raise_for_status()
    return r.json()["hash"]


async def _scan(file_hash: str, client: httpx.AsyncClient) -> None:
    r = await client.post(
        f"{MOBSF_URL}/api/v1/scan",
        data={"hash": file_hash, "re_scan": 0},
        headers=_headers(), timeout=600
    )
    r.raise_for_status()


async def _report(file_hash: str, client: httpx.AsyncClient) -> dict:
    r = await client.post(
        f"{MOBSF_URL}/api/v1/report_json",
        data={"hash": file_hash},
        headers=_headers(), timeout=60
    )
    r.raise_for_status()
    return r.json()


def _extract_summary(report: dict) -> ScanSummary:
    """Normalise le rapport MobSF en compteurs criticity."""
    appsec = report.get("appsec", {})
    findings = report.get("findings", {})

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in findings.values():
        sev = str(item.get("level", "")).lower()
        if sev in counts:
            counts[sev] += 1

    score = appsec.get("security_score")
    return ScanSummary(score=score, **counts)


async def _notify_aggregator(payload: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(AGGREGATOR_URL, json=payload)
            log.info(f"Aggregator notifié : {r.status_code}")
    except Exception as e:
        log.warning(f"Aggregator inaccessible : {e}")


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "mobsf", "port": 8001}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE_PATH, req.apk_filename)

    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    log.info(f"Scan MobSF : {req.apk_filename}")

    try:
        async with httpx.AsyncClient() as client:
            file_hash = await _upload(apk_path, client)
            await _scan(file_hash, client)
            report = await _report(file_hash, client)
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"MobSF erreur {e.response.status_code}: {e.response.text[:300]}")
    except httpx.RequestError as e:
        raise HTTPException(503, f"MobSF inaccessible : {e}")

    summary = _extract_summary(report)
    duration = round(time.time() - t0, 2)

    # Normaliser findings sous forme de list[dict]
    normalized_findings = []
    mobsf_findings = report.get("findings", {})
    if isinstance(mobsf_findings, dict):
        for key, item in mobsf_findings.items():
            severity = str(item.get("level", "low")).lower()
            if severity not in ["critical", "high", "medium", "low"]:
                severity = "low"
            normalized_findings.append({
                "severity": severity,
                "type": item.get("title", key),
                "description": item.get("description", "")
            })
    elif isinstance(mobsf_findings, list):
        for item in mobsf_findings:
            if isinstance(item, dict):
                severity = str(item.get("level", "low")).lower()
                if severity not in ["critical", "high", "medium", "low"]:
                    severity = "low"
                normalized_findings.append({
                    "severity": severity,
                    "type": item.get("title", "finding"),
                    "description": item.get("description", "")
                })

    result = ScanResult(
        status="success",
        apk_filename=req.apk_filename,
        findings=normalized_findings,
        summary=summary,
        duration_seconds=duration,
        message=f"Scan terminé en {duration}s — score {summary.score}/100"
    )

    # Envoyer à l'agrégateur sans bloquer la réponse
    bg.add_task(_notify_aggregator, {
        **result.model_dump(),
        "repo": req.repo,
        "branch": req.branch,
        "commit": req.commit,
    })

    return result


@app.get("/mobsf/status")
async def mobsf_status():
    """Vérifie que MobSF Docker est accessible."""
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{MOBSF_URL}/api/v1/scans", headers=_headers())
            return {"reachable": True, "status_code": r.status_code}
    except Exception as e:
        return {"reachable": False, "error": str(e)}
