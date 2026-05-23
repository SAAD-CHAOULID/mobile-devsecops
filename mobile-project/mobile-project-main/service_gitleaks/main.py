"""
service_gitleaks — :8002
Détecte les secrets hardcodés dans un repo via Gitleaks.
"""
import os
import json
import time
import subprocess
import logging
import tempfile

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

from config import REPOS_STORAGE_PATH, AGGREGATOR_URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Service Gitleaks Scanner", version="2.0.0")


# ── Schémas ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    repo_path: str
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
    service: str = "gitleaks"
    status: str
    repo_path: str
    findings: list[dict]
    summary: ScanSummary
    duration_seconds: float
    message: str


# ── Sévérité par règle ─────────────────────────────────────────────────────────
CRITICAL_RULES = {"aws-access-token", "aws-secret-access-key", "private-key", "github-pat", "gcp-api-key"}
HIGH_RULES     = {"generic-api-key", "generic-secret", "password", "stripe-api-key", "twilio-api-key"}

def _severity_from_rule(rule_id: str) -> str:
    r = rule_id.lower()
    if any(k in r for k in ("aws", "private-key", "gcp", "github-pat")):
        return "critical"
    if any(k in r for k in ("api-key", "secret", "password", "token", "stripe", "twilio")):
        return "high"
    return "medium"


def _compute_score(findings: list[dict]) -> int:
    if not findings:
        return 100
    penalty = sum({"critical": 40, "high": 20, "medium": 10, "low": 3}.get(f.get("severity", "medium"), 10) for f in findings)
    return max(0, 100 - penalty)


def _run_gitleaks(repo_path: str) -> list[dict]:
    """Lance gitleaks detect sur le repo avec --no-git pour scanner les fichiers."""

    # Utiliser un fichier temporaire pour le rapport
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_file = tmp.name

    try:
        cmd = [
            "gitleaks", "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", report_file,
            "--no-git",          # scanner les fichiers sans historique git
            "--no-banner",
            "--exit-code", "0",  # 0=ok, 1=secrets trouvés — les deux sont valides
        ]
        log.info(f"Gitleaks cmd : {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        log.info(f"Gitleaks exit code: {result.returncode}")
        if result.stderr:
            log.info(f"Gitleaks stderr: {result.stderr[:300]}")

        if result.returncode not in (0, 1):
            raise RuntimeError(f"Gitleaks a crashé (code {result.returncode}): {result.stderr[:300]}")

        # Lire le rapport JSON
        if not os.path.exists(report_file) or os.path.getsize(report_file) == 0:
            log.info("Rapport Gitleaks vide — aucun secret trouvé")
            return []

        with open(report_file) as f:
            raw = json.load(f)

        if not raw:
            return []

        findings = []
        for item in raw:
            rule_id     = item.get("RuleID", "unknown")
            severity    = _severity_from_rule(rule_id)
            secret      = item.get("Secret", "")
            # Masquer le secret — ne jamais l'exposer en clair
            masked      = secret[:4] + "****" + secret[-2:] if len(secret) > 6 else "****"

            findings.append({
                "rule_id":     rule_id,
                "severity":    severity,
                "description": item.get("Description", rule_id),
                "file":        item.get("File", ""),
                "line":        item.get("StartLine", 0),
                "commit":      item.get("Commit", ""),
                "author":      item.get("Author", ""),
                "secret":      masked,
                "match":       item.get("Match", "")[:100],
            })

        return findings

    finally:
        # Toujours nettoyer le fichier temporaire
        try:
            os.unlink(report_file)
        except Exception:
            pass


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
    try:
        r = subprocess.run(["gitleaks", "version"], capture_output=True, text=True)
        version = r.stdout.strip()
    except FileNotFoundError:
        version = "NON INSTALLÉ"
    return {"status": "ok", "service": "gitleaks", "port": 8002, "gitleaks": version}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    # Sécurité : vérifier que le path est dans REPOS_STORAGE_PATH
    repo_path = req.repo_path
    if not os.path.exists(repo_path):
        raise HTTPException(404, f"Repo introuvable : {repo_path}")

    t0 = time.time()
    log.info(f"Scan Gitleaks : {repo_path}")

    try:
        findings = _run_gitleaks(repo_path)
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Timeout Gitleaks (> 300s)")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in counts:
            counts[sev] += 1

    score    = _compute_score(findings)
    duration = round(time.time() - t0, 2)
    nb       = len(findings)

    summary = ScanSummary(score=score, **counts)
    result  = ScanResult(
        status="success",
        repo_path=repo_path,
        findings=findings,
        summary=summary,
        duration_seconds=duration,
        message=f"{nb} secret(s) détecté(s) en {duration}s — score {score}/100"
    )

    bg.add_task(_notify_aggregator, {
        **result.model_dump(),
        "repo": req.repo,
        "branch": req.branch,
        "commit": req.commit,
    })

    return result
