"""
service_aggregator — :8011
Reçoit les résultats de tous les scanners, génère en parallèle :
  - Un rapport HTML via Jinja2
  - Un rapport IA via Ollama
Envoie le rapport HTML sur Discord.
"""
import os, json, time, logging, asyncio, hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx
from jinja2 import Environment, FileSystemLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Service Aggregator", version="1.0.0")

# ── Config ─────────────────────────────────────────────────────────────────────
OLLAMA_URL          = os.getenv("OLLAMA_URL",          "http://172.17.0.1:11434")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
REPORTS_DIR         = os.getenv("REPORTS_DIR",         "/reports")
OLLAMA_MODEL        = os.getenv("OLLAMA_MODEL",        "qwen2.5:3b")

os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Jinja2 ─────────────────────────────────────────────────────────────────────
jinja_env = Environment(
    loader=FileSystemLoader("/app/templates"),
    autoescape=True
)

# ── Stockage en mémoire ────────────────────────────────────────────────────────
# pipeline_id → { services reçus, timestamp, meta }
pending: dict[str, dict] = {}
reports: list[dict] = []   # historique des rapports finalisés

EXPECTED_APK_SERVICES  = {"androguard", "permissions", "network", "obfuscation", "ssl", "virustotal", "syft_grype", "mobsf"}
EXPECTED_REPO_SERVICES = {"gitleaks"}


# ── Schémas ────────────────────────────────────────────────────────────────────
class ServiceResult(BaseModel):
    service: str
    status: str
    repo: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None
    apk_filename: Optional[str] = None
    repo_path: Optional[str] = None
    findings: Optional[list] = []
    summary: Optional[dict] = {}
    duration_seconds: Optional[float] = None
    message: Optional[str] = None
    # Champs spécifiques par service
    urls: Optional[list] = None
    domains: Optional[list] = None
    ips: Optional[list] = None
    permissions_total: Optional[int] = None
    obfuscation_score: Optional[int] = None
    domains_found: Optional[int] = None
    domains_scanned: Optional[int] = None
    file_hash: Optional[str] = None
    sbom: Optional[dict] = None
    model_config = {"extra": "allow"}


# ── Helpers ────────────────────────────────────────────────────────────────────
def _pipeline_id(repo: str, commit: str) -> str:
    return hashlib.md5(f"{repo}:{commit}".encode()).hexdigest()[:12]


def _severity_color(sev: str) -> str:
    return {"critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#65a30d"}.get(sev, "#6b7280")


def _global_score(scans: dict) -> int:
    scores = []
    for svc, data in scans.items():
        if isinstance(data, dict):
            s = data.get("summary", {})
            score = s.get("score") if isinstance(s, dict) else None
            if score is not None:
                scores.append(int(score))
    return round(sum(scores) / len(scores)) if scores else 0


def _global_risk(scans: dict) -> str:
    total = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for svc, data in scans.items():
        if isinstance(data, dict):
            s = data.get("summary", {})
            if isinstance(s, dict):
                for k in total:
                    total[k] += s.get(k, 0)
    if total["critical"] > 0: return "critical"
    if total["high"] > 0:     return "high"
    if total["medium"] > 0:   return "medium"
    return "low"


def _count_findings(scans: dict) -> dict:
    total = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for svc, data in scans.items():
        if isinstance(data, dict):
            for f in data.get("findings", []):
                sev = f.get("severity", "low") if isinstance(f, dict) else "low"
                if sev in total:
                    total[sev] += 1
    return total


# ── Ollama ─────────────────────────────────────────────────────────────────────
async def _call_ollama(scans: dict, meta: dict) -> dict:
    # Résumé compact pour ne pas dépasser le context window
    compact = {}
    for svc, data in scans.items():
        if not isinstance(data, dict):
            continue
        findings = data.get("findings", [])
        compact[svc] = {
            "score": data.get("summary", {}).get("score", "N/A") if isinstance(data.get("summary"), dict) else "N/A",
            "findings_count": len(findings),
            "top_findings": [
                {"severity": f.get("severity"), "type": f.get("type", f.get("rule_id", f.get("cve_id", ""))),
                 "description": str(f.get("description", f.get("message", "")))[:100]}
                for f in findings[:4] if isinstance(f, dict)
            ]
        }

    prompt = f"""Tu es un expert en sécurité mobile Android. Voici les résultats d'analyse de l'APK "{meta.get('apk_filename', 'inconnu')}" du repo "{meta.get('repo', '')}".

Résultats par scanner:
{json.dumps(compact, indent=2, ensure_ascii=False)}

Génère un rapport JSON avec exactement cette structure (sans markdown, sans texte avant ou après):
{{
  "risk_level": "critical",
  "summary": "Résumé en 2-3 phrases en français.",
  "key_findings": ["finding 1", "finding 2", "finding 3"],
  "tickets": [
    {{
      "title": "titre court",
      "severity": "critical",
      "category": "secrets",
      "description": "description en français",
      "remediation": "comment corriger",
      "effort": "medium"
    }}
  ],
  "release_notes": "Ce qui doit être corrigé avant release.",
  "push_recommendation": false
}}

Règles: risk_level doit être critical/high/medium/low. Génère 1 ticket par finding important. Réponds UNIQUEMENT avec le JSON valide.
"""
    try:
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(f"{OLLAMA_URL}/api/generate", json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            })
            text = r.json().get("response", "{}")
            import re
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if not match:
                raise ValueError("No JSON in Ollama response")
            return json.loads(match.group())
    except Exception as e:
        log.error(f"Ollama error: {e}")
        return {
            "risk_level": _global_risk(scans),
            "summary": "Analyse IA indisponible — rapport basé sur les scanners.",
            "key_findings": [],
            "tickets": [],
            "release_notes": "Vérifier manuellement les findings critiques.",
            "push_recommendation": False
        }


# ── HTML Report ────────────────────────────────────────────────────────────────
def _generate_html(scans: dict, ai: dict, meta: dict) -> str:
    template = jinja_env.get_template("report.html")
    score = _global_score(scans)
    counts = _count_findings(scans)
    risk = ai.get("risk_level", _global_risk(scans))

    # Aplatir tous les findings avec leur service
    all_findings = []
    for svc, data in scans.items():
        if isinstance(data, dict):
            for f in data.get("findings", []):
                if isinstance(f, dict):
                    all_findings.append({**f, "_service": svc})
    all_findings.sort(key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),4))

    return template.render(
        meta=meta,
        score=score,
        risk=risk,
        counts=counts,
        scans=scans,
        ai=ai,
        all_findings=all_findings,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        severity_color=_severity_color,
    )


# ── Discord ────────────────────────────────────────────────────────────────────
async def _send_discord(html_path: str, ai: dict, meta: dict, score: int) -> None:
    if not DISCORD_WEBHOOK_URL:
        return

    risk   = ai.get("risk_level", "unknown").upper()
    push   = ai.get("push_recommendation", False)
    color  = {"CRITICAL":15158332,"HIGH":15105570,"MEDIUM":16776960,"LOW":3066993}.get(risk, 9807270)
    icon   = "✅" if push else "🚫"

    tickets_txt = ""
    for t in ai.get("tickets", [])[:5]:
        sev = t.get("severity","?").upper()
        tickets_txt += f"• **[{sev}]** {t.get('title','')}\n"

    embed = {
        "title": f"{icon} MobSecOps — {meta.get('repo','?')}@{str(meta.get('commit',''))[:8]}",
        "color": color,
        "fields": [
            {"name": "Risque global",   "value": risk,                              "inline": True},
            {"name": "Score",           "value": f"{score}/100",                    "inline": True},
            {"name": "Push autorisé",   "value": "Oui" if push else "Non",          "inline": True},
            {"name": "Résumé IA",       "value": ai.get("summary","N/A")[:300],     "inline": False},
            {"name": "Tickets (top 5)", "value": tickets_txt or "Aucun",            "inline": False},
            {"name": "Release notes",   "value": ai.get("release_notes","N/A")[:200], "inline": False},
        ],
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": "MobSecOps • Rapport HTML joint"}
    }

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            # 1. Envoyer l'embed
            await c.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]})

            # 2. Envoyer le fichier HTML
            if os.path.exists(html_path):
                with open(html_path, "rb") as f:
                    filename = os.path.basename(html_path)
                    await c.post(
                        DISCORD_WEBHOOK_URL,
                        files={"file": (filename, f, "text/html")},
                        data={"content": f"📄 Rapport HTML complet : `{filename}`"}
                    )
    except Exception as e:
        log.error(f"Discord error: {e}")


# ── Pipeline finalization ──────────────────────────────────────────────────────
async def _finalize_pipeline(pipeline_id: str) -> None:
    state = pending.get(pipeline_id)
    if not state:
        return

    scans = state["scans"]
    meta  = state["meta"]
    log.info(f"Finalisation pipeline {pipeline_id} — {len(scans)} services reçus")

    # Lancer Ollama et HTML en parallèle
    ai_task   = asyncio.create_task(_call_ollama(scans, meta))
    ai_result = await ai_task

    score     = _global_score(scans)
    html      = _generate_html(scans, ai_result, meta)

    # Sauvegarder le HTML
    repo   = meta.get("repo", "unknown")
    commit = str(meta.get("commit", ""))[:8]
    ts     = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname  = f"report_{repo}_{commit}_{ts}.html"
    fpath  = os.path.join(REPORTS_DIR, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(html)
    log.info(f"Rapport HTML sauvegardé : {fpath}")

    # Discord
    await _send_discord(fpath, ai_result, meta, score)

    # Historique
    final = {
        "pipeline_id": pipeline_id,
        "meta": meta,
        "scans": scans,
        "ai_report": ai_result,
        "score": score,
        "risk": ai_result.get("risk_level", _global_risk(scans)),
        "html_path": fpath,
        "timestamp": datetime.utcnow().isoformat(),
        "services_received": list(scans.keys()),
    }
    reports.append(final)
    if len(reports) > 50:
        reports.pop(0)

    del pending[pipeline_id]
    log.info(f"Pipeline {pipeline_id} finalisé — score {score}/100")


# ── Auto-finalize après timeout ────────────────────────────────────────────────
async def _schedule_finalize(pipeline_id: str, delay: int = 30) -> None:
    """Finalise le pipeline même si tous les services n'ont pas répondu."""
    await asyncio.sleep(delay)
    if pipeline_id in pending:
        log.warning(f"Timeout — finalisation forcée de {pipeline_id}")
        await _finalize_pipeline(pipeline_id)


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "aggregator", "port": 8011,
            "pending_pipelines": len(pending), "reports_count": len(reports)}


@app.post("/results")
async def receive_result(result: ServiceResult, bg: BackgroundTasks):
    """Point d'entrée pour tous les services scanners."""
    service = result.service
    repo    = result.repo or "unknown"
    commit  = result.commit or "unknown"
    pid     = _pipeline_id(repo, commit)

    log.info(f"Résultat reçu de {service} pour pipeline {pid} ({repo}@{commit[:8]})")

    if pid not in pending:
        # Nouveau pipeline
        pending[pid] = {
            "scans": {},
            "meta": {
                "repo":         repo,
                "commit":       commit,
                "branch":       result.branch,
                "apk_filename": result.apk_filename,
                "repo_path":    result.repo_path,
            },
            "started_at": time.time(),
            "has_apk":    bool(result.apk_filename),
        }
        # Timeout de sécurité : finaliser après 3 minutes même si services manquants
        bg.add_task(_schedule_finalize, pid, 180)

    pending[pid]["scans"][service] = result.model_dump()

    # Déterminer les services attendus
    has_apk     = pending[pid]["has_apk"] or bool(result.apk_filename)
    expected    = set(EXPECTED_REPO_SERVICES)
    if has_apk:
        expected |= EXPECTED_APK_SERVICES

    received = set(pending[pid]["scans"].keys())
    log.info(f"Pipeline {pid}: {len(received)}/{len(expected)} services — {received}")

    # Finaliser si tous les services ont répondu
    if expected.issubset(received):
        log.info(f"Tous les services reçus pour {pid} — finalisation")
        bg.add_task(_finalize_pipeline, pid)

    return {"status": "received", "pipeline_id": pid,
            "services_received": len(received), "services_expected": len(expected)}


@app.get("/reports")
def get_reports():
    return {"reports": reports[-20:]}


@app.get("/reports/{pipeline_id}")
def get_report(pipeline_id: str):
    for r in reports:
        if r["pipeline_id"] == pipeline_id:
            return r
    raise HTTPException(404, f"Pipeline {pipeline_id} introuvable")


@app.get("/pending")
def get_pending():
    return {
        pid: {
            "services_received": list(state["scans"].keys()),
            "meta": state["meta"],
            "age_seconds": round(time.time() - state["started_at"])
        }
        for pid, state in pending.items()
    }
