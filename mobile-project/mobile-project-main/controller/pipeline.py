import asyncio, httpx, json, logging, glob, os
from datetime import datetime
from config import INTERNAL_SERVICES, OLLAMA_URL, DISCORD_WEBHOOK_URL

log = logging.getLogger(__name__)
pipeline_history = []

REPO_SERVICES = ["gitleaks"]
APK_SERVICES  = ["mobsf", "androguard", "permissions", "network",
                 "obfuscation", "ssl", "virustotal", "syft_grype"]

async def _call_service(name: str, url: str, payload: dict) -> dict:
    try:
        async with httpx.AsyncClient(timeout=180) as c:
            r = await c.post(f"{url}/scan", json=payload)
            r.raise_for_status()
            return {"service": name, "status": "ok", "data": r.json()}
    except Exception as e:
        log.error(f"[{name}] erreur: {e}")
        return {"service": name, "status": "error", "error": str(e)}

async def _call_grok(aggregated: dict) -> dict:
    from config import GROK_API_KEY
    scans_summary = {}
    for service, data in aggregated.get("scans", {}).items():
        if isinstance(data, dict):
            findings = data.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            scans_summary[service] = {
                "score": data.get("summary", {}).get("score", "N/A") if isinstance(data.get("summary"), dict) else "N/A",
                "findings": findings[:5],
            }
        else:
            scans_summary[service] = str(data)[:200]

    prompt = f"""Tu es un expert en sécurité mobile. Voici les résultats d'analyse d'un APK Android.
repo: {aggregated['repo']} | commit: {aggregated['commit']} | apk: {aggregated.get('apk_filename')}
Résultats: {json.dumps(scans_summary, ensure_ascii=False)}
Génère un JSON valide UNIQUEMENT (sans markdown) avec cette structure exacte:
{{"risk_level":"critical|high|medium|low","summary":"3 phrases","tickets":[{{"title":"...","severity":"critical|high|medium|low","category":"...","description":"...","remediation":"...","effort":"low|medium|high"}}],"release_notes":"...","push_recommendation":true}}"""

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post("https://api.groq.com/openai/v1/chat/completions", 
                headers={"Authorization": f"Bearer {GROK_API_KEY}", "Content-Type": "application/json"},
                json={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": prompt}], "temperature": 0}
            )
            text = r.json()["choices"][0]["message"]["content"]
            import re
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if not match:
                raise ValueError("No JSON in Grok response")
            return json.loads(match.group())
    except Exception as e:
        log.error(f"Grok error: {e}")
        return {
            "risk_level": "unknown",
            "summary": "Grok indisponible — rapport basé sur les scanners.",
            "tickets": [],
            "release_notes": "Vérifier manuellement les findings critiques.",
            "push_recommendation": False
        }

async def _notify_discord(report: dict, ctx: dict) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    ai = report.get("ai_report", {})
    risk = ai.get("risk_level", "unknown").upper()
    push_ok = ai.get("push_recommendation", False)
    color = {"CRITICAL": 15158332, "HIGH": 15105570,
             "MEDIUM": 16776960, "LOW": 3066993}.get(risk, 9807270)

    scans = report.get("scans", {})
    scores = [v.get("summary", {}).get("score") for v in scans.values()
              if isinstance(v, dict) and isinstance(v.get("summary"), dict)]
    scores = [s for s in scores if s is not None]
    avg_score = round(sum(scores)/len(scores)) if scores else "N/A"

    tickets_txt = ""
    for t in ai.get("tickets", [])[:5]:
        tickets_txt += f"• **[{t['severity'].upper()}]** {t['title']}\n"

    embed = {
        "title": f"{'✅' if push_ok else '🚫'} MobSecOps — {ctx['repo']}@{ctx['commit'][:8]}",
        "color": color,
        "fields": [
            {"name": "Risque global", "value": risk, "inline": True},
            {"name": "Score", "value": f"{avg_score}/100", "inline": True},
            {"name": "Push autorisé", "value": "Oui" if push_ok else "Non", "inline": True},
            {"name": "Résumé IA", "value": ai.get("summary", "N/A")[:300], "inline": False},
            {"name": "Tickets (top 5)", "value": tickets_txt or "Aucun", "inline": False},
            {"name": "Release notes", "value": ai.get("release_notes", "N/A")[:200], "inline": False},
        ],
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
    except Exception as e:
        log.error(f"Discord notify error: {e}")

async def run_pipeline(ctx: dict) -> None:
    log.info(f"Pipeline démarré: {ctx['repo']}@{ctx['commit'][:8]}")
    start = datetime.utcnow()

    requested = ctx.get("services") or (REPO_SERVICES + APK_SERVICES)

    # Initialiser le pipeline temporaire "running" dans l'historique
    running_pipeline = {
        "repo": ctx["repo"],
        "commit": ctx["commit"],
        "branch": ctx["branch"],
        "apk_filename": ctx.get("apk_filename"),
        "services": requested,
        "scans": {},
        "timestamp": start.isoformat(),
        "status": "running"
    }
    pipeline_history.append(running_pipeline)
    if len(pipeline_history) > 100:
        pipeline_history.pop(0)

    # Helper interne pour mettre à jour l'historique en temps réel
    async def _call_and_update(name: str, url: str, payload: dict) -> dict:
        res = await _call_service(name, url, payload)
        if res.get("status") == "ok":
            running_pipeline["scans"][name] = res.get("data")
        else:
            running_pipeline["scans"][name] = {"status": "error", "error": res.get("error")}
        return res

    tasks = []

    # REPO services (gitleaks) — seulement si repo_path non vide
    for name in REPO_SERVICES:
        if name not in requested:
            continue
        if not ctx.get("repo_path"):
            log.info(f"[{name}] skipped — repo_path vide (trigger manuel)")
            continue
        url = INTERNAL_SERVICES.get(name)
        if url:
            tasks.append(_call_and_update(name, url, {
                "repo_path": ctx["repo_path"],
                "repo": ctx["repo"],
                "branch": ctx["branch"],
                "commit": ctx["commit"],
            }))

    # APK services — auto-détecte si apk_filename non fourni
    apk_filename = ctx.get("apk_filename")
    if not apk_filename:
        candidates = (
            glob.glob(f"/apk_storage/{ctx['repo']}*.apk") +
            glob.glob("/apk_storage/allsafe.apk")
        )
        candidates = [f for f in candidates if os.path.getsize(f) > 0]
        if candidates:
            apk_filename = os.path.basename(candidates[0])
            log.info(f"APK auto-détecté: {apk_filename}")

    if apk_filename:
        running_pipeline["apk_filename"] = apk_filename
        for name in APK_SERVICES:
            if name not in requested:
                continue
            url = INTERNAL_SERVICES.get(name)
            if url:
                tasks.append(_call_and_update(name, url, {
                    "apk_filename": apk_filename,
                    "repo": ctx["repo"],
                    "branch": ctx["branch"],
                    "commit": ctx["commit"],
                }))

    scan_results = await asyncio.gather(*tasks)

    aggregated = {
        "repo": ctx["repo"],
        "commit": ctx["commit"],
        "branch": ctx["branch"],
        "apk_filename": apk_filename or ctx.get("apk_filename"),
        "services": requested,
        "scans": {r["service"]: r.get("data", {"error": r.get("error")}) for r in scan_results},
        "timestamp": start.isoformat(),
    }

    ai_report = await _call_grok(aggregated)
    risk = ai_report.get("risk_level", "unknown").lower()
    if risk in ("critical", "high"):
        ai_report["push_recommendation"] = False
    push_allowed = ai_report.get("push_recommendation", False)

    final = {
        **aggregated,
        "ai_report": ai_report,
        "push_allowed": push_allowed,
        "duration_seconds": (datetime.utcnow() - start).total_seconds(),
        "status": "success" if push_allowed else "blocked",
    }

    # Remplacer l'entrée temporaire de type "running" par la version finale
    for i, p in enumerate(pipeline_history):
        if p.get("repo") == ctx["repo"] and p.get("commit") == ctx["commit"] and p.get("status") == "running":
            pipeline_history[i] = final
            break
    else:
        pipeline_history.append(final)
        if len(pipeline_history) > 100:
            pipeline_history.pop(0)

    await _notify_discord(final, ctx)
    log.info(f"Pipeline terminé: {ctx['repo']} — push={'OK' if push_allowed else 'BLOQUÉ'}")
