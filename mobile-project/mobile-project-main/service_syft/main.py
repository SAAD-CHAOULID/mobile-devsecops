"""
service_syft — :8003
Analyse les dépendances d'un APK Android en lisant :
  - META-INF/*.version  (AndroidX / Jetpack)
  - META-INF/*.properties (metadata Gradle)
  - classes.dex (présence détectée)
Puis scanne les CVE avec Grype sur ces packages.
"""
import os
import json
import time
import subprocess
import logging
import shutil
import zipfile
import tempfile
import re

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

from config import APK_STORAGE_PATH, AGGREGATOR_URL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Service Syft/Grype Scanner", version="3.0.0")


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
    service: str = "syft_grype"
    status: str
    apk_filename: str
    sbom: dict | None = None
    findings: list[dict]
    summary: ScanSummary
    duration_seconds: float
    message: str


# ── Extraction des packages depuis l'APK ──────────────────────────────────────
def _extract_packages_from_apk(apk_path: str) -> list[dict]:
    """
    Extrait les packages depuis un APK Android en lisant :
    - META-INF/<group>_<artifact>.version  → version des libs AndroidX/Jetpack
    - META-INF/com/android/build/gradle/app-metadata.properties → metadata app
    """
    packages = []
    seen = set()

    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()

            for name in names:
                # Pattern : META-INF/androidx.core_core-ktx.version
                if name.startswith("META-INF/") and name.endswith(".version"):
                    basename = name.replace("META-INF/", "").replace(".version", "")

                    # Séparer group et artifact : "androidx.core_core-ktx" → group=androidx.core, artifact=core-ktx
                    if "_" in basename:
                        parts = basename.split("_", 1)
                        group = parts[0]
                        artifact = parts[1]
                    else:
                        group = "android"
                        artifact = basename

                    try:
                        version = z.read(name).decode("utf-8").strip()
                    except Exception:
                        version = "unknown"

                    key = f"{group}:{artifact}"
                    if key not in seen and version:
                        seen.add(key)
                        packages.append({
                            "name": artifact,
                            "version": version,
                            "type": "java-archive",
                            "group": group,
                            "source": name,
                        })

                # Lire les metadata Gradle
                elif name == "META-INF/com/android/build/gradle/app-metadata.properties":
                    try:
                        content = z.read(name).decode("utf-8")
                        for line in content.splitlines():
                            if "=" in line:
                                k, v = line.split("=", 1)
                                log.info(f"App metadata: {k.strip()}={v.strip()}")
                    except Exception:
                        pass

                # Détecter les .jar embarqués
                elif name.endswith(".jar") and "META-INF" not in name:
                    jar_name = os.path.basename(name).replace(".jar", "")
                    if jar_name not in seen:
                        seen.add(jar_name)
                        packages.append({
                            "name": jar_name,
                            "version": "embedded",
                            "type": "java-archive",
                            "group": "embedded",
                            "source": name,
                        })

    except zipfile.BadZipFile:
        log.error(f"Fichier APK invalide ou corrompu : {apk_path}")

    log.info(f"{len(packages)} packages extraits de l'APK")
    return packages


def _build_syft_sbom(apk_path: str, packages: list[dict]) -> dict:
    """Construit un SBOM au format Syft à partir des packages extraits."""
    artifacts = []
    for i, pkg in enumerate(packages):
        artifacts.append({
            "id": f"pkg-{i:04d}",
            "name": pkg["name"],
            "version": pkg["version"],
            "type": pkg["type"],
            "foundBy": "apk-meta-inf-cataloger",
            "locations": [{"path": pkg["source"]}],
            "licenses": [],
            "language": "java",
            "cpes": [
                f"cpe:2.3:a:{pkg['group']}:{pkg['name']}:{pkg['version']}:*:*:*:*:*:*:*"
            ],
            "purl": f"pkg:maven/{pkg['group']}/{pkg['name']}@{pkg['version']}",
            "metadataType": "JavaMetadata",
            "metadata": {"groupId": pkg["group"], "artifactId": pkg["name"]}
        })

    return {
        "artifacts": artifacts,
        "source": {
            "type": "file",
            "target": apk_path,
        },
        "schema": {"version": "16.0.0"}
    }


def _scan_cve_with_grype(sbom_data: dict) -> list[dict]:
    """Scanne les CVE avec Grype en lui passant le SBOM via stdin."""
    sbom_json = json.dumps(sbom_data)
    env = {**os.environ, "GRYPE_CHECK_FOR_APP_UPDATE": "false"}

    r = subprocess.run(
        ["grype", "-o", "json", "-"],
        input=sbom_json,
        capture_output=True,
        text=True,
        timeout=120,
        env=env
    )

    if r.returncode not in (0, 1):
        if "database does not exist" in r.stderr:
            log.warning("Base CVE absente — scan CVE ignoré")
            return []
        log.warning(f"Grype code {r.returncode}: {r.stderr[:200]}")
        return []

    stdout = r.stdout.strip()
    json_start = stdout.find('{')
    if json_start < 0:
        return []
    stdout = stdout[json_start:]

    try:
        raw = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    matches = raw.get("matches", [])
    findings = []
    sev_map = {"critical":"critical","high":"high","medium":"medium",
               "low":"low","negligible":"low","unknown":"low"}

    for m in matches:
        vuln     = m.get("vulnerability", {})
        artifact = m.get("artifact", {})
        severity = sev_map.get(vuln.get("severity","unknown").lower(), "low")

        findings.append({
            "cve_id":      vuln.get("id", ""),
            "severity":    severity,
            "cvss":        vuln.get("cvss",[{}])[0].get("metrics",{}).get("baseScore") if vuln.get("cvss") else None,
            "description": vuln.get("description","")[:300],
            "package":     artifact.get("name",""),
            "version":     artifact.get("version",""),
            "fix_version": vuln.get("fix",{}).get("versions",[None])[0],
            "urls":        vuln.get("urls",[])[:2],
        })

    return findings


def _compute_score(findings: list[dict]) -> int:
    if not findings:
        return 100
    penalty = sum({"critical":35,"high":15,"medium":7,"low":2}.get(f.get("severity","low"),2) for f in findings)
    return max(0, 100 - penalty)


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
    tools = {}
    for tool in ["syft", "grype"]:
        try:
            r = subprocess.run([tool, "version"], capture_output=True, text=True)
            tools[tool] = r.stdout.strip().split("\n")[0]
        except FileNotFoundError:
            tools[tool] = "NON INSTALLÉ"

    db_check = subprocess.run(
        ["grype", "db", "status"],
        capture_output=True, text=True,
        env={**os.environ, "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    )
    tools["grype_db"] = "ok" if db_check.returncode == 0 else "ABSENTE"
    return {"status": "ok", "service": "syft_grype", "port": 8003, "tools": tools}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE_PATH, req.apk_filename)

    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    log.info(f"Scan APK : {req.apk_filename}")

    try:
        # 1. Extraire les packages depuis META-INF de l'APK
        packages = _extract_packages_from_apk(apk_path)

        # 2. Construire un SBOM synthétique
        sbom = _build_syft_sbom(apk_path, packages)

        # 3. Scanner les CVE avec Grype
        findings = _scan_cve_with_grype(sbom)

    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Timeout Grype (> 120s)")
    except Exception as e:
        raise HTTPException(500, str(e))

    counts = {"critical":0,"high":0,"medium":0,"low":0}
    for f in findings:
        sev = f.get("severity","low")
        if sev in counts:
            counts[sev] += 1

    score    = _compute_score(findings)
    duration = round(time.time() - t0, 2)
    nb_pkg   = len(packages)
    nb_cve   = len(findings)

    summary = ScanSummary(score=score, **counts)
    result  = ScanResult(
        status="success",
        apk_filename=req.apk_filename,
        sbom={
            "packages_count": nb_pkg,
            "packages": packages,
            "artifacts": sbom.get("artifacts", [])[:50],
        },
        findings=findings,
        summary=summary,
        duration_seconds=duration,
        message=f"{nb_pkg} packages détectés, {nb_cve} CVE trouvées en {duration}s — score {score}/100"
    )

    bg.add_task(_notify_aggregator, {
        **result.model_dump(),
        "repo": req.repo, "branch": req.branch, "commit": req.commit,
    })

    return result
