"""
service_permissions — :8006
Analyse les permissions Android déclarées dans AndroidManifest.xml.
Classe chaque permission par niveau de dangerosité.
"""
import os, time, logging, zipfile, re
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service Permissions", version="1.0.0")

# Classification des permissions Android
PERMISSIONS_DB = {
    "critical": [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.MASTER_CLEAR",
        "android.permission.FACTORY_RESET",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.MOUNT_FORMAT_FILESYSTEMS",
    ],
    "high": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.GET_ACCOUNTS",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
    ],
    "medium": [
        "android.permission.INTERNET",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.NFC",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.READ_LOGS",
    ],
    "low": [
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.FLASHLIGHT",
        "android.permission.RECEIVE_NOTIFICATION",
        "android.permission.POST_NOTIFICATIONS",
    ],
}

# Mapping inversé permission → sévérité
PERM_SEVERITY = {}
for sev, perms in PERMISSIONS_DB.items():
    for p in perms:
        PERM_SEVERITY[p] = sev


def _parse_manifest(apk_path: str) -> list[str]:
    """Extrait les permissions depuis AndroidManifest.xml (binaire ou texte)."""
    permissions = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' not in z.namelist():
                log.warning("AndroidManifest.xml absent")
                return []

            manifest_data = z.read('AndroidManifest.xml')

            # Chercher les permissions dans le binaire XML Android
            # Les strings sont encodées en UTF-16 LE dans le manifest binaire
            content = manifest_data.decode('utf-8', errors='ignore')

            # Pattern pour permissions dans XML binaire/texte
            patterns = [
                r'android\.permission\.[A-Z_]+',
                r'uses-permission.*?android:name="([^"]+)"',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, content)
                permissions.extend(matches)

            # Aussi chercher en UTF-16
            try:
                content16 = manifest_data.decode('utf-16-le', errors='ignore')
                matches16 = re.findall(r'android\.permission\.[A-Z_]+', content16)
                permissions.extend(matches16)
            except Exception:
                pass

    except zipfile.BadZipFile:
        raise RuntimeError(f"APK invalide : {apk_path}")

    # Dédupliquer
    return list(set(permissions))


def _classify_permissions(permissions: list[str]) -> list[dict]:
    findings = []
    for perm in permissions:
        severity = PERM_SEVERITY.get(perm)
        if not severity:
            # Permission inconnue ou tierce
            if "permission" in perm.lower():
                severity = "low"
            else:
                continue

        # Description lisible
        short_name = perm.split(".")[-1].replace("_", " ").title()
        descriptions = {
            "critical": f"Permission critique : permet {short_name} — risque élevé d'abus",
            "high":     f"Permission sensible : accès à {short_name}",
            "medium":   f"Permission modérée : {short_name}",
            "low":      f"Permission standard : {short_name}",
        }

        findings.append({
            "permission":  perm,
            "severity":    severity,
            "short_name":  short_name,
            "description": descriptions.get(severity, perm),
        })

    # Trier par sévérité
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: order.get(x["severity"], 4))
    return findings


def _compute_score(findings: list[dict]) -> int:
    if not findings:
        return 100
    penalty = sum({"critical":20,"high":10,"medium":4,"low":1}.get(f.get("severity","low"),1) for f in findings)
    return max(0, 100 - penalty)


async def _notify_aggregator(payload):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(AGGREGATOR_URL, json=payload)
    except Exception as e:
        log.warning(f"Aggregator: {e}")


class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanResult(BaseModel):
    service: str = "permissions"
    status: str
    apk_filename: str
    permissions_total: int
    findings: list[dict]
    summary: dict
    duration_seconds: float
    message: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "permissions", "port": 8006,
            "permissions_db": sum(len(v) for v in PERMISSIONS_DB.values())}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE, req.apk_filename)
    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    try:
        permissions = _parse_manifest(apk_path)
        findings    = _classify_permissions(permissions)
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    counts = {"critical":0,"high":0,"medium":0,"low":0}
    for f in findings:
        sev = f.get("severity","low")
        if sev in counts: counts[sev] += 1

    score = _compute_score(findings)
    duration = round(time.time()-t0, 2)
    counts["score"] = score

    result = ScanResult(
        status="success", apk_filename=req.apk_filename,
        permissions_total=len(permissions),
        findings=findings, summary=counts, duration_seconds=duration,
        message=f"{len(permissions)} permissions — {counts['critical']} critiques, {counts['high']} high — score {score}/100"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(),"repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
