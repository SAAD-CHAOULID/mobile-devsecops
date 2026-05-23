"""
service_androguard — :8004
Analyse statique du bytecode DEX Android.
Détecte : APIs dangereuses, strings suspectes, fichiers embarqués, libs natives.
"""
import os, json, time, logging, zipfile, struct
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service Androguard", version="1.0.0")

DANGEROUS_APIS = {
    "critical": [
        "Ljava/lang/Runtime;->exec(",
        "Landroid/telephony/SmsManager;->sendTextMessage(",
        "Ljava/lang/reflect/Method;->invoke(",
        "Ldalvik/system/DexClassLoader;",
    ],
    "high": [
        "Landroid/location/LocationManager;",
        "Landroid/hardware/Camera;",
        "Landroid/media/AudioRecord;",
        "Ljavax/crypto/Cipher;",
        "Landroid/webkit/WebView;->addJavascriptInterface(",
    ],
    "medium": [
        "Ljava/net/URL;->openConnection(",
        "Landroid/webkit/WebView;->loadUrl(",
        "Ljava/io/FileOutputStream;",
        "Landroid/content/SharedPreferences;",
    ],
}

SUSPICIOUS_STRINGS = [
    "/system/bin/su", "chmod 777", "superuser", "base64_decode",
    ".onion", "exec(", "Runtime.getRuntime",
]

class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanResult(BaseModel):
    service: str = "androguard"
    status: str
    apk_filename: str
    findings: list[dict]
    summary: dict
    duration_seconds: float
    message: str


def _extract_strings_from_dex(dex_data: bytes) -> list[str]:
    strings = []
    try:
        if dex_data[:3] != b'dex':
            return []
        str_count  = struct.unpack_from('<I', dex_data, 0x38)[0]
        str_offset = struct.unpack_from('<I', dex_data, 0x3C)[0]
        for i in range(min(str_count, 8000)):
            try:
                ptr = struct.unpack_from('<I', dex_data, str_offset + i * 4)[0]
                # ULEB128 — lire la longueur
                length = 0
                shift  = 0
                pos    = ptr
                while True:
                    b = dex_data[pos]
                    length |= (b & 0x7F) << shift
                    pos += 1
                    if not (b & 0x80):
                        break
                    shift += 7
                s = dex_data[pos:pos + length].decode('utf-8', errors='ignore')
                if len(s) > 5:
                    strings.append(s)
            except Exception:
                continue
    except Exception as e:
        log.debug(f"Erreur DEX: {e}")
    return strings


def _scan_apk(apk_path: str) -> list[dict]:
    findings = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            dex_files = [n for n in names if n.endswith('.dex')]

            all_strings = []
            for dex_name in dex_files:
                dex_data = z.read(dex_name)
                all_strings.extend(_extract_strings_from_dex(dex_data))

            log.info(f"{len(dex_files)} DEX, {len(all_strings)} strings extraites")

            # APIs dangereuses
            for severity, apis in DANGEROUS_APIS.items():
                for api in apis:
                    matches = [s for s in all_strings if api in s]
                    if matches:
                        findings.append({
                            "type": "dangerous_api", "severity": severity,
                            "api": api,
                            "description": f"API sensible détectée : {api}",
                            "occurrences": len(matches),
                            "examples": [m[:80] for m in matches[:3]],
                        })

            # Strings suspectes
            for pattern in SUSPICIOUS_STRINGS:
                matches = [s for s in all_strings if pattern.lower() in s.lower()]
                if matches:
                    findings.append({
                        "type": "suspicious_string", "severity": "high",
                        "pattern": pattern,
                        "description": f"String suspecte : {pattern}",
                        "occurrences": len(matches),
                        "examples": [m[:80] for m in matches[:3]],
                    })

            # Fichiers suspects embarqués
            for name in names:
                if any(name.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb']):
                    findings.append({
                        "type": "suspicious_file", "severity": "high",
                        "file": name,
                        "description": f"Script embarqué : {name}",
                        "occurrences": 1, "examples": [name],
                    })

            # Libs natives
            native_libs = [n for n in names if n.endswith('.so')]
            if native_libs:
                findings.append({
                    "type": "native_libraries", "severity": "low",
                    "description": f"{len(native_libs)} lib(s) native(s)",
                    "occurrences": len(native_libs),
                    "examples": native_libs[:5],
                })

    except zipfile.BadZipFile:
        raise RuntimeError(f"APK invalide : {apk_path}")
    return findings


def _compute_score(findings):
    if not findings:
        return 100
    penalty = sum({"critical":30,"high":15,"medium":7,"low":2}.get(f.get("severity","low"),2) for f in findings)
    return max(0, 100 - penalty)


async def _notify_aggregator(payload):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(AGGREGATOR_URL, json=payload)
    except Exception as e:
        log.warning(f"Aggregator: {e}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "androguard", "port": 8004}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE, req.apk_filename)
    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")
    t0 = time.time()
    try:
        findings = _scan_apk(apk_path)
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
        findings=findings, summary=counts, duration_seconds=duration,
        message=f"{len(findings)} finding(s) — score {score}/100"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(), "repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
