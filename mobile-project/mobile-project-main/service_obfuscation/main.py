"""
service_obfuscation — :8008
Détecte l'obfuscation et les techniques anti-debug/anti-analysis dans un APK.
"""
import os, time, logging, zipfile, re, struct, math
from collections import Counter
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service Obfuscation Detection", version="1.0.0")

# Signatures d'obfuscateurs connus
OBFUSCATOR_SIGNATURES = {
    "ProGuard":    ["proguard", "R8"],
    "DexGuard":    ["dexguard", "guardsquare"],
    "DashO":       ["DashO", "preemptive"],
    "Allatori":    ["allatori"],
    "Obfuscapk":   ["obfuscapk"],
}

# Techniques anti-debug/anti-analysis
ANTI_DEBUG_APIS = [
    "isDebuggerConnected",
    "android.os.Debug",
    "detectDebugger",
    "Landroid/content/pm/ApplicationInfo;->FLAG_DEBUGGABLE",
    "ro.debuggable",
    "ro.secure",
    "TracerPid",
]

ANTI_EMULATOR_APIS = [
    "Build.FINGERPRINT",
    "Build.MODEL",
    "generic",
    "goldfish",
    "sdk_gphone",
    "Genymotion",
    "android.os.Build",
    "telephony.imei",
]

ROOT_DETECTION_APIS = [
    "/system/app/Superuser.apk",
    "/sbin/su",
    "/system/bin/su",
    "/system/xbin/su",
    "eu.chainfire.supersu",
    "com.topjohnwu.magisk",
    "RootBeer",
]

DYNAMIC_LOADING = [
    "DexClassLoader",
    "PathClassLoader",
    "dalvik.system",
    "loadDex",
    "BaseDexClassLoader",
]


class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanResult(BaseModel):
    service: str = "obfuscation"
    status: str
    apk_filename: str
    obfuscation_score: int
    findings: list[dict]
    summary: dict
    duration_seconds: float
    message: str


def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counter = Counter(data)
    length  = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counter.values() if c > 0)


def _extract_strings_from_dex(dex_data: bytes) -> list[str]:
    strings = []
    try:
        if dex_data[:3] != b'dex': return []
        str_count  = struct.unpack_from('<I', dex_data, 0x38)[0]
        str_offset = struct.unpack_from('<I', dex_data, 0x3C)[0]
        for i in range(min(str_count, 10000)):
            try:
                ptr = struct.unpack_from('<I', dex_data, str_offset + i * 4)[0]
                length = 0; shift = 0; pos = ptr
                while True:
                    b = dex_data[pos]; length |= (b & 0x7F) << shift; pos += 1
                    if not (b & 0x80): break
                    shift += 7
                s = dex_data[pos:pos+length].decode('utf-8', errors='ignore')
                if s: strings.append(s)
            except Exception:
                continue
    except Exception:
        pass
    return strings


def _detect_short_names(strings: list[str]) -> bool:
    """Détecte si les classes/méthodes ont des noms obfusqués (a, b, c...)."""
    short = [s for s in strings if re.match(r'^[a-z]{1,2}$', s)]
    return len(short) > 50


def _scan_apk(apk_path: str) -> list[dict]:
    findings = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()
            all_strings = []
            dex_entropies = []

            for name in names:
                if name.endswith('.dex'):
                    dex_data = z.read(name)
                    ent = _entropy(dex_data)
                    dex_entropies.append(ent)
                    strings = _extract_strings_from_dex(dex_data)
                    all_strings.extend(strings)

            combined = '\n'.join(all_strings)

            # 1. Entropie élevée → code chiffré/compressé
            if dex_entropies:
                avg_entropy = sum(dex_entropies) / len(dex_entropies)
                log.info(f"Entropie DEX moyenne: {avg_entropy:.2f}")
                if avg_entropy > 7.2:
                    findings.append({
                        "type": "high_entropy", "severity": "critical",
                        "description": f"Entropie DEX très élevée ({avg_entropy:.2f}/8.0) — code probablement chiffré ou packé",
                        "value": round(avg_entropy, 3),
                    })
                elif avg_entropy > 6.5:
                    findings.append({
                        "type": "high_entropy", "severity": "high",
                        "description": f"Entropie DEX élevée ({avg_entropy:.2f}/8.0) — possible obfuscation",
                        "value": round(avg_entropy, 3),
                    })

            # 2. Noms de classes obfusqués
            if _detect_short_names(all_strings):
                findings.append({
                    "type": "obfuscated_names", "severity": "high",
                    "description": "Noms de classes/méthodes obfusqués détectés (noms d'1-2 caractères)",
                })

            # 3. Obfuscateurs connus
            for obf_name, signatures in OBFUSCATOR_SIGNATURES.items():
                if any(sig.lower() in combined.lower() for sig in signatures):
                    findings.append({
                        "type": "known_obfuscator", "severity": "medium",
                        "description": f"Obfuscateur détecté : {obf_name}",
                        "obfuscator": obf_name,
                    })

            # 4. Anti-debug
            anti_debug_found = [api for api in ANTI_DEBUG_APIS if api in combined]
            if anti_debug_found:
                findings.append({
                    "type": "anti_debug", "severity": "high",
                    "description": f"Techniques anti-debug détectées ({len(anti_debug_found)} APIs)",
                    "examples": anti_debug_found[:5],
                })

            # 5. Anti-émulateur
            anti_emu_found = [api for api in ANTI_EMULATOR_APIS if api in combined]
            if len(anti_emu_found) >= 3:
                findings.append({
                    "type": "anti_emulator", "severity": "high",
                    "description": f"Détection d'émulateur ({len(anti_emu_found)} indicateurs)",
                    "examples": anti_emu_found[:5],
                })

            # 6. Détection root
            root_found = [api for api in ROOT_DETECTION_APIS if api in combined]
            if root_found:
                findings.append({
                    "type": "root_detection", "severity": "medium",
                    "description": f"Détection de root/jailbreak ({len(root_found)} indicateurs)",
                    "examples": root_found[:5],
                })

            # 7. Chargement dynamique de code
            dyn_found = [api for api in DYNAMIC_LOADING if api in combined]
            if dyn_found:
                findings.append({
                    "type": "dynamic_loading", "severity": "critical",
                    "description": "Chargement dynamique de code DEX détecté — possible malware dropper",
                    "examples": dyn_found[:3],
                })

            # 8. Plusieurs fichiers DEX (multi-dex suspect)
            dex_count = len([n for n in names if n.endswith('.dex')])
            if dex_count > 3:
                findings.append({
                    "type": "multidex", "severity": "low",
                    "description": f"{dex_count} fichiers DEX — application volumineuse ou packing suspect",
                    "value": dex_count,
                })

    except zipfile.BadZipFile:
        raise RuntimeError(f"APK invalide : {apk_path}")
    return findings


def _obfuscation_score(findings: list[dict]) -> int:
    """Score d'obfuscation de 0 (aucune) à 100 (très obfusqué)."""
    score = 0
    for f in findings:
        score += {"critical":30,"high":20,"medium":10,"low":5}.get(f.get("severity","low"),5)
    return min(100, score)


def _security_score(obf_score: int) -> int:
    return max(0, 100 - obf_score)


async def _notify_aggregator(payload):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(AGGREGATOR_URL, json=payload)
    except Exception as e:
        log.warning(f"Aggregator: {e}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "obfuscation", "port": 8008}


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

    obf_score = _obfuscation_score(findings)
    sec_score = _security_score(obf_score)
    duration  = round(time.time()-t0, 2)
    counts["score"] = sec_score
    counts["obfuscation_level"] = obf_score

    result = ScanResult(
        status="success", apk_filename=req.apk_filename,
        obfuscation_score=obf_score,
        findings=findings, summary=counts, duration_seconds=duration,
        message=f"Niveau obfuscation : {obf_score}/100 — {len(findings)} technique(s) détectée(s)"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(),"repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
