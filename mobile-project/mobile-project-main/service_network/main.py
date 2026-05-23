"""
service_network — :8007
Analyse statique des endpoints réseau dans un APK.
Extrait URLs, IPs, domaines depuis le bytecode DEX et les ressources.
"""
import os, time, logging, zipfile, re, struct
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service Network Analysis", version="1.0.0")

# Patterns de détection
URL_PATTERN    = re.compile(r'https?://[^\s\'"<>]{4,200}', re.IGNORECASE)
IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|api|xyz|info|biz|online)\b', re.IGNORECASE)

# Domaines/IPs considérés suspects
SUSPICIOUS_DOMAINS = [".onion", "ngrok.io", "pastebin.com", "bit.ly", "tinyurl.com", "raw.githubusercontent.com"]
PRIVATE_IPS        = ["192.168.", "10.", "172.16.", "127.0.0.1", "0.0.0.0"]
CLEARTEXT_HTTP     = re.compile(r'^http://', re.IGNORECASE)


class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class ScanResult(BaseModel):
    service: str = "network"
    status: str
    apk_filename: str
    urls: list[str]
    domains: list[str]
    ips: list[str]
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
        for i in range(min(str_count, 10000)):
            try:
                ptr    = struct.unpack_from('<I', dex_data, str_offset + i * 4)[0]
                length = 0; shift = 0; pos = ptr
                while True:
                    b = dex_data[pos]; length |= (b & 0x7F) << shift; pos += 1
                    if not (b & 0x80): break
                    shift += 7
                s = dex_data[pos:pos+length].decode('utf-8', errors='ignore')
                if len(s) > 6: strings.append(s)
            except Exception:
                continue
    except Exception:
        pass
    return strings


def _scan_apk(apk_path: str) -> tuple[list[str], list[str], list[str]]:
    all_text = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            names = z.namelist()

            # Extraire strings des DEX
            for name in names:
                if name.endswith('.dex'):
                    strings = _extract_strings_from_dex(z.read(name))
                    all_text.extend(strings)

            # Lire les fichiers texte (XML, JSON, properties)
            text_exts = ('.xml', '.json', '.properties', '.txt', '.html', '.js')
            for name in names:
                if any(name.endswith(ext) for ext in text_exts):
                    try:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        all_text.append(content)
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        raise RuntimeError(f"APK invalide : {apk_path}")

    combined = '\n'.join(all_text)

    urls    = list(set(URL_PATTERN.findall(combined)))
    ips     = list(set(IP_PATTERN.findall(combined)))
    domains = list(set(DOMAIN_PATTERN.findall(combined)))

    # Filtrer les faux positifs évidents
    urls    = [u for u in urls if len(u) < 200 and 'android.com' not in u][:100]
    ips     = [ip for ip in ips if not ip.startswith(('0.0', '255.'))][:50]
    domains = [d for d in domains if len(d) > 5 and d not in ['example.com']][:100]

    return urls, ips, domains


def _analyze_findings(urls, ips, domains) -> list[dict]:
    findings = []

    # URLs en clair (HTTP)
    http_urls = [u for u in urls if CLEARTEXT_HTTP.match(u)]
    if http_urls:
        findings.append({
            "type": "cleartext_http", "severity": "high",
            "description": f"{len(http_urls)} URL(s) en clair HTTP (non chiffré)",
            "examples": http_urls[:5],
        })

    # Domaines suspects
    for domain in domains:
        for sus in SUSPICIOUS_DOMAINS:
            if sus in domain:
                findings.append({
                    "type": "suspicious_domain", "severity": "critical",
                    "description": f"Domaine suspect : {domain}",
                    "examples": [domain],
                })

    # IPs hardcodées (hors localhost)
    public_ips = [ip for ip in ips if not any(ip.startswith(p) for p in PRIVATE_IPS)]
    if public_ips:
        findings.append({
            "type": "hardcoded_ip", "severity": "medium",
            "description": f"{len(public_ips)} IP(s) publique(s) hardcodée(s)",
            "examples": public_ips[:5],
        })

    # IPs privées (debug/dev ?)
    private_ips = [ip for ip in ips if any(ip.startswith(p) for p in PRIVATE_IPS) and ip != "127.0.0.1"]
    if private_ips:
        findings.append({
            "type": "private_ip", "severity": "low",
            "description": f"IP(s) privée(s) trouvée(s) — possibles endpoints de dev",
            "examples": private_ips[:5],
        })

    # Beaucoup d'URLs → surface d'attaque large
    if len(urls) > 20:
        findings.append({
            "type": "large_attack_surface", "severity": "medium",
            "description": f"{len(urls)} URLs détectées — surface d'attaque réseau étendue",
            "examples": urls[:3],
        })

    return findings


def _compute_score(findings):
    if not findings:
        return 100
    penalty = sum({"critical":35,"high":15,"medium":7,"low":2}.get(f.get("severity","low"),2) for f in findings)
    return max(0, 100 - penalty)


async def _notify_aggregator(payload):
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            await c.post(AGGREGATOR_URL, json=payload)
    except Exception as e:
        log.warning(f"Aggregator: {e}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "network", "port": 8007}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE, req.apk_filename)
    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    try:
        urls, ips, domains = _scan_apk(apk_path)
        findings = _analyze_findings(urls, ips, domains)
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
        urls=urls[:50], domains=domains[:50], ips=ips[:20],
        findings=findings, summary=counts, duration_seconds=duration,
        message=f"{len(urls)} URLs, {len(domains)} domaines, {len(ips)} IPs — score {score}/100"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(),"repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
