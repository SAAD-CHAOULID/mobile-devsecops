"""
service_ssl — :8009
Extrait les domaines d'un APK et vérifie leurs certificats SSL/TLS.
Détecte : certs expirés, TLS faible, cipher suites obsolètes, self-signed.
"""
import os, time, logging, zipfile, re, struct, ssl, socket
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import httpx

APK_STORAGE    = os.getenv("APK_STORAGE_PATH", "/apk_storage")
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8004/results")
SSL_TIMEOUT    = int(os.getenv("SSL_TIMEOUT", "5"))
MAX_DOMAINS    = int(os.getenv("MAX_DOMAINS", "20"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)
app = FastAPI(title="Service SSL/TLS Scanner", version="1.0.0")

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|app|dev|api|xyz|info)\b',
    re.IGNORECASE
)

# Domaines à ignorer (trop génériques)
IGNORE_DOMAINS = {
    "android.com", "google.com", "googleapis.com", "gstatic.com",
    "schema.org", "example.com", "w3.org", "mozilla.org",
    "apache.org", "github.com", "raw.githubusercontent.com",
}

WEAK_TLS  = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}


class ScanRequest(BaseModel):
    apk_filename: str
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None

class DomainResult(BaseModel):
    domain: str
    reachable: bool
    tls_version: str | None = None
    cipher: str | None = None
    cert_expiry: str | None = None
    days_until_expiry: int | None = None
    issues: list[str] = []
    severity: str = "ok"

class ScanResult(BaseModel):
    service: str = "ssl"
    status: str
    apk_filename: str
    domains_found: int
    domains_scanned: int
    domain_results: list[DomainResult]
    findings: list[dict]
    summary: dict
    duration_seconds: float
    message: str


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
            except Exception: continue
    except Exception: pass
    return strings


def _extract_domains(apk_path: str) -> list[str]:
    all_text = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for name in z.namelist():
                if name.endswith('.dex'):
                    all_text.extend(_extract_strings_from_dex(z.read(name)))
                elif any(name.endswith(e) for e in ('.xml','.json','.properties')):
                    try:
                        all_text.append(z.read(name).decode('utf-8', errors='ignore'))
                    except Exception: pass
    except zipfile.BadZipFile:
        raise RuntimeError(f"APK invalide : {apk_path}")

    combined = '\n'.join(all_text)
    domains = set(DOMAIN_PATTERN.findall(combined))
    # Filtrer les domaines ignorés et garder les plus pertinents
    filtered = [d.lower() for d in domains if d.lower() not in IGNORE_DOMAINS and len(d) > 6]
    return filtered[:MAX_DOMAINS]


def _check_ssl(domain: str) -> DomainResult:
    issues = []
    result = DomainResult(domain=domain, reachable=False)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result.reachable    = True
                result.tls_version  = ssock.version()
                cipher_info         = ssock.cipher()
                result.cipher       = cipher_info[0] if cipher_info else None

                # Vérifier la version TLS
                if result.tls_version in WEAK_TLS:
                    issues.append(f"Version TLS faible : {result.tls_version}")

                # Vérifier le cipher
                if result.cipher and any(w in result.cipher for w in WEAK_CIPHERS):
                    issues.append(f"Cipher faible : {result.cipher}")

                # Vérifier l'expiration du certificat
                cert = ssock.getpeercert()
                if cert:
                    expiry_str = cert.get('notAfter', '')
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        now    = datetime.now(timezone.utc)
                        days   = (expiry - now).days
                        result.cert_expiry         = expiry.isoformat()
                        result.days_until_expiry   = days
                        if days < 0:
                            issues.append(f"Certificat EXPIRÉ depuis {-days} jours")
                        elif days < 30:
                            issues.append(f"Certificat expire dans {days} jours")

    except ssl.SSLCertVerificationError as e:
        result.reachable = True
        issues.append(f"Certificat invalide/self-signed : {str(e)[:80]}")
    except ssl.SSLError as e:
        result.reachable = True
        issues.append(f"Erreur SSL : {str(e)[:80]}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        result.reachable = False  # Domaine non joignable — pas une erreur
    except Exception as e:
        log.debug(f"Erreur SSL pour {domain}: {e}")

    result.issues = issues
    if issues:
        if any("EXPIRÉ" in i or "self-signed" in i or "invalide" in i for i in issues):
            result.severity = "critical"
        elif any("faible" in i or "expire" in i for i in issues):
            result.severity = "high"
        else:
            result.severity = "medium"

    return result


def _build_findings(domain_results: list[DomainResult]) -> list[dict]:
    findings = []
    expired     = [r for r in domain_results if r.reachable and any("EXPIRÉ" in i for i in r.issues)]
    expiring    = [r for r in domain_results if r.reachable and r.days_until_expiry is not None and 0 <= r.days_until_expiry < 30]
    weak_tls    = [r for r in domain_results if r.reachable and r.tls_version in WEAK_TLS]
    invalid_cert= [r for r in domain_results if r.reachable and any("self-signed" in i or "invalide" in i for i in r.issues)]

    if expired:
        findings.append({"type":"expired_cert","severity":"critical",
            "description":f"{len(expired)} certificat(s) expiré(s)",
            "examples":[r.domain for r in expired]})
    if invalid_cert:
        findings.append({"type":"invalid_cert","severity":"critical",
            "description":f"{len(invalid_cert)} certificat(s) invalide(s)/self-signed",
            "examples":[r.domain for r in invalid_cert]})
    if weak_tls:
        findings.append({"type":"weak_tls","severity":"high",
            "description":f"{len(weak_tls)} domaine(s) avec TLS faible ({', '.join(set(r.tls_version for r in weak_tls))})",
            "examples":[r.domain for r in weak_tls]})
    if expiring:
        findings.append({"type":"expiring_cert","severity":"medium",
            "description":f"{len(expiring)} certificat(s) expirant dans moins de 30 jours",
            "examples":[f"{r.domain} ({r.days_until_expiry}j)" for r in expiring]})
    return findings


def _compute_score(findings):
    if not findings: return 100
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
    return {"status": "ok", "service": "ssl", "port": 8009,
            "ssl_timeout": SSL_TIMEOUT, "max_domains": MAX_DOMAINS}


@app.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest, bg: BackgroundTasks):
    apk_path = os.path.join(APK_STORAGE, req.apk_filename)
    if not os.path.exists(apk_path):
        raise HTTPException(404, f"APK introuvable : {apk_path}")

    t0 = time.time()
    try:
        domains = _extract_domains(apk_path)
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    log.info(f"{len(domains)} domaines extraits — scan SSL...")
    domain_results = [_check_ssl(d) for d in domains]
    reachable      = [r for r in domain_results if r.reachable]
    findings       = _build_findings(reachable)

    counts = {"critical":0,"high":0,"medium":0,"low":0}
    for f in findings:
        sev = f.get("severity","low")
        if sev in counts: counts[sev] += 1

    score    = _compute_score(findings)
    duration = round(time.time()-t0, 2)
    counts["score"] = score

    result = ScanResult(
        status="success", apk_filename=req.apk_filename,
        domains_found=len(domains), domains_scanned=len(reachable),
        domain_results=domain_results, findings=findings, summary=counts,
        duration_seconds=duration,
        message=f"{len(domains)} domaines trouvés, {len(reachable)} joignables, {len(findings)} problème(s) SSL — score {score}/100"
    )
    bg.add_task(_notify_aggregator, {**result.model_dump(),"repo":req.repo,"branch":req.branch,"commit":req.commit})
    return result
