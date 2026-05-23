# Contrat API — Les 3 scanners

## Endpoint commun : POST /scan

Tous les services exposent le même endpoint et le même format de réponse.
L'orchestrateur n'a qu'à changer l'URL et le body selon le scanner.

---

## service_mobsf — :8001

**Request**
```json
POST http://service_mobsf:8001/scan
{
  "apk_filename": "monapp_main_abc123_20250518.apk",
  "repo": "monapp",
  "branch": "main",
  "commit": "abc123"
}
```

**Response**
```json
{
  "service": "mobsf",
  "status": "success",
  "apk_filename": "monapp_main_abc123_20250518.apk",
  "findings": { ...rapport MobSF complet... },
  "summary": { "critical": 2, "high": 5, "medium": 8, "low": 3, "score": 72 },
  "duration_seconds": 45.2,
  "message": "Scan terminé en 45.2s — score 72/100"
}
```

---

## service_gitleaks — :8002

**Request**
```json
POST http://service_gitleaks:8002/scan
{
  "repo_path": "/repos_storage/monapp_main_20250518",
  "repo": "monapp",
  "branch": "main",
  "commit": "abc123"
}
```

**Response**
```json
{
  "service": "gitleaks",
  "status": "success",
  "repo_path": "/repos_storage/monapp_main_20250518",
  "findings": [
    {
      "rule_id": "aws-access-token",
      "severity": "critical",
      "file": "app/src/main/java/Config.java",
      "line": 42,
      "secret": "AKIA***",
      "commit": "abc123",
      "author": "dev@example.com"
    }
  ],
  "summary": { "critical": 1, "high": 0, "medium": 2, "low": 0, "score": 50 },
  "duration_seconds": 3.1,
  "message": "3 secret(s) détecté(s) en 3.1s — score 50/100"
}
```

---

## service_syft — :8003

**Request**
```json
POST http://service_syft:8003/scan
{
  "apk_filename": "monapp_main_abc123_20250518.apk",
  "repo": "monapp",
  "branch": "main",
  "commit": "abc123"
}
```

**Response**
```json
{
  "service": "syft_grype",
  "status": "success",
  "apk_filename": "monapp_main_abc123_20250518.apk",
  "sbom": { "packages_count": 87, "artifacts": [...] },
  "findings": [
    {
      "cve_id": "CVE-2023-12345",
      "severity": "high",
      "cvss": 8.1,
      "package": "okhttp",
      "version": "3.12.0",
      "fix_version": "4.9.3",
      "description": "..."
    }
  ],
  "summary": { "critical": 0, "high": 3, "medium": 12, "low": 7, "score": 55 },
  "duration_seconds": 18.7,
  "message": "87 packages analysés, 22 CVE trouvées en 18.7s — score 55/100"
}
```

---

## Healthchecks

```
GET http://service_mobsf:8001/health
GET http://service_gitleaks:8002/health
GET http://service_syft:8003/health
```

Réponse : `{ "status": "ok", "service": "...", "port": ... }`

---

## Volumes partagés (à créer avec init.sh)

| Volume | Utilisé par |
|---|---|
| `apk_storage` | orchestrateur → service_mobsf, service_syft |
| `repos_storage` | orchestrateur → service_gitleaks |

## Réseau

Tous les services rejoignent `pipeline_net` (réseau Docker externe).
L'orchestrateur appelle les services par leur nom de container.
