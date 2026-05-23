# MobSecOps — Pipeline de Sécurité Mobile

> **Intercepte chaque push GitHub, analyse votre APK Android avec 9 scanners parallèles, génère un rapport IA et bloque automatiquement les releases dangereuses — avant qu'elles n'atteignent la production.**

![Version](https://img.shields.io/badge/version-2.0.0-00d4ff?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-microservices-green?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square)
![IA](https://img.shields.io/badge/IA-Groq%20llama--3.1-7fff7f?style=flat-square)

---

## Sommaire

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Services & Ports](#services--ports)
- [Les 9 Scanners](#les-9-scanners)
- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Intégration GitHub Webhook](#intégration-github-webhook)
- [API Reference](#api-reference)
- [Rapport IA](#rapport-ia)
- [Notifications Discord](#notifications-discord)
- [Tests](#tests)
- [Variables d'environnement](#variables-denvironnement)

---

## Vue d'ensemble

MobSecOps est un pipeline CI/CD de sécurité dédié aux applications Android. Il s'intègre directement à GitHub via webhook et automatise l'analyse de sécurité de bout en bout :

```
git push → Webhook → 9 Scanners parallèles → IA Groq → Discord → Push ✅ / 🚫
```

**En moins de 90 secondes**, chaque push est analysé, scoré et décision de déploiement prise automatiquement.

### Chiffres clés

| Métrique | Valeur |
|---|---|
| Scanners parallèles | 9 |
| Services microservices | 11 |
| Temps d'analyse complet | < 90s |
| Score de sécurité | /100 par scanner |
| Moteurs antivirus (VirusTotal) | 70+ |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitHub Push                              │
│                     webhook (HMAC-SHA256)                       │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Controller :8000    │
              │  Orchestrateur async  │
              └───────────┬───────────┘
                          │  asyncio.gather()
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐   ┌──────────────┐
    │  MobSF   │    │ Gitleaks │   │  Androguard  │
    │  :8001   │    │  :8002   │   │    :8004     │
    └──────────┘    └──────────┘   └──────────────┘
    ┌──────────┐    ┌──────────┐   ┌──────────────┐
    │  Network │    │ Permiss. │   │  Obfuscation │
    │  :8005   │    │  :8006   │   │    :8007     │
    └──────────┘    └──────────┘   └──────────────┘
    ┌──────────┐    ┌──────────┐   ┌──────────────┐
    │  SSL/TLS │    │VirusTot. │   │  Syft/Grype  │
    │  :8008   │    │  :8009   │   │    :8003     │
    └──────────┘    └──────────┘   └──────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Aggregator :8011    │
              │  Fusion des résultats │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    IA Groq (llama-3.1)│
              │  Rapport + Décision   │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Discord Webhook     │
              │  Embed + Push status  │
              └───────────────────────┘
```

---

## Services & Ports

| Service | Port | Rôle | Type |
|---|---|---|---|
| **Controller** | `:8000` | Point d'entrée, orchestrateur HMAC | — |
| **MobSF** | `:8001` | Analyse statique complète APK | APK |
| **Gitleaks** | `:8002` | Détection secrets dans le repo | REPO |
| **Syft/Grype** | `:8003` | SBOM + audit CVE | APK |
| **Androguard** | `:8004` | Analyse bytecode DEX | APK |
| **VirusTotal** | `:8005` | 70+ moteurs antivirus | APK |
| **Permissions** | `:8006` | Audit AndroidManifest | APK |
| **Network** | `:8007` | Extraction URLs/IPs/domaines | APK |
| **Obfuscation** | `:8008` | Score d'obfuscation | APK |
| **SSL/TLS** | `:8009` | Audit certificats et TLS | APK |
| **Aggregator** | `:8011` | Fusion résultats + rapport HTML | — |

---

## Les 9 Scanners

### 🛡️ MobSF — `:8001`
Analyse statique approfondie de l'APK Android. Inspecte le manifest, le code Java/Kotlin, les permissions et génère un rapport de sécurité complet.

**Détecte :** Manifest · Permissions · Crypto · Network · Score /100

---

### 🔑 Gitleaks — `:8002`
Scan du repo Git à la recherche de secrets hardcodés — API keys, tokens, credentials exposés dans le code ou l'historique des commits.

**Détecte :** AWS Keys · GitHub PAT · GCP Keys · Passwords · Stripe · Clés privées

---

### 📦 Syft / Grype — `:8003`
Génère un SBOM complet de l'APK via Syft, puis Grype audite chaque package contre la base CVE. Identifie les dépendances vulnérables avec fix version.

**Détecte :** SBOM · CVE · CVSS · Fix version · okhttp · androidx

---

### 🔍 Androguard — `:8004`
Analyse du bytecode DEX directement. Détecte les appels à des APIs dangereuses, les strings suspectes et les bibliothèques natives embarquées.

**Détecte :** `Runtime.exec` · SMS · Reflection · `DexClassLoader` · Root detection

---

### 🌐 Network — `:8005`
Extrait et analyse toutes les URLs, domaines et adresses IP présents dans l'APK. Évalue leur réputation et détecte les endpoints suspects.

**Détecte :** URLs · Domaines · IPs · HTTP hardcodé · Onion · Endpoints

---

### 🔒 Permissions — `:8006`
Audit complet des permissions déclarées dans le manifest Android. Classifie chaque permission par niveau de risque et détecte les abus.

**Détecte :** `CAMERA` · `LOCATION` · `CONTACTS` · `STORAGE` · `DEVICE_ADMIN`

---

### 🎭 Obfuscation — `:8007`
Mesure le niveau d'obfuscation du code. Un score trop faible expose la logique métier ; un score anormalement élevé peut indiquer du code malveillant caché.

**Détecte :** Score 0-100 · ProGuard · R8 · Anti-debug · Code packing

---

### 🔐 SSL/TLS — `:8008`
Vérifie la configuration SSL : certificate pinning, vérification des certificats, configurations TLS faibles, et mauvaises pratiques de sécurité réseau.

**Détecte :** Pinning manquant · TLS 1.0/1.1 · `AllowAllHostnames` · Cert validation

---

### 🦠 VirusTotal — `:8009`
Soumet le hash de l'APK à l'API VirusTotal et agrège les résultats de +70 moteurs antivirus pour détecter les malwares connus.

**Détecte :** 70+ AV engines · Hash lookup · Malware connu · Réputation APK

---

## Fonctionnalités

**Déclenchement automatique**
Chaque `git push` déclenche le pipeline via webhook GitHub avec vérification de signature HMAC-SHA256.

**9 scans en parallèle**
Tous les scanners s'exécutent simultanément via `asyncio.gather()`, réduisant le temps total à moins de 90 secondes.

**Analyse IA (Groq + Ollama)**
Les résultats agrégés sont analysés par `llama-3.1` via Groq API. L'IA génère un niveau de risque, des tickets structurés et une recommandation de push.

**Blocage automatique**
Si le niveau de risque est `critical` ou `high`, le push est marqué comme bloqué et l'équipe est notifiée instantanément.

**Score de sécurité unifié**
Chaque scanner produit un score /100. L'agrégateur calcule un score global en temps réel.

**SBOM + CVE Analysis**
Syft génère un Software Bill of Materials complet. Grype audite ensuite toutes les dépendances pour identifier les CVEs connues.

**Notifications Discord riches**
Embed Discord complet : score, niveau de risque coloré, top 5 tickets, release notes générées par IA.

**Admin protégé par API Key**
Routes `/admin/status` et `/admin/pipelines` protégées. Historique des 20 derniers pipelines disponible.

---

## Installation

### Prérequis

- Docker & Docker Compose
- Git
- Un webhook GitHub configuré
- Clé API Groq (pour l'analyse IA)
- Clé API VirusTotal (optionnel)
- Webhook Discord

### Démarrage rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-org/mobsecops.git
cd mobsecops

# 2. Copier et configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos clés API

# 3. Initialiser l'infrastructure (volumes, réseau Docker)
chmod +x init.sh && ./init.sh

# 4. Démarrer tous les services
docker-compose up -d

# 5. Vérifier que tout est UP
for port in 8000 8001 8002 8003 8004 8005 8006 8007 8008 8009 8011; do
  echo -n ":$port → "
  curl -s -o /dev/null -w "%{http_code}" http://localhost:$port/health
  echo ""
done
```

---

## Intégration GitHub Webhook

### Étape 1 — Configurer le webhook

Dans les settings de votre repo GitHub :

```
Payload URL : https://votre-serveur:8000/webhook/github
Content type: application/json
Secret      : votre_secret_hmac
Events      : push
```

Le controller vérifie automatiquement la signature `X-Hub-Signature-256` à chaque événement.

### Étape 2 — Démarrer l'infrastructure

```bash
./init.sh         # Crée apk_storage/, repos_storage/, pipeline_net
docker-compose up # Démarre les 11 services
```

### Étape 3 — Pousser

```bash
git push origin main
# → Webhook reçu par le controller
# → Repo cloné dans /repos_storage/
# → APK détecté dans /apk_storage/
# → 9 scans parallèles lancés
# → Rapport IA généré (Groq llama-3.1)
# → Notification Discord envoyée
# → Push: ✅ AUTORISÉ | 🚫 BLOQUÉ
```

### Trigger manuel (tests)

```bash
curl -s -X POST http://localhost:8000/trigger/manual \
  -H "Content-Type: application/json" \
  -d '{
    "repo":         "myapp",
    "branch":       "main",
    "commit":       "abc123",
    "apk_filename": "myapp.apk",
    "services":     ["mobsf", "gitleaks", "androguard"]
  }'
```

---

## API Reference

Tous les scanners partagent la même interface. L'orchestrateur n'a qu'à changer l'URL.

### `POST /scan` — Lancer un scan

**Request :**
```json
{
  "apk_filename": "myapp_main_abc123.apk",
  "repo":         "myapp",
  "branch":       "main",
  "commit":       "abc123"
}
```

> Pour Gitleaks, utiliser `repo_path` à la place de `apk_filename`.

**Response unifiée :**
```json
{
  "service":       "mobsf",
  "status":        "success",
  "apk_filename":  "myapp_main_abc123.apk",
  "findings": [
    {
      "rule_id":  "aws-access-token",
      "severity": "critical",
      "file":     "Config.java",
      "line":     42
    }
  ],
  "summary": {
    "critical": 1,
    "high":     3,
    "medium":   8,
    "low":      2,
    "score":    61
  },
  "duration_seconds": 45.2,
  "message": "Scan terminé en 45.2s — score 61/100"
}
```

### `GET /health` — Healthcheck

```bash
curl http://localhost:8001/health
# {"status": "ok", "service": "mobsf", "port": 8001}
```

### `GET /admin/pipelines` — Historique *(auth requis)*

```bash
curl http://localhost:8000/admin/pipelines \
  -H "X-API-Key: votre_cle_admin"
```

### `GET /admin/status` — État des services *(auth requis)*

```bash
curl http://localhost:8000/admin/status \
  -H "X-API-Key: votre_cle_admin"
```

---

## Rapport IA

L'agrégateur envoie les résultats de tous les scanners à **Groq (llama-3.1)** qui produit :

```json
{
  "risk_level":  "high",
  "summary":     "3 vulnérabilités critiques détectées : token AWS exposé, Runtime.exec() sans validation, CVE-2023-3655 (CVSS 8.1) dans okhttp 3.12.0.",
  "tickets": [
    {
      "title":       "Token AWS exposé dans Config.java",
      "severity":    "critical",
      "remediation": "Supprimer du code source, utiliser AWS Secrets Manager. Révoquer immédiatement.",
      "effort":      "low"
    }
  ],
  "release_notes":       "Correction urgente : supprimer token AWS, mettre à jour okhttp ≥ 4.9.3.",
  "push_recommendation": false
}
```

### Niveaux de risque

| Niveau | Score | Décision push |
|---|---|---|
| 🔴 `CRITICAL` | 0–49 | **Bloqué** — intervention immédiate |
| 🟠 `HIGH` | 50–64 | **Bloqué** — correction avant déploiement |
| 🟡 `MEDIUM` | 65–79 | **Autorisé** — tickets créés, correction planifiée |
| 🟢 `LOW` | 80–100 | **Autorisé** — amélioration recommandée |

---

## Notifications Discord

À chaque pipeline, un embed Discord est envoyé avec :

- Repo, branche, commit hash
- Score de sécurité global /100
- Niveau de risque (couleur)
- Top 5 tickets de remédiation
- Release notes générées par IA
- Durée d'exécution du pipeline
- Statut push : ✅ AUTORISÉ / 🚫 BLOQUÉ

---

## Tests

### Health check de tous les services

```bash
for port in 8000 8001 8002 8003 8004 8005 8006 8007 8008 8009 8011; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:$port/health)
  echo ":$port → $status"
done
```

### Suite de tests complète

```bash
bash test.sh
# Teste : health checks, scans individuels (MobSF, Gitleaks, Androguard,
#         Permissions, Network, Syft/Grype), pipeline complet via trigger/manual
```

### Tester un scanner individuellement

```bash
# Exemple : scan MobSF
curl -s --max-time 120 \
  -X POST http://localhost:8001/scan \
  -H "Content-Type: application/json" \
  -d '{
    "apk_filename": "allsafe.apk",
    "repo":         "myapp",
    "branch":       "main",
    "commit":       "abc123"
  }' | python3 -m json.tool
```

### Vérifier le dernier pipeline

```bash
curl -s http://localhost:8000/admin/pipelines \
  -H "X-API-Key: votre_cle_admin" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
p = d['pipelines'][-1]
ai = p.get('ai_report', {})
print(f\"repo:{p['repo']} commit:{p['commit'][:8]}\")
print(f\"Risk: {ai.get('risk_level')} | Push: {'✅' if p.get('push_allowed') else '🚫'}\")
"
```

---

## Variables d'environnement

Créer un fichier `.env` à la racine du projet :

```env
# Controller
GITHUB_WEBHOOK_SECRET=votre_secret_hmac
ADMIN_API_KEY=votre_cle_admin_forte

# Intelligence Artificielle
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy

# Scanners optionnels
VIRUSTOTAL_API_KEY=votre_cle_virustotal

# Stockage
APK_STORAGE_PATH=/apk_storage
REPOS_STORAGE_PATH=/repos_storage
```

---

## Stack technique

| Composant | Technologie |
|---|---|
| Framework API | FastAPI (Python 3.11) |
| Concurrence | `asyncio.gather()` |
| Infrastructure | Docker Compose |
| Réseau interne | `pipeline_net` |
| Analyse statique | MobSF, Androguard |
| Secrets | Gitleaks |
| SBOM / CVE | Syft + Grype |
| Intelligence IA | Groq API (llama-3.1), Ollama |
| Notifications | Discord Webhooks |
| Antivirus | VirusTotal API |

---

## Licence

Ce projet est développé dans le cadre d'un projet académique/professionnel sur la sécurité mobile.

---

*MobSecOps v2.0.0 — FastAPI · Docker · Python 3.11*
