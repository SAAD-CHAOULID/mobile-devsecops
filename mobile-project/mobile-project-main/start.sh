#!/bin/bash
# =============================================================================
# start.sh — Démarrage complet du pipeline DevSecOps
# Usage: bash start.sh [--build]
# =============================================================================
set -e

BUILD_FLAG=""
if [[ "$1" == "--build" ]]; then
  BUILD_FLAG="--build"
  echo ">>> Mode: rebuild des images"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         MobSecOps — Démarrage du pipeline            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Infrastructure partagée ─────────────────────────────────────────────
echo "[1/4] Infrastructure (réseau + volumes)..."
bash _infra/init.sh 2>/dev/null || true

# ── 2. MobSF officiel (port 8000 interne) ──────────────────────────────────
echo ""
echo "[2/4] MobSF (moteur d'analyse Android)..."
if docker ps --format '{{.Names}}' | grep -q "^mobsf$"; then
  echo "      mobsf déjà en cours d'exécution — ok"
else
  if docker ps -a --format '{{.Names}}' | grep -q "^mobsf$"; then
    echo "      Redémarrage de mobsf..."
    docker start mobsf
  else
    echo "      Création du conteneur mobsf..."
    docker run -d \
      --name mobsf \
      --network pipeline_net \
      --restart unless-stopped \
      -e MOBSF_API_KEY_VALUE=add_ur_api_key_here \
      -v "$(pwd)/service_mobsf/mobsf_data:/home/mobsf/.MobSF" \
      -v apk_storage:/apk_storage \
      --health-cmd "wget -qO- http://localhost:8000/ > /dev/null 2>&1 || exit 1" \
      --health-interval 30s \
      --health-timeout 10s \
      --health-retries 3 \
      opensecurity/mobile-security-framework-mobsf:latest
  fi
  docker update --restart=unless-stopped mobsf 2>/dev/null || true
fi

# ── 3. Tous les micro-services ──────────────────────────────────────────────
echo ""
echo "[3/4] Micro-services..."

SERVICES=(
  "service_mobsf"
  "service_gitleaks"
  "service_syft"
  "service_androguard"
  "service_virustotal"
  "service_permissions"
  "service_network"
  "service_obfuscation"
  "service_ssl"
  "service_aggregator"
  "controller"
)

for svc in "${SERVICES[@]}"; do
  if [ -d "$svc" ] && [ -f "$svc/docker-compose.yml" ]; then
    echo "      → $svc"
    docker compose -f "$svc/docker-compose.yml" up -d $BUILD_FLAG 2>&1 | tail -1
  fi
done

# ── 4. Vérification santé ───────────────────────────────────────────────────
echo ""
echo "[4/4] Vérification des services (attente 10s)..."
sleep 10

PORTS=(8001 8002 8003 8004 8005 8006 8007 8008 8009 8010 8011)
NAMES=("service_mobsf" "service_gitleaks" "service_syft" "service_androguard" "service_virustotal" "service_permissions" "service_network" "service_obfuscation" "service_ssl" "controller" "service_aggregator")

ALL_OK=true
for i in "${!PORTS[@]}"; do
  PORT="${PORTS[$i]}"
  NAME="${NAMES[$i]}"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://localhost:$PORT/health" 2>/dev/null || echo "000")
  if [ "$STATUS" == "200" ]; then
    echo "      ✅  $NAME :$PORT"
  else
    echo "      ❌  $NAME :$PORT (HTTP $STATUS)"
    ALL_OK=false
  fi
done

# MobSF natif
MOBSF_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:8000/" 2>/dev/null || echo "000")
if [ "$MOBSF_STATUS" == "200" ]; then
  echo "      ✅  mobsf (MobSF natif) :8000"
else
  echo "      ⏳  mobsf (MobSF natif) :8000 — encore en démarrage (normal, ~60s)"
fi

echo ""
if $ALL_OK; then
  echo "✅ Tous les services sont opérationnels !"
  echo ""
  echo "   Frontend  → cd frontend && python3 -m http.server 8080"
  echo "   Frontend  → http://localhost:8080"
  echo "   Tests     → bash test.sh"
else
  echo "⚠️  Certains services ne répondent pas encore."
  echo "   Attends 30s supplémentaires et relance: bash test.sh"
fi
echo ""
