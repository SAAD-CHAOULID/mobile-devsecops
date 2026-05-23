#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# init.sh — exécuter UNE SEULE FOIS avant de lancer les services
# Crée l'infrastructure partagée (réseau + volumes Docker)
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "=== Infrastructure DevSecOps Pipeline ==="
echo ""

echo "[1/2] Réseau partagé : pipeline_net"
docker network create pipeline_net 2>/dev/null \
  && echo "      pipeline_net créé" \
  || echo "      pipeline_net existe déjà — ok"

echo "[2/2] Volume partagé : apk_storage"
docker volume create apk_storage 2>/dev/null \
  && echo "      apk_storage créé" \
  || echo "      apk_storage existe déjà — ok"

echo ""
echo "=== Prêt. Lance chaque service indépendamment ==="
echo ""
echo "  cd service_mobsf    && docker-compose up -d --build"
echo "  cd service_gitleaks && docker-compose up -d --build"
echo "  cd service_syft     && docker-compose up -d --build"
echo ""
echo "=== Healthchecks ==="
echo "  http://localhost:8001/health  → MobSF scanner"
echo "  http://localhost:8002/health  → Gitleaks scanner"
echo "  http://localhost:8003/health  → Syft/Grype scanner"
