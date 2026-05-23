#!/bin/bash
# =============================================================================
# test.sh — Test complet de tous les services du pipeline DevSecOps
# Usage: bash test.sh
# =============================================================================

APK="allsafe.apk"
REPO="allsafe"
BRANCH="main"
COMMIT="abc123test"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✅ PASS${NC} — $1"; ((PASS++)); }
fail() { echo -e "  ${RED}❌ FAIL${NC} — $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}⚠️  SKIP${NC} — $1"; }

test_service() {
  local name=$1
  local port=$2
  local endpoint=${3:-/health}
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:$port$endpoint" 2>/dev/null || echo "000")
  if [ "$status" == "200" ]; then
    ok "$name health (:$port)"
    return 0
  else
    fail "$name health (:$port) → HTTP $status"
    return 1
  fi
}

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║       MobSecOps — Suite de tests complète            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Health checks ────────────────────────────────────────────────────────────
echo "▶ Health checks"
test_service "controller"          8010
test_service "service_aggregator"  8011
test_service "service_mobsf"       8001
test_service "service_gitleaks"    8002
test_service "service_syft"        8003
test_service "service_androguard"  8004
test_service "service_virustotal"  8005
test_service "service_permissions" 8006
test_service "service_network"     8007
test_service "service_obfuscation" 8008
test_service "service_ssl"         8009

# MobSF natif
MOBSF_NATIVE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:8000/" 2>/dev/null || echo "000")
if [ "$MOBSF_NATIVE" == "200" ]; then
  ok "mobsf natif (:8000)"
else
  warn "mobsf natif (:8000) — HTTP $MOBSF_NATIVE (encore en démarrage?)"
fi

echo ""

# ── Test scan ANDROGUARD ─────────────────────────────────────────────────────
echo "▶ Scan ANDROGUARD (:8004)"
RESULT=$(curl -s --max-time 30 -X POST http://localhost:8004/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
COUNT=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['findings']))" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100 | Findings: $COUNT"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan PERMISSIONS ────────────────────────────────────────────────────
echo "▶ Scan PERMISSIONS (:8006)"
RESULT=$(curl -s --max-time 30 -X POST http://localhost:8006/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
TOTAL=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['permissions_total'])" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100 | Permissions totales: $TOTAL"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan NETWORK ────────────────────────────────────────────────────────
echo "▶ Scan NETWORK (:8007)"
RESULT=$(curl -s --max-time 30 -X POST http://localhost:8007/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan OBFUSCATION ────────────────────────────────────────────────────
echo "▶ Scan OBFUSCATION (:8008)"
RESULT=$(curl -s --max-time 30 -X POST http://localhost:8008/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan SSL ────────────────────────────────────────────────────────────
echo "▶ Scan SSL (:8009)"
RESULT=$(curl -s --max-time 30 -X POST http://localhost:8009/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan VIRUSTOTAL ─────────────────────────────────────────────────────
echo "▶ Scan VIRUSTOTAL (:8005)"
RESULT=$(curl -s --max-time 60 -X POST http://localhost:8005/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
MALICIOUS=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['malicious'])" 2>/dev/null)
TOTAL=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['total'])" 2>/dev/null)
if [ -n "$MALICIOUS" ]; then
  ok "Malicious: $MALICIOUS / $TOTAL moteurs"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan GITLEAKS ───────────────────────────────────────────────────────
echo "▶ Scan GITLEAKS (:8002)"
REPO_PATH="/repos_storage/mobile"
if docker exec service_gitleaks test -d "$REPO_PATH" 2>/dev/null; then
  RESULT=$(curl -s --max-time 30 -X POST http://localhost:8002/scan \
    -H "Content-Type: application/json" \
    -d "{\"repo_path\":\"$REPO_PATH\",\"repo\":\"mobile\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
  SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
  COUNT=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['findings']))" 2>/dev/null)
  if [ -n "$SCORE" ]; then
    ok "Score: $SCORE/100 | Secrets détectés: $COUNT"
  else
    fail "Réponse invalide: ${RESULT:0:100}"
  fi
else
  warn "GITLEAKS — repo_path $REPO_PATH absent (besoin d'un push GitHub d'abord)"
fi

# ── Test scan SYFT/GRYPE ─────────────────────────────────────────────────────
echo "▶ Scan SYFT/GRYPE (:8003)"
RESULT=$(curl -s --max-time 120 -X POST http://localhost:8003/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary']['score'])" 2>/dev/null)
COUNT=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('findings',[])))" 2>/dev/null)
if [ -n "$SCORE" ]; then
  ok "Score: $SCORE/100 | CVEs: $COUNT"
else
  fail "Réponse invalide: ${RESULT:0:100}"
fi

# ── Test scan MOBSF ──────────────────────────────────────────────────────────
echo "▶ Scan MOBSF (:8001)"
RESULT=$(curl -s --max-time 120 -X POST http://localhost:8001/scan \
  -H "Content-Type: application/json" \
  -d "{\"apk_filename\":\"$APK\",\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT\"}" 2>/dev/null)
STATUS=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null)
SCORE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('summary',{}).get('score','?'))" 2>/dev/null)
if [ "$STATUS" == "success" ]; then
  ok "Status: $STATUS | Score: $SCORE/100"
else
  fail "Réponse invalide ou erreur: ${RESULT:0:150}"
fi

# ── Test pipeline complet via controller ─────────────────────────────────────
echo "▶ Pipeline complet (controller :8010)"
COMMIT_ID="testpipeline$(date +%s)"
curl -s --max-time 5 -X POST http://localhost:8010/trigger/manual \
  -H "Content-Type: application/json" \
  -d "{\"repo\":\"$REPO\",\"branch\":\"$BRANCH\",\"commit\":\"$COMMIT_ID\",\"apk_filename\":\"$APK\",\"services\":[\"androguard\",\"permissions\",\"network\",\"obfuscation\",\"ssl\"]}" > /dev/null
sleep 20
RESULT=$(curl -s http://localhost:8010/admin/pipelines -H "X-API-Key: une_cle_admin_forte" 2>/dev/null)
PIPE_STATUS=$(echo "$RESULT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
pipes=[p for p in d.get('pipelines',[]) if p.get('commit','').startswith('testpipeline')]
if pipes:
    p=pipes[-1]
    print(p.get('status','?'))
else:
    print('not_found')
" 2>/dev/null)
if [ "$PIPE_STATUS" == "success" ] || [ "$PIPE_STATUS" == "blocked" ]; then
  ok "Pipeline status: $PIPE_STATUS (services scannés)"
elif [ "$PIPE_STATUS" == "running" ]; then
  warn "Pipeline encore en cours — attends 30s et recheck"
else
  fail "Pipeline introuvable ou erreur: $PIPE_STATUS"
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
TOTAL_TESTS=$((PASS + FAIL))
echo -e "  Résultats : ${GREEN}$PASS OK${NC} / ${RED}$FAIL FAIL${NC} (sur $TOTAL_TESTS tests)"
if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}✅ Tous les tests sont passés !${NC}"
else
  echo -e "  ${RED}❌ $FAIL test(s) ont échoué — voir détails ci-dessus${NC}"
fi
echo "══════════════════════════════════════════════════════"
echo ""
