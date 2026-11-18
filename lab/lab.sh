#!/usr/bin/env bash
# Gestione del laboratorio.  Uso:  ./lab.sh su | verifica | zap | giu | reset
set -euo pipefail
cd "$(dirname "$0")"

PORTE=(8081 8082 8083)
ADMIN_USER="admin"
ADMIN_PASS="Lab-Only-Pass-123!"   # solo laboratorio

attendi() {
  local porta=$1
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "http://127.0.0.1:${porta}/wp-admin/install.php"; then return 0; fi
    sleep 2
  done
  echo "Timeout in attesa della porta ${porta}" >&2; return 1
}

installa() {
  local porta=$1
  # Se WordPress è già installato, install.php risponde con "Already Installed"
  if curl -s "http://127.0.0.1:${porta}/wp-admin/install.php" | grep -qi "already installed"; then
    echo "  porta ${porta}: già installato"; return 0
  fi
  curl -s -o /dev/null \
    --data-urlencode "weblog_title=Lab ${porta}" \
    --data-urlencode "user_name=${ADMIN_USER}" \
    --data-urlencode "admin_password=${ADMIN_PASS}" \
    --data-urlencode "admin_password2=${ADMIN_PASS}" \
    --data-urlencode "pw_weak=1" \
    --data-urlencode "admin_email=lab@example.com" \
    --data-urlencode "blog_public=0" \
    --data-urlencode "Submit=Install WordPress" \
    "http://127.0.0.1:${porta}/wp-admin/install.php?step=2"
  echo "  porta ${porta}: installato"
}

cmd=${1:-su}
case "$cmd" in
  su)
    docker compose up -d
    for p in "${PORTE[@]}"; do attendi "$p"; installa "$p"; done
    echo "Laboratorio pronto: 8081 (vulnerabile), 8082 (protetto), 8083 (misto)."
    ;;
  verifica)
    # Controllo indipendente dallo scanner: serve a validare la ground truth.
    for p in "${PORTE[@]}"; do
      u="http://127.0.0.1:${p}"
      echo "=== ${u} ==="
      echo -n "utenti REST      : "; curl -s -o /dev/null -w "HTTP %{http_code}\n" "$u/wp-json/wp/v2/users"
      echo -n "?author=1        : "; curl -s -o /dev/null -w "HTTP %{http_code} -> %{url_effective}\n" -L "$u/?author=1"
      echo -n "xmlrpc listMethods: "; curl -s -X POST -H 'Content-Type: text/xml' \
        -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
        -w " [HTTP %{http_code}]\n" "$u/xmlrpc.php" | head -c 120 || true; echo
      echo "header sicurezza :"; curl -sI "$u/" | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy" || echo "  (nessuno)"
      echo -n "meta generator   : "; curl -s "$u/" | grep -io '<meta name="generator"[^>]*>' || echo "assente"
      echo -n "uploads listing  : "; curl -s -o /dev/null -w "HTTP %{http_code}\n" "$u/wp-content/uploads/"
      # controlli aggiunti per la ground truth v4 (permalink semplici, valori degli header)
      echo -n "utenti ?rest_route: "; curl -s -o /dev/null -w "HTTP %{http_code}\n" "$u/?rest_route=/wp/v2/users"
      echo -n "feed ?feed=rss2  : "; curl -s "$u/?feed=rss2" | grep -o "<generator>[^<]*</generator>" || echo "nessun generator"
      echo -n "?ver= core       : "; curl -s "$u/" | grep -oE "/wp-includes/[^\"' ]+\?ver=[0-9]+\.[0-9.]+" | sort -u | tr '\n' ' '; echo
      echo "header informativi:"; curl -sI "$u/" | grep -iE "^(server|x-powered-by):" || echo "  (nessuno)"
      echo -n "debug.log        : "; curl -s -o /dev/null -w "HTTP %{http_code}\n" "$u/wp-content/debug.log"
      echo -n "cookie sulla home: "; curl -sI "$u/" | grep -ic "^set-cookie" || true
    done
    ;;
  zap)
    # Avvia OWASP ZAP in modalità daemon sulla porta 8090 (solo locale).
    chiave="${ZAP_API_KEY:-chiave-lab-zap}"
    docker compose --profile zap up -d zap
    echo -n "Attendo ZAP (la prima volta può volerci un minuto)"
    for _ in $(seq 1 90); do
      if curl -s -o /dev/null "http://127.0.0.1:8090/JSON/core/view/version/?apikey=${chiave}"; then
        echo; echo "ZAP pronto su http://127.0.0.1:8090"
        echo "Uso:  python3 ../agente.py --url http://127.0.0.1:8081 --si-autorizzato --zap --zap-key ${chiave}"
        exit 0
      fi
      echo -n "."; sleep 2
    done
    echo; echo "ZAP non risponde su 127.0.0.1:8090. Vedi i log con: docker compose logs zap" >&2; exit 1
    ;;
  giu)   docker compose --profile zap down ;;
  reset) docker compose --profile zap down -v ;;
  *) echo "Uso: $0 su | verifica | zap | giu | reset"; exit 1 ;;
esac
