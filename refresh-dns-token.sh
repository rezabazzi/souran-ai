#!/bin/bash
# Version: v5.1.0 | Souran AI Network Server
set -euo pipefail
DNS_API_URL="${DNS_API_URL:-http://127.0.0.1:5380}"
TOKEN_FILE="${TOKEN_FILE:-/etc/dns/api-token.txt}"
DNS_DIR_TOKEN="${DNS_DIR_TOKEN:-/opt/souran-ai/dns/api-key.txt}"
if ! curl -s --max-time 3 "${DNS_API_URL}/api/status" >/dev/null 2>&1; then
    echo "DNS server not reachable"
    exit 1
fi
RESP=$(curl -s "${DNS_API_URL}/api/user/createToken" -G --data-urlencode "user=admin" --data-urlencode "pass=admin" --data-urlencode "tokenName=souran-refresh" 2>/dev/null)
TOKEN=$(printf '%s' "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$TOKEN" ] || [ "$TOKEN" = "None" ]; then
    echo "Failed to get token"
    exit 1
fi
mkdir -p "$(dirname "$TOKEN_FILE")"
echo -n "$TOKEN" | sudo -S -p '' tee "$TOKEN_FILE" > /dev/null 2>&1 || echo -n "$TOKEN" > "$TOKEN_FILE"
if [ -d "$(dirname "$DNS_DIR_TOKEN")" ]; then
    echo -n "$TOKEN" > "$DNS_DIR_TOKEN"
    chown reza:reza "$DNS_DIR_TOKEN" 2>/dev/null || true
fi
echo "Token refreshed: ${TOKEN:0:16}..."
exit 0
