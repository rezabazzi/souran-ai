#!/bin/bash
# Zapret DPI bypass configuration for Souran AI Network Server v4.2.0
# File: /opt/souran-ai/censorship/config/zapret-config.sh

export ZAPRET_HOSTS_FILE="/opt/souran-ai/censorship/config/zapret-hosts.txt"
export ZAPRET_METHOD="nfqws"
export ZAPRET_DESYNC="split2,fake"
export ZAPRET_PORTS="80,443,8080,8443"
export ZAPRET_BYPASS_PROTOCOLS="tls,http"
export ZAPRET_NFQWS="/usr/local/bin/nfqws"
export ZAPRET_TPWS="/usr/local/bin/tpws"

# Censored domains list
cat > "$ZAPRET_HOSTS_FILE" << 'EOF'
telegram.org
instagram.com
youtube.com
x.com
reddit.com
twitter.com
facebook.com
netflix.com
whatsapp.com
signal.org
discord.com
stackoverflow.com
github.com
google.com
EOF

echo "[zapret] Configured with $(wc -l < "$ZAPRET_HOSTS_FILE") domains"