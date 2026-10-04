#!/bin/bash
SOURAN_DIR="/opt/souran-ai"
python3 $SOURAN_DIR/dns/resolver.py &>/dev/null &
python3 $SOURAN_DIR/dns/dot_server.py &>/dev/null &
python3 $SOURAN_DIR/dns/doh_server.py &>/dev/null &
python3 $SOURAN_DIR/dns/web3_resolver.py &>/dev/null &
bash $SOURAN_DIR/watchdog.sh &>/dev/null &
echo "All Souran services started"
