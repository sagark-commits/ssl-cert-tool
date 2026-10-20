#!/bin/bash
# Author: Sagar K | 2026 | MIT licence
cd "$(dirname "$0")"
ASNB_CERT="${ASNB_CERT:-/path/to/ASNB CERT}"

echo ""
echo "  SSL DEPLOY - EASY MENU"
echo "  1) Test certs"
echo "  2) Dry-run (safe)"
echo "  3) Deploy (live)"
echo "  4) Exit"
read -p "Choice: " c
case "$c" in
  1) python3 ssl-auto.py inspect --input "$ASNB_CERT" --key "$ASNB_CERT/asnbcc.tmone.com.my.key" ;;
  2) python3 ssl-auto.py run --config asnb --input "$ASNB_CERT" --key "$ASNB_CERT/asnbcc.tmone.com.my.key" --dry-run ;;
  3) read -p "Type YES to deploy: " ok; [ "$ok" = "YES" ] && python3 ssl-auto.py run --config asnb --input "$ASNB_CERT" --key "$ASNB_CERT/asnbcc.tmone.com.my.key" ;;
  *) exit 0 ;;
esac