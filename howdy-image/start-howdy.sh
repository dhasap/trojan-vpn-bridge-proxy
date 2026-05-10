#!/usr/bin/env sh
set -eu

: "${HOWDY_SERVER:?HOWDY_SERVER is required, example vpn.example.com:443}"
: "${HOWDY_USER:?HOWDY_USER is required}"
: "${HOWDY_PASS:?HOWDY_PASS is required}"

HOWDY_SOCKS_PORT="${HOWDY_SOCKS_PORT:-1080}"
HOWDY_PROTOCOL="${HOWDY_PROTOCOL:-anyconnect}"

# Use TCP CSTP only. DTLS/UDP is not needed for SOCKS proxy mode and is often blocked.
# ocproxy runs a userland lwIP SOCKS5 server; no TUN device or NET_ADMIN capability is required.
if [ -n "${HOWDY_FINGERPRINT:-}" ]; then
    printf '%s\n' "$HOWDY_PASS" | exec openconnect \
        --protocol="$HOWDY_PROTOCOL" \
        --servercert "$HOWDY_FINGERPRINT" \
        --user "$HOWDY_USER" \
        --passwd-on-stdin \
        --script-tun \
        --script "ocproxy --allow-remote -D ${HOWDY_SOCKS_PORT}" \
        --no-dtls \
        "$HOWDY_SERVER"
else
    printf '%s\n' "$HOWDY_PASS" | exec openconnect \
        --protocol="$HOWDY_PROTOCOL" \
        --user "$HOWDY_USER" \
        --passwd-on-stdin \
        --script-tun \
        --script "ocproxy --allow-remote -D ${HOWDY_SOCKS_PORT}" \
        --no-dtls \
        "$HOWDY_SERVER"
fi
