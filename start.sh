#!/usr/bin/env bash
# Start the safe, loopback-only MIRAGE HTTP prototype.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
umask 077

CONFIG_FILE="$ROOT_DIR/config/prototype-http.toml"
EVIDENCE_DIR="$ROOT_DIR/var/mirage"
EVIDENCE_FILE="$EVIDENCE_DIR/events.jsonl"
HOST="127.0.0.1"
PORT="${MIRAGE_PORT:-8080}"
PROFILE_ID="local-web"

if [[ ! -f "$CONFIG_FILE" ]]; then
    printf 'MIRAGE: missing configuration: %s\n' "$CONFIG_FILE" >&2
    exit 1
fi

if [[ -x "$ROOT_DIR/.venv/bin/mirage" ]]; then
    MIRAGE=("$ROOT_DIR/.venv/bin/mirage")
elif command -v mirage >/dev/null 2>&1; then
    MIRAGE=("$(command -v mirage)")
else
    printf '%s\n' "MIRAGE is not installed. Run: python3 -m pip install -e '.[dev]'" >&2
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

printf '\nMIRAGE — Local Deception Prototype\n'
printf '%s\n' '----------------------------------'
printf 'Listener: http://%s:%s\n' "$HOST" "$PORT"
printf 'Evidence: %s\n\n' "$EVIDENCE_FILE"

printf '[1/2] Validating configuration...\n'
"${MIRAGE[@]}" validate-config "$CONFIG_FILE"

printf '\n[2/2] Starting HTTP decoy...\n'
printf 'Press Ctrl+C to stop.\n\n'
"${MIRAGE[@]}" serve-http "$CONFIG_FILE" \
    --profile-id "$PROFILE_ID" \
    --host "$HOST" \
    --port "$PORT" \
    --evidence "$EVIDENCE_FILE"

printf '\nMIRAGE stopped. Verify evidence with:\n'
printf '  mirage verify-evidence %q\n' "$EVIDENCE_FILE"
