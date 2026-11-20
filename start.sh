#!/usr/bin/env bash
# Start the safe, loopback-only MIMCLAVE HTTP prototype.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
umask 077

CONFIG_FILE="$ROOT_DIR/config/prototype-http.toml"
EVIDENCE_DIR="$ROOT_DIR/var/mimclave"
EVIDENCE_FILE="$EVIDENCE_DIR/events.jsonl"
HOST="127.0.0.1"
PORT="${MIMCLAVE_PORT:-8080}"
PROFILE_ID="local-web"

if [[ ! -f "$CONFIG_FILE" ]]; then
    printf 'MIMCLAVE: missing configuration: %s\n' "$CONFIG_FILE" >&2
    exit 1
fi

if [[ -x "$ROOT_DIR/.venv/bin/mimclave" ]]; then
    MIMCLAVE=("$ROOT_DIR/.venv/bin/mimclave")
elif command -v mimclave >/dev/null 2>&1; then
    MIMCLAVE=("$(command -v mimclave)")
else
    printf '\nMIMCLAVE is not installed in this repository or on your PATH.\n'
    read -r -p "Install MIMCLAVE into a local .venv now? [Y/n] " answer
    case "${answer,,}" in
        n|no)
            printf 'Installation cancelled. No changes were made.\n'
            exit 0
            ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        printf 'MIMCLAVE needs Python 3.12 or newer. Install Python, then rerun ./start.sh.\n' >&2
        exit 1
    fi

    if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
        printf '\nCreating local Python environment...\n'
        if ! python3 -m venv "$ROOT_DIR/.venv"; then
            printf '\nCould not create .venv. On Ubuntu, install the venv package first:\n' >&2
            printf '  sudo apt install python3-venv\n' >&2
            printf 'Then rerun ./start.sh.\n' >&2
            exit 1
        fi
    fi

    printf '\nInstalling MIMCLAVE...\n'
    "$ROOT_DIR/.venv/bin/python" -m pip install -e .
    MIMCLAVE=("$ROOT_DIR/.venv/bin/mimclave")
fi

mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

printf '\nMIMCLAVE — Local Deception Prototype\n'
printf '%s\n' '----------------------------------'
printf 'Listener: http://%s:%s\n' "$HOST" "$PORT"
printf 'Evidence: %s\n\n' "$EVIDENCE_FILE"

printf '[1/2] Validating configuration...\n'
"${MIMCLAVE[@]}" validate-config "$CONFIG_FILE"

printf '\n[2/2] Starting HTTP decoy...\n'
printf 'Press Ctrl+C to stop.\n\n'
"${MIMCLAVE[@]}" serve-http "$CONFIG_FILE" \
    --profile-id "$PROFILE_ID" \
    --host "$HOST" \
    --port "$PORT" \
    --evidence "$EVIDENCE_FILE"

printf '\nMIMCLAVE stopped. Verify evidence with:\n'
printf '  %q verify-evidence %q\n' "${MIMCLAVE[0]}" "$EVIDENCE_FILE"
