#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LLAMA_DIR="$PROJECT_DIR/external/llama.cpp"
SERVER_BIN="$LLAMA_DIR/build/bin/llama-server"

if [ ! -x "$SERVER_BIN" ]; then
    echo "llama-server not found at $SERVER_BIN"
    echo "Run: bash scripts/build-llama-server.sh"
    exit 1
fi

MODEL="${POSEIDON_LLAMA_MODEL:-}"
if [ -z "$MODEL" ] || [ ! -f "$MODEL" ]; then
    echo "Model not found: ${MODEL:-<unset>}"
    echo "Set POSEIDON_LLAMA_MODEL=/path/to/model.gguf or run: bash scripts/download-model.sh"
    echo
    echo "Available pre-downloaded models:"
    find "$PROJECT_DIR/models" -name "*.gguf" -type f 2>/dev/null || echo "  (none)"
    exit 1
fi

HOST="${POSEIDON_LLAMA_HOST:-127.0.0.1}"
PORT="${POSEIDON_LLAMA_PORT:-8081}"
CTX="${POSEIDON_LLAMA_CTX:-8192}"
THREADS="${POSEIDON_LLAMA_THREADS:-$(nproc 2>/dev/null || echo 4)}"
GPU_LAYERS="${POSEIDON_LLAMA_GPU_LAYERS:-99}"

echo "=== Starting llama.cpp server ==="
echo "Model:      $MODEL"
echo "Endpoint:   http://$HOST:$PORT"
echo "Context:    $CTX"
echo "Threads:    $THREADS"
echo "GPU layers: $GPU_LAYERS"
echo

exec "$SERVER_BIN" \
    --model "$MODEL" \
    --host "$HOST" \
    --port "$PORT" \
    --ctx-size "$CTX" \
    --threads "$THREADS" \
    --n-gpu-layers "$GPU_LAYERS" \
    --flash-attn on \
    "$@"
