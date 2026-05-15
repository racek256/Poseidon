#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Download GGUF model ==="

MODEL_VARIANT="${1:-small}"

if [ -z "$MODEL_VARIANT" ]; then
    echo "Usage: bash scripts/download-model.sh <variant>"
    echo
    echo "Variants:"
    echo "  small   - Gemma 3 1B IT Q4_0      (~1 GB, default)"
    echo "  medium  - Gemma 4 4B IT Q4_K_M    (~3 GB)"
    echo "  large   - Gemma 4 12B IT Q4_K_M   (~8 GB)"
    echo
    echo "Set POSEIDON_MODELS_DIR to change download directory (default: models/)"
    echo "Set POSEIDON_GGUF_URL to use a custom HuggingFace GGUF model URL"
    echo
    echo "Without a variant, this script downloads 'small'."
    echo "After download, run: cargo run"
    exit 1
fi

MODELS_DIR="${POSEIDON_MODELS_DIR:-$PROJECT_DIR/models}"
mkdir -p "$MODELS_DIR"

if [ -n "${POSEIDON_GGUF_URL:-}" ]; then
    URL="$POSEIDON_GGUF_URL"
    FILENAME="$(basename "$URL")"
else
    case "$MODEL_VARIANT" in
        small)
            URL="https://huggingface.co/unsloth/gemma-3-1b-it-GGUF/resolve/main/gemma-3-1b-it-Q4_0.gguf"
            FILENAME="gemma-3-1b-it-Q4_0.gguf"
            ;;
        medium)
            URL="https://huggingface.co/bartowski/gemma-4-4b-it-GGUF/resolve/main/gemma-4-4b-it-Q4_K_M.gguf"
            FILENAME="gemma-4-4b-it-Q4_K_M.gguf"
            ;;
        large)
            URL="https://huggingface.co/bartowski/gemma-4-12b-it-GGUF/resolve/main/gemma-4-12b-it-Q4_K_M.gguf"
            FILENAME="gemma-4-12b-it-Q4_K_M.gguf"
            ;;
        *)
            echo "Unknown variant: $MODEL_VARIANT"
            echo "Use: small, medium, or large"
            exit 1
            ;;
    esac
fi

DEST="$MODELS_DIR/$FILENAME"

if [ -f "$DEST" ]; then
    echo "Model already exists: $DEST"
    echo "Set POSEIDON_LLAMA_MODEL=$DEST to use it."
    exit 0
fi

echo "Downloading: $FILENAME"
echo "From:       $URL"
echo "To:         $DEST"
echo

TMP="$DEST.tmp"
rm -f "$TMP"
if command -v wget &>/dev/null; then
    wget -O "$TMP" "$URL"
elif command -v curl &>/dev/null; then
    curl -fL -o "$TMP" "$URL"
else
    echo "Neither wget nor curl found. Install one of them."
    exit 1
fi
mv "$TMP" "$DEST"

echo
echo "=== Download complete ==="
echo "Model: $DEST"
echo
echo "Start Poseidon:"
echo "  cargo run"
