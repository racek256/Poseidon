#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv_rocm"
TMP_DIR="${PROJECT_DIR}/.tmp_pip"
ROCM_INDEX="${POSEIDON_ROCM_TORCH_INDEX:-https://download.pytorch.org/whl/rocm7.2/}"

echo "=== Installing ROCm torch + Unsloth for Poseidon finetuning ==="

# Detect ROCm
if ! command -v rocminfo &>/dev/null; then
    echo "ERROR: ROCm not found (rocminfo missing). Install ROCm first."
    exit 1
fi

# Detect Python 3.12 (needed for ROCm torch wheels)
PYTHON=""
for candidate in python3.12 python3; do
    ver=$($candidate --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
    if [ "$ver" = "3.12" ]; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.12 required. Install via pyenv:"
    echo "  pyenv install 3.12.9 && pyenv local 3.12.9"
    exit 1
fi

# Create venv if needed
if [ ! -f "$VENV_DIR/bin/python3" ]; then
    echo "Creating venv at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip

# pip/uv extract the 6GB ROCm torch wheel under TMPDIR. /tmp is often tmpfs
# and too small, so keep temporary extraction on the project filesystem.
mkdir -p "$TMP_DIR"

# Install Python dependencies first. Unsloth's resolver may otherwise replace
# ROCm torch with a CUDA wheel, so ROCm torch is force-installed afterwards.
echo "Installing Unsloth and deps..."
TMP="$TMP_DIR" TMPDIR="$TMP_DIR" TEMP="$TMP_DIR" \
    pip install -r "$SCRIPT_DIR/requirements.txt"

echo "Installing ROCm torch from $ROCM_INDEX ..."
if command -v uv &>/dev/null; then
    TMP="$TMP_DIR" TMPDIR="$TMP_DIR" TEMP="$TMP_DIR" \
        uv pip install --python "$VENV_DIR/bin/python3" \
        torch torchvision torchaudio \
        --index-url "$ROCM_INDEX" \
        --force-reinstall --no-cache
else
    TMP="$TMP_DIR" TMPDIR="$TMP_DIR" TEMP="$TMP_DIR" \
        pip install torch torchvision torchaudio \
        --index-url "$ROCM_INDEX" \
        --force-reinstall --no-cache-dir
fi

# Verify ROCm torch
python3 -c "
import torch
print(f'torch {torch.__version__}')
print(f'HIP available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'GPU: {torch.cuda.get_device_name(0)}')
else:
    print('WARNING: CUDA/HIP not available - will use CPU fallback')
"

echo ""
echo "=== Install complete ==="
echo "Activate with: source $VENV_DIR/bin/activate"
echo "Then run: python3 scripts/finetune/train.py"
