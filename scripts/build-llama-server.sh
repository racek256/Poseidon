#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LLAMA_DIR="$PROJECT_DIR/external/llama.cpp"
BUILD_DIR="$LLAMA_DIR/build"

if [ ! -f "$LLAMA_DIR/CMakeLists.txt" ]; then
    echo "llama.cpp source not found at $LLAMA_DIR"
    echo "Run: git submodule update --init --recursive"
    exit 1
fi

CMAKE_FLAGS=(
    -DCMAKE_BUILD_TYPE=Release
)

if [ "${POSEIDON_LLAMA_VULKAN:-OFF}" = "ON" ]; then
    VULKAN_SDK_DIR="${POSEIDON_LLAMA_VULKAN_SDK:-/tmp/vulkan-sdk}"
    if [ ! -d "$VULKAN_SDK_DIR/x86_64/include/vulkan" ]; then
        echo "Vulkan SDK not found at $VULKAN_SDK_DIR. Downloading..."
        mkdir -p "$VULKAN_SDK_DIR"
        curl -sL 'https://sdk.lunarg.com/sdk/download/1.4.341.0/linux/vulkansdk-linux-x86_64-1.4.341.0.tar.xz' | tar xJ -C "$VULKAN_SDK_DIR" --strip-components=1
    fi
    CMAKE_FLAGS+=(
        -DGGML_VULKAN=ON
        -DVulkan_INCLUDE_DIR="$VULKAN_SDK_DIR/x86_64/include"
    )
fi

JOBS="${POSEIDON_LLAMA_BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"

echo "=== Building llama.cpp server ==="
echo "Source: $LLAMA_DIR"
echo "Build:  $BUILD_DIR"
echo "Jobs:   $JOBS"
echo

cmake -S "$LLAMA_DIR" -B "$BUILD_DIR" "${CMAKE_FLAGS[@]}"
cmake --build "$BUILD_DIR" --config Release --target llama-server -j "$JOBS"

echo
echo "=== llama.cpp server ready ==="
echo "$BUILD_DIR/bin/llama-server"
