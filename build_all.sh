#! /bin/bash
set -euo pipefail

# support: ARM64, ARMv7, x86_64 linux, Windows x86_64
targets=("aarch64-unknown-linux-gnu" "armv7-unknown-linux-gnueabihf" "x86_64-unknown-linux-musl" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-msvc")
binaries=("xelis_daemon" "xelis_miner" "xelis_wallet")
extra_files=("README.md" "API.md" "CHANGELOG.md" "LICENSE")

# If not running inside the container, run this script inside messense/cargo-xwin
if [[ "${IN_XWIN_DOCKER:-0}" != "1" ]]; then
    # Ensure docker is available
    if ! command -v docker &> /dev/null; then
        echo "Docker is required but not found"
        exit 1
    fi

    # Pull only if missing, and show normal docker progress output
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "Docker image $IMAGE_NAME not found locally, pulling..."
        docker pull "$IMAGE_NAME"
    else
        echo "Docker image $IMAGE_NAME already present, skipping pull."
    fi

    echo "Re-running inside $IMAGE_NAME..."
    exec docker run --rm -it \
        -e IN_XWIN_DOCKER=1 \
        -v "$PWD:/work" \
        -w /work \
        "$IMAGE_NAME" \
        bash "$0" "$@"
fi

# --------- From here on, we are inside messense/cargo-xwin ---------

echo "Using messense/cargo-xwin inside Docker"

echo "Deleting build folder"
rm -rf build

echo "Compiling binaries for all targets"
for target in "${targets[@]}"; do
    echo "Clean build cache for $target"
    cargo clean

    # Idempotent; cheap even if already added
    rustup target add "$target"

    if [[ "$target" == *"windows"* ]]; then
        for binary in "${binaries[@]}"; do
            echo "Building $binary for $target with cargo-xwin..."
            cargo xwin build \
                --target "$target" \
                --bin "$binary" \
                --profile release-with-lto
        done
    else
        for binary in "${binaries[@]}"; do
            echo "Building $binary for $target with cargo..."
            cargo build \
                --target "$target" \
                --profile release-with-lto \
                --bin "$binary"
        done
    fi

    mkdir -p "build/$target"

    # copy generated binaries to build directory
    for binary in "${binaries[@]}"; do
        out_bin="$binary"
        if [[ "$target" == *"windows"* ]]; then
            out_bin="$binary.exe"
        fi
        cp "target/$target/release-with-lto/$out_bin" "build/$target/$out_bin"
    done

    # copy extra files
    for file in "${extra_files[@]}"; do
        if [[ -f "$file" ]]; then
            cp "$file" "build/$target/$file"
        fi
    done
done

echo "Creating archives for all targets"
for target in "${targets[@]}"; do
    echo "Generating checksums for $target"
    cd "build/$target"
    > checksums.txt
    for binary in "${binaries[@]}"; do
        out_bin="$binary"
        if [[ "$target" == *"windows"* ]]; then
            out_bin="$binary.exe"
        fi
        sha256sum "$out_bin" >> checksums.txt
    done
    cd ../..

    cd build
    if [[ "$target" == *"windows"* ]]; then
        zip -r "$target.zip" "$target"
    else
        tar -czf "$target.tar.gz" "$target"
    fi
    cd ..
done

echo "Generating final checksums.txt in build/"
cd build
> checksums.txt
for target in "${targets[@]}"; do
    if [[ "$target" == *"windows"* ]]; then
        sha256sum "$target.zip" >> checksums.txt
    else
        sha256sum "$target.tar.gz" >> checksums.txt
    fi
done
cd ..

echo "Done 🎉"
