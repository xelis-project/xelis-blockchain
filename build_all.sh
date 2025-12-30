#! /bin/bash
set -euo pipefail

IMAGE_NAME="messense/cargo-xwin"

# support: ARM64, ARMv7, x86_64 linux, Windows x86_64 (MSVC)
targets=("aarch64-unknown-linux-gnu" "armv7-unknown-linux-gnueabihf" "x86_64-unknown-linux-musl" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-msvc")
binaries=("xelis_daemon" "xelis_miner" "xelis_wallet")
extra_files=("README.md" "API.md" "CHANGELOG.md" "LICENSE")

# verify that we have cross installed
if ! command -v cross &> /dev/null; then
    echo "cross could not be found, please install it for cross compilation"
    exit 1
fi

# Cross (and our Windows build) need docker to be running
echo "Starting docker daemon"
if ! sudo systemctl start docker 2>/dev/null; then
    echo "Warning: could not start docker via systemd; make sure Docker is running if needed."
fi

echo "Updating using rustup"
rustup update stable

echo "Only build in stable"
rustup default stable

echo "Deleting build folder"
rm -rf build

# store the commit hash used for this build
commit_hash=$(git rev-parse HEAD)
echo "Using commit hash: $commit_hash"
export XELIS_COMMIT_HASH="$commit_hash"

# compile all binaries for all targets
echo "Compiling binaries for all targets"
for target in "${targets[@]}"; do
    echo "Clean build cache for $target"
    cross clean

    # support the target (for tooling, even if Windows build happens in Docker)
    rustup target add "$target"

    if [[ "$target" == *"windows"* ]]; then
        # ---- Windows (MSVC) build via cargo-xwin in Docker ----
        # Ensure docker CLI is available
        if ! command -v docker &> /dev/null; then
            echo "docker could not be found, required for Windows build"
            exit 1
        fi

        # Pull the image once if missing
        if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
            echo "Docker image $IMAGE_NAME not found locally, pulling..."
            docker pull "$IMAGE_NAME"
        else
            echo "Docker image $IMAGE_NAME already present, skipping pull."
        fi

        docker run --rm -it -e XELIS_COMMIT_HASH="$commit_hash" -v "$PWD:/work" -w /work "$IMAGE_NAME" cargo xwin build --target "$target" --profile release-with-lto 
    else
        # ---- Non-Windows builds via cross ----
        XELIS_COMMIT_HASH="$commit_hash" cross build --target "$target" --profile release-with-lto
    fi

    mkdir -p "build/$target"

    # copy generated binaries to build directory
    for binary in "${binaries[@]}"; do
        out_bin="$binary"
        # add .exe extension to windows binaries
        if [[ "$target" == *"windows"* ]]; then
            out_bin="$binary.exe"
        fi
        cp "target/$target/release-with-lto/$out_bin" "build/$target/$out_bin"
    done

    # copy extra files
    for file in "${extra_files[@]}"; do
        cp "$file" "build/$target/$file"
    done
done

echo "Creating archives for all targets"
for target in "${targets[@]}"; do
    # generate checksums
    echo "Generating checksums for $target"
    cd "build/$target"
    > checksums.txt
    for binary in "${binaries[@]}"; do
        out_bin="$binary"
        # add .exe extension to windows binaries
        if [[ "$target" == *"windows"* ]]; then
            out_bin="$binary.exe"
        fi
        sha256sum "$out_bin" >> checksums.txt
    done
    cd ../..

    # create archive
    cd build/
    if [[ "$target" == *"windows"* ]]; then
        zip -r "$target.zip" "$target"
    else
        tar -czf "$target.tar.gz" "$target"
    fi
    cd ..
done

# Generate final checksums.txt in build/
echo "Generating final checksums.txt in build/"
cd build/
> checksums.txt
for target in "${targets[@]}"; do
    if [[ "$target" == *"windows"* ]]; then
        sha256sum "$target.zip" >> checksums.txt
    else
        sha256sum "$target.tar.gz" >> checksums.txt
    fi
done
cd ..

echo "Done"
