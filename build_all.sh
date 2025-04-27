#! /bin/bash

# support: ARM64, ARMv7, x86_64 linux, Windows x86_64
targets=("aarch64-unknown-linux-gnu" "armv7-unknown-linux-gnueabihf" "x86_64-unknown-linux-musl" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-gnu")
binaries=("xelis_daemon" "xelis_miner" "xelis_wallet")
extra_files=("README.md" "API.md" "CHANGELOG.md" "LICENSE")

# verify that we have cross installed
if ! command -v cross &> /dev/null
then
    echo "cross could not be found, please install it for cross compilation"
    exit
fi

# Cross needs docker to be running
echo "Starting docker daemon"
sudo systemctl start docker

echo "Updating using rustup"
rustup update stable

echo "Only build in stable"
rustup default stable

echo "Deleting build folder"
rm -rf build

# compile all binaries for all targets
echo "Compiling binaries for all targets"
for target in "${targets[@]}"; do
    echo "Clean build cache for " $target
    cross clean

    # support the target to build it
    rustup target add $target
    cross build --target $target --profile release-with-lto

    mkdir -p build/$target
    # copy generated binaries to build directory
    for binary in "${binaries[@]}"; do
        # add .exe extension to windows binaries
        if [[ "$target" == *"windows"* ]]; then
            binary="$binary.exe"
        fi
        cp target/$target/release-with-lto/$binary build/$target/$binary
    done

    # copy extra files
    for file in "${extra_files[@]}"; do
        cp $file build/$target/$file
    done
done

echo "Creating archives for all targets"
for target in "${targets[@]}"; do
    # generate checksums
    echo "Generating checksums for $target"
    cd build/$target
    > checksums.txt
    for binary in "${binaries[@]}"; do
        # add .exe extension to windows binaries
        if [[ "$target" == *"windows"* ]]; then
            binary="$binary.exe"
        fi
        sha256sum $binary >> checksums.txt
    done
    cd ../..

    # create archive
    cd build/
    if [[ "$target" == *"windows"* ]]; then
        zip -r $target.zip $target
    else
        tar -czf $target.tar.gz $target
    fi
    cd ..
done

# Generate final checksums.txt in build/
echo "Generating final checksums.txt in build/"
cd build/
> checksums.txt
for target in "${targets[@]}"; do
    if [[ "$target" == *"windows"* ]]; then
        sha256sum $target.zip >> checksums.txt
    else
        sha256sum $target.tar.gz >> checksums.txt
    fi
done
cd ..

echo "Done"