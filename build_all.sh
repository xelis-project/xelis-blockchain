#! /bin/bash

# support: ARM64, x86_64 linux, Windows x86_64
targets=("aarch64-unknown-linux-gnu" "x86_64-unknown-linux-musl" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-gnu")
binaries=("xelis_daemon" "xelis_miner" "xelis_wallet")
extra_files=("README.md" "API.md")

# verify that we have cross installed
if ! command -v cross &> /dev/null
then
    echo "cross could not be found, please install it for cross compilation"
    exit
fi

# Cross needs docker to be running
echo "Starting docker daemon"
sudo systemctl start docker

# compile all binaries for all targets
echo "Compiling binaries for all targets"
for target in "${targets[@]}"; do
    for binary in "${binaries[@]}"; do
        cross build --profile release-with-lto --bin $binary --target $target
    done
done

echo "Deleting build folder"
rm -rf build

echo "Creating archives for all targets"
for target in "${targets[@]}"; do
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

    # create archive
    cd build/
    if [[ "$target" == *"windows"* ]]; then
        zip -r $target.zip $target
    else
        tar -czf $target.tar.gz $target
    fi
    cd ..
done

echo "Done"