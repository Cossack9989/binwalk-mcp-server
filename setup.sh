#!/usr/bin/env bash

os=$(uname -s)

if [ "$os" = "Darwin" ]; then
    brew install sleuthkit dtc curl git \
        unyaffs srecord cpio lzop lz4
elif [ "$os" = "Linux" ]; then
    apt update
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt install -y \
        7zip unzip zstd 7zip-standalone tar unrar lz4 lzop cpio \
        sleuthkit cabextract unyaffs srecord \
        curl wget git python3-pip build-essential clang \
        liblzo2-dev libucl-dev liblz4-dev libbz2-dev zlib1g-dev libfontconfig1-dev liblzma-dev libssl-dev \
        device-tree-compiler
    curl -L -o /tmp/sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_$(dpkg --print-architecture).deb"
    dpkg -i /tmp/sasquatch_1.0.deb
else
    echo "unsupported os: $os"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "installing rust from rsproxy.cn ..."
    echo 'export RUSTUP_DIST_SERVER="https://rsproxy.cn"' >> "$HOME/.bashrc"
    echo 'export RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"' >> "$HOME/.bashrc"
    curl --proto '=https' --tlsv1.2 -sSf https://rsproxy.cn/rustup-init.sh | sh -s -- -y
    CARGO_CONFIG_DIR="$HOME/.cargo"
    mkdir -p "$CARGO_CONFIG_DIR"
    CARGO_CONFIG="$CARGO_CONFIG_DIR/config.toml"
    cat <<EOF > "$CARGO_CONFIG"
[source.crates-io]
replace-with = 'rsproxy-sparse'
[source.rsproxy]
registry = "https://rsproxy.cn/crates.io-index"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
[registries.rsproxy]
index = "https://rsproxy.cn/crates.io-index"
[net]
git-fetch-with-cli = true
EOF
    source "$HOME/.cargo/env"
    cargo install binwalk
fi

pip3 install fastmcp hexdump --break-system-packages