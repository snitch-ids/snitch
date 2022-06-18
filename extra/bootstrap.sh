#/bin/bash

# Bootstrap snitch on Ubuntu

apt update -y
apt install vim screen -y
apt install gcc build-essential pkg-config libssl-dev -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
rustup default nightly

cargo install snitch

snitch --init
