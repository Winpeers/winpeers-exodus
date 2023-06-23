#!/usr/bin/env bash
sudo apt-get install libpq-dev
cargo build --release
cargo install diesel_cli --no-default-features --features "postgres"
diesel database setup