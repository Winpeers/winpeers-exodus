#!/usr/bin/env bash
cargo build --release
cargo install diesel_cli --no-default-features --features "postgres,r2d2,chrono,uuid"
diesel database setup