# Run

A typical run with logs at DEBUG level (INFO is the default):
```bash
RUSTFLAGS=-Awarnings RUST_LOG="debug" cargo run --release
```

The CLI supports flags for device and filter for simpler development.
For example, to capture only traffic to eyalzo.com (that supports clear text http), use this (the -d is optional):
```bash
RUSTFLAGS=-Awarnings RUST_LOG="trace" cargo run -- -f "host 50.87.176.106 and tcp" -d "en0"
```