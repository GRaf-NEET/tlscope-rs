# Contributing

## Local Checks

```powershell
cargo fmt --all -- --check
cargo test --locked
```

For changes that touch proxy behavior, add or update integration tests under `tests/`.

## Safety Notes

Do not commit generated CA private keys, captured session exports, logs with tokens, or local environment files. The repository `.gitignore` excludes common TLScope outputs, but review staged files before committing.