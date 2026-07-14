# Contributing

**[English](CONTRIBUTING.md) | [Русский](../ru-RU/CONTRIBUTING.md)**

## Local Checks

```powershell
cargo fmt --all -- --check
cargo test --locked
```

For changes that touch proxy behavior, add or update integration tests under `tests/`.

## Architecture Notes

Keep reusable core and application logic outside UI-specific folders. `src/tui` should contain terminal rendering, terminal input handling, TUI state, and Ratatui-specific layout code. Logic that could also be used by a future GUI, such as diagnostics storage, filter suggestions, request detail formatting, capture processing, process tracking, or export behavior, belongs in shared modules such as `src/capture`, `src/diagnostics`, `src/process`, or the application layer.

Before adding logic to `src/tui`, check whether it is truly terminal-specific. If the logic would still be useful without Ratatui or crossterm, put it in a shared module and call it from the TUI.

## Safety Notes

Do not commit generated CA private keys, captured session exports, logs with tokens, or local environment files. The repository `.gitignore` excludes common TLScope outputs, but review staged files before committing.