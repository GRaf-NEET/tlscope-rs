# TLScope

**[English](README.md) | [Русский](../ru-RU/README.md)**

![Rust 2021](https://img.shields.io/badge/Rust-2021-orange)
![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-lightgrey)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

Local explicit HTTP/HTTPS debugging proxy for child processes.

TLScope helps developers inspect traffic from applications they start through the tool or explicitly configure to use its local proxy. It is intended for controlled development and test environments, not for hidden or system-wide interception.

## Contents

- [Project Description](#project-description)
- [Features](#features)
- [Safety and Scope](#safety-and-scope)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [API / CLI](#api--cli)
- [Examples](#examples)
- [Project Structure](#project-structure)
- [Development](#development)
- [Building](#building)
- [Testing](#testing)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Project Description

TLScope is a local explicit HTTP/HTTPS debugging proxy written in Rust. It can launch a child process with proxy-related environment variables, capture the traffic that process sends through the proxy, and show requests, responses, TLS details, process logs, filters, and exports in a terminal UI.

The primary workflow is:

```bash
TLScope run -- ./target/debug/my_application --config test.toml
```

TLScope starts a proxy listener on `127.0.0.1:8080` by default, spawns the child process without shell argument concatenation, passes proxy environment variables to the child, and shuts the proxy down when the session ends.

TLScope does not transparently intercept all system traffic. A target application must either be started by `TLScope run` or explicitly configured to use TLScope as an HTTP/HTTPS proxy.

## Features

- Explicit HTTP proxy for local debugging.
- `CONNECT` support for HTTPS traffic.
- Optional HTTPS inspection through a local debugging certificate authority.
- HTTP/2 inspection for HTTPS connections that negotiate ALPN `h2`.
- HTTP/1.1 WebSocket upgrade tunneling after the `101 Switching Protocols` handshake.
- Child process launcher that sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase variants.
- Optional CA-related environment variables for common clients: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS`.
- Terminal UI for live request lists, request details, response details, TLS information, raw previews, process logs, filtering, and JSON export.
- Local CA lifecycle commands: create, show path, show fingerprint, install on Windows, and remove local files.
- Default sensitive header redaction, optional JSON/form body field redaction, and explicit opt-in for showing secrets.
- Localhost-only integration tests for proxy behavior, HTTPS inspection, process launch, and redaction.

## Safety and Scope

Use TLScope only with applications, systems, and traffic you own or have permission to test.

TLScope does not implement and should not be used for:

- hidden traffic interception;
- injection into unrelated processes;
- ARP spoofing, DNS spoofing, packet injection, or network redirection;
- automatic system proxy configuration changes;
- automatic CA installation during traffic inspection;
- certificate pinning bypass;
- disabling target application security controls;
- telemetry or uploading captured data to external services.

HTTPS inspection reveals plaintext contents of encrypted traffic from configured test clients. Enable it only in a controlled environment and treat captured sessions, local CA files, and exports as sensitive data.

## Requirements

| Requirement | Notes |
| --- | --- |
| Rust | Stable Rust toolchain, edition 2021. |
| Cargo | Required for local builds and tests. |
| Terminal | Required for the launcher and TUI. |
| Target application | Must honor proxy environment variables or be explicitly configured to use the proxy. |
| Windows trust store | `TLScope ca install` is implemented for the current user's Windows Root store. Other platforms require manual trust setup. |

TODO: document minimum supported Rust version if the project starts enforcing one.

## Installation

Build from source:

```bash
git clone https://github.com/GRaf-NEET/tlscope-rs.git
cd tlscope-rs
cargo build --release
```

The release binary is created under `target/release/`.

On Windows:

```powershell
.\target\release\TLScope.exe --help
```

On Unix-like systems:

```bash
./target/release/TLScope --help
```

TODO: add package manager, prebuilt binary, or crates.io installation instructions when releases are published.

## Quick Start

Open the interactive launcher:

```bash
cargo run
```

Run a child application through TLScope:

```bash
cargo run -- run -- ./target/debug/my_application --config test.toml
```

Run the built binary directly:

```bash
TLScope run -- ./my_application --config test.toml
```

Run only the proxy and configure a client manually:

```bash
TLScope proxy --listen 127.0.0.1:8080
```

By default, CLI `run` and `proxy` modes ask for explicit confirmation before HTTPS inspection. Type `inspect` when prompted to enable decryption, or press Enter to tunnel `CONNECT` traffic without decrypting it. The interactive launcher starts with HTTPS inspection off and lets you enable it deliberately.

## Configuration

TLScope is configured through CLI flags and the interactive launcher. There is no documented project configuration file at this time.

TODO: document a file-based configuration format if one is added.

Common proxy options:

| Option | Default | Description |
| --- | --- | --- |
| `--listen <addr>` | `127.0.0.1:8080` | Proxy listener address. |
| `--no-tls-decryption` | `false` | Tunnel HTTPS `CONNECT` streams without decrypting them. |
| `--ca-dir <path>` | Platform config directory + `TLScope/ca` | Directory for the local debugging CA. |
| `--max-body-size <bytes>` | `1048576` | Maximum captured body bytes kept in memory per request or response. Traffic is still forwarded. |
| `--redact` | `false` in CLI, `true` in launcher | Redact known sensitive JSON/form fields in bodies. Sensitive headers are redacted by default. |
| `--show-secrets` | `false` | Show sensitive values in the UI and exports. Prints a warning. |
| `--save-session <path>` | disabled | Save the captured session as JSON when TLScope exits. |
| `--allow-external` | `false` | Permit a non-loopback listener after a warning. Use only on trusted test networks. |

`run`-only options:

| Option | Description |
| --- | --- |
| `--workdir <path>` | Working directory for the child process. |
| `--env KEY=VALUE` | Extra environment variable for the child process. Can be repeated. |
| `--no-extra-ca-env` | Do not pass `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS`. |

Proxy variables passed to child processes:

```text
HTTP_PROXY
HTTPS_PROXY
ALL_PROXY
http_proxy
https_proxy
all_proxy
```

When HTTPS inspection is enabled and extra CA variables are not disabled, TLScope also passes:

```text
SSL_CERT_FILE
REQUESTS_CA_BUNDLE
CURL_CA_BUNDLE
NODE_EXTRA_CA_CERTS
```

## Usage Examples

Run a child process with common debugging options:

```bash
TLScope run \
  --listen 127.0.0.1:18080 \
  --ca-dir ./local-ca \
  --max-body-size 1048576 \
  --redact \
  --env RUST_LOG=debug \
  --save-session session.json \
  -- ./target/debug/my_application --config test.toml
```

Tunnel HTTPS without decrypting it:

```bash
TLScope run --no-tls-decryption -- ./my_application
```

Run a proxy that other clients can use explicitly:

```bash
TLScope proxy --listen 127.0.0.1:8080
```

Listen on a non-loopback interface only when you intentionally expose the proxy on a trusted test network:

```bash
TLScope proxy --listen 0.0.0.0:8080 --allow-external
```

Manage the local debugging CA:

```bash
TLScope ca create
TLScope ca path
TLScope ca fingerprint
TLScope ca install
TLScope ca install --yes
TLScope ca remove
```

Use a custom CA directory:

```bash
TLScope ca --ca-dir ./local-ca create
TLScope run --ca-dir ./local-ca -- ./my_application
```

`TLScope ca remove` removes local CA files created by TLScope when confirmed. It does not remove certificates from an operating system trust store.

## API / CLI

The documented interface is the CLI:

```text
TLScope [COMMAND]
TLScope run [OPTIONS] -- <program> [args...]
TLScope proxy [OPTIONS]
TLScope ca [--ca-dir <path>] <COMMAND>
```

Commands:

| Command | Description |
| --- | --- |
| `run` | Start the proxy, launch a child program with proxy environment variables, and open the TUI. |
| `proxy` | Start only the proxy and TUI. Configure clients manually. |
| `ca create` | Create or load the local debugging CA. |
| `ca path` | Print the CA certificate path. |
| `ca fingerprint` | Print the CA certificate SHA-256 fingerprint. |
| `ca install [--yes]` | Install the CA into the current user's Windows Root trust store. Other platforms currently return an error. |
| `ca remove` | Remove local CA files created by TLScope after confirmation. |

The crate also exposes public Rust modules for internal use and integration tests. A stable library API is not documented yet.

TODO: document a supported Rust library API if the project intends to expose one.

## Examples

TUI shortcuts:

| Shortcut | Action |
| --- | --- |
| `Up` / `Down` or `j` / `k` | Select a request or scroll logs. |
| `Enter` | Open request details. |
| `Esc` | Return to the previous screen. |
| `Tab` / `Shift+Tab` | Switch detail tabs. |
| `l` | Toggle process logs. |
| `Home` / `End` | Jump to oldest or latest log lines. |
| `PgUp` / `PgDn` | Page through logs. |
| `/` | Enter filter mode. |
| `Space` | Pause or resume live updates. |
| `c` | Clear the current session. |
| `e` | Export JSON to `TLScope-export.json`. |
| `r` | Reapply the current filter. |
| `y` | Show the selected URL in the status line. |
| `?` | Show help. |
| `q` | Quit. If a child process is running, choose whether to stop it or leave it running. |

Filter examples:

```text
method:POST
host:api.example.com
path:/v1/users
status:404
status:>=400
type:json
has:request-body
has:response-body
error:true
tls:false
duration:>500ms
```

Multiple filter tokens are combined with logical `AND`.

Export behavior:

- `e` in the TUI writes a JSON session to `TLScope-export.json`.
- `--save-session <path>` writes a JSON session on exit.
- Code-level helpers exist for HAR, text report, and cURL export, but no documented CLI command currently exposes those formats.

## Project Structure

```text
src/
  main.rs              CLI entrypoint
  lib.rs               Public module exports
  cli.rs               clap command definitions
  config.rs            Runtime configuration parsing and validation
  app.rs               Command orchestration
  interactive.rs       Startup launcher TUI

  process/             Child process launch and log capture
  proxy/               HTTP/HTTPS proxy, CONNECT, TLS, HTTP/2, upstream handling
  certificates/        Local debugging CA, certificate cache, trust-store helpers
  capture/             Traffic model, store, filters, redaction, decoding, export helpers
  tui/                 ratatui/crossterm interface

tests/                 Localhost-only integration tests
.github/workflows/     CI workflow
```

## Development

Recommended local checks:

```bash
cargo fmt --all -- --check
cargo test --locked
```

Optional linting:

```bash
cargo clippy --all-targets
```

For changes that affect proxy behavior, add or update integration tests under `tests/`.

Do not commit generated CA private keys, captured sessions, logs containing tokens, or local environment files.

## Building

Debug build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Run from source:

```bash
cargo run -- --help
```

## Testing

Run the test suite:

```bash
cargo test --locked
```

The current tests cover:

- plain HTTP proxying;
- body capture truncation without truncating forwarded traffic;
- HTTP/1.1 WebSocket upgrade tunneling;
- HTTPS inspection with a local test server;
- HTTP/2 inspection over TLS;
- child process proxy environment setup;
- redaction and JSON export.

CI runs formatting and tests on Ubuntu and Windows.

## FAQ

**Does TLScope capture all traffic on my machine?**

No. TLScope is an explicit proxy. The application must use the proxy environment variables or be configured to use the proxy manually.

**Why do I see only `CONNECT` entries for HTTPS?**

HTTPS inspection may be disabled, the local CA may not be trusted by the client, or the client may not use the proxy as expected. Enable inspection only in a controlled test environment.

**Does TLScope bypass certificate pinning?**

No. If the application uses certificate pinning, TLScope reports the resulting TLS/proxy failure and does not try to bypass the protection.

**Is the CA installed automatically?**

No. Traffic inspection creates or loads a local CA, but trust installation is explicit. `TLScope ca install` can install it into the current user's Windows Root store after confirmation.

**What if port `127.0.0.1:8080` is already in use?**

Choose another listener:

```bash
TLScope run --listen 127.0.0.1:18080 -- ./my_application
```

**Are secrets hidden in captures and exports?**

Known sensitive headers are redacted by default. JSON/form body field redaction requires `--redact` in CLI mode and is enabled by default in the launcher. `--show-secrets` disables redaction and prints a warning.

**Can I use TLScope with clients that ignore proxy variables?**

Only if the client supports explicit proxy configuration through another mechanism. TLScope does not inject itself into arbitrary processes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local checks and contribution guidance.

Security-related guidance is available in [SECURITY.md](SECURITY.md).

## License

TLScope is licensed under the [MIT License](../../../LICENSE).
