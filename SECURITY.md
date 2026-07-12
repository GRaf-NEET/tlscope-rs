# Security Policy

TLScope is a local debugging proxy that can expose plaintext HTTP traffic when HTTPS inspection is enabled. Treat captured sessions, local CA files, and exported JSON as sensitive data.

## Supported Versions

Security fixes are tracked on the `main` branch until the project starts publishing versioned releases.

## Reporting a Vulnerability

If the GitHub repository has private vulnerability reporting enabled, use GitHub Security Advisories. Otherwise, open an issue with a minimal description and avoid posting secrets, captured traffic, private keys, tokens, or exploit details that would put users at immediate risk.

## Safe Use

- Use HTTPS inspection only in controlled test environments.
- Do not commit or share `TLScope-ca-key.pem`.
- Review exported sessions before attaching them to issues.
- Prefer loopback listeners. Use `--allow-external` only on trusted test networks.