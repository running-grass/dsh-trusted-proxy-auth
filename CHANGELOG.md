# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-20

### Added

- `dsh-trusted-proxy-auth` host plugin for DeepSeek Harness that permits a
  request authenticated by a trusted reverse proxy via the `X-DSH-Proxy-Auth`
  header and the `DSH_PROXY_AUTH_SECRET` environment secret.
- Constant-time secret comparison over UTF-8 bytes with a 32-byte minimum.
- `requestRejection` decoration that only converts an upstream `401` into a
  permit, never an upstream `403`.
- `authorizeIndex` decoration that keeps the Host/Origin fence while bypassing
  native browser authentication for trusted-proxy requests.
- Fail-closed activation with rollback of partial decoration.
- Compare-and-swap cleanup that restores the original connection instance shape
  and cannot stack wrappers across HMR/reload.
- 39 unit tests and a 35-check real-DSH integration harness.
- Documentation: README, threat model, validation record, Traefik contract.
