# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.4] - 2026-10-15

### Fixed

- Decorate `connection.admit` and `connection.admitConnection` for DeepSeek
  Harness `0.2.1-alpha.3`, which moved the trust-and-credential decision out of
  `requestRejection` into `admit` (`requestRejection` now delegates to `admit`
  instead of the reverse):
  - The `/api` prefix route and the Gateway WebSocket upgrade admit through
    `admit` and `admitConnection`, so they no longer passed through the
    `requestRejection` decoration. Every proxy-authenticated request without a
    native DSH cookie answered `401` while the index (decorated
    `authorizeIndex`) still served `200`, and `/api/remote.mux` never
    upgraded.
  - `admit` now promotes a `401` carrying the shared secret to the shared
    browser Peer. `admitConnection` does the same and reports a no-op
    `release`, because the shared browser Peer owns no socket. An upstream
    `403` is still never promoted, so the Host/Origin fence keeps refusing
    DNS-rebinding and cross-site requests.
  - Both decorations are installed only where the installed DSH exposes the
    method, so a host that admits solely through `requestRejection` keeps its
    current behaviour.
  - Added unit coverage for both entry points, the fence/secret matrix, the
    no-op release, and the optional-method guards (97 unit tests pass).

## [0.2.3] - 2026-09-25

### Fixed

- Intercept `webServer.match` for runtime route normalisation:
  - In DeepSeek Harness (`@deepseek-ai/dsh-host-webserver@0.1.5-rc.2`), `webServer.handle`
    is a local closure inside `[Service.init]()` rather than an instance method on
    the `WebServer` service. As a result, wrapping `webServer.handle` alone did not
    intercept routes during live HTTP dispatch.
  - Intercepted `webServer.match(pathname)` instead, which dynamically decorates
    the matched route's `handler` at dispatch time with loopback normalisation
    (`req.headers.host` -> `127.0.0.1:<port>` and `req.headers.origin` -> `http://127.0.0.1:<port>`).
  - Preserves DSH's internal routing table (`exact` and `prefixes` maps) untouched,
    ensuring clean disposal on plugin unload.
  - Fixes HTTP 403 `untrusted origin` on `dshmarket` discovery and mutation endpoints
    (`/dsh-market/discovery-compatibility`, `/dsh-market/update`, etc.) when accessed
    through reverse proxies.
  - Maintained `webServer.handle` wrapping as a backward-compatible fallback for
    custom test harnesses and standalone web server implementations.
  - Added unit test simulating the real-DSH `WebServer` dispatch pattern without a `handle` method (86 unit tests pass).

## [0.2.2] - 2026-09-25

### Added

- Loopback normalisation for third-party plugin routes:
  - Decorates `webServer.handle` to normalise incoming proxy-authenticated requests
    to the local loopback authority (`127.0.0.1:<port>`).
  - Enables third-party plugins with strict loopback/same-origin checks (such as
    `dshmarket@1.65.1` protecting `/dsh-market/discovery-compatibility`,
    `/dsh-market/update`, etc.) to work seamlessly across reverse-proxied domains.
  - Strict security fence: evaluates DSH's native Host/Origin/Cross-Site checks
    (`requestRejection`) against real inbound headers *before* normalising;
    cross-origin CSRF attacks, cross-site fetch metadata, or untrusted Hosts are
    immediately rejected with HTTP 403 Forbidden and never reach downstream handlers.
  - Preserves the incoming public authority in `X-Forwarded-Host` and
    `X-Forwarded-Proto`.
- Extensive third-party plugin test coverage:
  - 23 new unit tests covering `dshmarket` discovery and mutation endpoints,
    multiple plugins registering diverse routes (exact and prefix), CSRF prevention,
    custom ports, query parameters, other HTTP methods, and lifecycle cleanup
    (85 unit tests pass).

### Changed

- Cleaned up deprecated `attachBootstrapInjection` stub to keep the codebase concise
  and maintainable.
- Generalised `captureMethod` and `installWrapper` with `targetName` parameter for
  uniform transactional decoration across `connection` and `webServer`.

## [0.2.1] - 2026-09-25

### Fixed

- Eliminated 502 Bad Gateway / empty HTTP reply on authenticated index requests:
  reverted `ServerResponse.writeHead`, `write`, and `end` monkey-patching in
  `authorizeIndex`. Response streaming and headers are now left entirely to DSH's
  native HTTP pipeline.
- Migrated `ownsHost` bootstrap injection to DSH's supported extension seams:
  - `webServer.tapIndex`: registers a pure HTML transform applied by DSH's
    `renderIndex` pipeline.
  - `webserver/index-inject`: listens for the structured injection event and pushes
    `{ kind: 'global', name: '__DSH_TRANSPORT__', value: { ownsHost: true } }`.
- Made HTML injection idempotent so that `tapIndex` skips injection if structured
  `__DSH_TRANSPORT__` injection is already present in the rendered document.
- Unit tests updated to verify native response preservation and extension seam
  registration (62 unit tests pass).

## [0.2.0] - 2026-09-25

### Added

- Proxy-authenticated browser bootstrap injection: when `authorizeIndex` verifies
  a request carrying a valid `X-DSH-Proxy-Auth` secret, it attaches a response
  decorator that injects `globalThis.__DSH_TRANSPORT__.ownsHost = true` into the
  served `index.html`.
- Enables DSH host persistence (`ctx.remote.$host.isLoopback === true` ->
  `persistence = "host"`) for reverse-proxied domains (such as
  `dsh.terraurbs.com`), fixing the issue where the Models directory, Plugin
  settings, and Provider configuration appeared empty or reported "settings are
  unavailable in this browser".
- Server-verified: the bootstrap script is only injected when the reverse proxy
  has supplied the correct shared secret. Unauthenticated or native loopback
  access receives standard unmodified HTML.
- Safe HTTP streaming handling: strips or suppresses stale `Content-Length`
  response headers so chunked encoding transfers the injected document cleanly
  without truncation.
- Unit tests covering bootstrap injection, HTML insertion rules (in `<head>`,
  before `</head>`, or prepended), and `Content-Length` removal.

## [0.1.0] - 2026-09-20

### Added

- `dsh-trusted-proxy-auth` host plugin for DeepSeek Harness that permits a
  request authenticated by a trusted reverse proxy via the `X-DSH-Proxy-Auth`
  header and the `DSH_PROXY_AUTH_SECRET` environment secret.
- Constant-time secret comparison over UTF-8 bytes with a 32-byte minimum and a
  printable-ASCII-minus-comma charset.
- `requestRejection` decoration that only converts an upstream `401` into a
  permit, never an upstream `403`.
- `authorizeIndex` decoration that keeps the Host/Origin fence while bypassing
  native browser authentication for trusted-proxy requests.
- Startup semantic invariant: activation probes the original `requestRejection`
  and refuses to start unless the trust fence still returns `403` and missing
  native browser authentication still returns `401`.
- Fail-closed, transactional activation: bad configuration fails the profile,
  and any partial decoration (a write that failed verification, or a disposer
  that failed to register) is rolled back.
- Compare-and-swap cleanup that restores the original connection instance shape
  and cannot stack wrappers across HMR/reload; wrappers carry a registered
  (`Symbol.for`) marker so two module generations unwrap each other.
- 50 unit tests and a 35-check real-DSH integration harness.
- CI with a pinned real-DSH integration gate on push/PR and a scheduled
  `@latest` drift watch.
- Documentation: README, threat model, validation record, Traefik contract.
