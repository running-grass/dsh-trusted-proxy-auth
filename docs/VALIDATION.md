# Validation record

Results captured on the machine that this plugin was developed and tested on.
They are recorded here as evidence; re-run the commands to reproduce.

## Environment

| Item | Value |
| --- | --- |
| DSH version | `0.1.5-rc.2` |
| DSH install | global `@deepseek-ai/dsh` (`/usr/lib/node_modules/@deepseek-ai/dsh`) |
| Node version | `v24.21.0` |
| Test isolation | throwaway `DSH_HOME` under `/tmp`, private profile derived from the shipped `web` template, loopback port selected at runtime |
| DSH install files modified | none (`find … -newermt` returned no files) |
| Production profile touched | no (the running server and its profile were left untouched) |

## Unit tests — 86 passed, 0 failed

```console
$ npm test
ℹ tests 86
ℹ suites 9
ℹ pass 86
ℹ fail 0
```

Coverage: `requestRejection` result mapping (including pass-through of an
unexpected upstream status); `authorizeIndex` decision tree; proxy bootstrap
HTML injection (`__DSH_TRANSPORT__.ownsHost = true` script insertion via
`webServer.tapIndex` and `webserver/index-inject` in `<head>`, `</head>`, or
fragment; idempotency; Buffer handling; native response preservation);
`normalizeToLoopback` authority and origin rewriting (custom ports, port 80,
plain objects, Fetch `Headers`, case insensitivity, idempotency);
`webServer.match` / `webServer.handle` third-party plugin route compatibility (`dshmarket@1.65.1`
discovery and mutation routes with `sameOrigin` loopback checks; cross-origin
CSRF attack rejection before normalization; cross-site fetch metadata rejection;
untrusted Host rejection; unauthenticated request rejection; direct loopback
passthrough; real-DSH WebServer structure without handle method;
multiple plugins registering diverse routes; query parameter
handling; other HTTP methods; error bubbling; and lifecycle cleanup/restoration);
header parsing (exact, off-by-one, empty, missing, absent headers, array,
non-string, duplicate, joined, `Headers` case-insensitivity); configuration
failures (missing/empty/short/comma/whitespace/non-ASCII secret, missing
`ctx.effect`, missing service, missing methods, non-extensible service,
undecoratable method with rollback, a mutation that landed but failed
verification, and rollback when `ctx.effect` fails); the startup semantic
invariant; lifecycle (install, exact-shape restore for inherited and own
methods, apply→cleanup→apply, overlapping activations, cross-generation
global-marker unwrap, `authenticatedUrl` untouched, no secret in logs).

## Integration tests — 37 passed, 0 failed

`npm run test:integration` boots the real Harness Web server with this plugin
loaded next to `@deepseek-ai/dsh-client-connection` and asserts:

```
== profile setup (isolated DSH_HOME) ==
  ok    dsh plugin add links this checkout and reconciles bundles
  ok    dump-config loads dsh-trusted-proxy-auth
  ok    dump-config still loads @deepseek-ai/dsh-client-connection

== index route (/): trusted-proxy authentication ==
  ok    no proxy header -> 401 native authentication
  ok    wrong proxy header -> 401
  ok    valid proxy header -> 200
  ok    valid proxy header serves the HTML application
  ok    valid proxy header injects ownsHost bootstrap into index HTML
  ok    valid proxy header + untrusted Host -> 403
  ok    untrusted Host 403 body is minimal
  ok    untrusted Host 403 sets no-store
  ok    valid proxy header + cross-site fetch metadata -> 403

== /api route: request-trust fence is not bypassed ==
  ok    /api without proxy header -> 401
  ok    /api with valid proxy header reaches the application (not 401/403)
  ok    /api cross-origin with valid secret -> 403
  ok    /api cross-site with valid secret -> 403
  ok    /api untrusted Host with valid secret -> 403

== WebSocket /api/remote.mux ==
  ok    ws without proxy header -> 401
  ok    ws wrong proxy header -> 401
  ok    ws valid proxy header + trusted Host -> upgraded
  ok    ws valid proxy header + same Origin -> upgraded
  ok    ws valid proxy header + untrusted Host -> 403
  ok    ws valid proxy header + wrong Origin -> 403

== native DSH authentication regression (no proxy header) ==
  ok    native ?token= exchange -> 303
  ok    native token exchange mints a session cookie
  ok    native session cookie -> 200
  ok    native session cookie does not inject proxy ownsHost bootstrap
  ok    invalid native token -> 401
  ok    native cookie is authority-bound (evil Host -> 401)

== log hygiene ==
  ok    captured server output never contains the secret
  ok    server stopped cleanly

== fail-closed activation ==
  ok    missing secret -> non-zero exit
  ok    missing secret -> names the plugin and variable
  ok    missing secret -> no listener
  ok    short secret -> non-zero exit
  ok    short secret -> no listener

== filesystem hygiene ==
  ok    secret never written under DSH_HOME

PASS: 37 passed, 0 failed
```

## Startup semantic invariant

`requestRejection` shape is checked, but so is its meaning. Before decorating
anything, activation calls the original, undecorated method with four
credential-free probe requests and requires:

| Probe | Required result |
| --- | --- |
| `host: 127.0.0.1`, no credentials | `401` (native browser auth missing) |
| `host: dsh-proxy-probe-<pid>.invalid` | `403` (Host/DNS-rebinding fence) |
| `host: 127.0.0.1`, `origin: https://dsh-proxy-probe.invalid` | `403` |
| `host: 127.0.0.1`, `sec-fetch-site: cross-site` | `403` |

Anything else fails activation with `unsupported DSH requestRejection
semantics`, so a DSH upgrade that, for example, authenticates before applying
the trust fence (making an untrusted Host return `401`) cannot silently turn
into a bypass. The real-DSH integration run above boots the server with this
probe active, so the invariant is also proven against `0.1.5-rc.2` end to end.

## Admission interface moved out of `requestRejection` (DSH 0.2.1-alpha.3)

Recorded on 2026-10-15 against a live `0.2.1-alpha.3` checkout fronted by a
reverse proxy that injects `X-DSH-Proxy-Auth`. Upstream moved the
trust-and-credential decision into `connection.admit` and made
`requestRejection` delegate to it; the `/api` prefix route and the Gateway
WebSocket upgrade admit through `admit` and `admitConnection`, so neither ever
reaches the `requestRejection` decoration.

With the shared secret, on `0.2.3` and on `0.2.4`:

| Request | `0.2.3` | `0.2.4` |
| --- | --- | --- |
| `GET /` | `200` | `200` |
| `GET /api` | `401` | `404` (reaches the application) |
| `GET /api`, no secret | `401` | `401` |
| `GET /api`, wrong secret | `401` | `401` |
| `GET /api`, valid secret, untrusted Host | `403` | `403` |
| `Upgrade /api/remote.mux` | `401` | `101 Switching Protocols` |
| `Upgrade /api/remote.mux`, no secret | `401` | `401` |

`npm run test:integration` against that host, comparing the two releases:

| Check | `0.2.3` | `0.2.4` |
| --- | --- | --- |
| `/api with valid proxy header reaches the application (not 401/403)` | FAIL (got 401) | ok |
| `ws valid proxy header + trusted Host -> upgraded` | FAIL (got 401) | ok |
| `ws valid proxy header + same Origin -> upgraded` | FAIL (got 401) | ok |
| `valid proxy header injects ownsHost bootstrap into index HTML` | FAIL | ok (expectation updated, see below) |
| totals | 27 passed, 5 failed | 31 passed, 1 failed |

Both runs end in `FATAL: spawnSync … ETIMEDOUT` in the fail-closed phase, so the
last two sections do not run either time; the remaining failure is unrelated to
admission and is listed under known compatibility issues.

## Runtime interface probe (DSH 0.1.5-rc.2)

Probe output against the real `HostConnectionService`:

```
ctx.connection identity === raw service : false
ctx.connection is a traceable proxy     : true
Object.isExtensible(ctx.connection)     : true
requestRejection   own=false proto=true  writable=true  enumerable=false
authorizeIndex     own=false proto=true  writable=true  enumerable=false
authenticatedUrl   own=false proto=true  writable=true  enumerable=false
assign via ctx -> raw own property      : true
raw value is the assigned wrapper       : wrapped
ctx get returns a shadow-method proxy   : true
delete via ctx -> raw own property gone : true
prototype method intact                 : true
```

### Interpretation / adjustments required

- `requestRejection` and `authorizeIndex` are ordinary **writable, inherited
  prototype methods**, exactly as assumed. Decoration by instance assignment
  works.
- `ctx.connection` is **not** the raw instance but a Cordis traceable proxy, and
  each property read wraps a function in a **fresh shadow-method proxy**. A
  naive `connection.requestRejection === installedWrapper` identity check is
  therefore always false.
- Adjustment: the plugin captures, compares, and restores through
  `Object.getOwnPropertyDescriptor` (walking the prototype chain), which reaches
  the real instance value. Restore is compare-and-swap and unwraps any wrapper
  it finds, so overlapping or repeated activation cannot stack wrappers and
  cleanup returns the object to its original shape (`delete` when the method was
  inherited, assignment when it was an own property).
- `authenticatedUrl` is intentionally left untouched, so the native
  `http://127.0.0.1:3080/?token=…` URL keeps working as an emergency/admin path.
- Hardening applied after external review: the startup semantic probe (above);
  transactional installation (a write that landed but failed verification is
  undone before the function throws, and installation and disposer registration
  share one rollback path); a `Symbol.for` wrapper marker so two module
  generations unwrap each other; and a secret charset restricted to printable
  ASCII minus comma/whitespace.

## Known compatibility issues

None observed on DSH `0.1.5-rc.2`. The plugin validates the interface shape and
the `requestRejection` semantics on every activation, so a future DSH that
changes either fails the profile loudly instead of silently removing
authentication. CI runs the real-DSH integration suite on every push/PR against
the pinned `0.1.5-rc.2`, and on a weekly schedule against
`@deepseek-ai/dsh@latest` as an early-warning signal.

### `0.2.1-alpha.3`

One integration expectation still fails on `0.2.1-alpha.3`; it fails on `0.2.3`
as well, so it was not introduced by this release.

- `missing secret -> non-zero exit` and `short secret -> non-zero exit` — the
  harness spawns the server and expects a failed plugin activation to abort the
  boot. On `0.2.1-alpha.3` the process was still running when the 90 s
  `spawnSync` timeout expired, so the run ends in `spawnSync … ETIMEDOUT` before
  those checks. The mechanism was not confirmed: it reads as the boot keeping
  the application running with the plugin absent, rather than a failed
  activation terminating the process. That is still fail-closed for
  authentication (no plugin means no secret promotion, so proxied requests
  answer `401`), but it is no longer fail-closed for process startup, and the
  harness expectation needs a decision. Re-check before relying on "a bad secret
  makes the profile fail to boot" as an operational guarantee.

Resolved in this release: `valid proxy header injects ownsHost bootstrap into
index HTML` failed because `0.2.1-alpha.3` renders the structured
`webserver/index-inject` row as JSON (`{"ownsHost":true}`), while the check
matched the older tapIndex form (`{ownsHost:true}`). The bootstrap is delivered
either way — a live index carried
`<script>globalThis["__DSH_TRANSPORT__"] = {"ownsHost":true}</script>` — and the
check now accepts both forms.
