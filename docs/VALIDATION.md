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

## Unit tests — 39 passed, 0 failed

```console
$ npm test
ℹ tests 39
ℹ suites 5
ℹ pass 39
ℹ fail 0
```

Coverage: `requestRejection` result mapping; `authorizeIndex` decision tree;
header parsing (exact, off-by-one, empty, missing, array, duplicate, joined,
`Headers` case-insensitivity); configuration failures (missing/empty/short
secret, missing service, missing methods, non-extensible service, undecoratable
method with rollback); lifecycle (install, exact-shape restore for inherited and
own methods, apply→cleanup→apply, overlapping activations, `authenticatedUrl`
untouched, no secret in logs).

## Integration tests — 35 passed, 0 failed

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

PASS: 35 passed, 0 failed
```

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

## Known compatibility issues

None observed on DSH `0.1.5-rc.2`. The plugin validates the interface on every
activation, so a future DSH that changes these methods fails the profile loudly
instead of silently removing authentication.
