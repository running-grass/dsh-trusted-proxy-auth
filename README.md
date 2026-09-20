# dsh-trusted-proxy-auth

A small, host-only [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(DSH) plugin that adds a **second, independent authentication path** for
deployments fronted by a trusted reverse proxy — for example
`Traefik → Keycloak OIDC → DSH`.

When the reverse proxy has already authenticated the caller, it injects a
private shared secret in a request header. DSH then treats that request as
authenticated. When the header is absent or wrong, DSH's native browser
launch-token/cookie authentication runs exactly as it always did, so direct
loopback/SSH access keeps working.

The plugin does **not** replace DSH's transport, patch any file inside the DSH
installation, or implement OIDC/JWT logic. It is an authentication-boundary
adapter and nothing more.

```
External browser
      │
      ▼
   Traefik ───────────► Keycloak OIDC
      │  (identity, login, roles, sessions)
      │
      │  injects:  X-DSH-Proxy-Auth: <private secret>
      ▼
     DSH ─────────────► trusted-proxy-auth
      │                  401 native browser auth + valid secret ──► permit
      │                  403 Host/Origin fence                   ──► still 403
      ▼
  native DSH transport, unchanged
```

```
SSH tunnel / direct access
      │  (no X-DSH-Proxy-Auth header)
      ▼
     DSH ─────────────► native ?token=… / cookie flow
```

## Status

- Tested against **DSH 0.1.5-rc.2** on **Node v24.21.0** (Node 20 and 22 are
  covered by CI).
- 50 unit tests and 35 live-DSH integration checks pass. See
  [`docs/VALIDATION.md`](docs/VALIDATION.md).
- A startup invariant re-proves DSH's `403`/`401` semantics on every boot, so a
  semantics change cannot silently turn the plugin into a bypass.
- No runtime dependencies — only `node:crypto`.
- No build step; plain ESM.

## Install

Generate a secret (96 hex characters is plenty):

```bash
openssl rand -hex 48
```

Add it to the environment the DSH service already reads (for example
`/etc/dsh/env`, `root:dsh`, mode `0640`):

```bash
SECRET="$(openssl rand -hex 48)"
printf 'DSH_PROXY_AUTH_SECRET=%s\n' "$SECRET" | sudo tee -a /etc/dsh/env >/dev/null
sudo chown root:dsh /etc/dsh/env
sudo chmod 0640 /etc/dsh/env
```

Install the plugin bundle into the Web profile and restart:

```bash
# from a Git checkout
dsh plugin --profile web add /path/to/dsh-trusted-proxy-auth

# or directly from this repository, pinned to the released tag
dsh plugin --profile web add git+https://github.com/lukepoo101/dsh-trusted-proxy-auth.git#v0.1.0

# an exact commit is equally acceptable for an authentication-boundary plugin
dsh plugin --profile web add git+https://github.com/lukepoo101/dsh-trusted-proxy-auth.git#<40-char-commit>

sudo systemctl restart deepseek-harness
```

Pin the tag or commit rather than following `main`: this plugin sits on the
authentication boundary, so the installed revision should be the one you
reviewed. Bump it deliberately when you upgrade.

Verify the composed profile contains the plugin **in addition to** the
Connection transport:

```bash
dsh web --dump-config | grep -E -A1 "connection|trusted-proxy-auth"
```

```yaml
- id: connection
  name: '@deepseek-ai/dsh-client-connection'
...
- id: trusted-proxy-auth
  name: dsh-trusted-proxy-auth
```

The plugin must also be told which public authority it serves. Add the final
public hostname to the DSH launch flags:

```bash
dsh web --trusted-host dsh.example.com
```

## Configuration

| Setting | Where | Notes |
| --- | --- | --- |
| `DSH_PROXY_AUTH_SECRET` | environment | **Required.** At least 32 bytes of printable ASCII other than comma. Never put it in YAML. |
| `X-DSH-Proxy-Auth` | request header | Injected by the reverse proxy only. Never sent to the browser. |

There are no plugin configuration keys. A missing, empty, too-short, or
malformed secret makes plugin activation fail loudly, which makes the profile
fail to boot — the server never starts half-authenticated. `openssl rand -hex 48`
(hex) and `openssl rand -base64 48` both satisfy the accepted character set;
excluding comma and whitespace is what makes the duplicate/joined-header
guarantee unambiguous.

## Behaviour

`requestRejection()` (used by `/api` and the WebSocket mux):

| Upstream result | Secret | Result |
| --- | --- | --- |
| `403` (Host/Origin/DNS-rebinding fence) | valid | `403` |
| `403` | missing/wrong | `403` |
| `401` (native browser auth) | valid | permitted |
| `401` | missing/wrong | `401` |
| `undefined` (native auth already passed) | any | permitted |

`authorizeIndex()` (the frontend `/` route):

| Secret | Host fence | Result |
| --- | --- | --- |
| missing/wrong | — | delegated to the original native flow |
| valid | `403` | `403 forbidden`, response ended |
| valid | `401` or `undefined` | index served |

The plugin is **never** allowed to turn an upstream `403` into success, so
DNS-rebinding and cross-site protections keep working even with a correct
secret.

## Reverse-proxy contract

Traefik (or any equivalent proxy) must:

1. Require successful Keycloak OIDC authentication.
2. Remove or overwrite any inbound `X-DSH-Proxy-Auth` value.
3. Add the private `X-DSH-Proxy-Auth` value only on the authenticated DSH route.
4. Forward that header on normal HTTP requests **and** WebSocket upgrades.
5. Preserve the original public `Host`.
6. Preserve browser `Origin` behaviour.

Setting the header on the router satisfies (2) and (3) at once, because
Traefik overwrites the incoming value:

```yaml
# Traefik dynamic configuration (illustrative)
http:
  middlewares:
    dsh-proxy-auth:
      headers:
        customRequestHeaders:
          X-DSH-Proxy-Auth: '<private secret>'
  routers:
    dsh:
      rule: 'Host(`dsh.example.com`)'
      entryPoints: [websecure]
      middlewares: [dsh-proxy-auth]
      service: dsh
  services:
    dsh:
      loadBalancer:
        servers:
          - url: 'http://10.0.20.103:3081'
```

The DSH service must include the final public authority in `--trusted-host`:

```bash
--trusted-host dsh.example.com
```

**The proxy→DSH hop carries the secret in clear text.** The example above
forwards to `http://10.0.20.103:3081`; anything that can passively observe that
path can recover `X-DSH-Proxy-Auth` and replay it. Firewalling blocks unwanted
connections but does not prevent sniffing, so do one of the following:

- keep the hop on an isolated trusted network segment or encrypted overlay
  (WireGuard, VXLAN+IPsec) **and document that as an explicit deployment
  assumption**; or
- terminate TLS — ideally mTLS — between the proxy and DSH.

**Network restriction is still required.** The shared secret is
defence-in-depth, not a replacement for a firewall: anyone who can reach the
DSH port directly *and* knows the secret bypasses native authentication.
Firewall the VM/LAN port so only the Kubernetes/Traefik network can reach it.

## Operations

**Rotate the secret.** Generate a new value, update `/etc/dsh/env` and the
Traefik middleware, then restart DSH. Requests in flight during the change fall
back to native authentication.

**Emergency/admin access.** The native authenticated URL printed by `dsh web`
(`http://127.0.0.1:3080/?token=…`) is untouched. Over an SSH tunnel you can
always log in with DSH's own browser session, independent of Traefik.

**Upgrade DSH.** The plugin validates the runtime interface on every start:

```bash
sudo npm install -g @deepseek-ai/dsh@latest
sudo systemctl restart deepseek-harness
systemctl status deepseek-harness
journalctl -u deepseek-harness -n 100
```

If a future DSH renames or removes `requestRejection` / `authorizeIndex`, or
changes their `403`/`401` semantics, the plugin refuses to activate and the
profile fails to boot, rather than silently dropping authentication.

**Uninstall.**

```bash
dsh plugin --profile web remove dsh-trusted-proxy-auth
sudo systemctl restart deepseek-harness
```

## Security properties

- The entire assertion is "the caller knows a private secret only the proxy
  and DSH share". No `X-Forwarded-User`, email, username, role, or JWT claim is
  ever treated as authentication.
- Comparison uses `crypto.timingSafeEqual()` over UTF-8 bytes.
- A malformed, duplicated, array-valued, combined, or non-string header fails
  authentication.
- The secret, the header value, cookies, and launch tokens are never logged.
- The secret must be printable ASCII without comma or whitespace, so a
  duplicate or joined HTTP header value can never equal it.
- Every activation probes the original `requestRejection` and refuses to start
  unless `403` still means the Host/Origin trust fence and `401` still means
  "native browser session missing". A DSH upgrade that changes those semantics
  fails the profile instead of quietly becoming a bypass.
- The plugin decorates only the single live `ctx.connection` instance; it never
  touches `HostConnectionService.prototype` and never writes inside the DSH
  installation.
- Activation is fail-closed and transactional: a bad configuration stops the
  profile from starting, any partial decoration (including a write that failed
  verification, or a disposer that failed to register) is rolled back, and
  unexpected runtime exceptions preserve native authentication or fail the
  request — never a silent `true`.

See [`SECURITY.md`](SECURITY.md) for the full threat model.

## Testing

```bash
npm test                 # 50 unit tests, node:test, no dependencies
npm run test:integration # 35 live checks against a real DSH server
```

`npm run test:integration` creates a throwaway `DSH_HOME`, derives a private
profile from the shipped `web` template, installs this checkout, boots the real
Harness Web server on a free loopback port, and exercises the HTTP index route,
`/api`, the `/api/remote.mux` WebSocket upgrade, native token/cookie login,
fail-closed startup, and log hygiene. It never touches an existing Harness home
or a running server. Use `KEEP_TMP=1` to keep the temporary home for
inspection.

CI has two tracks: the unit suite on Node 20/22/24 and the real-DSH integration
suite run on every push and pull request against the pinned `0.1.5-rc.2`, while
a scheduled job runs the same integration suite against
`@deepseek-ai/dsh@latest` as an early-warning signal for upstream drift.

## Runtime compatibility

DSH 0.1.5-rc.2 hands plugins a Cordis **traceable proxy** for `ctx.connection`,
not the raw service instance. Reading a method through that proxy returns a
fresh shadow-method proxy on every access, so reference-equality checks are not
stable. The plugin therefore captures and restores methods through
`Object.getOwnPropertyDescriptor`, which reaches the real instance:

- `ctx.connection` is a proxy; `Object.isExtensible(ctx.connection)` is `true`.
- `requestRejection`, `authorizeIndex`, and `authenticatedUrl` are inherited,
  writable, non-enumerable prototype methods (`own=false`).
- Assignment through the proxy creates an own property on the raw instance;
  `delete` through the proxy removes it and exposes the prototype method again.

Cleanup is compare-and-swap and unwraps any wrapper it finds, so repeated or
overlapping activation cannot stack wrappers and the instance returns exactly to
its original shape (own property deleted when the method was inherited). The
wrapper marker is a registered (`Symbol.for`) symbol, so two generations of the
module loaded at once still recognise each other. See `docs/VALIDATION.md` for
the raw probe output.

Shape is not the whole contract, so activation also asserts DSH's **semantics**
against the original method: an unauthenticated loopback request must be `401`,
an untrusted Host must be `403`, and cross-origin/cross-site requests must be
`403`. If a future DSH ever authenticated before applying the trust fence — so
an untrusted Host returned `401` — promoting that `401` would no longer be safe,
and the plugin refuses to start.

## Non-goals

This plugin deliberately contains none of the following:

- Keycloak libraries, JWT validation, OAuth/OIDC discovery
- user management, login pages, sessions, TOTP, roles, permission mapping
- browser-side code
- inspection of the Keycloak access token, or passing it into DSH
- exposure of the shared secret to the browser

Traefik and Keycloak own those concerns. This plugin is an
authentication-boundary adapter only.

## License

[MIT](LICENSE)
