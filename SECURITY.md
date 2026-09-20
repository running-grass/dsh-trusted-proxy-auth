# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's
[Security Advisories](https://github.com/lukepoo101/dsh-trusted-proxy-auth/security/advisories/new)
rather than in a public issue. Include a minimal reproduction and the DSH and
Node versions involved. You can expect an acknowledgement within a few days.

## What this plugin protects

`dsh-trusted-proxy-auth` exists so that a reverse proxy which already
authenticated a user can tell DSH "this request is authenticated" without DSH
implementing OIDC itself. The trust anchor is a single shared secret in
`DSH_PROXY_AUTH_SECRET`, sent in the `X-DSH-Proxy-Auth` request header.

The plugin converts exactly one upstream outcome — a `401` from DSH's native
browser authentication — into a permit, and only when the secret matches. It
never converts a `403` (DSH's Host/Origin/DNS-rebinding fence) into a permit.

## Threats considered

| Threat | Mitigation |
| --- | --- |
| Attacker guesses the secret | Minimum 32 bytes; compare with `crypto.timingSafeEqual()`; use `openssl rand -hex 48`. |
| Timing side channel on comparison | Constant-time comparison over UTF-8 bytes. |
| Header smuggling / ambiguity | Malformed, duplicated, array-valued, combined, or non-string header values fail authentication. The accepted secret charset excludes comma and whitespace, so a joined duplicate can never equal the secret. |
| DNS rebinding to the DSH port | The upstream Host/Origin fence still returns `403` even with a valid secret. |
| Cross-site requests from a malicious page | `Origin` mismatch and `Sec-Fetch-Site: cross-site` still return `403`. |
| Client-supplied identity headers (`X-Forwarded-User`, etc.) | Never read; only the shared secret is considered. |
| Secret sniffed on the proxy→DSH hop | The hop must sit on an isolated trusted network or be encrypted (TLS/mTLS or an encrypted overlay); it carries a bearer secret in clear text over plain HTTP. |
| A future DSH reorders the `403`/`401` statuses | Activation probes the original `requestRejection` and fails unless the trust fence still returns `403` and missing browser auth still returns `401`. |
| Secret leaking into logs | The plugin never logs the secret, header values, cookies, or tokens. |
| Secret leaking into configuration files | The secret is read only from the environment and is never a plugin config key. |
| Partial activation leaving a half-decorated service | Activation fails loudly and rolls back any partial decoration; the profile fails to boot. |
| Wrapper stacking across HMR/reload | Cleanup is compare-and-swap and unwraps prior wrappers, restoring the exact original object shape. |
| Silent loss of authentication after a DSH upgrade | The runtime interface is validated on every activation; a missing method fails the profile instead of degrading to "allow". |

## Security requirements on the deployment

The shared secret is **defence in depth, not a substitute for network
isolation**. An attacker who can reach the DSH port directly *and* knows the
secret bypasses native authentication. Therefore:

1. Firewall the DSH listen port so only the reverse proxy / cluster network can
   reach it.
2. Keep the proxy→DSH hop on an isolated trusted network segment or encrypt it
   (TLS, ideally mTLS, or an encrypted overlay such as WireGuard or
   VXLAN+IPsec). The header is a bearer secret; over plain HTTP any passive
   observer of that path can replay it. If isolation is the chosen control,
   record that assumption explicitly for the deployment.
3. Keep `DSH_PROXY_AUTH_SECRET` out of source control, YAML, and logs.
4. Ensure the proxy **overwrites** any inbound `X-DSH-Proxy-Auth` header so a
   client cannot inject its own value.
5. Serve the public entry point over TLS; the native DSH flow and the shared
   secret both assume a trusted transport.
6. Restrict read access to the environment file (for example `root:dsh 0640`).
7. Pin the installed plugin revision to a reviewed tag or commit, and re-run the
   smoke tests after a DSH upgrade.

## Scope

In scope: the plugin's authentication decision, header parsing, comparison,
lifecycle/restoration, and log hygiene.

Out of scope: DSH itself, Traefik, Keycloak, the reverse-proxy configuration,
and native DSH authentication — report those to their respective projects.
