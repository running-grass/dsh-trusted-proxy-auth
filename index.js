/**
 * dsh-trusted-proxy-auth — a host-only DeepSeek Harness plugin that adds a
 * second, independent authentication path for deployments fronted by a
 * trusted reverse proxy (for example Traefik terminating Keycloak OIDC).
 *
 * The plugin does not replace DSH's transport and does not implement any
 * OIDC/JWT logic. It decorates the live `ctx.connection` service so that a
 * request carrying a private shared secret — injected by the reverse proxy
 * only after it has authenticated the caller — is treated as authenticated,
 * while native DSH launch-token/cookie authentication keeps working as a
 * fallback for direct loopback/SSH access.
 *
 * Security model
 * --------------
 * The shared secret in `DSH_PROXY_AUTH_SECRET` is the entire assertion:
 * whoever knows it has already passed the upstream identity provider. The
 * plugin therefore:
 *
 * - refuses to activate when the secret is missing, empty, or shorter than
 *   {@link MIN_SECRET_BYTES};
 * - never turns an upstream DSH `403` (the Host/Origin/DNS-rebinding fence)
 *   into success;
 * - only converts an upstream `401` (native browser authentication) into a
 *   permit, and only when the secret matches;
 * - compares with `crypto.timingSafeEqual()` over UTF-8 bytes;
 * - rejects malformed, duplicated, array-valued, combined, or non-string
 *   header values;
 * - never logs the secret, the header value, cookies, or launch tokens.
 *
 * @module dsh-trusted-proxy-auth
 */

import { timingSafeEqual } from 'node:crypto'

/** Stable Cordis plugin name. */
export const name = 'trusted-proxy-auth'

/** Services required before the plugin activates. */
export const inject = ['connection']

/** Request header carrying the shared secret. Lowercase is canonical. */
export const HEADER_NAME = 'x-dsh-proxy-auth'

/** Environment variable holding the shared secret. Never logged. */
export const SECRET_ENV = 'DSH_PROXY_AUTH_SECRET'

/** Minimum accepted secret size in bytes. */
export const MIN_SECRET_BYTES = 32

/** Prefix for every log line and error message this plugin emits. */
const LOG_PREFIX = 'trusted-proxy-auth'

/**
 * Hidden back-reference installed on every wrapper, so a later activation can
 * unwrap a wrapper it finds instead of stacking on top of it, and so cleanup
 * can tell "our wrapper is still installed" from "someone else changed it".
 *
 * Registered with `Symbol.for` so two generations of this module loaded at the
 * same time (for example around a live reload) share the marker and unwrap each
 * other instead of stacking.
 */
const INNER = Symbol.for('dsh-trusted-proxy-auth.inner.v1')

/**
 * Accepted secret shape: printable ASCII other than comma.
 *
 * Excluding comma and whitespace makes the duplicate/joined-header guarantee
 * unambiguous, because HTTP header folding joins duplicates with `", "`, which
 * can then never equal the secret.
 */
const SECRET_PATTERN = /^[\x21-\x2b\x2d-\x7e]+$/

/**
 * Read the expected secret from the environment and enforce its minimum size.
 * The value itself is never included in the returned or thrown text.
 *
 * @returns the configured shared secret.
 * @throws when the variable is missing, empty, or too short.
 */
function readExpectedSecret() {
  const value = process.env[SECRET_ENV]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${LOG_PREFIX}: required environment variable ${SECRET_ENV} is missing or empty`)
  }
  if (Buffer.byteLength(value, 'utf8') < MIN_SECRET_BYTES) {
    throw new Error(
      `${LOG_PREFIX}: ${SECRET_ENV} must be at least ${MIN_SECRET_BYTES} bytes; `
        + 'generate one with `openssl rand -hex 48`',
    )
  }
  if (!SECRET_PATTERN.test(value)) {
    throw new Error(
      `${LOG_PREFIX}: ${SECRET_ENV} must contain only printable ASCII characters other than comma`,
    )
  }
  return value
}

/**
 * Extract one header value from either a Fetch `Headers` instance or a
 * node:http headers object.
 *
 * A value is returned only when exactly one string-valued key matches:
 * missing, array-valued, non-string, differently-cased duplicates, or any
 * other ambiguous shape fail closed.
 *
 * @param headers - request headers from a Fetch or node:http representation.
 * @param name - lowercase canonical header name.
 * @returns the header value, or `undefined` when it is absent or ambiguous.
 */
function headerValue(headers, name) {
  if (headers === null || headers === undefined) return undefined
  if (typeof Headers === 'function' && headers instanceof Headers) {
    const value = headers.get(name)
    return typeof value === 'string' ? value : undefined
  }
  if (typeof headers !== 'object') return undefined
  let value
  let matches = 0
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== name) continue
    matches += 1
    value = headers[key]
  }
  if (matches !== 1) return undefined
  return typeof value === 'string' ? value : undefined
}

/**
 * Constant-time comparison of a supplied header value against the secret.
 *
 * @param supplied - candidate value from the request header.
 * @param expected - configured shared secret.
 * @returns true only when both are strings of equal UTF-8 length.
 */
function secretMatches(supplied, expected) {
  if (typeof supplied !== 'string') return false
  const suppliedBytes = Buffer.from(supplied, 'utf8')
  const expectedBytes = Buffer.from(expected, 'utf8')
  return suppliedBytes.length === expectedBytes.length && timingSafeEqual(suppliedBytes, expectedBytes)
}

/**
 * Read a property through the object's own descriptors rather than through
 * property access.
 *
 * Cordis hands plugins a traceable proxy over the service instance, and that
 * proxy wraps every function it returns in a fresh shadow-method proxy. Using
 * descriptors reaches the real instance value, which is what lets the plugin
 * recognise its own wrapper and restore the object's original shape exactly.
 *
 * @param target - object or service proxy to inspect.
 * @param property - property name to read.
 * @returns the first `{ value, own }` descriptor found in the prototype chain,
 *   or `undefined` when the property does not exist.
 */
function readMethod(target, property) {
  let owner = target
  while (owner !== null && owner !== undefined) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, property)
    if (descriptor !== undefined) return { value: descriptor.value, own: owner === target }
    owner = Object.getPrototypeOf(owner)
  }
  return undefined
}

/**
 * Validate one upstream method and record what it originally was.
 *
 * When the current value is a wrapper this plugin installed earlier, the
 * wrapper's hidden back-reference is used instead, so repeated activation
 * cannot stack wrappers.
 *
 * @param connection - the `ctx.connection` service.
 * @param property - `requestRejection` or `authorizeIndex`.
 * @returns the effective original method and whether it was an own property.
 * @throws when the method is missing or not a function.
 */
function captureMethod(connection, property) {
  const found = readMethod(connection, property)
  if (found === undefined || typeof found.value !== 'function') {
    throw new Error(`${LOG_PREFIX}: unsupported DSH connection interface: ${property} is not a function`)
  }
  const decorated = found.value[INNER]
  if (decorated === undefined) return { property, original: found.value, originalWasOwn: found.own }
  return { property, original: decorated.original, originalWasOwn: decorated.originalWasOwn }
}

/**
 * Install one wrapper as an own property of the connection instance and
 * return a cleanup function.
 *
 * Installation is transactional: if the assignment takes effect but
 * verification fails, the mutation is undone before this function throws, so
 * no caller is ever left holding a half-installed wrapper.
 *
 * Cleanup is compare-and-swap: it restores only when this exact wrapper is
 * still installed, and it deletes the instance override when the method was
 * originally inherited from the prototype, so the object's shape returns to
 * exactly what upstream created.
 *
 * @param connection - the `ctx.connection` service.
 * @param captured - result of {@link captureMethod}.
 * @param wrapper - replacement function to install.
 * @returns a function restoring the original state.
 * @throws when the wrapper cannot be verified as installed.
 */
function installWrapper(connection, captured, wrapper) {
  Object.defineProperty(wrapper, INNER, {
    value: { original: captured.original, originalWasOwn: captured.originalWasOwn },
    enumerable: false,
  })
  const restore = () => {
    const current = readMethod(connection, captured.property)
    if (current === undefined || current.value !== wrapper) return
    if (captured.originalWasOwn) connection[captured.property] = captured.original
    else delete connection[captured.property]
  }
  const rollback = () => {
    if (captured.originalWasOwn) connection[captured.property] = captured.original
    else delete connection[captured.property]
  }
  const unsupported = () => new Error(
    `${LOG_PREFIX}: unsupported DSH connection interface: ${captured.property} could not be decorated`,
  )
  try {
    try {
      connection[captured.property] = wrapper
    } catch {
      throw unsupported()
    }
    const installed = readMethod(connection, captured.property)
    if (installed === undefined || installed.value !== wrapper) throw unsupported()
  } catch (error) {
    // Verification can fail after the write landed (for example if a future
    // proxy reports the value differently). Undo it here, because this
    // function cannot hand its restore callback back to the caller.
    try {
      rollback()
    } catch {
      // Best effort; activation still fails loudly below.
    }
    throw error
  }
  return restore
}

/**
 * Inline script tag injected into the index HTML when the request is verified
 * by the trusted proxy.
 *
 * It explicitly sets `globalThis.__DSH_TRANSPORT__.ownsHost = true`, signalling
 * to `@deepseek-ai/dsh-client-connection` that this session is host-privileged.
 * This instructs `@deepseek-ai/dsh-client-ui-settings` to use `'host'`
 * persistence instead of falling back to `'memory'`, unlocking the Models and
 * Plugins configuration panels for reverse-proxy deployments.
 */
export const BOOTSTRAP_SCRIPT = '<script>globalThis.__DSH_TRANSPORT__=Object.assign(globalThis.__DSH_TRANSPORT__||{},{ownsHost:true});</script>'

/**
 * Inject the bootstrap script into an HTML string or Buffer.
 *
 * @param html - HTML string, Buffer, or other body representation.
 * @returns the modified HTML in the original representation.
 */
export function injectBootstrapHtml(html) {
  if (typeof html === 'string') {
    if (/<head\b[^>]*>/i.test(html)) {
      return html.replace(/(<head\b[^>]*>)/i, `$1${BOOTSTRAP_SCRIPT}`)
    }
    if (/<\/head>/i.test(html)) {
      return html.replace(/(<\/head>)/i, `${BOOTSTRAP_SCRIPT}$1`)
    }
    return `${BOOTSTRAP_SCRIPT}${html}`
  }
  if (Buffer.isBuffer(html)) {
    const text = html.toString('utf8')
    const modified = injectBootstrapHtml(text)
    return Buffer.from(modified, 'utf8')
  }
  return html
}

/**
 * Decorate a response object to inject the bootstrap script when the index
 * HTML payload is written.
 *
 * Strips or ignores stale Content-Length headers so chunked encoding transfers
 * the augmented document cleanly without truncation.
 *
 * @param response - node:http ServerResponse or test stand-in.
 */
export function attachBootstrapInjection(response) {
  if (response === null || typeof response !== 'object') return

  let injected = false

  const applyInjection = (chunk) => {
    if (injected || chunk === undefined || chunk === null) return chunk
    injected = true
    if (typeof response.removeHeader === 'function') {
      response.removeHeader('content-length')
    }
    return injectBootstrapHtml(chunk)
  }

  const originalSetHeader = response.setHeader
  if (typeof originalSetHeader === 'function') {
    response.setHeader = function setHeader(name, value) {
      if (typeof name === 'string' && name.toLowerCase() === 'content-length') {
        return this
      }
      return originalSetHeader.call(this, name, value)
    }
  }

  const originalWriteHead = response.writeHead
  if (typeof originalWriteHead === 'function') {
    response.writeHead = function writeHead(statusCode, ...args) {
      for (const arg of args) {
        if (typeof arg === 'object' && arg !== null) {
          for (const key of Object.keys(arg)) {
            if (key.toLowerCase() === 'content-length') delete arg[key]
          }
        }
      }
      return originalWriteHead.call(this, statusCode, ...args)
    }
  }

  const originalWrite = response.write
  if (typeof originalWrite === 'function') {
    response.write = function write(chunk, encoding, callback) {
      const modified = applyInjection(chunk)
      return originalWrite.call(this, modified, encoding, callback)
    }
  }

  const originalEnd = response.end
  if (typeof originalEnd === 'function') {
    response.end = function end(chunk, encoding, callback) {
      let data = chunk
      let cb = callback
      let enc = encoding
      if (typeof data === 'function') {
        cb = data
        data = undefined
      } else if (typeof enc === 'function') {
        cb = enc
        enc = undefined
      }
      const modified = data !== undefined ? applyInjection(data) : data
      return originalEnd.call(this, modified, enc, cb)
    }
  }
}

/**
 * Answer the frontend index request with a deliberately minimal 403 body.
 *
 * @param response - the index response the caller would otherwise own.
 */
function writeForbidden(response) {
  response.writeHead(403, {
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  })
  response.end('forbidden')
}

/**
 * Emit one generic diagnostic line. Never called with request or secret data.
 *
 * @param ctx - owning Cordis context.
 * @param message - fixed, non-sensitive message text.
 */
function info(ctx, message) {
  ctx?.logger?.info?.(`${LOG_PREFIX}: ${message}`)
}

/**
 * Verify the Cordis context can register the cleanup disposer. Checked before
 * anything is decorated, so a context without `ctx.effect` never leaves the
 * connection half-wrapped.
 *
 * @param ctx - owning Cordis context.
 * @throws when `ctx.effect` is unavailable.
 */
function assertContext(ctx) {
  if (ctx === null || typeof ctx !== 'object' || typeof ctx.effect !== 'function') {
    throw new Error(`${LOG_PREFIX}: unsupported DSH context: ctx.effect is not available`)
  }
}

/**
 * Prove the `requestRejection` semantic contract this plugin's security model
 * depends on, using the original, undecorated method:
 *
 * - an unauthenticated loopback request is `401` (native browser auth failed);
 * - an untrusted Host is `403` (the Host/DNS-rebinding fence refused it);
 * - a cross-origin request is `403`;
 * - a cross-site request is `403`.
 *
 * A future DSH that keeps the methods but reorders or remaps these statuses
 * must fail activation, because promoting a `401` is only safe while `401`
 * exclusively means "native browser session missing". The probe requests carry
 * no credentials and have no side effects.
 *
 * @param connection - the `ctx.connection` service.
 * @param rejection - captured original `requestRejection`.
 * @throws when the observed statuses do not match the contract.
 */
function assertSemantics(connection, rejection) {
  const probe = (headers) => rejection.original.call(connection, { headers })
  const loopbackUnauthenticated = probe({ host: '127.0.0.1' })
  const untrustedHost = probe({ host: `dsh-proxy-probe-${process.pid}.invalid` })
  const crossOrigin = probe({ host: '127.0.0.1', origin: 'https://dsh-proxy-probe.invalid' })
  const crossSite = probe({ host: '127.0.0.1', 'sec-fetch-site': 'cross-site' })
  if (
    loopbackUnauthenticated !== 401
    || untrustedHost !== 403
    || crossOrigin !== 403
    || crossSite !== 403
  ) {
    throw new Error(
      `${LOG_PREFIX}: unsupported DSH requestRejection semantics: `
        + `loopback=${String(loopbackUnauthenticated)} untrustedHost=${String(untrustedHost)} `
        + `crossOrigin=${String(crossOrigin)} crossSite=${String(crossSite)}`,
    )
  }
}

/**
 * Verify the connection service exists and can carry an instance override.
 *
 * @param connection - value read from `ctx.connection`.
 * @throws when the service is absent or not extensible.
 */
function assertConnection(connection) {
  if (connection === null || typeof connection !== 'object') {
    throw new Error(`${LOG_PREFIX}: unsupported DSH connection interface: connection service unavailable`)
  }
  if (!Object.isExtensible(connection)) {
    throw new Error(`${LOG_PREFIX}: unsupported DSH connection interface: connection service is not extensible`)
  }
}

/**
 * Activate the trusted-proxy authentication path.
 *
 * The plugin decorates the single live connection instance; it never touches
 * `HostConnectionService.prototype` and never modifies files in the DSH
 * installation.
 *
 * @param ctx - Cordis context carrying the `connection` service.
 * @throws on missing configuration or an unsupported DSH connection interface.
 */
export function apply(ctx) {
  const expectedSecret = readExpectedSecret()
  assertContext(ctx)
  const connection = ctx.connection
  assertConnection(connection)

  const rejection = captureMethod(connection, 'requestRejection')
  const index = captureMethod(connection, 'authorizeIndex')
  assertSemantics(connection, rejection)

  const hasValidSecret = (request) => secretMatches(headerValue(request?.headers, HEADER_NAME), expectedSecret)

  const restores = []
  try {
    restores.push(installWrapper(connection, rejection, function requestRejection(request) {
      const result = rejection.original.call(connection, request)
      if (result === undefined || result === 403) return result
      if (result === 401 && hasValidSecret(request)) return undefined
      return result
    }))

    restores.push(installWrapper(connection, index, function authorizeIndex(request, response) {
      if (!hasValidSecret(request)) return index.original.call(connection, request, response)
      // The proxy established identity; the Host/Origin fence still applies.
      const result = rejection.original.call(connection, request)
      if (result === undefined || result === 401) {
        attachBootstrapInjection(response)
        return true
      }
      writeForbidden(response)
      return false
    }))

    ctx.effect(() => () => {
      for (const restore of [...restores].reverse()) restore()
    }, `${LOG_PREFIX}: connection decoration`)
  } catch (error) {
    // Roll back everything installed in this activation, including the case
    // where ctx.effect failed to register the disposer.
    for (const restore of [...restores].reverse()) {
      try {
        restore()
      } catch {
        // Best effort; the activation still fails loudly below.
      }
    }
    throw error
  }

  info(ctx, 'activated')
}
