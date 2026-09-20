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
 */
const INNER = Symbol('trusted-proxy-auth.inner')

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
  try {
    connection[captured.property] = wrapper
  } catch {
    throw new Error(
      `${LOG_PREFIX}: unsupported DSH connection interface: ${captured.property} could not be decorated`,
    )
  }
  const installed = readMethod(connection, captured.property)
  if (installed === undefined || installed.value !== wrapper) {
    throw new Error(
      `${LOG_PREFIX}: unsupported DSH connection interface: ${captured.property} could not be decorated`,
    )
  }
  return () => {
    const current = readMethod(connection, captured.property)
    if (current === undefined || current.value !== wrapper) return
    if (captured.originalWasOwn) connection[captured.property] = captured.original
    else delete connection[captured.property]
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
  const connection = ctx?.connection
  assertConnection(connection)

  const rejection = captureMethod(connection, 'requestRejection')
  const index = captureMethod(connection, 'authorizeIndex')

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
      if (result === undefined || result === 401) return true
      writeForbidden(response)
      return false
    }))
  } catch (error) {
    for (const restore of restores.reverse()) restore()
    throw error
  }

  ctx.effect(() => () => {
    for (const restore of [...restores].reverse()) restore()
  }, `${LOG_PREFIX}: connection decoration`)

  info(ctx, 'activated')
}
