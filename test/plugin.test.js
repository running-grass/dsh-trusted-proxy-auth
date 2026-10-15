/**
 * Unit tests for dsh-trusted-proxy-auth.
 *
 * These tests exercise the plugin against a fake Cordis context and a fake
 * `connection` service that mirrors DSH's current `requestRejection`
 * semantics. The real-DSH integration suite lives in `test/integration/run.mjs`
 * and proves the same behaviour against a running Harness HTTP server.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'

import {
  BOOTSTRAP_SCRIPT,
  HEADER_NAME,
  MIN_SECRET_BYTES,
  SECRET_ENV,
  apply,
  injectBootstrapHtml,
  normalizeToLoopback,
  resolveWebServer,
} from '../index.js'

/** A known-good secret of exactly 48 bytes. */
const SECRET = 'unit-test-secret-'.padEnd(48, '0')

/** A loopback authority the fake treats as trusted, like DSH does. */
const LOOPBACK_HOST = '127.0.0.1'

/** Cookie marker that makes a fake request look natively authenticated. */
const NATIVE_SESSION = 'dsh-fake-session'

/** The registered marker a wrapper from any generation of this module carries. */
const INNER = Symbol.for('dsh-trusted-proxy-auth.inner.v1')

assert.ok(Buffer.byteLength(SECRET) >= MIN_SECRET_BYTES)

/** Restore the process environment after every test. */
const ORIGINAL_SECRET = process.env[SECRET_ENV]
afterEach(() => {
  if (ORIGINAL_SECRET === undefined) delete process.env[SECRET_ENV]
  else process.env[SECRET_ENV] = ORIGINAL_SECRET
})

/** Minimal Cordis-like context: synchronous effect collection plus a logger. */
function fakeContext(connection, options = {}) {
  const log = []
  const disposers = []
  const events = new Map()
  const exactMap = new Map()
  const prefixesMap = new Map()
  const webServer = options.webServer ?? {
    port: 3080,
    taps: [],
    routes: [],
    exact: exactMap,
    prefixes: prefixesMap,
    tapIndex(transform) {
      this.taps.push(transform)
      return () => {
        const idx = this.taps.indexOf(transform)
        if (idx !== -1) this.taps.splice(idx, 1)
      }
    },
    register(route) {
      this.routes.push(route)
      const table = route.kind === 'prefix' || route.prefix ? this.prefixes : this.exact
      const key = route.path ?? route.prefix
      table.set(key, route)
      return () => {
        const idx = this.routes.indexOf(route)
        if (idx !== -1) this.routes.splice(idx, 1)
        table.delete(key)
      }
    },
    match(pathname) {
      const exact = this.exact.get(pathname)
      if (exact !== undefined) return exact
      for (const [prefix, route] of this.prefixes) {
        if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return route
      }
      return undefined
    },
    async handle(req, res) {
      const url = req.url ?? '/'
      const pathname = new URL(url, 'http://x').pathname
      const route = this.match(pathname)
      if (route !== undefined) {
        return await route.handler(req, res)
      }
      // Also fallback to iterating routes for custom test routes
      const method = (req.method ?? 'GET').toUpperCase()
      for (const r of this.routes) {
        const pathMatches = r.path ? r.path === pathname || r.path === url : (r.prefix ? pathname.startsWith(r.prefix) || url.startsWith(r.prefix) : false)
        const methodMatches = !r.method || r.method.toUpperCase() === method
        if (pathMatches && methodMatches) {
          return await r.handler(req, res)
        }
      }
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found')
    },
  }
  return {
    connection,
    webServer: options.noWebServer ? undefined : webServer,
    log,
    events,
    logger: {
      info: (message) => log.push(`info ${String(message)}`),
      warn: (message) => log.push(`warn ${String(message)}`),
      error: (message) => log.push(`error ${String(message)}`),
    },
    on(event, listener) {
      if (!events.has(event)) events.set(event, [])
      events.get(event).push(listener)
      return () => {
        const list = events.get(event)
        const idx = list.indexOf(listener)
        if (idx !== -1) list.splice(idx, 1)
      }
    },
    emit(event, ...args) {
      const list = events.get(event) ?? []
      for (const fn of list) fn(...args)
    },
    effect(execute) {
      const disposer = execute()
      if (typeof disposer === 'function') disposers.push(disposer)
      return disposer
    },
    dispose() {
      while (disposers.length > 0) disposers.pop()()
    },
  }
}

/** Minimal node:http ServerResponse stand-in. */
function fakeResponse() {
  const headersMap = new Map()
  return {
    status: undefined,
    headers: undefined,
    body: undefined,
    ended: false,
    writeHead(status, headers) {
      this.status = status
      this.headers = headers
      return this
    },
    setHeader(name, value) {
      headersMap.set(String(name).toLowerCase(), value)
      return this
    },
    getHeader(name) {
      return headersMap.get(String(name).toLowerCase())
    },
    hasHeader(name) {
      return headersMap.has(String(name).toLowerCase())
    },
    removeHeader(name) {
      headersMap.delete(String(name).toLowerCase())
    },
    write(chunk) {
      const str = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)
      this.body = (this.body ?? '') + str
      return true
    },
    end(body) {
      if (body !== undefined) {
        const str = Buffer.isBuffer(body) ? body.toString('utf8') : String(body)
        this.body = (this.body ?? '') + str
      }
      this.ended = true
      return this
    },
  }
}

/** Read a header from a Fetch `Headers` instance or a plain object. */
function readHeader(headers, name) {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers?.[name]
  return typeof value === 'string' ? value : undefined
}

/** Whether an admission result refuses the request rather than naming a Peer. */
function isRejection(result) {
  return result !== null && typeof result === 'object' && 'rejection' in result
}

/**
 * Connection service whose methods live on the prototype, as upstream does.
 *
 * The default `evaluate` mirrors DSH's trust-and-credential decision: the
 * Host/Origin fence returns 403, and missing native browser authentication
 * returns 401. Pass `semantics` to simulate a future DSH that changed that
 * mapping.
 *
 * Admission follows DSH 0.2.1-alpha.3: `admit` owns the decision and
 * `requestRejection` delegates to it, so a caller that admits through `admit`
 * or `admitConnection` never reaches the `requestRejection` decoration. A host
 * without those methods is covered by the plugin's optional decoration.
 */
class FakeConnection {
  constructor(options = {}) {
    this.semantics = options.semantics
    this.rejectionCalls = 0
    this.indexCalls = 0
    this.admitCalls = 0
    this.connectionAdmitCalls = 0
    this.browserPeer = { id: 'browser-peer' }
  }

  requestRejection(request) {
    this.rejectionCalls += 1
    const admission = this.admit(request)
    return isRejection(admission) ? admission.rejection : undefined
  }

  admit(request) {
    this.admitCalls += 1
    const status = typeof this.semantics === 'function' ? this.semantics(request) : this.evaluate(request)
    return status === undefined ? { peer: this.browserPeer } : { rejection: status }
  }

  admitConnection(request) {
    this.connectionAdmitCalls += 1
    const admission = this.admit(request)
    if (isRejection(admission)) return admission
    return { ...admission, release: () => Promise.resolve() }
  }

  /** DSH trust-and-credential semantics, reusable by custom `semantics` overrides. */
  evaluate(request) {
    const headers = request?.headers ?? {}
    const host = readHeader(headers, 'host')
    if (host === undefined) return 403
    let hostUrl
    try {
      hostUrl = new URL(`http://${host}`)
    } catch {
      return 403
    }
    const loopback = hostUrl.hostname === LOOPBACK_HOST
      || hostUrl.hostname === 'localhost'
      || hostUrl.hostname === '[::1]'
    if (!loopback && hostUrl.host !== 'dsh.test.example') return 403
    if (readHeader(headers, 'sec-fetch-site') === 'cross-site') return 403
    const origin = readHeader(headers, 'origin')
    if (origin !== undefined) {
      try {
        if (new URL(origin).host !== hostUrl.host) return 403
      } catch {
        return 403
      }
    }
    return readHeader(headers, 'cookie') === NATIVE_SESSION ? undefined : 401
  }

  authorizeIndex(request, response) {
    this.indexCalls += 1
    response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
    response.end('unauthorized')
    return false
  }

  authenticatedUrl(baseUrl) {
    return `${baseUrl}?token=launch`
  }
}

/**
 * Activate the plugin against a fake connection, then reset call counters so a
 * test observes only the requests it issues itself (activation runs the
 * semantic probe).
 */
function activate(connection, secret = SECRET, options = {}) {
  process.env[SECRET_ENV] = secret
  const ctx = fakeContext(connection, options)
  apply(ctx)
  connection.rejectionCalls = 0
  connection.indexCalls = 0
  connection.admitCalls = 0
  connection.connectionAdmitCalls = 0
  return ctx
}

/** Run one request through the decorated `requestRejection`. */
function rejectWith(headers, options = {}) {
  const connection = options.connection ?? new FakeConnection()
  const ctx = activate(connection, options.secret)
  const requestHeaders = headers === undefined
    ? undefined
    : headers instanceof Headers
      ? headers
      : { host: LOOPBACK_HOST, ...headers }
  const result = connection.requestRejection({ headers: requestHeaders })
  return { result, connection, ctx }
}

describe('requestRejection', () => {
  const cases = [
    {
      title: 'untrusted Host (403) with a valid secret stays 403',
      host: 'evil.example',
      header: SECRET,
      expected: 403,
    },
    {
      title: 'untrusted Host (403) with a wrong secret stays 403',
      host: 'evil.example',
      header: 'z'.repeat(48),
      expected: 403,
    },
    {
      title: 'native 401 with a valid secret is permitted',
      host: LOOPBACK_HOST,
      header: SECRET,
      expected: undefined,
    },
    {
      title: 'native 401 with a missing header stays 401',
      host: LOOPBACK_HOST,
      header: undefined,
      expected: 401,
    },
    {
      title: 'native 401 with a wrong secret stays 401',
      host: LOOPBACK_HOST,
      header: 'w'.repeat(48),
      expected: 401,
    },
    {
      title: 'already authenticated (undefined) with no header stays undefined',
      native: true,
      host: LOOPBACK_HOST,
      header: undefined,
      expected: undefined,
    },
    {
      title: 'already authenticated (undefined) with a valid secret stays undefined',
      native: true,
      host: LOOPBACK_HOST,
      header: SECRET,
      expected: undefined,
    },
  ]

  for (const testCase of cases) {
    it(testCase.title, () => {
      const connection = new FakeConnection()
      const ctx = activate(connection)
      const headers = { host: testCase.host }
      if (testCase.native === true) headers.cookie = NATIVE_SESSION
      if (testCase.header !== undefined) headers[HEADER_NAME] = testCase.header
      assert.equal(connection.requestRejection({ headers }), testCase.expected)
      assert.equal(connection.rejectionCalls, 1, 'the upstream method runs exactly once')
      ctx.dispose()
    })
  }

  it('passes an unexpected upstream status through unchanged', () => {
    const connection = new FakeConnection()
    // Correct semantics for the startup probe (no proxy header), an unexpected
    // status otherwise.
    connection.semantics = (request) => (
      readHeader(request?.headers, HEADER_NAME) === undefined ? connection.evaluate(request) : 418
    )
    const ctx = activate(connection)
    assert.equal(
      connection.requestRejection({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }),
      418,
    )
    ctx.dispose()
  })
})

describe('admit', () => {
  const cases = [
    {
      title: 'untrusted Host (403) with a valid secret stays 403',
      host: 'evil.example',
      header: SECRET,
      rejection: 403,
    },
    {
      title: 'native 401 with a valid secret is admitted as the shared browser Peer',
      header: SECRET,
      peer: true,
    },
    {
      title: 'native 401 with a missing header stays 401',
      header: undefined,
      rejection: 401,
    },
    {
      title: 'native 401 with a wrong secret stays 401',
      header: 'w'.repeat(48),
      rejection: 401,
    },
    {
      title: 'already authenticated (undefined) is left to upstream',
      native: true,
      header: undefined,
      peer: true,
    },
    {
      title: 'already authenticated (undefined) with a valid secret is still admitted',
      native: true,
      header: SECRET,
      peer: true,
    },
  ]

  for (const testCase of cases) {
    it(testCase.title, () => {
      const connection = new FakeConnection()
      const ctx = activate(connection)
      const headers = { host: testCase.host ?? LOOPBACK_HOST }
      if (testCase.native === true) headers.cookie = NATIVE_SESSION
      if (testCase.header !== undefined) headers[HEADER_NAME] = testCase.header
      const result = connection.admit({ headers })
      assert.equal(connection.admitCalls, 1, 'the upstream method runs exactly once')
      if (testCase.peer === true) {
        assert.equal(isRejection(result), false, 'the request is admitted')
        assert.equal(result.peer, connection.browserPeer, 'the shared browser Peer speaks for it')
      } else {
        assert.equal(result.rejection, testCase.rejection)
      }
      ctx.dispose()
    })
  }

  it('leaves a host without admit undecorated', () => {
    const reference = new FakeConnection()
    const connection = {
      requestRejection: (request) => reference.evaluate(request),
      authorizeIndex() {},
    }
    const ctx = activate(connection)
    assert.equal(Object.hasOwn(connection, 'admit'), false)
    assert.equal(Object.hasOwn(connection, 'requestRejection'), true, 'the other decorations stay')
    ctx.dispose()
  })
})

describe('admitConnection', () => {
  it('admits a secret-bearing 401 with the shared browser Peer and a no-op release', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const result = connection.admitConnection({
      headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET },
    })
    assert.equal(isRejection(result), false, 'the upgrade is admitted')
    assert.equal(result.peer, connection.browserPeer)
    assert.equal(connection.connectionAdmitCalls, 1, 'the upstream method runs exactly once')
    assert.equal(typeof result.release, 'function')
    // The shared browser Peer owns no socket, so releasing is idempotent.
    await result.release()
    await result.release()
    ctx.dispose()
  })

  it('keeps an untrusted Host at 403 even with a valid secret', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    assert.deepEqual(
      connection.admitConnection({ headers: { host: 'evil.example', [HEADER_NAME]: SECRET } }),
      { rejection: 403 },
    )
    ctx.dispose()
  })

  it('keeps a 401 without the secret', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    assert.deepEqual(
      connection.admitConnection({ headers: { host: LOOPBACK_HOST } }),
      { rejection: 401 },
    )
    ctx.dispose()
  })

  it('leaves a host without admitConnection undecorated', () => {
    const reference = new FakeConnection()
    const connection = {
      requestRejection: (request) => reference.evaluate(request),
      admit(request) {
        const status = reference.evaluate(request)
        return status === undefined ? { peer: connection.browserPeer } : { rejection: status }
      },
      authorizeIndex() {},
      browserPeer: { id: 'browser-peer' },
    }
    const ctx = activate(connection)
    assert.equal(Object.hasOwn(connection, 'admit'), true, 'the present method stays decorated')
    assert.equal(Object.hasOwn(connection, 'admitConnection'), false)
    ctx.dispose()
  })
})

describe('authorizeIndex', () => {
  it('valid secret + trust 401 -> true without calling the original authorizeIndex', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response), true)
    assert.equal(connection.indexCalls, 0)
    assert.equal(response.ended, false)
    ctx.dispose()
  })

  it('valid secret + trust undefined -> true', () => {
    const connection = new FakeConnection()
    activate(connection)
    assert.equal(
      connection.authorizeIndex(
        { headers: { host: LOOPBACK_HOST, cookie: NATIVE_SESSION, [HEADER_NAME]: SECRET } },
        fakeResponse(),
      ),
      true,
    )
  })

  it('valid secret + trust 403 -> false, HTTP 403, response ended', () => {
    const connection = new FakeConnection()
    activate(connection)
    const response = fakeResponse()
    assert.equal(
      connection.authorizeIndex({ headers: { host: 'evil.example', [HEADER_NAME]: SECRET } }, response),
      false,
    )
    assert.equal(response.status, 403)
    assert.equal(response.headers['cache-control'], 'no-store')
    assert.equal(response.headers['content-type'], 'text/plain; charset=utf-8')
    assert.equal(response.body, 'forbidden')
    assert.equal(response.ended, true)
  })

  it('missing secret delegates to the original authorizeIndex', () => {
    const connection = new FakeConnection()
    activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { host: LOOPBACK_HOST } }, response), false)
    assert.equal(connection.indexCalls, 1)
    assert.equal(response.status, 401)
  })

  it('wrong secret delegates to the original authorizeIndex', () => {
    const connection = new FakeConnection()
    activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: 'nope' } }, response), false)
    assert.equal(connection.indexCalls, 1)
    assert.equal(response.status, 401)
  })

  it('valid secret permits index access and leaves response methods unwrapped', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    const origEnd = response.end
    const origWrite = response.write
    const origWriteHead = response.writeHead
    assert.equal(
      connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response),
      true,
    )
    assert.equal(response.end, origEnd)
    assert.equal(response.write, origWrite)
    assert.equal(response.writeHead, origWriteHead)
    assert.equal(response.ended, false)
    ctx.dispose()
  })

  it('registers webServer.tapIndex transform which injects ownsHost script', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    assert.equal(ctx.webServer.taps.length, 1)
    const transform = ctx.webServer.taps[0]
    const html = '<!doctype html><html><head><meta charset="utf-8"></head><body><h1>DSH</h1></body></html>'
    const result = transform(html)
    assert.ok(result.includes(BOOTSTRAP_SCRIPT))
    assert.ok(result.includes('<head>' + BOOTSTRAP_SCRIPT))
    assert.ok(result.includes('ownsHost:true'))
    ctx.dispose()
    assert.equal(ctx.webServer.taps.length, 0)
  })

  it('tapIndex transform handles Buffer input and bare fragments', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const transform = ctx.webServer.taps[0]
    const buf = Buffer.from('<html><head></head><body></body></html>', 'utf8')
    const resultBuf = transform(buf)
    assert.ok(resultBuf.toString('utf8').includes(BOOTSTRAP_SCRIPT))

    const fragment = '<div>Fragment</div>'
    const resultFrag = transform(fragment)
    assert.ok(resultFrag.includes(BOOTSTRAP_SCRIPT))
    ctx.dispose()
  })

  it('subscribes to webserver/index-inject and pushes global ownsHost row', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const table = []
    ctx.emit('webserver/index-inject', table)
    assert.equal(table.length, 1)
    assert.deepEqual(table[0], {
      kind: 'global',
      name: '__DSH_TRANSPORT__',
      value: { ownsHost: true },
    })
    ctx.dispose()
    const tableAfter = []
    ctx.emit('webserver/index-inject', tableAfter)
    assert.equal(tableAfter.length, 0)
  })

  it('activates cleanly and authorizes when webServer is absent', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection, SECRET, { noWebServer: true })
    const response = fakeResponse()
    assert.equal(
      connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response),
      true,
    )
    ctx.dispose()
  })

  it('missing secret does not authorize index', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { host: LOOPBACK_HOST } }, response), false)
    assert.equal(response.status, 401)
    assert.equal(response.body, 'unauthorized')
    ctx.dispose()
  })
})

describe('bootstrap HTML injection', () => {
  it('injects script immediately after <head>', () => {
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body></body></html>'
    const result = injectBootstrapHtml(html)
    assert.equal(
      result,
      '<!DOCTYPE html><html><head>' + BOOTSTRAP_SCRIPT + '<meta charset="utf-8"></head><body></body></html>',
    )
  })

  it('injects script immediately after <head> with attributes', () => {
    const html = '<html><head lang="en"><title>DSH</title></head></html>'
    const result = injectBootstrapHtml(html)
    assert.equal(
      result,
      '<html><head lang="en">' + BOOTSTRAP_SCRIPT + '<title>DSH</title></head></html>',
    )
  })

  it('injects script before </head> when opening head is absent', () => {
    const html = '<html><title>No Open</title></head><body></body></html>'
    const result = injectBootstrapHtml(html)
    assert.equal(
      result,
      '<html><title>No Open</title>' + BOOTSTRAP_SCRIPT + '</head><body></body></html>',
    )
  })

  it('prepends script when head tags are completely absent', () => {
    const html = '<div>Bare Fragment</div>'
    const result = injectBootstrapHtml(html)
    assert.equal(result, BOOTSTRAP_SCRIPT + '<div>Bare Fragment</div>')
  })

  it('handles Buffer input correctly', () => {
    const buf = Buffer.from('<html><head></head><body></body></html>', 'utf8')
    const result = injectBootstrapHtml(buf)
    assert.ok(Buffer.isBuffer(result))
    assert.ok(result.toString('utf8').includes(BOOTSTRAP_SCRIPT))
  })

  it('does not duplicate injection when already present', () => {
    const html = '<html><head>' + BOOTSTRAP_SCRIPT + '<title>DSH</title></head></html>'
    const result = injectBootstrapHtml(html)
    assert.equal(result, html)
  })
})

describe('header parsing', () => {
  it('accepts the exact secret', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: SECRET }).result, undefined)
  })

  it('rejects a one-character difference', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: `${SECRET.slice(0, -1)}1` }).result, 401)
  })

  it('rejects an empty value', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: '' }).result, 401)
  })

  it('rejects a missing value', () => {
    assert.equal(rejectWith({}).result, 401)
  })

  it('fails closed when the request carries no headers at all', () => {
    assert.equal(rejectWith(undefined).result, 403)
  })

  it('rejects an array-valued header', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: [SECRET] }).result, 401)
  })

  it('rejects a non-string value', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: 42 }).result, 401)
  })

  it('rejects duplicated header keys regardless of case', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: SECRET, 'X-DSH-Proxy-Auth': SECRET }).result, 401)
  })

  it('rejects a node-joined duplicated header', () => {
    assert.equal(rejectWith({ [HEADER_NAME]: `${SECRET}, ${SECRET}` }).result, 401)
  })

  it('accepts a Fetch Headers instance found case-insensitively', () => {
    const headers = new Headers({ Host: LOOPBACK_HOST, 'X-DSH-Proxy-Auth': SECRET })
    assert.equal(rejectWith(headers).result, undefined)
  })

  it('rejects a Fetch Headers instance with a different value', () => {
    const headers = new Headers({ Host: LOOPBACK_HOST, 'X-DSH-Proxy-Auth': 'wrong' })
    assert.equal(rejectWith(headers).result, 401)
  })
})

describe('configuration', () => {
  const connection = () => new FakeConnection()

  it('fails when the secret is missing', () => {
    delete process.env[SECRET_ENV]
    assert.throws(() => apply(fakeContext(connection())), /required environment variable/)
  })

  it('fails when the secret is empty', () => {
    process.env[SECRET_ENV] = ''
    assert.throws(() => apply(fakeContext(connection())), /missing or empty/)
  })

  it('fails when the secret is shorter than the minimum', () => {
    process.env[SECRET_ENV] = 'x'.repeat(MIN_SECRET_BYTES - 1)
    assert.throws(() => apply(fakeContext(connection())), /at least 32 bytes/)
  })

  it('fails when the secret contains a comma', () => {
    process.env[SECRET_ENV] = `${'a'.repeat(MIN_SECRET_BYTES - 1)},`
    assert.throws(() => apply(fakeContext(connection())), /printable ASCII characters other than comma/)
  })

  it('fails when the secret contains whitespace', () => {
    process.env[SECRET_ENV] = `${'a'.repeat(MIN_SECRET_BYTES - 1)} `
    assert.throws(() => apply(fakeContext(connection())), /printable ASCII characters other than comma/)
  })

  it('fails when the secret contains a non-ASCII character', () => {
    process.env[SECRET_ENV] = `${'a'.repeat(MIN_SECRET_BYTES - 1)}é`
    assert.throws(() => apply(fakeContext(connection())), /printable ASCII characters other than comma/)
  })

  it('accepts a base64-style secret', () => {
    process.env[SECRET_ENV] = 'aB0+/='.repeat(6)
    const ctx = fakeContext(connection())
    apply(ctx)
    ctx.dispose()
  })

  it('fails when ctx.effect is unavailable', () => {
    process.env[SECRET_ENV] = SECRET
    assert.throws(() => apply({ connection: connection() }), /ctx\.effect is not available/)
  })

  it('fails when the connection service is missing', () => {
    process.env[SECRET_ENV] = SECRET
    assert.throws(() => apply(fakeContext(undefined)), /connection service unavailable/)
  })

  it('fails when requestRejection is missing', () => {
    process.env[SECRET_ENV] = SECRET
    assert.throws(() => apply(fakeContext({ authorizeIndex() {} })), /requestRejection is not a function/)
  })

  it('fails when authorizeIndex is missing', () => {
    process.env[SECRET_ENV] = SECRET
    assert.throws(() => apply(fakeContext({ requestRejection() {} })), /authorizeIndex is not a function/)
  })

  it('fails when the connection service is not extensible', () => {
    process.env[SECRET_ENV] = SECRET
    const frozen = Object.preventExtensions({ requestRejection() {}, authorizeIndex() {} })
    assert.throws(() => apply(fakeContext(frozen)), /not extensible/)
  })

  it('fails and restores when a method cannot be decorated', () => {
    process.env[SECRET_ENV] = SECRET
    // requestRejection is inherited (so cleanup deletes); authorizeIndex is an
    // own non-writable property, so decorating it must fail.
    class PartiallyFrozen extends FakeConnection {
      constructor() {
        super()
        Object.defineProperty(this, 'authorizeIndex', {
          value: () => false,
          writable: false,
          configurable: false,
        })
      }
    }
    const connection = new PartiallyFrozen()
    assert.throws(() => apply(fakeContext(connection)), /could not be decorated/)
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false, 'partial decoration is rolled back')
  })

  it('undoes a mutation that landed but failed verification', () => {
    process.env[SECRET_ENV] = SECRET
    const target = new FakeConnection()
    // Simulate an incompatible future Cordis proxy: the write reaches the
    // target, but the descriptor read cannot see it, so verification fails.
    const connection = new Proxy(target, {
      getOwnPropertyDescriptor(object, property) {
        if (property === 'requestRejection') return undefined
        return Reflect.getOwnPropertyDescriptor(object, property)
      },
    })
    assert.throws(() => apply(fakeContext(connection)), /could not be decorated/)
    assert.equal(Object.hasOwn(target, 'requestRejection'), false, 'the landed mutation is undone')
    assert.equal(
      target.requestRejection,
      FakeConnection.prototype.requestRejection,
      'the prototype method is intact',
    )
  })

  it('rolls back installed wrappers when ctx.effect fails', () => {
    process.env[SECRET_ENV] = SECRET
    const connection = new FakeConnection()
    const ctx = fakeContext(connection)
    ctx.effect = () => {
      throw new Error('effect registration failed')
    }
    assert.throws(() => apply(ctx), /effect registration failed/)
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), false)
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)
  })
})

describe('startup semantic invariant', () => {
  it('fails when the Host fence no longer returns 403', () => {
    process.env[SECRET_ENV] = SECRET
    const connection = new FakeConnection({ semantics: () => 401 })
    assert.throws(() => apply(fakeContext(connection)), /unsupported DSH requestRejection semantics/)
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false, 'nothing is decorated')
  })

  it('fails when an unauthenticated loopback request is not 401', () => {
    process.env[SECRET_ENV] = SECRET
    const connection = new FakeConnection({ semantics: () => undefined })
    assert.throws(() => apply(fakeContext(connection)), /unsupported DSH requestRejection semantics/)
  })

  it('probes the original method even when a wrapper is already installed', () => {
    process.env[SECRET_ENV] = SECRET
    const connection = new FakeConnection()
    // A wrapper that would wrongly promote everything, tagged as ours.
    const foreign = function foreignWrapper() {
      return undefined
    }
    Object.defineProperty(foreign, INNER, {
      value: { original: FakeConnection.prototype.requestRejection, originalWasOwn: false },
      enumerable: false,
    })
    connection.requestRejection = foreign
    // Activation must probe the real original (which returns 401/403), so it
    // must succeed rather than trust the installed wrapper's semantics.
    const ctx = activate(connection)
    ctx.dispose()
  })
})

describe('lifecycle', () => {
  it('installs an instance wrapper and leaves the prototype untouched', () => {
    const connection = new FakeConnection()
    activate(connection)
    assert.equal(Object.hasOwn(connection, 'requestRejection'), true)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), true)
    assert.equal(Object.hasOwn(connection, 'admit'), true)
    assert.equal(Object.hasOwn(connection, 'admitConnection'), true)
    assert.notEqual(connection.requestRejection, FakeConnection.prototype.requestRejection)
    assert.notEqual(connection.admit, FakeConnection.prototype.admit)
    assert.notEqual(connection.admitConnection, FakeConnection.prototype.admitConnection)
    assert.equal(
      typeof FakeConnection.prototype.requestRejection,
      'function',
      'prototype method is never replaced',
    )
    assert.equal(
      typeof FakeConnection.prototype.admit,
      'function',
      'prototype method is never replaced',
    )
  })

  it('cleanup restores the exact original shape for inherited methods', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    ctx.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), false)
    assert.equal(Object.hasOwn(connection, 'admit'), false)
    assert.equal(Object.hasOwn(connection, 'admitConnection'), false)
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)
    assert.equal(connection.authorizeIndex, FakeConnection.prototype.authorizeIndex)
    assert.equal(connection.admit, FakeConnection.prototype.admit)
    assert.equal(connection.admitConnection, FakeConnection.prototype.admitConnection)
    assert.equal(
      connection.requestRejection({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }),
      401,
    )
  })

  it('cleanup restores own-property methods as own properties', () => {
    // An own-property method that still implements DSH's semantics, so the
    // startup probe succeeds and the test exercises restoration only.
    const reference = new FakeConnection()
    const original = function requestRejection(request) {
      return reference.evaluate(request)
    }
    const connection = { requestRejection: original, authorizeIndex() {} }
    const ctx = activate(connection)
    assert.notEqual(connection.requestRejection, original)
    ctx.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), true)
    assert.equal(connection.requestRejection, original)
  })

  it('apply -> cleanup -> apply does not stack wrappers', () => {
    const connection = new FakeConnection()
    const first = activate(connection)
    first.dispose()
    const second = activate(connection)
    assert.equal(
      connection.requestRejection({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }),
      undefined,
    )
    assert.equal(connection.rejectionCalls, 1, 'the upstream method is reached exactly once')
    second.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
  })

  it('two overlapping activations converge to the pristine object on cleanup', () => {
    const connection = new FakeConnection()
    const a = activate(connection)
    const b = activate(connection)
    a.dispose()
    b.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), false)
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)

    const c = activate(connection)
    const d = activate(connection)
    d.dispose()
    c.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(
      connection.requestRejection({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }),
      401,
    )
  })

  it('unwraps a wrapper carrying the shared global marker from another generation', () => {
    const connection = new FakeConnection()
    const foreign = function foreignWrapper() {
      return 401
    }
    Object.defineProperty(foreign, INNER, {
      value: { original: FakeConnection.prototype.requestRejection, originalWasOwn: false },
      enumerable: false,
    })
    connection.requestRejection = foreign
    const ctx = activate(connection)
    assert.notEqual(connection.requestRejection, foreign, 'the foreign wrapper is replaced')
    ctx.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)
  })

  it('leaves authenticatedUrl untouched', () => {
    const connection = new FakeConnection()
    const before = connection.authenticatedUrl
    const ctx = activate(connection)
    assert.equal(connection.authenticatedUrl, before)
    assert.equal(connection.authenticatedUrl('http://127.0.0.1:3080/'), 'http://127.0.0.1:3080/?token=launch')
    ctx.dispose()
  })

  it('never logs the secret or header contents', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    connection.requestRejection({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } })
    connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: 'wrong' } }, fakeResponse())
    const text = ctx.log.join('\n')
    assert.ok(text.includes('trusted-proxy-auth: activated'))
    assert.equal(text.includes(SECRET), false)
    assert.equal(text.includes('wrong'), false)
  })
})

describe('normalizeToLoopback', () => {
  it('normalizes plain object host and origin to default port 3080', () => {
    const req = {
      headers: {
        host: 'dsh.terraurbs.com',
        origin: 'https://dsh.terraurbs.com',
      },
    }
    normalizeToLoopback(req)
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.origin, 'http://127.0.0.1:3080')
    assert.equal(req.headers['x-forwarded-host'], 'dsh.terraurbs.com')
    assert.equal(req.headers['x-forwarded-proto'], 'https')
  })

  it('leaves origin undefined when not present in request', () => {
    const req = {
      headers: {
        host: 'dsh.terraurbs.com',
      },
    }
    normalizeToLoopback(req)
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.origin, undefined)
    assert.equal(req.headers['x-forwarded-host'], 'dsh.terraurbs.com')
    assert.equal(req.headers['x-forwarded-proto'], 'https')
  })

  it('handles custom port and standard HTTP port 80', () => {
    const req1 = { headers: { host: 'custom.example', origin: 'https://custom.example' } }
    normalizeToLoopback(req1, 8080)
    assert.equal(req1.headers.host, '127.0.0.1:8080')
    assert.equal(req1.headers.origin, 'http://127.0.0.1:8080')

    const req2 = { headers: { host: 'custom.example', origin: 'https://custom.example' } }
    normalizeToLoopback(req2, 80)
    assert.equal(req2.headers.host, '127.0.0.1')
    assert.equal(req2.headers.origin, 'http://127.0.0.1')
  })

  it('preserves existing x-forwarded-host and x-forwarded-proto', () => {
    const req = {
      headers: {
        host: 'dsh.terraurbs.com',
        'x-forwarded-host': 'original.public.example',
        'x-forwarded-proto': 'wss',
      },
    }
    normalizeToLoopback(req)
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers['x-forwarded-host'], 'original.public.example')
    assert.equal(req.headers['x-forwarded-proto'], 'wss')
  })

  it('handles Fetch Headers instances properly', () => {
    const headers = new Headers({
      Host: 'dsh.terraurbs.com',
      Origin: 'https://dsh.terraurbs.com',
    })
    const req = { headers }
    normalizeToLoopback(req)
    assert.equal(headers.get('host'), '127.0.0.1:3080')
    assert.equal(headers.get('origin'), 'http://127.0.0.1:3080')
    assert.equal(headers.get('x-forwarded-host'), 'dsh.terraurbs.com')
    assert.equal(headers.get('x-forwarded-proto'), 'https')
  })

  it('handles mixed-case keys in plain objects', () => {
    const req = {
      headers: {
        Host: 'dsh.terraurbs.com',
        Origin: 'https://dsh.terraurbs.com',
      },
    }
    normalizeToLoopback(req)
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.Host, undefined)
    assert.equal(req.headers.origin, 'http://127.0.0.1:3080')
    assert.equal(req.headers.Origin, undefined)
  })

  it('safely handles missing or empty headers', () => {
    assert.doesNotThrow(() => normalizeToLoopback(undefined))
    assert.doesNotThrow(() => normalizeToLoopback({}))
    assert.doesNotThrow(() => normalizeToLoopback({ headers: null }))
  })

  it('is idempotent when called repeatedly', () => {
    const req = {
      headers: {
        host: 'dsh.terraurbs.com',
        origin: 'https://dsh.terraurbs.com',
      },
    }
    normalizeToLoopback(req)
    normalizeToLoopback(req)
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.origin, 'http://127.0.0.1:3080')
    assert.equal(req.headers['x-forwarded-host'], 'dsh.terraurbs.com')
  })
})

describe('webServer third-party plugin route compatibility', () => {
  /** Reusable dshmarket-style sameOrigin check (from dshmarket@1.65.1). */
  function dshmarketSameOrigin(req) {
    const host = req.headers?.host
    const origin = req.headers?.origin
    const isLoopback = host === '127.0.0.1:3080'
      || host === 'localhost:3080'
      || host?.startsWith('127.0.0.1')
      || host?.startsWith('localhost')
    if (!isLoopback) return false
    if (!origin) return true
    return origin === `http://${host}`
  }

  it('dshmarket discovery route: valid proxy request is normalized to loopback and passes sameOrigin', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let handlerCalls = 0
    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        handlerCalls += 1
        if (!dshmarketSameOrigin(req)) {
          res.writeHead(403, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'forbidden' }))
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ compatible: true }))
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(handlerCalls, 1)
    assert.equal(res.status, 200)
    assert.deepEqual(JSON.parse(res.body), { compatible: true })
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.origin, 'http://127.0.0.1:3080')
    assert.equal(req.headers['x-forwarded-host'], 'dsh.test.example')
    assert.equal(req.headers['x-forwarded-proto'], 'https')
    ctx.dispose()
  })

  it('dshmarket update mutation route: valid proxy request succeeds', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let installedPlugin = null
    ctx.webServer.register({
      path: '/dsh-market/update',
      method: 'POST',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) {
          res.writeHead(403).end('forbidden')
          return
        }
        installedPlugin = 'dsh-plugin-sample'
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ status: 'updated' }))
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/update',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(res.status, 200)
    assert.equal(installedPlugin, 'dsh-plugin-sample')
    ctx.dispose()
  })

  it('dshmarket route: cross-origin CSRF attack is rejected with 403 before normalization or handler call', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let handlerCalls = 0
    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        handlerCalls += 1
        res.writeHead(200).end('ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://evil-attacker.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(handlerCalls, 0, 'third-party handler must never be called on CSRF')
    assert.equal(res.status, 403)
    assert.equal(res.headers['cache-control'], 'no-store')
    assert.equal(res.body, 'forbidden')
    // Crucial: headers were not normalized for the attacker
    assert.equal(req.headers.host, 'dsh.test.example')
    assert.equal(req.headers.origin, 'https://evil-attacker.example')
    ctx.dispose()
  })

  it('dshmarket route: cross-site fetch metadata is rejected with 403 before handler call', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let handlerCalls = 0
    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        handlerCalls += 1
        res.writeHead(200).end('ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        'sec-fetch-site': 'cross-site',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(handlerCalls, 0)
    assert.equal(res.status, 403)
    ctx.dispose()
  })

  it('dshmarket route: untrusted Host is rejected with 403 before handler call', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let handlerCalls = 0
    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        handlerCalls += 1
        res.writeHead(200).end('ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'evil-host.invalid',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(handlerCalls, 0)
    assert.equal(res.status, 403)
    ctx.dispose()
  })

  it('dshmarket route: request without proxy secret is not normalized and fails plugin loopback check', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    let handlerCalls = 0
    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        handlerCalls += 1
        if (!dshmarketSameOrigin(req)) {
          res.writeHead(403).end('forbidden by plugin')
          return
        }
        res.writeHead(200).end('ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        // No proxy secret header
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(handlerCalls, 1)
    assert.equal(res.status, 403)
    assert.equal(res.body, 'forbidden by plugin')
    assert.equal(req.headers.host, 'dsh.test.example')
    ctx.dispose()
  })

  it('dshmarket route: direct loopback request without proxy secret passes plugin check', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    ctx.webServer.register({
      path: '/dsh-market/discovery-compatibility',
      method: 'POST',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) {
          res.writeHead(403).end('forbidden')
          return
        }
        res.writeHead(200).end('loopback ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: '127.0.0.1:3080',
        origin: 'http://127.0.0.1:3080',
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)

    assert.equal(res.status, 200)
    assert.equal(res.body, 'loopback ok')
    ctx.dispose()
  })

  it('multiple third-party plugins registering diverse routes all work transparently', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    // Plugin 1: analytics plugin (GET exact route)
    ctx.webServer.register({
      path: '/plugins/analytics/stats',
      method: 'GET',
      async handler(req, res) {
        const isLoopback = req.headers.host?.startsWith('127.0.0.1')
        if (!isLoopback) return res.writeHead(403).end('non-loopback')
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ activeUsers: 42 }))
      },
    })

    // Plugin 2: file manager plugin (POST mutation route)
    ctx.webServer.register({
      path: '/plugins/files/upload',
      method: 'POST',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) return res.writeHead(403).end('cross-origin')
        res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ uploaded: true }))
      },
    })

    // Plugin 3: terminal proxy plugin (prefix route)
    ctx.webServer.register({
      prefix: '/plugins/term/',
      method: 'GET',
      async handler(req, res) {
        const isLoopback = req.headers.host === '127.0.0.1:3080'
        if (!isLoopback) return res.writeHead(403).end('remote forbidden')
        res.writeHead(200).end(`terminal session for ${req.url}`)
      },
    })

    // Issue request to Plugin 1
    const req1 = {
      method: 'GET',
      url: '/plugins/analytics/stats',
      headers: { host: 'dsh.test.example', [HEADER_NAME]: SECRET },
    }
    const res1 = fakeResponse()
    await ctx.webServer.handle(req1, res1)
    assert.equal(res1.status, 200)
    assert.deepEqual(JSON.parse(res1.body), { activeUsers: 42 })

    // Issue request to Plugin 2
    const req2 = {
      method: 'POST',
      url: '/plugins/files/upload',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res2 = fakeResponse()
    await ctx.webServer.handle(req2, res2)
    assert.equal(res2.status, 201)
    assert.deepEqual(JSON.parse(res2.body), { uploaded: true })

    // Issue request to Plugin 3
    const req3 = {
      method: 'GET',
      url: '/plugins/term/pty-session-123',
      headers: { host: 'dsh.test.example', [HEADER_NAME]: SECRET },
    }
    const res3 = fakeResponse()
    await ctx.webServer.handle(req3, res3)
    assert.equal(res3.status, 200)
    assert.equal(res3.body, 'terminal session for /plugins/term/pty-session-123')

    ctx.dispose()
  })

  it('restores webServer.handle on cleanup so subsequent requests are not normalized', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const originalHandle = ctx.webServer.handle

    ctx.webServer.register({
      path: '/test/cleanup',
      method: 'GET',
      async handler(req, res) {
        res.writeHead(200).end(req.headers.host)
      },
    })

    // Before disposal: normalized to loopback
    const reqBefore = {
      method: 'GET',
      url: '/test/cleanup',
      headers: { host: 'dsh.test.example', [HEADER_NAME]: SECRET },
    }
    const resBefore = fakeResponse()
    await ctx.webServer.handle(reqBefore, resBefore)
    assert.equal(resBefore.body, '127.0.0.1:3080')

    // Dispose
    ctx.dispose()

    // After disposal: handle restored, headers NOT normalized
    const reqAfter = {
      method: 'GET',
      url: '/test/cleanup',
      headers: { host: 'dsh.test.example', [HEADER_NAME]: SECRET },
    }
    const resAfter = fakeResponse()
    await ctx.webServer.handle(reqAfter, resAfter)
    assert.equal(resAfter.body, 'dsh.test.example')
  })

  it('rolls back connection decoration when webServer.handle cannot be decorated', () => {
    process.env[SECRET_ENV] = SECRET
    const connection = new FakeConnection()
    const frozenWebServer = {
      port: 3080,
      taps: [],
    }
    Object.defineProperty(frozenWebServer, 'handle', {
      value: async () => {},
      writable: false,
      configurable: false,
    })

    const ctx = fakeContext(connection, { webServer: frozenWebServer })
    assert.throws(() => apply(ctx), /unsupported DSH webServer interface: handle could not be decorated/)

    // Both connection methods were rolled back
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), false)
  })

  it('normalizes to custom webServer.port (e.g. 3081)', async () => {
    const connection = new FakeConnection()
    const customWebServer = {
      port: 3081,
      taps: [],
      routes: [],
      tapIndex(fn) { return () => {} },
      register(route) { this.routes.push(route) },
      async handle(req, res) {
        for (const route of this.routes) {
          if (route.path === req.url) return await route.handler(req, res)
        }
      },
    }
    const ctx = activate(connection, SECRET, { webServer: customWebServer })

    ctx.webServer.register({
      path: '/dsh-market/check',
      method: 'POST',
      async handler(req, res) {
        const expectedHost = '127.0.0.1:3081'
        const expectedOrigin = 'http://127.0.0.1:3081'
        if (req.headers.host !== expectedHost || req.headers.origin !== expectedOrigin) {
          return res.writeHead(403).end('port mismatch')
        }
        res.writeHead(200).end('custom port ok')
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/check',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)
    assert.equal(res.status, 200)
    assert.equal(res.body, 'custom port ok')
    ctx.dispose()
  })

  it('supports DELETE and PUT mutation routes from plugins', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    ctx.webServer.register({
      path: '/dsh-market/uninstall',
      method: 'DELETE',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) return res.writeHead(403).end('forbidden')
        res.writeHead(204).end()
      },
    })

    const req = {
      method: 'DELETE',
      url: '/dsh-market/uninstall',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)
    assert.equal(res.status, 204)
    ctx.dispose()
  })

  it('handles routes with query parameters gracefully', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    ctx.webServer.register({
      prefix: '/dsh-market/search',
      method: 'GET',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) return res.writeHead(403).end('forbidden')
        res.writeHead(200).end(`searched for ${req.url}`)
      },
    })

    const req = {
      method: 'GET',
      url: '/dsh-market/search?q=syntax-theme&page=1',
      headers: {
        host: 'dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    await ctx.webServer.handle(req, res)
    assert.equal(res.status, 200)
    assert.equal(res.body, 'searched for /dsh-market/search?q=syntax-theme&page=1')
    ctx.dispose()
  })

  it('bubbles downstream handler errors naturally', async () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)

    ctx.webServer.register({
      path: '/buggy/route',
      method: 'GET',
      async handler() {
        throw new Error('plugin internal crash')
      },
    })

    const req = {
      method: 'GET',
      url: '/buggy/route',
      headers: {
        host: 'dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    await assert.rejects(
      async () => { await ctx.webServer.handle(req, fakeResponse()) },
      /plugin internal crash/,
    )
    ctx.dispose()
  })

  it('two overlapping activations unwrap webServer.handle instead of stacking', async () => {
    const connection = new FakeConnection()
    const sharedWebServer = {
      port: 3080,
      taps: [],
      routes: [],
      tapIndex(fn) { return () => {} },
      register(route) { this.routes.push(route) },
      async handle(req, res) {
        for (const route of this.routes) {
          if (route.path === req.url) return await route.handler(req, res)
        }
        res.writeHead(404).end('not found')
      },
    }
    const ctx1 = activate(connection, SECRET, { webServer: sharedWebServer })
    const ctx2 = activate(connection, SECRET, { webServer: sharedWebServer })

    sharedWebServer.register({
      path: '/overlapping/test',
      method: 'GET',
      async handler(req, res) {
        res.writeHead(200).end(req.headers.host)
      },
    })

    const req = {
      method: 'GET',
      url: '/overlapping/test',
      headers: { host: 'dsh.test.example', [HEADER_NAME]: SECRET },
    }
    const res = fakeResponse()
    await sharedWebServer.handle(req, res)
    assert.equal(res.body, '127.0.0.1:3080')

    ctx1.dispose()
    ctx2.dispose()

    // Pristine original handle is restored
    assert.equal(Object.hasOwn(sharedWebServer, 'handle'), true)
    assert.equal(sharedWebServer.handle[INNER], undefined, 'wrapper marker removed')
  })

  it('dshmarket discovery route works on real-DSH WebServer structure without handle method', async () => {
    const connection = new FakeConnection()
    const realDshWebServer = {
      port: 3080,
      exact: new Map(),
      prefixes: new Map(),
      taps: [],
      tapIndex(fn) { return () => {} },
      register(route) {
        const table = route.kind === 'prefix' ? this.prefixes : this.exact
        table.set(route.path, route)
        return () => table.delete(route.path)
      },
      match(pathname) {
        const exact = this.exact.get(pathname)
        if (exact !== undefined) return exact
        for (const [prefix, route] of this.prefixes) {
          if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return route
        }
        return undefined
      },
      // Note: no handle() method on WebServer instance in real DSH!
    }
    const ctx = activate(connection, SECRET, { webServer: realDshWebServer })

    realDshWebServer.register({
      kind: 'exact',
      path: '/dsh-market/discovery-compatibility',
      async handler(req, res) {
        if (!dshmarketSameOrigin(req)) {
          res.writeHead(403, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'untrusted origin' }))
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ compatible: true }))
      },
    })

    const req = {
      method: 'POST',
      url: '/dsh-market/discovery-compatibility',
      headers: {
        host: 'dsh.test.example',
        origin: 'https://dsh.test.example',
        [HEADER_NAME]: SECRET,
      },
    }
    const res = fakeResponse()
    // Simulate DSH's internal createServer handle loop:
    const rawPath = new URL(req.url, 'http://x').pathname
    const matched = realDshWebServer.match(rawPath)
    assert.ok(matched !== undefined, 'route matched')
    await matched.handler(req, res)

    assert.equal(res.status, 200)
    assert.deepEqual(JSON.parse(res.body), { compatible: true })
    assert.equal(req.headers.host, '127.0.0.1:3080')
    assert.equal(req.headers.origin, 'http://127.0.0.1:3080')
    ctx.dispose()
  })
})

