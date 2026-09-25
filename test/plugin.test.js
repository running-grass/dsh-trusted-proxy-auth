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
  attachBootstrapInjection,
  injectBootstrapHtml,
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
function fakeContext(connection) {
  const log = []
  const disposers = []
  return {
    connection,
    log,
    logger: {
      info: (message) => log.push(`info ${String(message)}`),
      warn: (message) => log.push(`warn ${String(message)}`),
      error: (message) => log.push(`error ${String(message)}`),
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

/**
 * Connection service whose methods live on the prototype, as upstream does.
 *
 * The default `requestRejection` mirrors DSH 0.1.5-rc.2: the Host/Origin fence
 * returns 403, and missing native browser authentication returns 401. Pass
 * `semantics` to simulate a future DSH that changed that mapping.
 */
class FakeConnection {
  constructor(options = {}) {
    this.semantics = options.semantics
    this.rejectionCalls = 0
    this.indexCalls = 0
  }

  requestRejection(request) {
    this.rejectionCalls += 1
    if (typeof this.semantics === 'function') return this.semantics(request)
    return this.evaluate(request)
  }

  /** DSH 0.1.5-rc.2 semantics, reusable by custom `semantics` overrides. */
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
function activate(connection, secret = SECRET) {
  process.env[SECRET_ENV] = secret
  const ctx = fakeContext(connection)
  apply(ctx)
  connection.rejectionCalls = 0
  connection.indexCalls = 0
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

  it('valid secret attaches bootstrap injection which inserts script into index HTML', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    assert.equal(
      connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response),
      true,
    )
    assert.equal(response.ended, false)
    response.end('<!doctype html><html><head><meta charset="utf-8"></head><body><h1>DSH</h1></body></html>')
    assert.equal(response.ended, true)
    assert.ok(response.body.includes(BOOTSTRAP_SCRIPT))
    assert.ok(response.body.includes('<head>' + BOOTSTRAP_SCRIPT))
    assert.ok(response.body.includes('ownsHost:true'))
    ctx.dispose()
  })

  it('valid secret handles Buffer payload in response.end', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response)
    response.end(Buffer.from('<html><head></head><body></body></html>', 'utf8'))
    assert.ok(response.body.includes(BOOTSTRAP_SCRIPT))
    ctx.dispose()
  })

  it('valid secret handles response.write then response.end', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response)
    response.write('<html><head><title>Test</title></head>')
    response.end('<body>App</body></html>')
    assert.ok(response.body.includes(BOOTSTRAP_SCRIPT))
    assert.ok(response.body.includes('App'))
    ctx.dispose()
  })

  it('valid secret strips stale Content-Length header', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    connection.authorizeIndex({ headers: { host: LOOPBACK_HOST, [HEADER_NAME]: SECRET } }, response)
    response.setHeader('content-length', 42)
    response.end('<html><head></head><body></body></html>')
    assert.equal(response.hasHeader('content-length'), false)
    ctx.dispose()
  })

  it('missing secret does not inject bootstrap script', () => {
    const connection = new FakeConnection()
    const ctx = activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { host: LOOPBACK_HOST } }, response), false)
    assert.equal(response.status, 401)
    assert.equal(response.body, 'unauthorized')
    assert.ok(!response.body.includes('ownsHost'))
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
    assert.notEqual(connection.requestRejection, FakeConnection.prototype.requestRejection)
    assert.equal(
      typeof FakeConnection.prototype.requestRejection,
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
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)
    assert.equal(connection.authorizeIndex, FakeConnection.prototype.authorizeIndex)
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
