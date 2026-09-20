/**
 * Unit tests for dsh-trusted-proxy-auth.
 *
 * These tests exercise the plugin against a fake Cordis context and a fake
 * `connection` service. The real-DSH integration suite lives in
 * `test/integration/run.mjs` and proves the same behaviour against a running
 * Harness HTTP server.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'

import { HEADER_NAME, MIN_SECRET_BYTES, SECRET_ENV, apply } from '../index.js'

/** A known-good secret of exactly 48 bytes. */
const SECRET = 'unit-test-secret-'.padEnd(48, '0')

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
    end(body) {
      this.body = body
      this.ended = true
      return this
    },
  }
}

/** Connection service whose methods live on the prototype, as upstream does. */
class FakeConnection {
  constructor(options = {}) {
    this.rejectionResult = options.rejectionResult
    this.rejectionCalls = 0
    this.indexCalls = 0
  }

  requestRejection() {
    this.rejectionCalls += 1
    return this.rejectionResult
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

/** Activate the plugin against a fake connection and return its context. */
function activate(connection, secret = SECRET) {
  process.env[SECRET_ENV] = secret
  const ctx = fakeContext(connection)
  apply(ctx)
  return ctx
}

/** Run one request through the decorated `requestRejection`. */
function rejectWith(headers, options = {}) {
  const connection = options.connection ?? new FakeConnection({ rejectionResult: 401 })
  const ctx = activate(connection, options.secret)
  const result = connection.requestRejection({ headers })
  return { result, connection, ctx }
}

describe('requestRejection', () => {
  const cases = [
    { title: 'original 403 with a valid secret stays 403', result: 403, header: SECRET, expected: 403 },
    { title: 'original 403 with a wrong secret stays 403', result: 403, header: 'z'.repeat(48), expected: 403 },
    { title: 'original 401 with a valid secret is permitted', result: 401, header: SECRET, expected: undefined },
    { title: 'original 401 with a missing header stays 401', result: 401, header: undefined, expected: 401 },
    { title: 'original 401 with a wrong secret stays 401', result: 401, header: 'w'.repeat(48), expected: 401 },
    { title: 'original undefined with no header stays undefined', result: undefined, header: undefined, expected: undefined },
    { title: 'original undefined with a valid secret stays undefined', result: undefined, header: SECRET, expected: undefined },
  ]

  for (const testCase of cases) {
    it(testCase.title, () => {
      const connection = new FakeConnection({ rejectionResult: testCase.result })
      const ctx = activate(connection)
      const headers = testCase.header === undefined ? {} : { [HEADER_NAME]: testCase.header }
      assert.equal(connection.requestRejection({ headers }), testCase.expected)
      assert.equal(connection.rejectionCalls, 1, 'original requestRejection runs exactly once')
      ctx.dispose()
    })
  }

  it('never calls the original with a different receiver contract', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    activate(connection)
    connection.requestRejection({ headers: { [HEADER_NAME]: SECRET } })
    assert.equal(connection.rejectionCalls, 1)
  })
})

describe('authorizeIndex', () => {
  it('valid secret + trust 401 -> true without calling the original authorizeIndex', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    const ctx = activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { [HEADER_NAME]: SECRET } }, response), true)
    assert.equal(connection.indexCalls, 0)
    assert.equal(response.ended, false)
    ctx.dispose()
  })

  it('valid secret + trust undefined -> true', () => {
    const connection = new FakeConnection({ rejectionResult: undefined })
    activate(connection)
    assert.equal(connection.authorizeIndex({ headers: { [HEADER_NAME]: SECRET } }, fakeResponse()), true)
  })

  it('valid secret + trust 403 -> false, HTTP 403, response ended', () => {
    const connection = new FakeConnection({ rejectionResult: 403 })
    activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { [HEADER_NAME]: SECRET } }, response), false)
    assert.equal(response.status, 403)
    assert.equal(response.headers['cache-control'], 'no-store')
    assert.equal(response.headers['content-type'], 'text/plain; charset=utf-8')
    assert.equal(response.body, 'forbidden')
    assert.equal(response.ended, true)
  })

  it('missing secret delegates to the original authorizeIndex', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: {} }, response), false)
    assert.equal(connection.indexCalls, 1)
    assert.equal(response.status, 401)
  })

  it('wrong secret delegates to the original authorizeIndex', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    activate(connection)
    const response = fakeResponse()
    assert.equal(connection.authorizeIndex({ headers: { [HEADER_NAME]: 'nope' } }, response), false)
    assert.equal(connection.indexCalls, 1)
    assert.equal(response.status, 401)
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

  it('rejects a missing headers object', () => {
    assert.equal(rejectWith(undefined).result, 401)
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
    const headers = new Headers({ 'X-DSH-Proxy-Auth': SECRET })
    assert.equal(rejectWith(headers).result, undefined)
  })

  it('rejects a Fetch Headers instance with a different value', () => {
    const headers = new Headers({ 'X-DSH-Proxy-Auth': 'wrong' })
    assert.equal(rejectWith(headers).result, 401)
  })
})

describe('configuration', () => {
  const connection = () => new FakeConnection({ rejectionResult: 401 })

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
})

describe('lifecycle', () => {
  it('installs an instance wrapper and leaves the prototype untouched', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
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
    const connection = new FakeConnection({ rejectionResult: 401 })
    const ctx = activate(connection)
    ctx.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
    assert.equal(Object.hasOwn(connection, 'authorizeIndex'), false)
    assert.equal(connection.requestRejection, FakeConnection.prototype.requestRejection)
    assert.equal(connection.authorizeIndex, FakeConnection.prototype.authorizeIndex)
    assert.equal(connection.requestRejection({ headers: { [HEADER_NAME]: SECRET } }), 401)
  })

  it('cleanup restores own-property methods as own properties', () => {
    const original = function requestRejection() {
      return 401
    }
    const connection = { requestRejection: original, authorizeIndex() {} }
    const ctx = activate(connection)
    assert.notEqual(connection.requestRejection, original)
    ctx.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), true)
    assert.equal(connection.requestRejection, original)
  })

  it('apply -> cleanup -> apply does not stack wrappers', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    const first = activate(connection)
    first.dispose()
    const second = activate(connection)
    assert.equal(connection.requestRejection({ headers: { [HEADER_NAME]: SECRET } }), undefined)
    assert.equal(connection.rejectionCalls, 1, 'the upstream method is reached exactly once')
    second.dispose()
    assert.equal(Object.hasOwn(connection, 'requestRejection'), false)
  })

  it('two overlapping activations converge to the pristine object on cleanup', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
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
    assert.equal(connection.requestRejection({ headers: { [HEADER_NAME]: SECRET } }), 401)
  })

  it('leaves authenticatedUrl untouched', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    const before = connection.authenticatedUrl
    const ctx = activate(connection)
    assert.equal(connection.authenticatedUrl, before)
    assert.equal(connection.authenticatedUrl('http://127.0.0.1:3080/'), 'http://127.0.0.1:3080/?token=launch')
    ctx.dispose()
  })

  it('never logs the secret or header contents', () => {
    const connection = new FakeConnection({ rejectionResult: 401 })
    const ctx = activate(connection)
    connection.requestRejection({ headers: { [HEADER_NAME]: SECRET } })
    connection.authorizeIndex({ headers: { [HEADER_NAME]: 'wrong' } }, fakeResponse())
    const text = ctx.log.join('\n')
    assert.ok(text.includes('trusted-proxy-auth: activated'))
    assert.equal(text.includes(SECRET), false)
    assert.equal(text.includes('wrong'), false)
  })
})
