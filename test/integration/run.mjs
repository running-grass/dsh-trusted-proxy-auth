#!/usr/bin/env node
/**
 * Real-DSH integration test for dsh-trusted-proxy-auth.
 *
 * The harness never touches a production Harness home or an already-running
 * server. It creates a throwaway `DSH_HOME`, derives a private profile from the
 * shipped `web` template, installs this checkout as a plugin bundle, boots the
 * real Harness Web server on a free loopback port, and drives the live HTTP,
 * API, WebSocket, native-authentication, fail-closed, and log-hygiene paths.
 *
 * Usage:
 *   node test/integration/run.mjs
 *
 * Environment:
 *   DSH_BIN      dsh executable to use (default: `dsh` from PATH)
 *   KEEP_TMP=1   keep the temporary Harness home for inspection
 */

import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { upgrade } from './ws-client.mjs'

const REPO_ROOT = path.resolve(fileURLToPath(new URL('../../', import.meta.url)))
const DSH_BIN = process.env.DSH_BIN ?? 'dsh'
const PROFILE = 'trusted-proxy-auth-integration'
const TRUSTED_HOST = 'dsh.test.example'
const EVIL_HOST = 'evil.example'

let passed = 0
let failed = 0

const log = (message = '') => process.stdout.write(`${message}\n`)
const section = (title) => log(`\n== ${title} ==`)
const delay = (ms) => new Promise((resolve) => { setTimeout(resolve, ms) })

/**
 * Record one assertion.
 *
 * @param title - human-readable expectation.
 * @param condition - whether it held.
 * @param detail - optional diagnostic appended on failure.
 */
function check(title, condition, detail = '') {
  if (condition) {
    passed += 1
    log(`  ok    ${title}`)
  } else {
    failed += 1
    log(`  FAIL  ${title}${detail === '' ? '' : ` (${detail})`}`)
  }
}

/** Find a free loopback TCP port. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

/** Whether a loopback port accepts a connection. */
function canConnect(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    const done = (value) => {
      socket.destroy()
      resolve(value)
    }
    socket.once('connect', () => done(true))
    socket.once('error', () => done(false))
    setTimeout(() => done(false), 2000)
  })
}

/**
 * Issue one HTTP request with full control over the Host header.
 *
 * @param options - request facts.
 * @returns `{ status, headers, body }`.
 */
function request({ port, path: requestPath = '/', method = 'GET', headers = {}, body, cookie }) {
  return new Promise((resolve, reject) => {
    const requestHeaders = { ...headers }
    if (cookie !== undefined) requestHeaders.cookie = cookie
    const req = http.request(
      { host: '127.0.0.1', port, path: requestPath, method, headers: requestHeaders },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
        })
      },
    )
    req.once('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

/** First `name=value` pair from a Set-Cookie response header. */
function firstCookie(response) {
  const header = response.headers['set-cookie']
  const value = Array.isArray(header) ? header[0] : header
  return typeof value === 'string' ? value.split(';', 1)[0] : undefined
}

/** Recursively scan regular files under a directory for a literal string. */
function containsLiteral(directory, needle, depth = 0) {
  if (depth > 6) return false
  let entries
  try {
    entries = readdirSync(directory, { withFileTypes: true })
  } catch {
    return false
  }
  for (const entry of entries) {
    const full = path.join(directory, entry.name)
    if (entry.isSymbolicLink()) continue
    if (entry.isDirectory()) {
      if (containsLiteral(full, needle, depth + 1)) return true
      continue
    }
    if (!entry.isFile()) continue
    try {
      if (statSync(full).size > 5 * 1024 * 1024) continue
      if (readFileSync(full, 'utf8').includes(needle)) return true
    } catch {
      // Unreadable or binary file: skip.
    }
  }
  return false
}

/** Run one dsh invocation to completion. */
function runDsh(args, env, timeout = 120000) {
  const result = spawnSync(DSH_BIN, args, {
    env: { ...process.env, DSH_HOME: home, ...env },
    encoding: 'utf8',
    timeout,
  })
  if (result.error) throw result.error
  return result
}

/** Spawn the real Harness Web server and collect its output. */
function startServer({ port, secret }) {
  const child = spawn(
    DSH_BIN,
    [
      '--profile', PROFILE,
      '--host', '127.0.0.1',
      '--port', String(port),
      '--no-open',
      '--trusted-host', TRUSTED_HOST,
    ],
    {
      env: { ...process.env, DSH_HOME: home, DSH_PROXY_AUTH_SECRET: secret },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  const output = { text: '' }
  child.stdout.on('data', (chunk) => { output.text += chunk })
  child.stderr.on('data', (chunk) => { output.text += chunk })
  return { child, output }
}

/** Wait until the server prints its native authenticated URL. */
async function waitForUrl(server, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const match = /dsh web: (http:\/\/\S+\?token=[A-Za-z0-9_-]+)/.exec(server.output.text)
    if (match !== null) return match
    if (server.child.exitCode !== null) {
      throw new Error(`dsh exited early with code ${server.child.exitCode}:\n${server.output.text}`)
    }
    await delay(200)
  }
  throw new Error(`timed out waiting for the dsh web URL:\n${server.output.text}`)
}

/** Stop the server, escalating to SIGKILL if it does not exit. */
async function stopServer(server) {
  if (server.child.exitCode !== null) return
  server.child.kill('SIGTERM')
  await Promise.race([
    once(server.child, 'exit'),
    delay(15000).then(() => server.child.kill('SIGKILL')),
  ])
}

const home = mkdtempSync(path.join(os.tmpdir(), 'dsh-trusted-proxy-auth-test-'))
const secret = randomBytes(48).toString('hex')
let server
let exitCode = 1

try {
  section('environment')
  const dshVersion = runDsh(['--version'], {}).stdout.trim().split('\n').at(-1)
  log(`  dsh:  ${dshVersion}`)
  log(`  node: ${process.version}`)
  log(`  home: ${home}`)

  section('profile setup (isolated DSH_HOME)')
  const init = runDsh(['--profile', PROFILE, '--from-default-profile', 'web', '--dump-config'], {})
  assert.equal(init.status, 0, `profile init failed:\n${init.stderr}`)

  const install = runDsh(['plugin', '--profile', PROFILE, 'add', REPO_ROOT], {})
  if (install.status !== 0) {
    throw new Error(`plugin install failed (${install.status}):\n${install.stdout}\n${install.stderr}`)
  }
  check('dsh plugin add links this checkout and reconciles bundles', install.status === 0)

  const dump = runDsh(['--profile', PROFILE, '--dump-config'], {})
  assert.equal(dump.status, 0, `dump-config failed:\n${dump.stderr}`)
  check('dump-config loads dsh-trusted-proxy-auth', dump.stdout.includes('name: dsh-trusted-proxy-auth'))
  check(
    'dump-config still loads @deepseek-ai/dsh-client-connection',
    dump.stdout.includes("name: '@deepseek-ai/dsh-client-connection'"),
  )

  const port = await freePort()
  const authority = `127.0.0.1:${port}`
  section(`live server on 127.0.0.1:${port}`)
  server = startServer({ port, secret })
  const urlMatch = await waitForUrl(server)
  const nativeToken = new URL(urlMatch[1]).searchParams.get('token')
  log(`  native launch URL: ${urlMatch[1].replace(nativeToken, '<redacted>')}`)

  const trusted = { host: TRUSTED_HOST }
  const proxy = { 'x-dsh-proxy-auth': secret }

  section('index route (/): trusted-proxy authentication')
  const noHeader = await request({ port, path: '/', headers: trusted })
  check('no proxy header -> 401 native authentication', noHeader.status === 401, `got ${noHeader.status}`)

  const wrongHeader = await request({ port, path: '/', headers: { ...trusted, 'x-dsh-proxy-auth': 'wrong' } })
  check('wrong proxy header -> 401', wrongHeader.status === 401, `got ${wrongHeader.status}`)

  const validHeader = await request({ port, path: '/', headers: { ...trusted, ...proxy } })
  check('valid proxy header -> 200', validHeader.status === 200, `got ${validHeader.status}`)
  check('valid proxy header serves the HTML application', /<!doctype html>/i.test(validHeader.body))
  check(
    'valid proxy header injects ownsHost bootstrap into index HTML',
    // 0.2.1-alpha.3 renders the structured `webserver/index-inject` row as JSON
    // (`{"ownsHost":true}`); the older tapIndex form was `{ownsHost:true}`.
    validHeader.body.includes('__DSH_TRANSPORT__')
      && (validHeader.body.includes('ownsHost:true') || validHeader.body.includes('"ownsHost":true')),
  )

  const evilHost = await request({ port, path: '/', headers: { host: EVIL_HOST, ...proxy } })
  check('valid proxy header + untrusted Host -> 403', evilHost.status === 403, `got ${evilHost.status}`)
  check('untrusted Host 403 body is minimal', evilHost.body === 'forbidden')
  check('untrusted Host 403 sets no-store', evilHost.headers['cache-control'] === 'no-store')

  const crossSite = await request({
    port,
    path: '/',
    headers: { ...trusted, ...proxy, 'sec-fetch-site': 'cross-site' },
  })
  check('valid proxy header + cross-site fetch metadata -> 403', crossSite.status === 403, `got ${crossSite.status}`)

  section('/api route: request-trust fence is not bypassed')
  const apiNoHeader = await request({ port, path: '/api/nonexistent', headers: trusted })
  check('/api without proxy header -> 401', apiNoHeader.status === 401, `got ${apiNoHeader.status}`)

  const apiValid = await request({ port, path: '/api/nonexistent', headers: { ...trusted, ...proxy } })
  check(
    '/api with valid proxy header reaches the application (not 401/403)',
    apiValid.status !== 401 && apiValid.status !== 403,
    `got ${apiValid.status}`,
  )

  const apiCrossOrigin = await request({
    port,
    path: '/api/nonexistent',
    headers: { ...trusted, ...proxy, origin: 'https://evil.example' },
  })
  check('/api cross-origin with valid secret -> 403', apiCrossOrigin.status === 403, `got ${apiCrossOrigin.status}`)

  const apiCrossSite = await request({
    port,
    path: '/api/nonexistent',
    headers: { ...trusted, ...proxy, 'sec-fetch-site': 'cross-site' },
  })
  check('/api cross-site with valid secret -> 403', apiCrossSite.status === 403, `got ${apiCrossSite.status}`)

  const apiEvilHost = await request({ port, path: '/api/nonexistent', headers: { host: EVIL_HOST, ...proxy } })
  check('/api untrusted Host with valid secret -> 403', apiEvilHost.status === 403, `got ${apiEvilHost.status}`)

  section('WebSocket /api/remote.mux')
  const wsNoHeader = await upgrade({ port, headers: { host: TRUSTED_HOST } })
  check('ws without proxy header -> 401', wsNoHeader.kind === 'http' && wsNoHeader.status === 401, JSON.stringify(wsNoHeader))

  const wsWrong = await upgrade({ port, headers: { host: TRUSTED_HOST, 'x-dsh-proxy-auth': 'wrong' } })
  check('ws wrong proxy header -> 401', wsWrong.kind === 'http' && wsWrong.status === 401, JSON.stringify(wsWrong))

  const wsValid = await upgrade({ port, headers: { host: TRUSTED_HOST, 'x-dsh-proxy-auth': secret } })
  check('ws valid proxy header + trusted Host -> upgraded', wsValid.kind === 'upgraded', JSON.stringify(wsValid))

  const wsSameOrigin = await upgrade({
    port,
    headers: { host: TRUSTED_HOST, origin: `https://${TRUSTED_HOST}`, 'x-dsh-proxy-auth': secret },
  })
  check('ws valid proxy header + same Origin -> upgraded', wsSameOrigin.kind === 'upgraded', JSON.stringify(wsSameOrigin))

  const wsEvilHost = await upgrade({ port, headers: { host: EVIL_HOST, 'x-dsh-proxy-auth': secret } })
  check('ws valid proxy header + untrusted Host -> 403', wsEvilHost.kind === 'http' && wsEvilHost.status === 403, JSON.stringify(wsEvilHost))

  const wsEvilOrigin = await upgrade({
    port,
    headers: { host: TRUSTED_HOST, origin: 'https://evil.example', 'x-dsh-proxy-auth': secret },
  })
  check('ws valid proxy header + wrong Origin -> 403', wsEvilOrigin.kind === 'http' && wsEvilOrigin.status === 403, JSON.stringify(wsEvilOrigin))

  section('native DSH authentication regression (no proxy header)')
  const tokenExchange = await request({ port, path: `/?token=${nativeToken}`, headers: { host: authority } })
  const sessionCookie = firstCookie(tokenExchange)
  check('native ?token= exchange -> 303', tokenExchange.status === 303, `got ${tokenExchange.status}`)
  check('native token exchange mints a session cookie', typeof sessionCookie === 'string')

  const nativeIndex = await request({ port, path: '/', headers: { host: authority }, cookie: sessionCookie })
  check('native session cookie -> 200', nativeIndex.status === 200, `got ${nativeIndex.status}`)
  check('native session cookie serves the HTML application', /<!doctype html>/i.test(nativeIndex.body))

  const badToken = await request({ port, path: '/?token=definitely-not-valid', headers: { host: authority } })
  check('invalid native token -> 401', badToken.status === 401, `got ${badToken.status}`)

  const cookieEvilHost = await request({ port, path: '/', headers: { host: EVIL_HOST }, cookie: sessionCookie })
  check('native cookie is authority-bound (evil Host -> 401)', cookieEvilHost.status === 401, `got ${cookieEvilHost.status}`)

  section('log hygiene')
  check('captured server output never contains the secret', !server.output.text.includes(secret))

  await stopServer(server)
  const portAfterStop = await canConnect(port)
  check('server stopped cleanly', portAfterStop === false)

  section('fail-closed activation')
  const missingSecretPort = await freePort()
  const missing = runDsh(
    ['--profile', PROFILE, '--host', '127.0.0.1', '--port', String(missingSecretPort), '--no-open', '--trusted-host', TRUSTED_HOST],
    { DSH_PROXY_AUTH_SECRET: '' },
    90000,
  )
  check('missing secret -> non-zero exit', missing.status !== 0, `status ${missing.status}`)
  check('missing secret -> names the plugin and variable', `${missing.stdout}${missing.stderr}`.includes('trusted-proxy-auth'))
  check('missing secret -> no listener', !(await canConnect(missingSecretPort)))

  const shortSecretPort = await freePort()
  const short = runDsh(
    ['--profile', PROFILE, '--host', '127.0.0.1', '--port', String(shortSecretPort), '--no-open', '--trusted-host', TRUSTED_HOST],
    { DSH_PROXY_AUTH_SECRET: 'too-short' },
    90000,
  )
  check('short secret -> non-zero exit', short.status !== 0, `status ${short.status}`)
  check('short secret -> no listener', !(await canConnect(shortSecretPort)))

  section('filesystem hygiene')
  check('secret never written under DSH_HOME', !containsLiteral(home, secret))

  exitCode = failed === 0 ? 0 : 1
} catch (error) {
  failed += 1
  log(`\nFATAL: ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  exitCode = 1
} finally {
  if (server !== undefined) await stopServer(server)
  if (process.env.KEEP_TMP === '1') log(`\nkept temporary Harness home: ${home}`)
  else rmSync(home, { recursive: true, force: true })
}

log(`\n${failed === 0 ? 'PASS' : 'FAIL'}: ${passed} passed, ${failed} failed`)
process.exit(exitCode)
