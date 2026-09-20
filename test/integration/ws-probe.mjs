/**
 * Standalone WebSocket auth-gate probe against an already-running isolated DSH.
 *
 * Usage:
 *   SECRET_FILE=/path/to/secret PORT=39180 node test/integration/ws-probe.mjs
 *
 * The automated harness (`run.mjs`) starts its own server and is the primary
 * integration test; this script exists for manual poking.
 */
import { readFileSync } from 'node:fs'
import process from 'node:process'

import { upgrade } from './ws-client.mjs'

const secret = readFileSync(process.env.SECRET_FILE, 'utf8').trim()
const port = Number(process.env.PORT ?? '39180')

const cases = [
  ['no proxy header + trusted Host', { host: 'dsh.test.example' }],
  ['wrong proxy header + trusted Host', { host: 'dsh.test.example', 'x-dsh-proxy-auth': 'wrong' }],
  ['valid proxy header + trusted Host', { host: 'dsh.test.example', 'x-dsh-proxy-auth': secret }],
  [
    'valid proxy header + trusted Host + same Origin',
    { host: 'dsh.test.example', origin: 'https://dsh.test.example', 'x-dsh-proxy-auth': secret },
  ],
  ['valid proxy header + untrusted Host', { host: 'evil.example', 'x-dsh-proxy-auth': secret }],
  [
    'valid proxy header + wrong Origin',
    { host: 'dsh.test.example', origin: 'https://evil.example', 'x-dsh-proxy-auth': secret },
  ],
  [
    'valid proxy header + cross-site fetch metadata',
    { host: 'dsh.test.example', 'sec-fetch-site': 'cross-site', 'x-dsh-proxy-auth': secret },
  ],
]

let failures = 0
for (const [title, headers] of cases) {
  const outcome = await upgrade({ port, headers })
  const detail = outcome.kind === 'upgraded'
    ? 'upgraded (101)'
    : `${outcome.kind} ${outcome.status ?? outcome.message ?? ''}`
  console.log(`${title.padEnd(52)} -> ${detail}`)
  if (outcome.kind === 'error' || outcome.kind === 'timeout') failures += 1
}
process.exitCode = failures === 0 ? 0 : 1
