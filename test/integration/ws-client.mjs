/**
 * Minimal, dependency-free WebSocket upgrade client used by the integration
 * tests. It performs the RFC 6455 opening handshake over node:http and reports
 * either a completed upgrade (HTTP 101) or the HTTP status the auth gate
 * answered with.
 */
import { randomBytes } from 'node:crypto'
import http from 'node:http'

/**
 * Attempt one WebSocket upgrade against a running DSH server.
 *
 * @param options - connection facts.
 * @param options.port - loopback port of the running server.
 * @param options.path - request path (default `/api/remote.mux`).
 * @param options.headers - extra request headers (Host, Origin, proxy secret).
 * @param options.timeoutMs - give-up delay (default 5000).
 * @returns `{ kind: 'upgraded', status }`, `{ kind: 'http', status }`,
 *   `{ kind: 'timeout' }`, or `{ kind: 'error', message }`.
 */
export function upgrade({ port, path = '/api/remote.mux', headers = {}, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: 'GET',
      headers: {
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-version': '13',
        'sec-websocket-key': randomBytes(16).toString('base64'),
        ...headers,
      },
    })
    const finish = (outcome) => {
      clearTimeout(timer)
      resolve(outcome)
    }
    const timer = setTimeout(() => {
      request.destroy()
      finish({ kind: 'timeout' })
    }, timeoutMs)
    request.on('upgrade', (response, socket) => {
      socket.destroy()
      finish({ kind: 'upgraded', status: response.statusCode })
    })
    request.on('response', (response) => {
      response.resume()
      finish({ kind: 'http', status: response.statusCode })
    })
    request.on('error', (error) => finish({ kind: 'error', message: error.message }))
    request.end()
  })
}
