// The page side of the link-web end-to-end test, run by browser_e2e.rs in
// Node (whose global WebSocket stands in for a browser's).  It reads its
// input as JSON on stdin and prints one `E2E_REPORT {...}` line.  Nothing
// secret is printed: the report carries lengths and outcomes, never the
// seed, the pairing secret or the route secret.

import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'

const input = JSON.parse(readFileSync(0, 'utf8'))
const require = createRequire(import.meta.url)
const { LinkEngine } = require(join(input.pkg, 'link_web.js'))

const utf8 = text => new TextEncoder().encode(text)
const text = bytes => new TextDecoder().decode(bytes)
const fromHex = hex => Uint8Array.from(hex.match(/../g), byte => parseInt(byte, 16))
const fromBase64 = b64 => new Uint8Array(Buffer.from(b64, 'base64'))
const within = (promise, label, ms = 30_000) =>
  Promise.race([
    promise,
    new Promise((_, fail) => setTimeout(() => fail(new Error(`${label} timed out`)), ms)),
  ])
const refused = async promise => {
  try {
    await promise
    return null
  } catch (error) {
    return String(error.message ?? error)
  }
}
const echoRequest = label => ({
  routeId: 'box',
  method: 'POST',
  path: '/cadence/v1/echo',
  authorization: 'Nostr YQ==',
  body: utf8(JSON.stringify({ v: 1, from: label })),
})

const report = {}
const seed = crypto.getRandomValues(new Uint8Array(32))

report.refusedWsRelay = await refused(
  LinkEngine.start({ transportSeed: seed, relayUrls: ['ws://127.0.0.1:9/link'], routes: [] }),
)

const engine = await LinkEngine.start({ transportSeed: seed, relayUrls: [input.relayUrl], routes: [] })

const route = await within(
  engine.pairRoute({
    routeId: 'box',
    serverCard: fromBase64(input.serverCard),
    pairingSecret: fromHex(input.pairingSecret),
    expiresAt: input.expiresAt,
  }),
  'pairing',
  60_000,
)
report.paired = {
  routeId: route.routeId,
  keys: Object.keys(route).sort(),
  card: Buffer.from(route.card).toString('base64'),
  secretBytes: route.pairedRouteSecret.length,
  // u64 fields cross as BigInt; reported as decimal strings.
  serialTypes: [typeof route.cardSerial, typeof route.cardVerifiedAt],
  cardSerial: String(route.cardSerial),
  cardVerifiedAt: String(route.cardVerifiedAt),
}

const reply = await within(engine.request(echoRequest('first')), 'request', 60_000)
report.request = { status: reply.status, body: text(reply.body), path: reply.path }

report.refused = {
  path: await refused(engine.request({ ...echoRequest('bad'), path: '/events' })),
  method: await refused(engine.request({ ...echoRequest('bad'), method: 'GET' })),
  socketPath: await refused(engine.openSocket(`ws://${input.serverNode}/other`, 'box', {})),
  socketPeer: await refused(engine.openSocket(`ws://${input.otherNode}/events`, 'box', {})),
  socketScheme: await refused(engine.openSocket(`wss://${input.serverNode}/events`, 'box', {})),
  unknownRoute: await refused(engine.request({ ...echoRequest('bad'), routeId: 'nope' })),
}

const events = []
let echoed
let closed
const gotEcho = new Promise(resolve => (echoed = resolve))
const gotClose = new Promise(resolve => (closed = resolve))
const socket = await within(
  engine.openSocket(`ws://${input.serverNode}/events`, 'box', {
    onOpen: () => events.push('open'),
    onText: message => {
      events.push('text')
      echoed(message)
    },
    onClosed: reason => {
      events.push('closed')
      closed(reason)
    },
  }),
  'socket open',
)
socket.sendText('hello over link')
report.socket = { echo: await within(gotEcho, 'socket echo'), path: socket.path().status }
report.socket.oversize = (() => {
  try {
    socket.sendText('x'.repeat(1_048_577))
    return null
  } catch (error) {
    return String(error.message ?? error)
  }
})()
socket.disconnect()
report.socket.closed = await within(gotClose, 'socket close')
report.socket.events = events

const stopping = engine.stop()
if (engine.stop() !== stopping) throw new Error("repeated stop did not return the completion barrier")
await within(stopping, "engine shutdown", 5_000)
report.refusedAfterStop = await refused(engine.request(echoRequest('stopped')))

// A restarted page: the same seed and only the persisted record.
const again = await LinkEngine.start({ transportSeed: seed, relayUrls: [input.relayUrl], routes: [route] })
const second = await within(again.request(echoRequest('restarted')), 'restarted request', 60_000)
report.restarted = { status: second.status, body: text(second.body) }
await within(again.retireRoute('box'), 'retire')
await within(again.finalizeRoute('box'), 'finalize')
await again.removeRoute('box')
report.removedRefuses = await refused(again.request(echoRequest('removed')))
await within(again.stop(), "restarted engine shutdown", 5_000)

console.log(`E2E_REPORT ${JSON.stringify(report)}`)
process.exit(0)
