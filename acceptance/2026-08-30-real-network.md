# ForgeSworn Link, real-network results, 30 August 2026

Re-run of the public-host rows on `main` at `fb657e6`, after the day's
changes: every-interface candidates, `punch-now`, the network monitor,
session-keyed probes, relay hints, raw public keys, and the one-session-per-
peer rule.  Two hosts, no personal identifiers:

- **mac**: macOS arm64 release build, behind a NAT it does not control (a
  venue network, private range `<mac-lan>`, egress `<mac-egress>`), no VPN.
- **pub**: public cloud host `<pub-host>`, 1 vCPU, 961 MB, no NAT, Linux
  x86_64 static musl build (`cross`).  Runs the relays, the reflectors and the
  serving endpoints.  Its firewall was opened for the mac's egress address
  only, for the duration of the run, and closed again.

Relays on pub: primary `wss` :7443, secondary `wss` :7444 (both self-signed
and pinned by fingerprint on every client), plain `ws` :7445 for the capture
row; reflectors :7450 / :7451 / :7452.  Serving endpoints bound :7460 (main,
under the RSS sampler) and :7461 (capture).  Both sides were configured with
the same relay list in the same order, which the card's relay hints then
reproduce; a hinted relay with a self-signed certificate is reachable only
that way, as SPEC 3.1 says.

`status` is what each PathReport reported, never inferred from a successful
transfer.  Every digest matched.

| Row | Setup | Result | Evidence |
| --- | --- | --- | --- |
| venue NAT to public | mac sends 64 MiB to pub | **DIRECT** proved `<pub-host>:7460`; pub proved `<mac-egress>:58878` | `relayed -> probing -> direct`; 10.1 s wall on the venue uplink; `log-send-mac-nat-to-pub-0830.txt` |
| same key, straight back | the same mac key sends 64 MiB again at once, while pub still holds the first session | **DIRECT**, 6.4 s (faster than the first run: no stall) | pub's first session: `direct -> failed(superseded)`; this is the rule #29 added, on a real network; `log-send-mac-nat-to-pub-samekey-0830.txt` |
| relay only | mac `--no-direct`, 32 MiB | **RELAYED**, never direct | 4.4 s; `log-send-mac-relayonly-0830.txt` |
| UDP blocked | pub drops all UDP from the mac's egress (firewall), 24 MiB | **RELAYED** only, nothing proved | candidates exchanged, the probing round was still open when the transfer completed (3.1 s), no pong ever arrived; `log-send-mac-udpblock-0830.txt` |
| privacy capture | `tcpdump` on pub during a 16 MiB relay-only transfer over the plain `ws` relay | **0 plaintext windows** in 32,507 packets / 37,969,575 bytes against 581,616 payload windows | `pcap-leak-check.py`, same method as 27 Aug |
| relay loss | mac over two relays `--no-direct`, 96 MiB, primary killed 3 s in | **failover** `relayed -> reconnecting -> relayed` on :7444 after 239 ms (mac) and 2 ms (pub, which reaches the relay on loopback); transfer completed, 13.8 s | `log-send-mac-failover-0830.txt`, `log-pub-serve-main-0830.txt` |
| streaming / memory | pub serves 64 then 256 MiB, both direct, one process | peak RSS **6,938,624 bytes** (6.6 MiB) across both | `rss-run.py`; 27 Aug on the Pi was 7.78 then 9.58 MiB |

Server-side logs for the main endpoint are in `log-pub-serve-main-0830.txt`; note
the venue NAT's per-session mappings (`:58878`, `:52241`, `:58331`, `:58668`)
are all proved by pub, so this NAT gives one stable mapping per socket.

## What changed since 27 August, as seen here

- The venue NAT is not a home NAT and not under our control; a direct path
  still proved in both directions.  That is one side of the "hostile NAT"
  class the 27 August record said had no data.
- The card now carries every interface of the serving host as a candidate
  (seven on pub, including its private and container-bridge addresses); the
  mac probed them all and only the public one answered, which is the point.
- The same-key row did not exist before.  It is the app-restart case, and it
  was broken until #29 (a 21 s handshake, or none).

## Not covered today

- **The LAN rows** (mac to Pi, explicit bind and VPN-default-route) and the
  **Pi-side rows**: the mac was not on the home LAN.  The VPN-default-route
  row is the one that changed (every interface is now offered) and it still
  has not been re-run on a real VPN.
- **Two hostile NATs at once**, and **carrier-grade NAT from a phone**: one
  side here was public.
- **Windows** as an endpoint host.
- **Android** and background operation.
