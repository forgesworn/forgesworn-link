# The founders' relay

This is configuration, not protocol. It stands up one `link-relay` (Phase 0
relay + reflector, this repository) as the founders' shared ForgeSworn Link
relay for Bothy Phase 1a and the 0-L acceptance gates. Nothing in
`crates/link-relay` changes to run it; this directory only says how one
instance is placed on the estate's shared box, hardened, and kept running.

**Sunset.** This relay is scaffolding, not infrastructure to depend on
indefinitely. It is retired — or demoted to one relay among several — once
three independent relays exist for the network to converge across (see
`SPEC.md`'s open problem on relay convergence, and Bothy's own plan to run
further relays as other keepers come online). Until then it is the only relay
either side has.

## Topology

```
                 wss://link1.forgesworn.dev
                          |
                          v
   +------------------------------------------------+
   |  Caddy (WebPKI cert, ordinary Let's Encrypt)    |
   |  reverse_proxy 127.0.0.1:7443                   |
   +------------------------------------------------+
                          |  ws:// (loopback only)
                          v
   +------------------------------------------------+
   |  link-relay --insecure-ws                       |
   |    --ws-bind 127.0.0.1:7443                     |
   |    --host link1.forgesworn.dev                  |
   |    --udp-bind 0.0.0.0:7450  <-- public, direct   |
   +------------------------------------------------+
                          ^
                          |  UDP 7450, firewall opened directly
                     (Caddy cannot proxy UDP, so the
                      reflector is not behind it)
```

- Caddy terminates WebPKI TLS for `link1.forgesworn.dev` and reverse-proxies
  the WebSocket upgrade to `link-relay --insecure-ws` listening on loopback,
  `127.0.0.1:7443`. `--insecure-ws` is safe here precisely because the bind is
  loopback: the plaintext `ws://` hop never leaves the box.
- The UDP reflector binds the public interface directly,
  `--udp-bind 0.0.0.0:7450`, because Caddy has no UDP reverse proxy. The
  firewall opening for UDP 7450 is a box-owner step, listed below.
- The firewall opening and the Caddy vhost are **the box owner's steps**, not
  this repository's. This directory ships the unit, the flags and a Caddyfile
  snippet to review; it does not touch the box's firewall or its running
  Caddy configuration.

## The five review points (Wildbloom side, ledger C9)

1. **`wss://` with an ordinary WebPKI certificate, never a pinned leaf.** The
   relay binary's own TLS path (`TlsMaterial::self_signed`) is a throwaway
   self-signed leaf for the loopback demo; a deployed relay must present a
   certificate an unmodified client trust store accepts. That is exactly why
   TLS is not the relay binary's job here — Caddy holds the WebPKI
   certificate and `--insecure-ws` keeps the relay out of the TLS business
   entirely.
2. **The public hostname, lowercase, is the exact string every client puts in
   its `RelaySpec` URL.** Tag derivation binds to it (`RENDEZVOUS.md` §2); a
   rename rotates every tag for every pair. `link1.forgesworn.dev` is
   therefore permanent once in use, not a label to tidy up later.
3. **The `--host` list matters only for identity-mode auth**, not for tag
   mode (tag sessions carry no node ID at all — `SECURITY.md`). Bothy runs
   tag mode exclusively, so `--host` is inert to the traffic this relay
   actually carries, but it is set correctly anyway (`--host
   link1.forgesworn.dev`) so identity-mode auth, if ever used against this
   relay, binds to the right name and not to the loopback default.
4. **Real `--bytes-per-second` and `--max-sessions` for the box size, modest
   `--reflector-per-second`.** `5000000` (5 MB/s) is twice a phone's realistic
   upstream ceiling per session; `2000` sessions fits a 1-vCPU box's file
   descriptors with margin; `20` reflector replies per source per second is
   the relay binary's own default, left alone rather than raised.
5. **The relay MUST NOT log tags — the code never does** (`link-relay`'s tag
   path never surfaces a `Tag` value to `tracing`; see `SECURITY.md`'s tag-mode
   paragraph). The deployment must not wrap it in anything that logs frames,
   which is why the Caddy vhost's access log is disabled (`Caddyfile.snippet`,
   `log { output discard }`) — an access log on the reverse proxy would
   otherwise record connection metadata Caddy itself has no business keeping
   for a relay that promises not to.

## Verify after deploy

```sh
curl -I https://link1.forgesworn.dev
```

Expect an HTTP response from Caddy (a `400`/`426` or similar on a plain GET
to a WebSocket-only path is fine and expected — the point is a valid WebPKI
TLS handshake and a response from Caddy, not an application-level 200).
Confirm with `openssl s_client -connect link1.forgesworn.dev:443
-servername link1.forgesworn.dev` or a browser that the certificate is an
ordinary, trusted, non-self-signed WebPKI leaf.

```sh
journalctl -u link-relay -f
```

Expect only tokens and counters: session-count and cap lines, accept/close
lines, byte and frame counters, reflector rate-limit lines. No node ID, no
Nostr key, no tag bytes, no frame payload. If a line ever shows a tag value,
that is a defect in the relay code, not a deployment misconfiguration, and
should be reported the way `SECURITY.md` describes.

## What the box owner does by hand

This directory does not touch any of these; they are listed here so nothing
falls through the gap between "the code is ready" and "the relay is live".

- **DNS.** A and AAAA records for `link1.forgesworn.dev` pointing at the
  shared box.
- **The Caddy vhost.** Add `Caddyfile.snippet`'s block to the box's running
  Caddy configuration and reload Caddy. The `log { output discard }` line is
  marked "to be confirmed" in the snippet — the box owner should check it
  against however Caddy is actually configured on that box (a global default
  that already discards access logs would make the per-site line redundant,
  not wrong).
- **Firewall.** Open UDP 7450 inbound (the reflector). TCP 443 for Caddy is
  presumably already open for the box's other vhosts.
- **Sudoers.** The `deploy` user needs passwordless `sudo` for exactly the
  commands the deploy workflow runs as that user: installing the unit file,
  `systemctl daemon-reload`, and `systemctl enable --now link-relay` /
  `systemctl restart link-relay`. Nothing broader.
- **The repository secret.** `HETZNER_SSH_KEY` on this repository (the same
  key and box the `joystick` broker and `cambium` site deploys already use),
  set up and owned by the box owner, as ever.

## Building and running it directly (for reference)

See the repository `README.md`'s "Running this on real machines" section for
the general shape. This deployment differs from that section's step 1 in one
respect: rather than dropping `--insecure-ws` and having `link-relay` present
its own certificate, TLS is terminated by Caddy in front of a loopback-bound,
`--insecure-ws` relay. Both get an ordinary WebPKI certificate to the client;
this way the relay binary never needs a certificate-renewal story of its own.

## Review record

Approved by the Wildbloom side on 2026-08-30 (ledger C9) with three
conditions, all folded in:

1. **Run the relay at a commit including `#13`** (`0a78b8cff`). Before it,
   `info` logging wrote each session's source IP into the journal; from `#13`
   session-up logs the token only and the address is `debug`. The deploy
   workflow builds `main`, which includes it; never deploy an older tag.
2. **Caddy proxies `/link` for WebSocket with no idle timeout** under the
   relay's 20-second ping cadence and **no buffering** that delays frames —
   see `Caddyfile.snippet` (`flush_interval -1`; Caddy applies no idle
   timeout to an upgraded connection).
3. **For the record:** Caddy as TLS terminator sees client IPs in the moment.
   With the vhost access log discarded that is as blind as a terminating
   proxy gets, and the relay behind it writes none.

Also from `#13`: `wss://` relays verify against bundled WebPKI roots by
default, so clients use `RelaySpec::plain("wss://link1.forgesworn.dev/link")`
with no pin and no flag.

`--sessions-per-source 16` (link `#16`, the relay's default, set explicitly): a tag session presents no identity, so the per-source cap is what stops one address holding every slot; the rendezvous section makes it a MUST.
