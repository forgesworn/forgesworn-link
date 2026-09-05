# Founders' Link relay

Bothy's default `wss://link1.forgesworn.dev/link` needs a running Link relay.
This deployment puts that service on an approved existing Linux host. It
does not require a new VPS for each keeper. Bothy can configure other Link
relays; this service remains an availability dependency for clients using
the default. A different architecture is outside this deployment.

**Selected host: `stall`, `62.238.98.53` (Hetzner Online GmbH, Helsinki).**
The existing app host has x86-64 Ubuntu, systemd and Caddy; its Caddyfile
imports `/etc/caddy/conf.d/*.Caddyfile`. Install this vhost as
`/etc/caddy/conf.d/link1.Caddyfile`, with a dedicated `link-relay-deploy`
account. This adds a service to the existing host and requires no new VPS.
Provider and host configuration were verified on 2026-09-05; setup is
complete only after the deployment and public checks below pass.

DigitalOcean and the retired `95.217.39.110` destination from the original
draft are excluded. In particular, `144.126.230.165` is DigitalOcean.
The workflow still requires an explicitly configured deployment host.

## Topology and limits

`link1.forgesworn.dev:443` terminates ordinary WebPKI TLS at Caddy and
proxies `/link` to `ws://127.0.0.1:7443`. The relay's plaintext listener is
loopback only. UDP 7450 reaches the reflector directly; Caddy does not
proxy it. Use DNS-only records, with an A record for the approved IPv4
address and an AAAA record only after proving service on IPv6.

An ordinary HTTPS request to `/link` returns `400 Bad Request` with a
message explaining the required WebSocket upgrade; `/` and other paths
return `404`. These responses omit the connection-specific `Upgrade`
header, which HTTP/2 forbids. Caddy supplies
these explanatory responses because the relay closes non-WebSocket
requests without an HTTP response, which an unrestricted proxy reports
as `502 Bad Gateway`. These static responses do not prove backend health:
the public check must also complete a real `101` WebSocket handshake, and
the transfer check below must pass before calling the data path live.

The unit uses a dynamic unprivileged user, read-only system files, no
capabilities, a 256 MiB memory ceiling, 64 tasks and at most one CPU's time.
The binary has 128 total sessions, 16 sessions per TCP source, a 5 MB/s
outbound limit per session and 20 reflector replies per source per second.
These are initial ceilings, not measured capacity claims.

**Proxy limitation:** every WebSocket connection reaches the relay from
Caddy's loopback address. The existing per-source cap therefore limits the
whole proxied service to 16 sessions; it does not isolate public clients.
Keep that conservative limit for the founders' trial. A larger deployment
needs a reviewed way to enforce limits at the public ingress. Do not trust
arbitrary forwarded headers or silently remove the cap.

The canonical lowercase hostname participates in tag derivation, so keep
it stable when moving the host. `--host` also sets the identity-mode host;
Bothy's tag mode does not use that authentication field. Clients use
`RelaySpec::plain("wss://link1.forgesworn.dev/link")` with ordinary trusted
roots and no leaf pin. The selected source must include the logging and
WebPKI fixes in PR #13 and the session limits in PR #16.

Run at `RUST_LOG=info` and discard the Caddy access log using the supplied
snippet. The TLS terminator sees client IPs while connections are active.
Do not enable debug logging, log frames or record pairing material. Check
the actual host's global logging configuration as well as this vhost.

## Operator setup

Confirm the approved host's provider, ownership, architecture, available
resources, existing TLS service and firewall before changing it. This
workflow builds **x86-64 Linux**; it is unsuitable for an ARM host. The
receiver requires `/usr/bin/python3` and `/usr/bin/systemctl`, using fixed
paths rather than searching a caller-controlled environment.

On that host, using the operator's existing trusted administrative access:

1. Create root-owned `/opt/link-relay` (0755). Install `install-release.py`
   as `/usr/local/libexec/install-link-relay` (root:root, 0755) and the unit
   as `/etc/systemd/system/link-relay.service` (root:root, 0644). Neither
   these files nor their parent directories may be writable by deployment
   or service users. Run `systemd-analyze verify` and `systemctl daemon-reload`.
2. Create a dedicated SSH deployment account and key. Its only authorised
   key uses `restrict,command="sudo -n /usr/local/libexec/install-link-relay"`.
   Keep the account's authorised-keys file and parents root-owned. Its
   sudoers rule permits only that receiver with **no arguments**; validate
   the rule with `visudo -cf`. Do not grant shell access, general sudo,
   service-file writes or access to another project's deployment key.
3. Add the Caddy snippet to the actual running TLS service, validate its
   complete configuration and reload it. Open TCP 443 and UDP 7450 only
   as needed; retain the loopback-only TCP 7443 listener. Preserve existing
   sites and the current configuration for rollback.
4. Create the DNS record for the approved host. Confirm both authoritative
   nameservers agree before relying on cached public answers.
5. Set repository variables `LINK_RELAY_SSH_HOST` and `LINK_RELAY_SSH_USER`.
   Set secrets `LINK_RELAY_DEPLOY_KEY` and `LINK_RELAY_KNOWN_HOSTS` from the
   dedicated key and a host key verified through the trusted operator
   channel. Deployment never runs `ssh-keyscan` to establish trust.

The receiver accepts a bounded JSON header and one binary, verifies length,
SHA-256 and x86-64 ELF format, then stores a root-owned release under its
source commit and digest. It never executes the upload as root. A locked,
atomic symlink switch activates the fixed sandboxed service. A failed
service start restores the previous release; failure of a first deployment
stops it. Retained release directories support operator rollback.

## Build, deploy and prove

Run `python3 -m unittest discover -s deploy/founders -p 'test_*.py' -v`.
Repository CI also checks these upload and rollback cases. Complete the
Rust format, Clippy and test jobs before merging the deployment change.

Dispatch `Deploy founders' relay` on `main` with `source_commit` equal to
the exact reviewed current main SHA. The workflow builds with locked
dependencies and Rust 1.94.1, streams the binary through the forced SSH
receiver and verifies trusted TLS plus an actual `/link` WebSocket upgrade.
It stores a receipt containing the source commit, binary digest and active
service result. A later `main` commit requires its own review and dispatch.

After the first successful installation, enable the service at boot using
the operator account. Record the remote current release, service status,
listener bindings and firewall result. Test an actual tag-mode transfer
through the public relay before calling the data path live; TLS alone does
not prove file delivery. Check logs for accidental identity or payload
logging without copying private session data into reports.

Run the opt-in public data check from the reviewed source:

```sh
LINK_PUBLIC_RELAY=wss://link1.forgesworn.dev/link \
  cargo test --locked -p link-endpoint --test public_relay -- --ignored
```

This transfers and verifies 1 MiB between two synthetic clients, with direct
paths disabled and a two-minute deadline. It verifies a public relay path
from one test host; it does not test real phones or different NATs. Normal
CI compiles this test but never contacts the public service.

The manual `Check public founders' relay` workflow verifies the ordinary
HTTP/1.1 and HTTP/2 responses, trusted TLS, the WebSocket upgrade and a
nonce-checked UDP reflector reply from a GitHub runner. It changes no service or DNS state
and needs no deployment secrets.
Use it to distinguish a problem on the operator's network from public
ingress failure. It is never triggered by ordinary pushes or pull requests.
The endpoint probe requires Python 3 and curl with HTTP/2 support.

For a failed public check after a successful service start, the operator
must diagnose DNS/TLS/ingress or restore the previous root-owned release
symlink and restart the service. Automatic receiver rollback covers a
failed local service start; it cannot repair DNS or Caddy.

Bothy issue #8 also needs an Android build that suppresses pairing codes
while disconnected. A public relay smoke test and Android unit tests do
not establish a successful two-phone pairing, keeper upload or second-copy
reconcile. Those require their separate acceptance evidence.
