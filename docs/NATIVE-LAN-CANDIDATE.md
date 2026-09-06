# Native LAN candidate

Status: local implementation for review, behind the `experimental-lan` feature
of `link-endpoint`. This is a separate endpoint and experimental protocol
identity. It does not amend `SPEC.md`, `RENDEZVOUS.md` or the ratified relay
pairing draft. Both owners must review the exact extension and product evidence
before a production compatibility claim. No Bothy implementation is included.

## Outcome and boundary

Fresh native processes can establish authenticated QUIC directly through
locally supplied addresses and verified Link cards. They need no relay,
reflector, STUN/TURN service, DNS lookup, discovery event or previous connection.
The implementation never initialises the relay-first path socket, a relay
driver or a rendezvous book. A relay hint in a card is not used.

This creates the transport needed for an internet-disconnected product journey.
It does not by itself supply a local signer, adopt a Bothy claim, grant Blossom
upload authority, replicate a vault or prove physical independence. Ordinary
Nostr relays remain an optional way for the application to exchange signed
coordination data; they are not the packet transport for this API.

## Explicit local configuration

`LanEndpoint::open(key, binding)` is the paired endpoint.
`LanPairingListener::open(key, binding, lifetime)` is a separate listener for
one first-contact window. They use separate UDP sockets and protocol identities.
Opening either is an explicit product action; an application must not call it
on load or while Tor-only is selected. Ending or changing the network selection
closes the corresponding endpoint and invalidates its streams.

`LanBinding::default()` is an ephemeral IPv4 loopback development listener.
`LoopbackDevelopment(address)` permits only the selected IP family's literal
loopback destinations. It is useful test infrastructure, not physical LAN proof.

For LAN use the operator chooses `LanBinding::Interface(address)`. The address
must be assigned to a local non-point-to-point interface, with a nonzero,
contiguous netmask. IPv4 private/link-local and IPv6 ULA/link-local addresses
are accepted. Unspecified, public, multicast and wildcard bindings are refused.
A remote destination must be in the same selected subnet; IPv4 network and
broadcast addresses and port zero are refused. Link-local IPv6 requires the
selected local scope ID; that interface ID is supplied locally, not imported
from another machine's card. Global IPv6, VPN/point-to-point and routed remote
subnets are outside this candidate profile.

This is an address and source-binding policy. The operating system still
controls routes; matching a private subnet does not prove a particular cable,
Wi-Fi network or physical interface carried the packets. Physical acceptance
must record the actual topology and traffic.

The caller selects one literal destination which must also match an IP/port
hint in the verified card. The UDP wrapper checks the same address policy
below Quinn, including incoming datagrams and any outgoing protocol packet.
There is no hostname resolution, multicast discovery, port mapping or automatic
address selection. Local interface/address/netmask removal is monitored every
250 ms. A product must still close the endpoint on a profile or network change
which retains the same interface/address; a transport cannot infer that change
from the local address alone.

Address migration and automatic reconnect are disabled. An address is a route
hint, never a peer identity. After a path loss the application must start a new
explicit operation with current consent and a valid selected address.

## Card admission and restart

Use `verify_peer_card(expected_node_id, raw_card, previous_checkpoint)` to
validate the exact bounded FSL1 bytes. The expected transport identity comes
from the product's verified claim relationship or locally trusted pairing
material. A self-signed card or an arbitrary relay response does not establish
that relationship.

Persist the returned `CardCheckpoint` beside that trusted peer before admitting
or dialing it. It contains the accepted serial and SHA-256 of the exact card.
A higher serial may replace a previous card. The same serial is usable only
for the byte-identical current card, allowing an application to restore its
saved record after restart. Older cards, same-serial conflicts, malformed
checkpoints, bad signatures, wrong identities and expired cards fail. The
checkpoint is local state, not a card wire extension or a storage receipt.
Link does not own the product's persistence transaction.

`admit_peer(expected_node_id, raw_card, checkpoint)` rechecks the card and
returns a `LanAdmission`. Keep that handle while the peer remains admitted;
dropping or replacing it immediately invalidates the old lease. Old handles
cannot revoke a replacement. The endpoint retains serial/digest floors for
up to 256 distinct peer identities during its lifetime, including after
revocation. Cross-restart rollback protection depends on the product's saved
checkpoint and trusted peer record.

Each side must explicitly admit the other's current card before ordinary
`connect`/`accept`. Incoming TLS requires an admitted Ed25519 raw public key and
a valid TLS 1.3 signature under that key. The dialler pins the expected server
key. Both sides use the existing raw-public-key identity implementation;
certificate names and public certificate authorities do not substitute for a
pin. The literal `lan.invalid` SNI is not resolved or used as identity.

Generation checks prevent a changed admission from handing an old handshake
to the product. Leases also have a monotonic ceiling so a backwards wall-clock
change cannot extend their initial lifetime. Removing the peer, expiring its
card or closing the endpoint blocks subsequent stream reads/writes, including
already buffered bytes. A remote clean close can still complete an already
authorised buffered response while local admission remains valid.

One current connection is retained per admitted peer. A subsequent completed
connection supersedes the earlier one. Simultaneous dials are bounded but have
no convergence protocol in this candidate: the product serialises dials and
handles a closed attempt explicitly. Shared sessions should be held while
their application streams run; do not open a new session per operation while
another operation still owns the peer's session.

## Candidate protocol

The ALPNs are deliberately separate from deployed Link:

| Surface | Candidate ALPN |
| --- | --- |
| Paired local session | `fsl-lan-candidate/0` |
| Provisional local session | `fsl-lan-pair-candidate/0` |

These names are experimental and not allocated production identifiers. Cards
retain their existing FSL1 encoding; no hint kind is added or reinterpreted.
The product's eventual local offer must distinguish the ordinary and pairing
ports and bind the appropriate card and claim material. That offer and its
local signer journey are Quill's integration work and require owner review.

After the server verifies the mutual TLS handshake and current admission, it
sends one unidirectional readiness stream containing exactly:

```text
ASCII: FSL-LAN-READY followed by byte 0x01
hex:   46 53 4c 2d 4c 41 4e 2d 52 45 41 44 59 01
```

The dialler must receive this exact 14-byte stream and its FIN before returning
a session. TLS client completion alone does not prove that the server accepted
client authentication. The server waits for QUIC acknowledgement, rechecks
admission and then exposes the session. Unknown or additional unidirectional
streams close the connection. No application bytes are carried in readiness.

TLS resumption, tickets and early data are disabled on both sides. Every
connection performs fresh raw-key authentication. Quinn's Retry validates an
incoming source address before its TLS handshake is admitted; this is QUIC
address validation, not a fabricated direct-path proof from the frozen Link
relay state machine. Server-side migration is disabled, and the pinned Quinn
version also refuses peer address migration on clients.

`LanSession` exposes `peer`, `is_live`, bounded stream opening/acceptance and
close operations. It has no relayed, reconnecting or probing state. `LanStream`
implements Tokio asynchronous read/write, so an agreed application protocol can
use it without bypassing admission checks. Its raw Quinn streams are private.
`finish()` waits for QUIC acknowledgement before the caller closes a session;
the application still owns its complete request/response transaction.

## First contact

The pairing listener is explicitly opened for 1–600 seconds and has its own
socket and ALPN. It accepts a well-formed Ed25519 transport key with a valid
TLS signature during that window, except its own identity. That key proves
connection-local possession only. The dialler still pins the box's verified
card before any application secret is sent.

The returned type is `LanPairingSession`, with `provisional_peer()` and exactly
one dialler-initiated application stream. It cannot become a `LanSession` or be
handed to the ordinary paired accept API. There is a 60-second absolute session
ceiling even while data is flowing, a one-MiB ceiling in each stream direction,
and no path upgrade or direct-to-relay fallback. The byte ceiling is strict:
attempting to read/write past it fails, including an EOF check at the boundary.
Pairing messages must fit below that ceiling.

Link does not receive, retain or verify the product's raw pairing secret in
this LAN API. For Bothy, proof of that secret inside box-pinned TLS remains the
claim authenticator; it must be checked before reading or applying a claim
body. Neither a provisional transport key nor readiness grants claim, upload
or storage authority. Quill must implement and test that product boundary.

After a successful product transaction, close the provisional session/window
and establish a separately admitted ordinary session. There is no automatic
promotion of provisional identity into a paired peer. Dropping the pairing
listener invalidates the entire window and its live provisional streams.

## Resource and privacy limits

- Eight active/pending connections per endpoint; at most four concurrent
  incoming TLS handshakes, each with a five-second deadline. The bounded accept
  queue contains at most eight sessions; completed handshake tasks are reaped.
- Sixteen buffered QUIC initial connections, at most 16 KiB each and 256 KiB
  total. Invalid or over-capacity arrivals are ignored, retried or refused.
- Eight ordinary bidirectional streams; one provisional application stream.
  Per-stream receive window is 1 MiB; connection receive/send windows are 4 MiB.
- Idle timeout is 15 seconds, with no keepalive or MTU discovery. An application
  may stream larger ordinary payloads through bounded buffers; the transport
  does not allocate a file-sized buffer.
- Closing network consent blocks further socket sends. A remote peer may learn
  closure through its bounded idle timeout when a close packet cannot drain.
- Routine candidate code emits no peer, address, card or application log data.
  `traffic()` returns aggregate sent/refused datagram counts only. Applications
  must apply their own private logging policy; underlying library tracing is
  not an anonymity guarantee.

Direct LAN exposes local addresses, timing and traffic volume. A pairing peer
also receives the box's transport identity. This is local reachability and
authentication, not an anonymity claim.

## Evidence and remaining gates

### Blob transport adapter

`link-blossom` now has an `experimental-lan` feature. Enable its separate
`shelter-kit` feature for `LanFetcher`, `fetch_blob_over_lan` and
`ShelterBlobSource`. The existing FSLB request, response and version bytes are
reused; there is no new blob wire format. This adapter accepts ordinary admitted
LAN sessions. Provisional pairing sessions cannot be passed to it.

The shared framing work also fixes the existing relayed reader's final-length
check: after its declared bytes it must receive FIN within ten seconds and
reject any extra byte. This enforces the existing T6 contract; the regression
test failed on the previous reader, which silently ignored trailing bytes.

`serve_lan(endpoint, source, limits)` serves at most eight concurrent operations
across the endpoint. `serve_lan_stream` supports an application which has
already read the FSLB prefix. The request must finish at exactly 37 bytes before
the source is consulted. Oversized source declarations fail before a body is
sent. A source's complete returned length is enforced while streaming.

`LanFetcher` takes a dedicated endpoint and locally selected `LanFetchPeer`
entries, each containing an existing admission and one literal card address.
Use one fetcher per dedicated endpoint. It does not discover peers, admit new
keys or resolve relay hints. One fetch per peer may run at a time; another is
refused without replacing the active session. Ending or dropping the returned
body releases that operation. Applications which already hold a session use
`fetch_blob_over_lan` to share it across streams and retain ownership.

The source is the existing `fsl://<node-id>/<sha256>[.<ext>]` URL, with the
transport selected by local configuration. The candidate refuses credentials,
ports, queries, fragments, extra path segments and extensions outside 1–16
ASCII letters/digits. The URL digest must equal the fetch request's digest.
Unknown peers and impossible expected sizes fail before any socket send.

Headers and bodies share one operation deadline. Defaults are one GiB per blob
and five minutes per operation; explicit limits permit up to eight GiB and one
hour. Body chunks are at most 64 KiB. Successful completion requires the exact
length, FIN and requested SHA-256, so a peer cannot supply an oversized,
truncated, corrupt or permanently unfinished response. The storage core still
independently checks every byte and owns authorisation, quota and atomic commit.
The native path is recorded as `FetchPath::Direct`; loopback test topology must
remain attached to that evidence.

`ShelterBlobSource` reads an existing store without creating claims, changing
retention or updating verification time. At most eight local file/database
operations or open bodies hold permits. Blocking operations retain their permit
even if the async caller is cancelled. File reads use 64-KiB buffers; no complete
blob is loaded. The transport emits no identifier logs, while a product must
still account for the storage core's logging policy.

The ordinary test suite exercises a signed BUD-02 upload streamed from LAN into
a second disk store, source recording after verification, deliberate loss and
repair, and recovery from the reopened replica after the original endpoint
stops. This is local-process core integration, not daemon, device or installer
acceptance.

Shelter Kit v0.4.1, still pinned by this branch, rejects native sources in
`PUT /mirror` even though joint contract T6 specifies them. The separate
Shelter Kit 0.4.2 candidate restores that path with authorisation and HTTP(S)
validation preserved. Its combined BUD-04 test is explicitly ignored on the
older pinned dependency. To run it against that candidate in a disposable
checkout, supply its absolute path as a local Cargo patch:

```sh
cargo --config 'patch."https://github.com/forgesworn/shelter-kit".shelter-kit.path="/absolute/path/to/shelter-kit"' \
  update -p shelter-kit
cargo --config 'patch."https://github.com/forgesworn/shelter-kit".shelter-kit.path="/absolute/path/to/shelter-kit"' \
  test -p link-blossom --all-features --test native_lan \
  native_bud04_mirror_and_repair_keep_authorisation_and_recover_after_original_loss -- --ignored
```

Verify Cargo metadata resolves `shelter-kit` to version 0.4.2 at the supplied
manifest path before counting the result. An existing lockfile can retain
0.4.1 and leave the patch unused; that warning invalidates candidate evidence.
Update the lockfile only in the disposable validation checkout.

Record both exact source commits. The patch is local validation only; it is not
a published dependency or a change to Bothy's manifests. The ordinary
dependency pin must move to an available reviewed release before a product
claims native BUD-04 support.

### Transport and product gates

Run `cargo test --workspace --all-features`, the all-target/all-feature Clippy
check, and formatting checks. `native_lan.rs` covers fresh mutual admission,
5 MiB + 31 bytes streamed with an exact digest, unknown clients, a real TLS
server presenting the wrong key, bad/expired/replayed cards, socket/address
restrictions, an unused relay hint, lease revocation, checkpoints and restart
on the retained keys/addresses. It also exercises provisional first contact,
window/stream bounds, capacity refusal and capacity recovery.
An interrupted readiness stream is refused before product admission.

The raw-client test bypasses the cooperative client's session timeout, keeps
transferring, and verifies that the server itself enforces the absolute
60-second pairing ceiling. These are local-process tests with synthetic keys
and traffic. They do not prove physical LAN operation or a Bothy claim journey.

Remaining requirements include the agreed local offer and signer flow, exact
owner review, daemon/app wiring and the reviewed native-mirror core release,
complete application authorisation,
cancelled/interrupted product transactions, hostile-peer review, cross-platform
and physical phone/Linux tests, and independent acquisition and recovery with
ForgeSworn endpoints blocked. The internet-disconnected two-device journey and
independent operator failure tests remain mandatory before completion.

Implementation references: Quinn's
[incoming address validation](https://docs.rs/quinn/0.11.11/quinn/struct.Incoming.html),
[server bounds](https://docs.rs/quinn/0.11.11/quinn/struct.ServerConfig.html) and
[transport controls](https://docs.rs/quinn/0.11.11/quinn/struct.TransportConfig.html).
The existing frozen Link TLS/card implementation remains the identity and card
encoding reference.
