# Private Link relays

Relay operators can issue and revoke a separate random key for each client.
An admitted client uses the same rendezvous tags and end-to-end QUIC as any
other paired Link client. This grant permits use of one relay and leaves the
app responsible for deciding which peers can talk to each other.

## Start a relay with an allowlist

Create a directory accessible only to the account running the relay. Generate
a different 32-byte key for each client, encoded as 64 hexadecimal characters.
Keep the key files outside source control and give each client only its own
key over a trusted channel. The example uses a private directory on macOS or
Linux.

```sh
relay_dir="$HOME/.link-relay"
mkdir -p "$relay_dir"
chmod 700 "$relay_dir"
umask 077
openssl rand -hex 32 > "$relay_dir/sender.key"
openssl rand -hex 32 > "$relay_dir/receiver.key"
cat "$relay_dir/sender.key" "$relay_dir/receiver.key" > "$relay_dir/allowed.keys"
```

From the Link repository root, start the relay on loopback for a local trial.
Use a reachable approved address for a two-device setup. Each client needs
the relay's `relay_url` and, for the self-signed leaf, its `tls_sha256`.

```sh
cargo run --locked -p link-relay -- \
  --ws-bind 127.0.0.1:7443 --host 127.0.0.1 \
  --admission-keys-file "$relay_dir/allowed.keys"
```

This mode accepts up to 256 distinct keys. The binary checks the file every
second. Write changes to a new private file and rename it over the current
one so readers see a complete list. An empty file denies access to all
clients. A missing, unreadable or invalid list closes access until a valid
file is available again. Without any admission option the relay uses ordinary
Link registration.

For example, keep only the receiver's grant to remove the sender's access.

```sh
cat "$relay_dir/receiver.key" > "$relay_dir/allowed.next"
mv "$relay_dir/allowed.next" "$relay_dir/allowed.keys"
```

The removed key's WebSockets are closed and subsequent connections using it
are refused. Other grants stay active. Issue a new key to re-authorise a
client after revocation. An app manages its peer permissions separately,
including any already authorised direct path or other relay. Use different
keys for different relays.

## Configure a Rust client

Attach the issued `RelayAdmissionKey` to the approved relay with
`RelaySpec::with_admission_key`. Load the key from protected local storage.
The client requires `wss://` with normal certificate verification or an
approved certificate pin. A loopback-only relay backend can sit behind a TLS
terminator operated by the relay owner. The same grant setting applies to
initial pairing and to restored paired routes.

The Rust relay library exposes the same policy through `start_with_admission`
and `RelayAdmission::replace_keys`.

## Wire extension version 1

On an admission-controlled listener the first frame is `0x05` followed by
32 fresh random challenge bytes. The client answers with `0x06`, a 32-byte
proof, then the ordinary encoded roster as `u16be count || tags`. The roster
has 1 to 256 tags, each 16 bytes. The proof is

```text
HMAC-SHA256(key, "forgesworn-link/relay-admission/v1\0" || challenge || SHA256(roster))
```

The relay checks configured keys and only adds the roster to its table after
one proof verifies. It replies with the ordinary `Welcome` and accepts the
ordinary replacement `Register` on that admitted connection. Refused or
revoked grants use `Close(3)`. A client configured with a grant requires the
admission challenge, and a client without one stops when it receives that
challenge. Ordinary relays keep the existing `Challenge` and registration.

The relay can associate separate connections with the same grant. It also
sees its usual connection metadata, including source addresses, timing,
traffic volume and the tags. The admission frames carry neither the raw key
nor a persistent peer ID. Verification of the remote peer and its authority
happens inside the end-to-end session.
