# Paired file transfers in Rust

Copy this directory into a new project to send files between two devices over
your own Link relay. The first transfer uses a five-minute invite. Each peer
saves its pairing locally and can transfer another file after a restart.

Build on each client with Rust 1.94.1 or newer.

```sh
cargo build --locked
```

## Start your relay

From the ForgeSworn Link repository root on the relay host, run this for a
one-machine trial.

```sh
cargo run --locked -p link-relay -- --ws-bind 127.0.0.1:7443 --host 127.0.0.1
```

For two machines, replace both loopback addresses with the relay host's
reachable private LAN or VPN address. Limit ingress to that network. Copy
the printed `relay_url` and `tls_sha256` to both clients through a trusted
channel. Keep this relay process running for the trial. Its self-signed
certificate is generated at startup, and the saved pair pins that certificate.
For a relay with a normally trusted certificate, omit `--relay-cert-sha256`.
For an [admission-controlled relay](https://github.com/forgesworn/forgesworn-link/blob/main/docs/relay-admission.md), each peer
adds `--relay-admission-key-file /path/to/my.key` to its first pairing command.
Use the individual file supplied by the operator and keep it private.

## Pair and send the first file

From the starter directory on each machine, set the URL and pin you received.
Use a state directory accessible only to your local account. These commands
set up a directory on macOS or Linux.

```sh
relay='wss://127.0.0.1:7443/link'
pin='<printed tls_sha256>'
state_dir="$HOME/.link-paired-files"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
```

On the receiver, use a fresh output path and a fresh pairing path.

```sh
cargo run --locked -- pair-receive --state "$state_dir/receiver.pair" \
  --relay "$relay" --relay-cert-sha256 "$pin" received-first.txt
```

Share the text after `invite` privately with the sender. On the sender, create
an example input file and paste the invite at the prompt.

```sh
printf '%s\n' 'hello from Link' > first.txt
cargo run --locked -- pair-send --state "$state_dir/sender.pair" \
  --relay "$relay" --relay-cert-sha256 "$pin" first.txt
```

Both processes exit after printing the byte count, SHA-256 and `path=relayed`.
The receiver saves the output after checking its digest and keeps any prior file
at the chosen path. The pairing files contain credentials. Keep them private.

## Start new processes and send again

On the receiver, start the next transfer and wait for `ready for paired transfer`.

```sh
cargo run --locked -- saved-receive --state "$state_dir/receiver.pair" received-next.txt
```

On the sender, the saved pairing supplies the relay, peer and route credentials.

```sh
printf '%s\n' 'hello again' > next.txt
cargo run --locked -- saved-send --state "$state_dir/sender.pair" next.txt
```

Each record belongs to one role in one pair. Use fresh state paths when
pairing again, including after changing a pinned relay certificate. If the
first transfer fails after both sides saved state, retry with the saved commands.
If you paired through a private relay, the saved pairing holds the path of
your grant file. To use a different grant file for one run, pass
`--relay-admission-key-file` to the saved command.

[`src/paired.rs`](src/paired.rs) shows the authenticated invite and verified
stream. [`src/state.rs`](src/state.rs) shows how to restore a pair and keep the
same pinned peer after the invite expires. Use your application's protected
storage when embedding this flow.
