# Private relay trial on two machines, 26 November 2026

The relay and diagnostic CLI were built from ForgeSworn Link commit
`54957eb261493afde22ae5a9838dc36d53a06cd6`. Both clients used release builds of
the copyable paired-files starter with its locked transport dependency at
`09fa9ae7e80840e5713da9b2d7b6e66d6a0f0165`.
[Tested source](https://github.com/forgesworn/forgesworn-link/tree/54957eb261493afde22ae5a9838dc36d53a06cd6)

## Setup

An Apple M4 Max running macOS 26.6.2 hosted the relay and sender. A Raspberry
Pi 5 running 64-bit Debian 12 with glibc 2.36 hosted the receiver. The relay
listened on a private IPv4 address and an ephemeral port on the Mac. The Pi
had an on-link route to that address, and the relay process showed an
established TCP socket to the Pi's own LAN address. Both clients pinned the
relay's TLS leaf and used distinct synthetic grants. The sender process
read the Pi's one-use invite from standard input.

The builds used Rust 1.94.1 and `--locked --release`. The Pi binaries were
cross-built with GCC 15.2.0 for `aarch64-unknown-linux-gnu`. Their SHA-256
digests matched after copying to the Pi.

| Binary used | SHA-256 |
| --- | --- |
| macOS `link-relay` | `bc8be30998a64c872f8f912f0e265a00fe297e99ae5aa52182fd918a62e5c424` |
| macOS `link-paired-files` | `e88a108e2d2ba16e57caa2cc16383da52ab0c3c93a06933d3ac8ce0c08e244b1` |
| Linux `link-paired-files` | `306f6b9e09d0b32cb0f380882d0ca74cf4360a66d750b01c7ae2999467fcf371` |
| Linux `link-spike` | `1d1048cc70e0859dc3df801b29aa2c93be713824dbaca888547ba87a56816e5a` |

## Results

Each transfer carried 1 MiB of synthetic data generated with SHAKE-256 from
`Link two-machine LAN acceptance round N`, where `N` is 1, 2 or 3. Both clients
reported the same SHA-256 and `path=relayed`. Independently hashing each saved
file on the Pi matched both reports.

| Transfer | Pi file SHA-256 |
| --- | --- |
| First invite and transfer | `627d2813b4f19d33685faecb0765cf3b2231e24d08bf1c51d8e82e8227e054a8` |
| New processes on both machines with the saved pairing | `13a548149dfe8cff8e2e93826ebac561461ac7514b867622ea948feb8da5e1de` |
| Original pairing with a replacement receiver grant | `3f85b86324bc510b3bc37a1c7a87ec01b9ddd342b1d6dbfef23c1882d48deef1` |

- **Live revocation.** A fresh `link-spike saved-receive` on the Pi reported
  ready. The operator atomically replaced the relay allowlist with just the
  sender's grant. The Mac observed the original Pi TCP connection disappear
  after 595 ms. This is one observation taken on the relay host from just
  before file replacement to the first `lsof` sample without that socket,
  with 100 ms between samples. The still-running Pi process then logged
  `relay admission refused` on an automatic reconnect.
- **Fresh retry and replacement.** A new receiver process using the removed
  grant also reported `relay admission refused` and created no output. After
  adding a new receiver grant, the third transfer succeeded using the same
  sender grant. Both pairing files kept their original SHA-256 digests.
- **Relay shutdown.** After the relay exited, a saved receiver on the Pi
  reported a refused TCP connection and failed waiting for the approved relay.
  The destination remained absent and the pairing file kept its original digest.

The test relay and client processes exited, and the isolated Pi directory
containing test credentials, binaries and output was removed.
An initial run's client close-reason log check timed out after the first two
transfers. The results above are from the completed repeat.

## Repeat the trial

Use the [private relay setup](../docs/relay-admission.md) and the
[paired-file starter](../examples/paired-files/README.md) on two machines.
After the saved transfer, leave the receiver ready and remove its grant as
described in the setup guide. Verify the existing socket closes, then use
the native diagnostic CLI with `RUST_LOG=link_endpoint::relay_client=debug`
to check the refusal on a fresh `saved-receive`. Give the receiver a new key
and use `--relay-admission-key-file` on its saved command to send again.

This run covers native Rust clients on one IPv4 LAN. WAN, carrier handover,
browser and handset grant integration, and independent security review have
their own acceptance requirements.
