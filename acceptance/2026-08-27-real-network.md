# ForgeSworn Link Phase 0, real-network results, 27 August 2026

Three hosts, no personal identifiers:
- **mac**: home LAN <mac-lan>, default route through a commercial WireGuard VPN (egress redacted). macOS arm64 release build.
- **pi**: same home LAN <pi-lan>, plain ISP NAT egress (<isp-egress>). Linux aarch64 static musl build.
- **pub**: public cloud host <pub-host>, 1 vCPU, no NAT. Runs the relays, reflector and the far endpoint. Linux x86_64 static musl build.

Relays on pub: primary wss :7443, secondary wss :7444, capture ws :7445; reflectors udp :7450/:7451/:7452. QUIC MTU capped so datagrams fit the relay frame bound. `status` is what each PathReport reported, never inferred from a successful transfer.

| Row | Setup | Result | Evidence |
| --- | --- | --- | --- |
| home NAT to public | pi sends 64 MiB to pub endpoint, relay on pub | **DIRECT** proved <pub-host>:7460 | digest matched; relayed then direct after signed pong |
| VPN egress to public | mac bound to VPN tunnel addr, 64 MiB to pub | **DIRECT** proved <pub-host>:7460 | digest matched over a WireGuard VPN egress |
| LAN, explicit bind | mac bound to <mac-lan>, 32 MiB to pi | **DIRECT** proved <pi-lan>:7470 | digest matched; direct over the LAN |
| LAN, VPN default route | mac 0.0.0.0 bind (probes leave via VPN), 64 MiB to pi | **RELAYED** fallback, transfer OK | direct_failed all probes timed out; a real finding: a VPN default route breaks intra-LAN direct discovery, and the relay fallback carried it correctly |
| relay only | mac --no-direct, 32 MiB to pi | **RELAYED**, never direct | digest matched; stayed relayed by owner choice |
| relay loss | mac over two relays --no-direct, primary killed mid-transfer, 96 MiB | **failover** relayed->reconnecting->relayed on the second relay after 258 ms, transfer completed | digest matched; stream survived a real mid-transfer relay kill |
| streaming / memory | pi sends 64 then 256 MiB | peak RSS 7.78 MiB then 9.58 MiB | 4x the bytes, ~1.8 MiB more memory: flat |
| UDP blocked | pi drops all UDP to pub (iptables), 24 MiB to pub endpoint | **RELAYED** only, no direct | digest matched; candidates exchanged but every probe and the reflector dropped, so no direct path formed and the WSS (TCP) relay carried it |
| privacy capture | tcpdump on pub during a relayed transfer over the PLAIN ws relay | **0 plaintext windows** in 26,053 packets / 25 MB against 581,616 payload windows | even a plaintext relay hop carries only opaque QUIC; the relay operator cannot read the payload |

Not covered (needs other networks or a device): two different home NATs, carrier-grade NAT (no phone attached), Windows. All direct paths proved here are within one home LAN or to a public host; no two-hostile-NAT hole punch was exercised.
