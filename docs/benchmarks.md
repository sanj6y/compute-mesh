# Benchmarks

Measured numbers only. Targets live in `LCM_DESIGN.md` §6. Every entry records the command, hardware, and date so it can be re-run.

## Peer discovery latency (mDNS)

**Date:** 2026-09-16 · **Commit:** 2bb30d0 · **Hardware:** Apple Silicon Mac, loopback (`--ifaces lo0`)

Two `meshd` daemons on the same host, same mesh. Timed from launching daemon B (process start included) to daemon A logging `peer added` for B.

| Trial | Latency |
|---|---|
| 1 | 39 ms |
| 2 | 36 ms |
| 3 | 37 ms |
| 4 | 38 ms |
| 5 | 36 ms |

**Result: ~37 ms mean, 36–39 ms range** on loopback. LAN numbers (two physical machines over Wi-Fi) still to be measured; target is < 2 s.

Measured at commit 2bb30d0, when `meshd` still took `--mesh-id` directly. Since
121ba67 the mesh comes from the node certificate, so the equivalent today is:

```bash
make build
./bin/meshctl init --data-dir /tmp/lcm-a --mesh-id bench --node-id a
./bin/meshd --data-dir /tmp/lcm-a --coordinator --grpc-port 17501 --pair-port 17502 --ifaces lo0 > a.log 2>&1 &
sleep 1
CODE=$(./bin/meshctl pair --data-dir /tmp/lcm-a --addr 127.0.0.1:17501 | grep -o 'code: [0-9]*' | cut -d' ' -f2)
./bin/meshctl join --data-dir /tmp/lcm-b --code $CODE --node-id b --coordinator 127.0.0.1:17502
date +%s%N
./bin/meshd --data-dir /tmp/lcm-b --grpc-port 17601 --ifaces lo0 > b.log 2>&1 &
# poll a.log for "peer added", note the timestamp delta
```
