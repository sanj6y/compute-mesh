# Benchmarks

Measured numbers only. Targets live in `LCM_DESIGN.md` §6. Every entry records the command, hardware, and date so it can be re-run.

## Peer discovery latency (mDNS)

**Date:** 2026-09-16 · **Commit:** 2bb30d0 · **Hardware:** Apple Silicon Mac, loopback (`--ifaces lo0`)

Two `meshd` daemons on the same host, same `--mesh-id`. Timed from launching daemon B (process start included) to daemon A logging `peer added` for B.

| Trial | Latency |
|---|---|
| 1 | 39 ms |
| 2 | 36 ms |
| 3 | 37 ms |
| 4 | 38 ms |
| 5 | 36 ms |

**Result: ~37 ms mean, 36–39 ms range** on loopback. LAN numbers (two physical machines over Wi-Fi) still to be measured; target is < 2 s.

```bash
make build
./bin/meshd --mesh-id bench --grpc-port 17501 --data-dir /tmp/lcm-a --ifaces lo0 > a.log 2>&1 &
sleep 1; date +%s%N
./bin/meshd --mesh-id bench --grpc-port 17601 --data-dir /tmp/lcm-b --ifaces lo0 > b.log 2>&1 &
# poll a.log for "peer added", note the timestamp delta
```
