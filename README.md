# Local Compute Mesh

A distributed inference runtime in Go. Install `meshd` on every machine you
trust; nodes discover each other over mDNS, pair with mutual TLS, stream
GPU/CPU telemetry to a coordinator, and the whole pool is exposed behind one
OpenAI-compatible HTTP endpoint. A workload-aware scheduler routes each request
to the node that already has the weights resident and has the VRAM headroom,
queue depth, and link latency to serve it fastest.

## Status

**Early — not usable yet.** Being built in the order below; each item is
checked when it runs on two real machines with tests.

- [x] Protobuf control plane (`proto/lcm/v1`): `NodeService`, `InferenceService`, `SchedulerService`, `PairingService`, `AdminService`
- [x] mDNS discovery: `meshd` advertises `_lcm._tcp.local`, browses, tracks peers in the same mesh
- [x] `meshctl init` / `pair` / `join`: mesh CA, one-time 8-digit code, Argon2id-stretched and channel-bound MACs ([ADR 0002](docs/adr/0002-pairing.md))
- [x] mTLS on every gRPC connection with mesh pinning and cert-based roles ([ADR 0001](docs/adr/0001-go-grpc-mtls.md))
- [ ] `Register` + `ReportTelemetry` stream (VRAM, resident models)
- [ ] llama.cpp backend adapter, streaming `Generate`
- [ ] Scheduler v0 (resident weights + VRAM headroom)
- [ ] OpenAI-compatible gateway (`/v1/chat/completions` SSE, `/v1/models`)

## Quickstart (what exists today)

On the first machine:

```bash
make build
./bin/meshctl init --mesh-id home --node-id sanjay-mac
./bin/meshd --coordinator --log-format text
```

In another terminal on that machine:

```bash
./bin/meshctl pair
# pairing code: 09397153   (valid for 1m0s, single use)
```

On every other machine (same LAN; the coordinator is found over mDNS):

```bash
./bin/meshctl join --code 09397153 --node-id gpu-box
./bin/meshd --log-format text
```

Every daemon logs `peer added` with the other's `node_id`, address and cert
fingerprint. State lives in `~/.lcm` (override with `--data-dir` or
`LCM_DATA_DIR`): `ca.crt`, `node.crt`, `node.key` (0600), plus `ca.key` and
`admin.*` on the machine that ran `init`.

## Development

```bash
make test        # go test ./...
make test-race   # with -race
make proto       # regenerate proto/lcm/v1/*.pb.go after editing .proto files
```

Generated protobuf code is checked in; CI fails if it drifts from the `.proto`
sources. No GPU is needed for the test suite.

## Layout

```
cmd/meshd/          daemon (worker; coordinator and gateway are roles within it)
cmd/meshctl/        operator CLI
proto/lcm/v1/       protobuf definitions + generated Go
internal/discovery/ mDNS advertise/browse (memberlist gossip to follow)
internal/identity/  persistent node_id
internal/pki/       mesh CA, cert issuance, pairing crypto (codes, Argon2id, MACs)
internal/pairing/   PairingService server + join client
internal/transport/ mTLS gRPC server/dialer, principal extraction, role guard
internal/coordinator/ AdminService (pairing codes); registry + scheduler glue later
docs/adr/           architecture decision records
```
