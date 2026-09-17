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

- [x] Protobuf control plane (`proto/lcm/v1`): `NodeService`, `InferenceService`, `SchedulerService`
- [x] mDNS discovery: `meshd` advertises `_lcm._tcp.local`, browses, tracks peers in the same mesh
- [ ] `meshctl init` / `pair` / `join`: mesh CA + one-time code pairing
- [ ] mTLS gRPC between nodes, `Register` + `ReportTelemetry` stream
- [ ] llama.cpp backend adapter, streaming `Generate`
- [ ] Scheduler v0 (resident weights + VRAM headroom)
- [ ] OpenAI-compatible gateway (`/v1/chat/completions` SSE, `/v1/models`)

## Try what exists

```bash
make build
./bin/meshd --mesh-id demo --grpc-port 17443 --log-format text
# on another machine on the same LAN (or another terminal, different port/data dir):
./bin/meshd --mesh-id demo --grpc-port 17444 --data-dir /tmp/lcm2 --log-format text
```

Each daemon logs `peer added` with the other's `node_id`, address and gRPC
port. Nodes with a different `--mesh-id` are ignored.

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
docs/adr/           architecture decision records
```
