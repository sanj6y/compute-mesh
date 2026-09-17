# ADR 0001: Go, gRPC, and mTLS everywhere

Date: 2026-09-16 · Status: accepted

## Context

Local Compute Mesh needs a control plane (registration, telemetry streams,
placement commands) and a data plane (token streams) between machines on a
home/office LAN that the owner trusts but that may also carry guests, IoT
devices, and VPN tunnels. It ships as one binary per machine.

## Decision

- **Go** for the daemon, CLI, scheduler and gateway. Single static binary,
  goroutine-per-stream proxying, first-class protobuf/gRPC, and the
  membership/consensus libraries we intend to use (`hashicorp/memberlist`,
  `hashicorp/raft`) are Go-native.
- **gRPC over HTTP/2** for every node-to-node and CLI-to-node call. The
  control plane is stream-heavy (1 s telemetry, token streams), and gRPC's
  server/client streaming plus generated clients beat hand-rolled REST+SSE
  for internal traffic. The *external* API stays OpenAI-compatible HTTP.
- **Mutual TLS on every gRPC connection**, with certificates issued by a
  mesh-private CA (`internal/pki`). Both peers verify the chain and that the
  peer's SAN URI (`lcm://<mesh_id>/<role>/<name>`) names their own mesh.
  There is no plaintext listener and no server-auth-only listener except
  the pairing bootstrap (ADR 0002).
- **Roles live in the certificate.** `node` certs are for `meshd`; `admin`
  certs are for `meshctl`. Authorization is a gRPC interceptor keyed on the
  role from the peer cert (`transport.RequireRole`), so the CLI uses the same
  transport as everything else rather than a local socket side channel.
- **TLS 1.3 minimum, ECDSA P-256.** Small certs, fast handshakes, and no
  legacy cipher negotiation to reason about.

## Consequences

- Nothing works until a node has a certificate, which is why pairing is the
  second thing built, not the last.
- Every test that touches the network creates a throwaway CA. There is no
  `insecure.NewCredentials()` in the tree.
- Cert lifetime is 30 days until automatic rotation exists; the target is
  24 h with rotation at 50 % of lifetime (week 3).
- Rust and a QUIC-first transport were considered and rejected for v1: the
  interviewer signal from Go+gRPC+mTLS is already strong, and QUIC can be
  added under the same credentials later.
