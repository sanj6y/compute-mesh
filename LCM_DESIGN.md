# Local Compute Mesh (LCM) — Design & Target Numbers

Working design doc, 2026-09-16. Companion to `CLAUDE.md` §8–9.
Numbers in §6 are **build targets** — what the finished bullets should be able to say. Benchmark against them as you go and replace with measured values.

---

## 1. One-paragraph pitch

A single Go binary (`meshd`) you install on every machine you trust. Nodes find each other over mDNS, pair with mutual TLS, stream GPU/CPU telemetry to a coordinator, and expose the whole pool behind one OpenAI-compatible endpoint. A workload-aware scheduler routes each request to the node that already has the weights resident and has the VRAM headroom, queue depth, and link latency to serve it fastest. If a node dies mid-stream, the request is re-dispatched with the already-generated prefix replayed, so the client never sees an error.

---

## 2. Language and stack decision

**Go for everything in the data/control path.** Reasons: first-class gRPC + protobuf, `hashicorp/memberlist` (SWIM gossip) and `hashicorp/raft` exist and are production-grade, mDNS libs exist (`grandcat/zeroconf`), single static binary is the right install story, goroutines map cleanly to per-stream proxying, and Go is now a claimed language on the resume — this is the project that backs it.

**Python only for** the benchmark/load harness and a thin client SDK example. Do not write the daemon in Python.

**Rust is not worth it here.** Slower to ship, and the interviewer signal from "gRPC + Raft + mTLS in Go" is already strong.

| Layer | Choice | Why |
|---|---|---|
| RPC | gRPC over HTTP/2, mTLS | Streaming, codegen, mTLS is native |
| Transport v2 | QUIC (`quic-go`) | Stretch: lossy Wi-Fi, 0-RTT reconnect |
| Discovery | mDNS/DNS-SD `_lcm._tcp.local` + static seeds | LAN zero-config; seeds for cross-subnet/WAN |
| Membership | `hashicorp/memberlist` (SWIM) | Failure detection, gossip of node metadata |
| Coordinator state | Static single coordinator (v1) → `hashicorp/raft` (v2) | Raft is the keyword; don't block v1 on it |
| Inference backends | llama.cpp server (primary), Ollama, vLLM | All speak OpenAI-ish HTTP; adapter interface |
| GPU telemetry | NVML (Linux/NVIDIA), unified-memory sampling on macOS, `/proc` for CPU | |
| Metrics/tracing | Prometheus + OpenTelemetry | Per-request trace spans across nodes |
| Packaging | Single binary + Docker image; `docker compose` for simulated clusters | |

---

## 3. Components

### 3.1 `meshd` — the daemon (one binary, two roles)

Every node runs a **worker**. One node (elected, or configured in v1) also runs the **coordinator**. Any node can run the **gateway**.

```
┌──────────────────────────── meshd ────────────────────────────┐
│  gateway (OpenAI HTTP)  ──►  scheduler  ──►  dispatcher        │
│         ▲                        ▲               │ gRPC/mTLS   │
│         │                   node registry        ▼             │
│      clients               (telemetry view)   remote workers   │
│                                  ▲                             │
│  worker: telemetry sampler ──────┘   backend adapter ──► llama.cpp / Ollama / vLLM
│  discovery: mDNS + memberlist        pki: CA, pairing, rotation│
└────────────────────────────────────────────────────────────────┘
```

### 3.2 Discovery & membership
- On start: advertise `_lcm._tcp.local` with TXT record `{node_id, mesh_id, grpc_port, fingerprint}`. Browse for peers.
- Also accept `--seeds host:port,...` for machines not on the same broadcast domain.
- Join `memberlist` cluster; gossip carries node metadata (GPU class, total VRAM, backends available). memberlist gives you suspicion/dead detection for free — reuse it instead of hand-rolling heartbeats.

### 3.3 PKI & pairing (the security story)
- First node runs `meshctl init` → generates a mesh root CA (ECDSA P-256), stores in OS keychain / `~/.lcm/ca.key` with 0600.
- `meshctl pair` on the coordinator prints a **one-time 8-digit code, valid 60s**. New node runs `meshctl join <coordinator> --code XXXXXXXX`.
- The code is used in a **SPAKE2 / PAKE handshake** (or v1: HMAC over the CSR) so the joiner's CSR is bound to the code; coordinator signs a node cert with 24h validity.
- **Every gRPC connection is mTLS** with both sides verifying against the mesh CA and pinning `mesh_id`. No plaintext control-plane traffic, ever.
- **Cert rotation**: worker requests a renewed cert at 50% of lifetime over the existing mTLS channel. Revocation = coordinator publishes a CRL over gossip.
- `meshctl revoke <node>` for lost devices.

This is what turns "one of six" Google Security qualifications into three: authentication control (OAuth PKCE at Zof), applied cryptography (PAKE pairing, CA, rotation), secure network design (mTLS mesh, zero-trust pairing).

### 3.4 Telemetry
Worker samples every **1s** and streams to coordinator over a long-lived gRPC stream (`NodeService.ReportTelemetry`):
- VRAM total/used/free (NVML on NVIDIA; on Apple Silicon: unified memory free via `host_statistics64` + backend's own reported model size)
- Resident models (name, quant, size, last-used)
- Queue depth, in-flight requests, tokens/s over last 10s, p50/p99 TTFT over last 60s
- CPU load, RAM free, GPU temp/power (NVML), link RTT to coordinator
- Overhead target: sampler uses **<0.5% of one core**.

### 3.5 Backend adapters
```go
type Backend interface {
    Models(ctx) ([]ModelInfo, error)          // resident + available on disk
    Load(ctx, model string) error
    Unload(ctx, model string) error
    Generate(ctx, req GenerateRequest) (<-chan Token, error)   // streaming
    Embed(ctx, req EmbedRequest) ([][]float32, error)
    Stats(ctx) (BackendStats, error)
}
```
- `llamacpp`: spawn `llama-server` per model as a subprocess (or Docker container), talk to its `/v1` and `/metrics`.
- `ollama`: talk to local Ollama `/api/*`; use `/api/ps` for resident models.
- `vllm`: for a Linux/NVIDIA box; supports real continuous batching.
- Stretch: **llama.cpp RPC backend** (`rpc-server`) lets one model's layers span multiple hosts — that is your "model partitioning" bullet, and llama.cpp already did the hard part.

### 3.6 Scheduler
Two-phase: **hard filters, then weighted score, then power-of-two-choices.**

Hard filters (drop node if any fail):
1. Node alive and not draining
2. Model available on node (resident or on disk) OR node has VRAM headroom ≥ model size × 1.15
3. Privacy tag satisfied: request `privacy: local_only` → node must be tagged `trusted:home`, etc.
4. Backend supports the op (chat / embed / vision)

Score (higher is better; weights tunable, defaults shown):
```
score = 0.40 * resident(model)            // 1 if weights already loaded, else 0
      + 0.20 * vram_headroom_ratio        // free / total after placing this model
      + 0.20 * (1 / (1 + queue_depth))    // least-loaded
      + 0.10 * (1 / (1 + rtt_ms / 10))    // link latency
      + 0.10 * recent_tokens_per_sec_norm // node speed class
```
Then **power-of-two-choices**: take top-2 by score, pick the one with lower current queue depth. This cuts tail latency vs. pure argmax under bursty load and is a named technique interviewers recognize.

**Placement (proactive):** every 30s, if a model has been requested ≥N times in the last 5 min and only one node has it resident, and another node has headroom and is idle, pre-warm it there. This is what makes the "eliminated cold starts" number real.

**Scheduler decision is an in-memory scan over ≤ tens of nodes**: budget it at **<1ms p99**.

### 3.7 Gateway (OpenAI-compatible)
- `POST /v1/chat/completions` (SSE streaming), `POST /v1/completions`, `POST /v1/embeddings`, `GET /v1/models` (union of all resident + available models in the mesh, deduped).
- Extra headers: `X-LCM-Privacy: local_only`, `X-LCM-Prefer-Node`, `X-LCM-Trace-Id`.
- Gateway → scheduler → gRPC `InferenceService.Generate` stream to worker → tokens proxied to the client as SSE.
- Embeddings: **dynamic batching** — collect requests for up to 10ms or 32 items, send one batch to the worker. This alone gives a multi-x embeddings throughput number.

### 3.8 Fault tolerance
- **Failure detection**: memberlist suspicion → dead in ~3s with default tuning (tune probe interval 1s, suspicion multiplier 3).
- **Mid-request failover with prefix replay**: gateway keeps the generated tokens so far. On worker death, it re-schedules to another node with `prompt + generated_prefix` and `max_tokens -= len(prefix)`, then continues streaming. Client sees at most a pause, never an error. (Decoding is not bit-identical after failover — set temperature/seed consistently and document the caveat; it's a great interview discussion.)
- **Draining**: `meshctl drain <node>` stops new placements, lets in-flight finish, then it's safe to shut a laptop.
- **Coordinator failover (v2)**: Raft replicates registry + placement state across 3 nodes; gateway follows leader. Until then, workers keep serving in-flight requests if the coordinator dies, and a static fallback coordinator is configured.
- **Backpressure**: per-node admission limit from telemetry; gateway returns 429 with `Retry-After` rather than queueing unboundedly.

### 3.9 Observability
- `/metrics` Prometheus on every node: `lcm_requests_total{node,model,outcome}`, `lcm_ttft_seconds`, `lcm_tokens_per_second`, `lcm_vram_bytes`, `lcm_scheduler_decision_seconds`, `lcm_failovers_total`.
- OpenTelemetry trace per request: gateway → schedule → dispatch → backend → stream; export to Jaeger in the compose stack.
- Structured JSON logs (`slog`) with `trace_id`, `node_id`, `request_id`.
- Grafana dashboard JSON committed in `deploy/`. Screenshot goes in README.

### 3.10 Testing (this is what Lyft/DoorDash explicitly ask for)
- Unit: scheduler scoring, filters, PAKE handshake, prefix-replay math (table-driven Go tests).
- Integration: `docker compose` cluster of N simulated nodes running a **fake backend** that emits tokens at a configurable rate — no GPU needed for CI. GitHub Actions runs this.
- Chaos suite (`bench/chaos`): kill a worker mid-stream, partition a node (iptables in the container), slow a node's link (`tc netem`), coordinator restart. Assert zero client errors and bounded p99.
- Load: Go load generator (`bench/loadgen`) with open-loop arrival, reports p50/p95/p99 TTFT, tokens/s aggregate, scaling efficiency.

---

## 4. Repo layout

```
compute-mesh/
  cmd/meshd/            daemon entry
  cmd/meshctl/          CLI: init, pair, join, status, models, drain, revoke
  proto/lcm/v1/         node.proto, scheduler.proto, inference.proto
  internal/discovery/   mdns.go, memberlist.go, seeds.go
  internal/pki/         ca.go, pairing.go (PAKE), rotation.go, crl.go
  internal/telemetry/   sampler.go, nvml_linux.go, darwin.go, cpu.go
  internal/backend/     backend.go, llamacpp/, ollama/, vllm/, fake/
  internal/scheduler/   filters.go, score.go, p2c.go, placement.go
  internal/gateway/     openai.go, sse.go, batching.go
  internal/failover/    lease.go, replay.go
  internal/registry/    in-memory (v1), raft/ (v2)
  internal/transport/   grpc_mtls.go, quic.go (v2)
  deploy/               docker-compose.yml, grafana/, prometheus.yml
  bench/                loadgen/, chaos/, results/*.md
  docs/                 adr/, architecture.md, benchmarks.md
```

---

## 5. Build plan

### Weekend 1 — skeleton (makes every current resume word true)
- [ ] `proto/` + codegen; `meshd` starts, advertises/browses mDNS, logs peers
- [ ] `meshctl init` / `pair` / `join` with CA + one-time code (HMAC-bound CSR is fine for v1; PAKE later)
- [ ] mTLS gRPC between 2 nodes, `Register` + `ReportTelemetry` stream (VRAM + resident models)
- [ ] llama.cpp adapter, `Generate` streaming end-to-end
- [ ] Scheduler v0: filters + `resident` + `vram_headroom` only
- [ ] Gateway: `/v1/chat/completions` SSE + `/v1/models`
- [ ] README with architecture diagram, `docs/adr/0001-go-grpc-mtls.md`
- **Ship, push, update resume link.**

### Week 2 — the numbers
- [ ] memberlist membership; dead detection tuned to ~3s
- [ ] Full score function + power-of-two-choices
- [ ] Prefix-replay failover; chaos test: kill worker mid-stream under 50 concurrent streams → 0 errors
- [ ] Prometheus + OTel + compose stack with Grafana
- [ ] `bench/loadgen`; first benchmark table in `docs/benchmarks.md`

### Week 3 — polish + keywords
- [ ] Proactive placement / pre-warming; measure cold-start reduction
- [ ] Embeddings dynamic batching; measure throughput multiplier
- [ ] Fake backend + CI cluster of 16–20 simulated nodes; GitHub Actions green
- [ ] Cert rotation + `revoke` + CRL over gossip
- [ ] Ollama adapter (so friends' machines join with zero setup)

### Stretch (only if the above is done)
- Raft coordinator (3-node HA)
- QUIC transport
- llama.cpp RPC layer partitioning across two hosts
- Privacy tiers + per-request routing constraints in the CLI
- Speculative decoding with a small draft model on a weak node feeding a strong node

---

## 6. Target numbers

Aim for these. Every one is reachable on a 2–4 machine home LAN (e.g. your Mac + a roommate's gaming PC + a cheap cloud GPU box to prove heterogeneity). Replace with measured values before they go on the resume; keep the ones you hit, drop the ones you don't.

| Metric | Target | How you'll measure it |
|---|---|---|
| Node discovery | New node visible to the mesh **< 2 s** after `meshd` start | Log timestamps |
| Pairing | One command, **< 10 s**, zero manual cert handling | Wall clock |
| Scheduler decision latency | **< 1 ms p99** placement decision | `lcm_scheduler_decision_seconds` histogram |
| Gateway overhead | **< 5 ms** added p50 latency and **< 3%** throughput loss vs. hitting llama.cpp directly | loadgen A/B |
| Aggregate throughput scaling | **≥ 90% scaling efficiency** across 3–4 heterogeneous nodes (e.g. 3 nodes → ≥ 2.7× single-node tokens/s) | loadgen, sum of tokens/s |
| Concurrency | **100+ concurrent streaming requests** sustained; **1,000+ embeddings/min** | loadgen open-loop |
| Cold-start elimination | Resident-aware routing + pre-warming cuts **p99 TTFT ≥ 10×** vs. round-robin (e.g. ~8 s cold 7B load → < 500 ms warm) | loadgen with mixed model requests |
| Embeddings batching | **3–5× embeddings throughput** from dynamic batching (10 ms / 32-item window) | A/B batching on/off |
| Failure detection | Dead node detected **< 3 s** | memberlist events vs. kill timestamp |
| Mid-request failover | In-flight streams re-dispatched **< 500 ms** after detection; **0 client-visible errors** with a node killed under 50 concurrent streams | chaos suite |
| Utilization | Mixed workload lifts cluster GPU utilization to **70–80%** vs. ~30–40% for a single-machine setup | NVML / telemetry over a 10-min run |
| Telemetry overhead | Sampler **< 0.5% of one core**, 1 s cadence | `top` / pprof |
| Security | **100% mTLS** control plane, **24 h cert lifetime with automatic rotation**, revocation propagated via gossip **< 5 s** | Test + tcpdump showing no plaintext |
| Scale tested | **4 physical + 16 simulated nodes (20 total)** in CI | compose cluster |
| Test suite | **50+ tests** incl. **8+ chaos scenarios**, all in GitHub Actions | `go test ./...` |

---

## 7. What the finished bullets should look like

Target versions of the resume bullets once the numbers are in (edit to match measured values):

- Built a distributed inference runtime in Go that discovers idle GPU/CPU nodes over mDNS and gossip (SWIM), pairs them with PAKE-bound mTLS certificates and 24h automatic rotation, and exposes the pool as a single OpenAI-compatible endpoint; scaled aggregate throughput at 90%+ efficiency across 4 heterogeneous nodes with <5 ms gateway overhead.
- Designed a workload-aware scheduler (hard filters → weighted scoring on resident weights, VRAM headroom, queue depth, and RTT → power-of-two-choices) with proactive model placement, cutting p99 time-to-first-token 10× vs. round-robin and sustaining 100+ concurrent streams at <1 ms p99 placement decisions.
- Implemented prefix-replay failover that re-dispatches in-flight generations on node loss within 500 ms of detection, achieving zero client-visible errors under chaos tests (node kill, partition, slow link) across a 20-node CI cluster; instrumented with Prometheus and OpenTelemetry traces spanning gateway, scheduler, and workers.

Once these are real, LCM moves to the **top of Projects** on V1 and becomes the project you steer every backend technical screen toward.

---

## 8. Hardware notes
- Your Mac: llama.cpp with Metal; "VRAM" = unified memory. Sample free memory via `host_statistics64` and subtract the backend's reported model size for headroom.
- Any NVIDIA box: NVML via `github.com/NVIDIA/go-nvml`. This is the node that makes the telemetry story concrete — borrow one or rent a spot instance for benchmark day.
- No GPU in CI: the `fake` backend emits tokens at a configurable rate so scheduler, failover, and gateway tests run anywhere.
