# ADR 0002: Pairing with a one-time code, Argon2id, and channel-bound MACs

Date: 2026-09-16 · Status: accepted

## Context

A new machine has nothing: no CA cert, no identity. It must obtain a
mesh-CA-signed certificate from the coordinator over a LAN that may contain
hostile devices, with an operator experience of "type an 8-digit code once."
Requirements:

1. An attacker on the LAN who does not know the code must not be able to
   join, and must not be able to trick the joiner into trusting a rogue CA.
2. A captured handshake must not let the attacker recover the code by
   offline brute force within the code's lifetime.
3. No manual certificate or fingerprint handling by the operator.

## Decision

`meshctl pair` (with an admin cert, over mTLS) asks the coordinator to mint a
random 8-digit code, valid 60 s, single use. `meshctl join --code` then runs:

```
joiner → Begin()                 → {session_id, salt, mesh_id}
K          = argon2id(code, salt; t=2, m=32 MiB, p=2)
client_mac = HMAC-SHA256(K, "lcm-pair-v1/client" ‖ session_id ‖ SHA256(server_tls_cert) ‖ csr)
joiner → Complete(session_id, csr, client_mac)
coordinator: for each active code, derive K', check HMAC (constant time);
             on match: consume code, sign CSR (24h..30d), reply
             {ca_cert, node_cert, server_mac = HMAC(K, "lcm-pair-v1/server" ‖ session_id ‖ ca ‖ node_cert)}
joiner: verify server_mac, verify node_cert chains to ca_cert and names us,
        verify the pairing listener's TLS cert chains to ca_cert too; persist.
```

The pairing listener is server-auth TLS 1.3 on a dedicated port serving only
`PairingService`. The joiner cannot verify that TLS cert (it has no CA yet),
so `InsecureSkipVerify` is set **for this connection only** and trust comes
from the MACs:

- **Channel binding.** The server's TLS certificate hash is inside
  `client_mac`. A relay presenting its own cert to the joiner produces a MAC
  the real coordinator rejects. The joiner also checks both RPCs hit the
  same TLS cert, and that this cert chains to the CA it was handed.
- **Mutual proof of the code.** `server_mac` proves the responder knew the
  code, so a rogue coordinator cannot hand the joiner a rogue CA.
- **Argon2id** stretches the code. Offline brute force of 10^8 codes at
  ~40 ms each is ~46 CPU-days per captured handshake against a 60 s code
  lifetime. Online guessing is bounded by the rate limit below.
- **Single use, single attempt.** A code is deleted on first successful
  `Complete`; a session is deleted on any `Complete`, success or failure.
  `Begin` is refused when no code is active (so an idle coordinator does no
  Argon2 work for strangers), after 5 failures per minute, or beyond 32
  open sessions.

The CSR's subject is *not* trusted; only its public key is. The issued
principal is `lcm://<mesh>/node/<node_id>` where `node_id` came from the
joiner's request and is validated as a DNS label.

## Alternatives considered

- **PAKE (SPAKE2/OPAQUE).** Strictly stronger: no offline attack at all,
  even with a weak KDF. Deferred because Go has no vetted stdlib PAKE and
  the Argon2id+HMAC construction already makes offline attack impractical
  inside the lifetime. Upgrade path is contained to `internal/pki/pairing.go`
  and one proto message.
- **Printing the CA fingerprint for the operator to compare.** Rejected:
  64 hex characters is exactly the manual cert handling the project exists
  to avoid.
- **Trust-on-first-use.** Rejected: a LAN attacker who is first wins.
- **Pairing over the mTLS port with a special "unauthenticated" path.**
  Rejected: keeps the mTLS listener pure and lets the pairing port be
  firewalled or closed independently.

## Consequences

- `meshctl join` needs the coordinator reachable on the pairing port; mDNS
  advertises it (`pair_port` TXT key) so no address is typed on a LAN.
- The coordinator does one Argon2 derivation per active code per attempt.
  With one code active that is ~40 ms; fine.
- Argon2 parameters and MAC labels are protocol constants; changing them is
  a version bump (`lcm-pair-v2/...`).
- Decoding is a one-shot exchange; there is no session resumption or
  re-keying to get wrong.
