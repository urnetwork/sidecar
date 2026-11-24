## 6. The sidecar subprotocol: envelope, RPC, streams, server push

### 6.1 Purpose and scope

This section owns the sidecar's wire protocol on connect's subprotocol layer: id, envelope, chunking, RPC, streams, push (X8), peer authentication, `HeadCheck` and its control contracts, typed `Signed`, encryption and contract modes, and the message, signed-type, code, topic and Hello feature registries. Sockets go to §9, policy and the config repo to §7 and §8, the witness rule to §2, evs notifications and remote search's rules to §11 (§11.14), keys to §5 and §10, payer and escrow to §20 (X11), wakes to §18 and §19, connect changes to §4 (X9).

### 6.2 Requirements

| id | requirement | source |
|---|---|---|
| R-PROTO-1 | Sidecar traffic rides connect; the sidecar depends only on connect | PLAN.md:7 |
| R-PROTO-2 | The subprotocol protobufs live in `sidecar/protocol` | PLAN.md:15-16 |
| R-PROTO-3 | Changes to a subscribed dir or subpath are notified "via a subprotocol message" | PLAN.md:55 |
| R-PROTO-4 | tlsedge reaches one listener over the subprotocol after find-listener and accept | PLAN.md:82 |
| R-PROTO-5 | Rules affecting a client are "sent in real time" | PLAN.md:119 |
| R-PROTO-6 | Every frame, with overheads, fits one 16 KiB transport message; connect does not fragment | connect/transfer.go:1700-1724 |
| R-PROTO-7 | Handlers never block and copy what they keep | connect/subprotocol.go:77-85 |
| R-PROTO-8 | Residents and relays cannot read peer traffic; pushes are hints, never content | CONVENTIONS §0; owner decision 17 |
| R-PROTO-9 | Memory is bounded per peer and per process, within §18.4's mobile budgets | [R:sdk-clients] |
| R-PROTO-10 | Every ack has stated semantics; a transfer ack is not delivery | connect/transfer.go:17309-17335 |
| R-PROTO-11 | Sidecar connect traffic runs e2e Required, never Opportunistic or Off | CONVENTIONS §0 |
| R-PROTO-12 | Any admitted reader sidecar, agents included, can witness a writer's pins, whatever the network's policy | owner decision 129; derived |

### 6.3 What exists today

- **Registration.** Ids below 1024 are refused, the reserved variants are unexported, and each id has one typed codec (connect/subprotocol.go:46-50, :512-535).
- **Dispatch.** Inline, with no source check; ControlId refuses sends and has no contract or e2e session (connect/subprotocol.go:590-651, :902-905; connect/transfer_encrypt.go:3684-3686).
- **Size and order.** A 16 KiB floor and pool classes up to 8 KiB (connect/transfer.go:1700-1724; connect/message_pool.go:423-431); order holds within a send sequence, which 60 s without an ack ends (connect/transfer.go:5781-5796, :904).
- **Encryption.** Off by default, Opportunistic in the sdk provider (sdk/device_local_provider.go:258). Required holds sends and discards received plaintext after acking it (connect/transfer_encrypt.go:470-497). `Peer` exposes no session key (connect/transfer.go:608-620).

Missing: peer RPC, streams, flow control, application acks, sidecar push (residents send only listener-produced control frames, with no ack callback, server/connect/resident.go:4901-4908, though `Client.Send` takes one per frame, connect/transfer.go:4228-4235), and a source check on ControlId frames over P2P.

### 6.4 Id allocation, versioning, negotiation, peer identity

- **Id.** One public id, `sidecar.SubprotocolId = 0x5552` (21842, "UR"), registered per client with `connect.RegisterSubprotocol`; 21843-21851 are held, and sdk refuses 21842-21851 for apps (§18). An inner `type` (§6.11) puts all services behind one dispatcher.
- **Versioning.** `version` is the wire major (1). An unknown major gets `Error{VERSION}` with the receiver's range in `Error.min_version` and `max_version` (§6.5), an unknown type UNIMPLEMENTED; unknown fields are skipped, and an unknown code fails its call or stream without retry.
- **Hello.** `Hello`/`HelloResult` carry versions, features (§6.11's registry: bit 0 serves remote search, bit 1 asks it; unknown bits are ignored), limits and the sender's `SidecarIdentityBinding` (§5.5). `HelloResult` and `HeadCheckResult` are messages of their own with their requests' fields and numbers (protocol/envelope.proto).
- **Identity check (D-PROTO-13).** Connect binds a session key to a client id only through the platform, so an operator can substitute keys at first contact (connect/transfer_key_history.go:22-26). A peer session carries no stream or non-Hello RPC until the binding's signatures verify, its `client_public_key` equals the session key that C15 exposes on `Peer` in M1 (connect/transfer_encrypt.go:1152-1157; owner decision 22), and its `identity_public_key` matches a pin: set on first use per `sidecar_id` in M1 (§2.8 EX6), and from M2 the peer's `SidecarAdmit` (§7.9; owner decisions 3, 5, 112), chained to the genesis its invite or auth key carried, or trusted on first use with a safety number (EX5).
  - A mismatch answers `Error{UNAUTHENTICATED}`, rejects opens with `StreamReject{INVALID}`, resets streams with IDENTITY and alarms.
  - **Hello endings (owner decisions 692, 693).** A side's Hello with a peer ends at `HelloCacheTimeout`, at a change of C15's session key, checked per frame, on a send's ack error, and when connect reports that the peer lost its session with this client (C22's `EncryptionEventPeerSessionLost`), as a peer restarted under its kept identity does (§6.9). A gate that holds no Hello with the sender refuses its call `UNAUTHENTICATED` and its open `StreamReject{INVALID}`, and refuses an answer to a call whose Hello ended while the call was in flight. A call meets either refusal once with a fresh Hello and the same request, under its request_id and deadline, so a handler that ran answers from what it kept (§6.6). An open meets an INVALID that way only when the Hello it went under ended while it was in flight; an INVALID under a Hello that still stands is the listener's own answer, §9.6's admission among its reasons, and is returned as it is, so no admission runs twice. A dispatcher that receives a HelloResult no Hello of its own awaits, from a sidecar it holds no Hello with, runs a fresh Hello toward that peer at once, at most one in flight per peer: it is the peer's word that its gate opened to this side under a Hello this side no longer holds, as when connect replays a Hello from before a restart (C21). An edge's dispatcher, and a peer it knows as an edge, run none.
  - Edges carry no binding; their tickets' `dialer_network_id` (`urnetwork-edge`) identifies them (§9, §13.5), so their opens need no Hello. A sidecar's calls and NO_REPLY sends to an edge need none either (owner decision 624): a call marked for an edge (`CallOptions.Edge`, as `StreamOpenRequest.Edge` marks an open) runs no Hello and no HeadCheck, is refused for a peer the dispatcher knows as a sidecar, and has its answer admitted from a Service-mode source, as the inline guard already admits an edge's answers to calls a sidecar made of it; `Subprotocol.SendEdge(clientId, messageType, body)` sends a NO_REPLY envelope under the same rule; and the edge role registers NO_REPLY handlers, which hand such an envelope to its engine. The edge's identity is the signed `ur/` ticket the dialer verified, the basis its stream already rests on, and the wire is unchanged. Cross-network peers reach sidecars only by IP (§6.10.1).
- **Security floor.** Required mode, the `Signed` rules, the identity check and the chunk limits are never feature-gated. Releases carry `MinSecureVersion`, which the `core` topic can raise; a lower `secure_version` gets VERSION. The raise is unsigned, so it is a live denial and never stored state (owner decision 295): a device applies the lesser of the floor `GET /sidecar/sync/core` currently reports and its own compiled `secure_version`, never below its compiled `MinSecureVersion`, and persists nothing, so a forged floor never refuses a peer at this device's version or newer and ends when the operator stops asserting it; a value above the device's own version prompts an upgrade through `ur status`, and §2.8's connect-4 discloses the raise under I-4 as a denial.
- **HeadCheck (D-PROTO-14, D-PROTO-17).** Sidecars compare the auth pin (§7.9), generations (§10.5), ref heads (§11.8), shared MLS epochs and recovery vetoes (§7.9) by `HeadCheck` (§6.5), at most 16 of each list (4 vetoes) a message, rotating, so a fork between two communicating peers shows within ⌈shared items / 16⌉ rounds. A witness never refreshes a pin it did not reconcile:

```text
auth     same n: A must match, else FORK
         peer ahead: fetch entries (mine, peer's] from api and check that they chain to the peer's A; if api
           does not serve them within HeadCheckFetchTimeout (2 tries, 10 min), ask the peer for a
           HeadCheckProof, which any sidecar, phones included, serves from what §7.9's retain row keeps, its
           newest 64 KiB of entries and any proof it verified (a responder whose kept entries do not reach
           back to my n within 64 KiB answers NOT_FOUND): one that chains from my A to the peer's, with valid
           signatures, is PROOF OF WITHHOLDING; with neither, the pin is UNVERIFIED, the peer its claimant:
           alarm and retry each round until I reach that pin, or its claimant withdraws it or is revoked or
           parked
         peer behind: it fetches up to my pin and repeats the check, or asks me for a proof
proven   a device holding PROOF OF WITHHOLDING or an auth FORK sends the withheld tip, or the pin it forks
           with, as HeadCheck.proven, keeping the proof it verified, if any (<= 64 KiB, by §7.9's retain
           row), and serving it while that state lasts; a peer reconciles proven as the auth rows say,
           except that a conflict no proof shows is UNVERIFIED, not a FORK
relay    a device sends the UNVERIFIED pins it holds, highest first, as HeadCheck.unverified, each with its
           path: the claimant, then each sidecar that relayed it; a receiver appends the sender and ignores
           a copy whose path then holds itself or more than 8; unless the auth rows resolve it (entries
           from api, or the claimant's proof: PROOF OF WITHHOLDING), it holds the copy as UNVERIFIED, never
           as its pin (a conflict at its position stays UNVERIFIED, never a FORK), until it reaches the pin
           or a sidecar on the path is revoked or parked in its state, and relays it in turn; a device
           holds at most 64 pins, 4 taken from one peer, keeping the highest; so a stop crosses each
           HeadCheck hop at that pair's next HeadCheck, at once with a proof and at witness_bound_hours
           without one, and a false copy stalls writers only until a sidecar on its path, its maker
           included, is revoked or parked, the denial FORK accepts
gens     same g: C_g must match, else FORK; else the lower side reads gen/ up to the higher, checking the chain
groups   same epoch: same epoch_authenticator, else FORK
refs     same version: same chain, else FORK; else the lower side reads the ref's signed statements from its
           version up (§11.9) and recomputes C forward; a chain that does not extend its pin is a FORK
vetoes   a receiver verifies each veto and acts on it by §7.9's precedence rule
FORK     alarm with both pins as evidence; stop sealing in the affected repo, or for auth in every shared group;
           a proof of entries only its prover signed, which api answers with another entry at that position, is
           a FORK naming the prover; if api answers "no such entry", sealing still stops, so an admitted sidecar
           can stall its peers' shared-group writes until revoked, a denial any compromised device can cause
round    the first RPC or stream per peer per hour, and each HeadCheckInterval (1 h) up to
           HeadCheckRoundPeerCount (4) admitted sidecars sharing a repo, at random, else any: up to 2 of other
           members (their devices or the agents they sponsor), the rest own devices and agents; in the
           foreground, an app host with remote search on counts its first-choice own search indexer (§11.14)
           among those own picks, the other picks staying random (D-SDK-27)
witness  refreshes witnessed_at only when, after reconciliation, the peer is admitted and neither revoked,
           parked nor suspended in my state, both hold the same auth pin, neither sends proven or
           unverified, no field forks and I hold no UNVERIFIED pin; a peer that stays behind, or is ahead
           with entries I cannot fetch, never counts
stops    no consistent witness: alarm at 24 h and, in shared groups, stop sealing new content at
           witness_bound_hours; PROOF OF WITHHOLDING: alarm and stop sealing in shared groups at once, until
           api serves the entries; rotations, Removes and revocations never stop
alarms   FORK, PROOF OF WITHHOLDING, UNVERIFIED and the 24 h alarm raise §5.4's head_alarm event (fork,
           withheld, unverified, unwitnessed) with both pins and the peer's sidecar_id; Status() shows
           witnessed_at and each UNVERIFIED pin held; a push reset that lowers a durable topic raises the
           event's fifth kind, rollback (§6.8; owner decision 300), fork staying for two pins that disagree
revoker  the signer of a revocation shows it unwitnessed until a HeadCheck peer holds an auth pin at or past
           its position, retrying every 10 min and at each start; the console alarms after 1 h
```

  - **Witnesses** (owner decision 129). Any admitted reader sidecar, agents included, witnesses, unless the counting device holds it revoked, parked (§7.9's cascade) or suspended: all read the config, so all compare auth pins, which carry revocations, and generations; only MLS leaves compare epochs, so agents, and the member devices past a network's first 1,000 that read the config group, or the team directory's, by wraps, compare generations there instead (owner decisions 114, 144, 182). Own devices count; peers of other members are what crosses a cohort the server draws along member lines. Sidecars show `witnessed_at`.
  - **Control contracts (D-PROTO-18, D-PROTO-21).** Witnessing and remote search need no reach grant: the contract gate issues a Network contract of class `control` only to two admitted sidecars of one network, neither revoked, parked nor suspended (§8.10, which governs), whose class C13 seals (§6.10). On it receivers accept only Hello, Ping, HeadCheck and HeadCheckProof exchanges and, at a sidecar that serves remote search (Hello feature bit 0), §11.14's SEARCH from an admitted member device of its network, answered with SEARCH_RESULT; they refuse other RPCs with PERMISSION_DENIED and streams with DENIED, and providers' EgressHook denies all IP.
  - **Bound** (D-TRUST-10). `ServiceSettings.witness_bound_hours` (default 72 h, 24-168 h) is per-network config (§7.9), which §2.8 publishes as the exposure bound for a withheld Remove; across a split, §2.8's bound does not hold. From M8, `POST /sidecar/wake` summons the member's silent app hosts (owner decision 88), never a desktop.

### 6.5 Envelope, size budget, chunking

```proto
syntax = "proto3";
package urnetwork.sidecar;               // not connect's "bringyour"
option go_package = "github.com/urnetwork/sidecar/protocol";

message Envelope {
  uint32 version = 1;      // wire major
  uint32 type = 2;         // MessageType (§6.11): service << 8 | message
  fixed64 request_id = 3;  // random: RPC correlation, idempotency key, chunk group
  uint32 flags = 4;        // 1 RESPONSE, 2 ERROR, 4 MORE, 8 NO_REPLY
  uint64 stream_id = 5;
  uint32 timeout_ms = 6;   // requests: relative deadline
  Chunk chunk = 7;
  bytes body = 15;
}
message Chunk { uint32 index = 1; uint32 count = 2; uint32 total_byte_count = 3;
                bytes sha256 = 4; }        // of the whole body; final chunk only
message Error {
  uint32 code = 1;             // ErrorCode
  string message = 2;
  uint32 retry_after_ms = 3;   // RESOURCE_EXHAUSTED, UNAVAILABLE
  bytes result_ref = 4;        // ALREADY_EXISTS for an uncached response
  uint32 min_version = 5;      // ERR_VERSION only: the receiver's range, with Hello's meaning
  uint32 max_version = 6;
}
enum ErrorCode {               // permanent once released (D-PROTO-20); prose drops the ERR_ prefix; OK is
                               //   never sent, and an Error carrying it fails its call as an unknown code does
  ERR_OK = 0; ERR_CANCELLED = 1; ERR_INVALID_ARGUMENT = 2; ERR_DEADLINE_EXCEEDED = 3;
  ERR_NOT_FOUND = 4; ERR_ALREADY_EXISTS = 5; ERR_PERMISSION_DENIED = 6; ERR_RESOURCE_EXHAUSTED = 7;
  ERR_FAILED_PRECONDITION = 8; ERR_ABORTED = 9; ERR_UNAVAILABLE = 10; ERR_UNIMPLEMENTED = 11;
  ERR_UNAUTHENTICATED = 12; ERR_TOO_LARGE = 13; ERR_VERSION = 14;
}
message Hello {                    // HelloResult has the same fields
  uint32 min_version = 1;
  uint32 max_version = 2;
  uint32 secure_version = 3;       // refused below MinSecureVersion
  uint64 features = 4;             // §6.11's registry; never security properties
  uint32 max_body_byte_count = 5;
  uint32 initial_window = 6;       // credit the sender grants a stream before accepting it (§6.7)
  bytes binding = 7;               // §5.5 SidecarIdentityBinding, both signatures; empty from edges
}
message HeadCheck {                // HeadCheckResult has the same fields (I-16); any admitted sidecar answers
  bytes   network_id = 1;
  AuthPin auth = 2;                // §7.9's (n, A_n), from protocol/bridge (§4.4)
  repeated GroupHead groups = 3;   // MLS groups both peers are leaves of, <= 16, rotating
  repeated GenHead gens = 4;       // repos both read, <= 16, rotating
  repeated RefHead refs = 5;       // refs both read, <= 16, rotating
  repeated bytes vetoes = 6;       // Signed RecoveryVetoes pending or recently activated in the sender's
                                   //   view (§7.9), <= 4
  AuthPin proven = 7;              // only while the sender holds PROOF OF WITHHOLDING or an auth FORK
                                   //   (§6.4): the withheld tip, or the pin it forks with
  repeated UnverifiedPin unverified = 8; // only while the sender holds UNVERIFIED pins (§6.4's relay):
                                         //   <= 4, highest first
}
message UnverifiedPin { AuthPin pin = 1; repeated bytes path = 2; } // sidecar_ids: the claimant, then
                                                                    //   each relayer before the sender
message GroupHead { bytes group_id = 1; uint64 epoch = 2; bytes epoch_authenticator = 3; }
message GenHead   { bytes group_id = 1; uint64 generation = 2; bytes commitment = 3; }    // C_g (§10.5)
message RefHead   { bytes repo_id = 1; bytes ref_id = 2; uint64 version = 3; bytes chain = 4; }  // C_v (§11.8)
message HeadCheckProofRequest { uint64 after = 1; }   // the requester's n
message HeadCheckProof { repeated bytes entries = 1; } // AuthEntries after it up to the responder's proven pin,
                                                      //   else its auth pin, <= 64 KiB; a base as its header
                                                      //   only, its rows by hash from api
```

```text
budget item (bytes)
transport message limit                    16,384
MaxEnvelopeByteCount (protocol's value)    4,080
header / body / StreamData data            <= 64 / <= 4,016 / <= 4,000
final chunk: header with sha256 / body     <= 70 / <= 3,980
carrier overheads: wrapper (connect/subprotocol.go:110-116), encrypted pack, contract frame,
  8 hops (inference)                       7 + ~180 + ~1,123 + ~150
worst-case carrier                         5,540 (34% of the limit)
StreamOpen                                 <= 3,800: target 128 (so §9's names <= 112), metadata 1,024,
                                           ticket 512, early data 2,048
StreamData; PushReset                      <= 4,016; <= 4,016 (48 versions, then complete=false)
Hello; HelloResult                         <= 512 B each with connect's wrapper, one envelope (~325 B with
                                           §5.5's binding)
HeadCheck; HeadCheckProof                  ~3.3 KB at 16 of each list, ~250 more a veto, ~200 an
                                           unverified pin, chunked past 4,016, two envelopes at most at
                                           those caps; <= 64 KiB, chunked (17 envelopes)
PushHint; control messages                 <= 400; <= 300; Ping and Pong carry no body (one envelope,
                                           <= 32 B with the wrapper)
search request (SEARCH, §11.14)            one envelope, no chunk header, body exactly 4,016 B, timeout_ms 10,000
search reply (SEARCH_RESULT)               steps x 16,384 B of body (steps 1-4; 1 in v1), chunked as 4 x steps
                                           envelopes of 4,016 B and a final one of 320 x steps B: five at one step
```

- **Why 4,080.** Frames stay in the 4 KiB pool class and carriers, with [R:connect-transport]'s overheads, in the 8 KiB class; an 8 KiB cap would halve frame counts but unpool data carriers (connect/transfer.go:1714-1718).
- **Enforcement.** Senders refuse oversized envelopes with TOO_LARGE, the codec refuses them on receive (connect/subprotocol.go:643-650), and a test asserts that every maximal envelope fits.
- **Chunking.** A body over 4,016 B, such as a PQ-sized MLS message, spans envelopes sharing a request_id, reassembled by (source, request_id, RESPONSE) and checked against the final chunk's sha256; chunks are cut every 4,016 B, and a rest over the final chunk's 3,980 B is followed by an empty final chunk, so a body's length fixes its envelope sizes; bodies past the reassembly cap (§6.6) use HTTPS (§10, §11). Chunks ride one sequence, so they arrive in order. MORE (4) is set on every chunk but the final, and every chunk repeats the first's type, flags apart from MORE, request_id and timeout_ms, a mismatch dropping the group. Connect signals no sequence exit, so a partial message ends at `ReassemblyIdleTimeout`, or when index 0 of its group arrives again, which restarts the group; the sender resends it whole.

### 6.6 Request/response RPC

- **Calls.** A request carries a random `request_id` and a `timeout_ms` (default 15 s, at most 55 s, before the 60 s sequence exit; always 10,000 on SEARCH, so its envelope has one length). The response echoes it with RESPONSE and the request's result type (§6.11), or on failure with RESPONSE, ERROR, type ERROR (0x0006) and an `Error` body; any other type fails the call without retry. It goes on the request's `peer.TransferKey` (connect/subprotocol.go:690-699); replies to edges settle as Service (§6.10.1).
- **Idempotency.** Retries keep their request_id. Receivers cache mutating methods' responses by (source, request_id) within the settings below; a response over 16 KiB is not cached, and its retry gets `Error{ALREADY_EXISTS}` with a `result_ref`. Cancel is best effort: an envelope of type CANCEL (0x0005) that names the call in `request_id`, with no body and the flag NO_REPLY (8), which Cancel and stream frames set. SEARCH mutates nothing and is never cancelled: a retry repeats its (search_id, page), which the indexer answers from the cursor's last reply (§11.14), never from this cache.
- **Threading.** The inline handler checks size, source (§6.8), identity and contract class (§6.4), and §8's hook, copies the bytes (`connect.RetainSubprotocolBytes`) into a bounded per-peer queue without waiting, and answers RESOURCE_EXHAUSTED when it is full.
- **Failure.** Only immediate send refusals are retried; a lost ack surfaces only at connect's 60 s AckTimeout (connect/transfer.go:904), after the deadline, so the call returns DEADLINE_EXCEEDED or UNAVAILABLE and the caller retries with its request_id.
- **Scope.** Peer RPC runs between a network's sidecars and with edges. Sidecar→server calls use HTTPS: ControlId refuses sends, and in-band control has no replies (server/connect/resident_controller.go:61-63).

**Bounds (D-PROTO-16; owner decision 297).** Every value that sets a limit, size, count, time, interval, threshold, retry or budget is a field of its owning component's settings object, set only by that object's `Default...Settings()` constructor, with `applyMobile...`-style overrides (connect/CODESTYLE.md:142-145), and read from the instance where it is used: no package-level `const` or `var` holds one, and no such literal sits in logic, tests alone using literals to configure settings. Protocol and format limits are fields too, the 4,080 B envelope, a DROP's 256 KiB body and 1,048,576 list values, the 1 MiB part and the maximum call timeout among them: their defaults are the protocol's values, and changing one is a protocol change, never made on one side alone, so wherever a section calls a limit a constant it reads as such a field. Only identifiers stay named constants: enum values, proto field numbers, error, type and statement codes, version numbers, magic strings and cryptographic constants such as the empty tree's SHA-256. Code this build writes follows the rule, and each change moves the constants of that kind in the files it touches, the drafted code's remaining ones moving in the review phase's sweep (§23.8; owner decision 552); upstream code that predates it moves when a change edits the function that reads the limit (connect/CODESTYLE.md's "Migrate when you touch it"), a one-line wiring change or an added struct field moving nothing around it, and file-wide or system-wide legacy constants, server's `model.DefaultContractExpiration` and network_client_model.go's limits among them, move in the review phase's sweep, one track per legacy area building that area's settings object once; vendored third_party code stays as its upstream wrote it. Process-wide caps inside §5's `MemoryBudgetByteCount` answer RESOURCE_EXHAUSTED.

```go
// SidecarSettings.ProtocolSettings *SidecarProtocolSettings (§5.4). Defaults: desktop; mobile after ";".
type SidecarProtocolSettings struct {
	HelloCacheTimeout               time.Duration // 10 min; Hello state also ends at any change of C15's
	                                              // session key, checked per frame, on a send's ack
	                                              // error, connect signaling no sequence exit, and at
	                                              // connect's report that the peer lost its session
	                                              // (C22; §6.4's Hello endings)
	DefaultCallTimeout              time.Duration // 15 s (protocol maximum 55 s)
	PeerQueueMessageCount           int           // 64
	ReassemblyMaxBodyByteCount      int64         // 256 KiB (protocol maximum 1 MiB)
	ReassemblyPeerCount             int           // 8; 4: two search pages (§11.14) and HeadCheck both ways at one peer
	ReassemblyPeerByteCount         int64         // 2 MiB; 512 KiB
	ReassemblyProcessByteCount      int64         // 16 MiB; 2 MiB
	ReassemblyIdleTimeout           time.Duration // 30 s from the last chunk
	IdempotencyTimeout              time.Duration // 10 min
	IdempotencyPeerByteCount        int64         // 256 KiB; 64 KiB
	IdempotencyProcessByteCount     int64         // 4 MiB; 512 KiB
	IdempotencyMaxResponseByteCount int64         // 16 KiB
	StreamInitialWindowByteCount    int64         // 16 KiB, advertised in Hello
	StreamMinWindowByteCount        int64         // 256 KiB; 64 KiB
	StreamMaxWindowByteCount        int64         // 1 MiB; 256 KiB
	StreamPeerCreditByteCount       int64         // 8 MiB; 1 MiB. Edge peers: grows with streams
	StreamProcessCreditByteCount    int64         // 64 MiB; 8 MiB
	StreamMaxPeerCreditFraction     float64       // 1/8 per stream
	PingTimeout                     time.Duration // 15 s without inbound traffic
	PeerSilenceTimeout              time.Duration // 45 s, before connect's 60 s exit
	HeadCheckInterval               time.Duration // 1 h per peer; overdue after 1 h without a consistent result (§6.4)
	HeadCheckRoundPeerCount         int           // 4 per round: up to 2 of other members, the rest own devices
	                                              // and agents (§6.4; owner decision 129)
	HeadCheckTimeout                time.Duration // 10 s per scheduled call; silent own app hosts get a wake (M8)
	HeadCheckFetchTimeout           time.Duration // 10 min (2 tries) for api to serve a peer's newer entries,
	                                              // before asking the peer for a HeadCheckProof
	HeadCheckUnwitnessedInterval    time.Duration // 10 min while a revocation this device signed is unwitnessed
	WakeInterval                    time.Duration // 1 h per woken device, as the api enforces; woken sidecars check first
	// The stop at ServiceSettings.witness_bound_hours (default 72 h, 24-168 h) is per-network config (§7.9),
	// the only per-network value here; the 24 h witness alarm is fixed by owner decision 129, neither a
	// ServiceSettings field nor a local setting.
	SyncRefetchInterval             time.Duration // 1 h
	EnablePeerP2p                   bool          // false: same-network P2P for a pair whose Hello verified,
	                                              // built at M6 and off until a later owner call (owner
	                                              // decision 296; D-PROTO-10)
	// The protocol's limits are settings fields too (owner decision 297), their defaults the protocol's values:
	// the 4,080 B envelope with its 4,016 B body, 3,980 B final chunk body and 4,000 B StreamData (§6.5), the
	// 55 s call maximum and the 1 MiB reassembly maximum; another value is another protocol.
}

// Resident publishers (server/connect) and the api long-poll.
type SidecarPublisherSettings struct {
	HintCoalesceTimeout time.Duration // 100 ms per topic
	PendingResetCount   int           // 1 per resident
	QueueByteCount      int64         // 64 KiB per resident
	LongPollHoldTimeout time.Duration // 25 s; the lb's proxy_read_timeout is 30 s
}
```

### 6.7 Streams

```proto
message StreamOpen { string target = 1; bytes metadata = 2; bytes ticket = 3; uint32 window = 4; bytes early_data = 5; }
message StreamAccept { uint32 window = 1; }
message StreamReject { uint32 code = 1; uint32 retry_after_ms = 2; }  // StreamRejectCode
message StreamData { uint64 offset = 1; bytes data = 2; }             // data <= 4,000 B
message StreamWindow { uint64 consumed_offset = 1; uint64 max_offset = 2; }
message StreamClose { uint64 final_offset = 1; }                      // half-close; offsets: below
message StreamReset { uint32 code = 1; uint64 final_offset = 2; }     // StreamResetCode
enum StreamRejectCode {   // §9's ticket codes, same numbers; QUOTA §20; prose drops the prefixes; zero: §6.11
  SR_UNSPECIFIED = 0; SR_RETRY = 1; SR_BUSY = 2; SR_DENIED = 3; SR_INVALID = 4; SR_QUOTA = 5; }
enum StreamResetCode {    // QUOTA §20.6, IDENTITY §6.4; zero: §6.11
  RST_UNSPECIFIED = 0; RST_DRAINING = 1; RST_REVOKED = 2; RST_PEER_TIMEOUT = 3; RST_TRANSFER_FAILED = 4;
  RST_PROTOCOL = 5; RST_CANCELLED = 6; RST_QUOTA = 7; RST_IDENTITY = 8; }
```

- **Open.** Ids are uint64, never reused per peer, and even from the side with the lower client id. `target` is a `<net>:<name>` socket (§9) or a service target (§13, §15), with a per-target `metadata` schema such as §13.5's `TlsEdgeOpen`; the acceptor checks `ticket` with §9's admission and §8's local policy. `early_data` (≤2,048 B, such as a ClientHello) is the stream's first bytes, and StreamData may follow at once. A sidecar's open rejected INVALID after the Hello it went under ended is opened once more under a fresh Hello, and an INVALID under a standing Hello is returned as it is (§6.4's Hello endings; owner decision 692).
- **Credit.** Each receiver grants credit per direction (as SSH windows, RFC 4254 §5.2) within the per-peer and per-process budgets; an edge's budget grows with its streams, so one slow visitor cannot stall the rest. StreamData lands in per-stream, credit-bounded buffers, not §5's component queues (connect/CODESTYLE.md:123).

```text
offsets  per direction, from 0, early_data first; an offset counts the bytes before it: StreamData.offset
         is data[0]'s, consumed_offset (the delivery ack) the bytes the reader took, offset + len(data) never
         passes max_offset, and final_offset (StreamClose, StreamReset) counts every byte sent, QUIC's final
         size (RFC 9000 §4.5); data past max_offset or a known final_offset, or a final_offset that changes
         or is below the bytes received, resets with PROTOCOL
open     data to the acceptor: max_offset is the acceptor's Hello.initial_window (StreamInitialWindowByteCount;
           16 KiB without a Hello, as from edges) until StreamAccept.window replaces it, the pre-accept part
           held against the acceptor's peer credit and discarded on reject; data to the opener: max_offset
           starts at StreamOpen.window
window   a receiver commits StreamMinWindowByteCount (64 KiB above half of GOMEMLIMIT, §13.6) of its peer
           and process credit before sending its window (StreamOpen's or StreamAccept's), else the acceptor
           answers StreamReject{BUSY} and the opener fails locally with RESOURCE_EXHAUSTED; each StreamWindow
           it then sends sets max_offset - consumed_offset between that minimum and
           min(StreamMaxWindowByteCount, 1/8 of the peer's credit), growing toward the maximum while the
           reader keeps up; max_offset never falls
```

- **Errors.** Ack errors reset with TRANSFER_FAILED; offsets leave room for a later resume.
- **Keepalive.** While streams are open, 15 s without inbound traffic sends a Ping, and 45 s resets the peer's streams with PEER_TIMEOUT, before connect's 60 s exit. The same loop rereads, at least every 15 s while streams run, each sidecar peer's admission in this side's state, and this side's own, since a sidecar not itself admitted gets no peer (§5.6): a peer the state has revoked, parked or let expire has its streams reset with REVOKED, and a side the state revokes resets its own sidecar streams with REVOKED, each end at its own wake on its own view of the state, so either may reset first; an edge, which carries no admission, is not reread.
- **Shared sequence.** A lost pack stalls a peer's streams until resent (300 ms floor; connect/transfer.go:883-923), but ~4 KB carriers already ride a reliable carrier whose blocking dominates (connect/transport_h3_datagram.go:22-41). A pair's 2 MiB resend queue (connect/transfer.go:961) allows about 20 MiB/s at 100 ms RTT (inference), so bulk evs data uses HTTPS.

### 6.8 Server push (X8)

A resident exists only while its client is connected, so push is idempotent state sync, not a mailbox.

```text
owning service           Redis, slot of {scp_<C>}         resident of C (connect)             sidecar C
 one script on the slot: ver (hash), hint (stream),
 HSET if higher, INCR n, n (string; INCR is class $);
 XADD seq; returns h,    tok and live, read only
 tok, live ------------> keyspace event on {scp_C}n --> publisher: XRANGE hint after the
                                                        last id sent ------ PushHint ----> newer version: fetch it
                                                        on start: HGETALL ver - PushReset -> checks pins (I-16)
                                                        frame ack: SET ack h if higher,    seq gap or incomplete
                                                        while tok exists                   reset: GET /sidecar/sync/versions
 then, if tok and the topic is mail, team, evs or core: a separate XADD to §18.7's {wakeq_<shard>}, due now
 if forced or live is absent, else in 15 s --> §19's push sender, unless ack >= h -- APNs/FCM wake
                                                                  {topic class, version} --> app resyncs
```

```proto
message PushReset { uint64 epoch = 1; repeated TopicVersion versions = 2; bool complete = 3; } // <= 48 versions a part
message TopicVersion { string topic = 1; uint64 version = 2; }
message PushHint {
  uint64 seq = 1;        // the INCR value; a gap means hints were lost
  string topic = 2;      // the topic registry below
  uint64 version = 3;
  uint32 kind = 4;       // the owner's MessageType (§6.11), or 0
  bytes hint = 5;        // that message, <= 256 B: ids, kinds, versions; never content; dropped when coalesced
}
message PollResponse {   // sidecar/protocol/push.proto: GET /sidecar/sync/poll's 200 body, application/octet-stream
  bytes cursor = 1;      // opaque: the last hint stream id included, unchanged after an empty hold
  repeated PushHint hints = 2;
  PushReset reset = 3;   // first, for an empty cursor or one past the stream's retention
}
```

```go
type SidecarPublisher interface { Start(ctx context.Context, env *PublisherEnv); Reset(); Close() }
type PublisherEnv struct {
	ClientId, NetworkId connect.Id
	Send   func(frame *protocol.Frame, ack connect.AckFunction) bool // the resident's ControlId send with connect's
	                                                                 // frame ack (server/connect/resident.go:4901-4908;
	                                                                 // connect/transfer.go:4228-4235)
	Redis  PublisherRedis             // GET, HGETALL, XRANGE, the ack script, §18.7's {scp_<C>}live refresh
	Topics []string                   // all; ["team"] for an acl_enforcing device client (§18.6)
}
```

- **Publishers (D-PROTO-5).** Server-only types in `sidecar/pushservice` (owner decision 104) on the exchange's shared keyEventSubscriber (server/connect/key_event_subscriber.go:62-73), hosted by residents of clients whose token carries §7.4's sidecar mark and, for topic `team` only, of `acl_enforcing` device clients (§18.6), a resident reading `strict_exp` and `acl_enforcing` from `network_client_owner` once at construction, in its existing profile read; they read Redis without per-client subscriptions (server/model/peer_model.go:31-35).
- **State rules.** A reset follows the resident's start, then hints with monotonic per-topic versions. A reset is a run of `PushReset` parts with one `epoch`, on the resident and the poll alike; the client applies their union only once `complete = true`, and an incomplete reset or a `seq` gap sends it to `GET /sidecar/sync/versions` (paged). `epoch` is any value unique per run for that client, publishers using the resident's start time in ms; `seq` is the script's INCR value, taken before its XADD and stored in the entry, and `n` restarts at 1 when its 1 h key expires, so any `seq` but the last plus one, a lower one included, is a gap. Clients ignore versions at or below their own, fetch newer state over HTTPS (the owner's API, or for `core` alone `GET /sidecar/sync/core`), and resync on reconnect and hourly, so once a reset completes or a `versions` refetch has run, correctness never depends on delivery. A reset never lowers a persisted durable version (a topic it omits keeps the client's): a reset, a resident's or a poll's, that shows a durable topic lower than or conflicting with the version held applies its other topics and sends the client to `versions` once, and only that page, read from the stores that never fall, judges the fall and alarms if it is real (owner decision 603), state gating inbound access (§8) failing closed until consistent (I-16); a clock version's fall is a gap (topic registry). The alarm for a `versions` page that presents a durable topic (`team`, `dns`, `gkm:<group_id>`) below the version the client holds is `head_alarm` of kind `rollback` (owner decision 300), its evidence the two `TopicVersion`s as protobuf bytes, the held one first, then the offered one; `Consistent()` is false until reconciled, as for every head alarm, and `fork` stays for two pins that disagree, so a person reading the alarm sees that api lowered a version.
- **Sync routes.** `GET /sidecar/sync/versions?cursor=` answers 200 `PollResponse` with `reset` set and no hints, at most 48 versions a page, `complete = false` and a cursor until the last: `team` from `network_acl_head`, `dns` from its serial, `core` from `{scp_<C>}ver` or else api's clock, so an hourly resync always fetches `core`, and the rest from `{scp_<C>}ver`, omitting what has expired, which a client keeps. `GET /sidecar/sync/<topic>?since=` serves `core` only; other topics answer 404 and use their owners' routes. `GET /sidecar/sync/core` always answers 200 with JSON `{"version": "<decimal>", "min_secure_version": n, "gates": ["evs", ...], "revoked": bool}`: `gates` is `SidecarConfig.GatesFor` of the token's network, and `revoked` whether api holds this sidecar revoked, a candidate the client verifies against the config (§5.6); it names no other sidecar, a client serving one. `{scp_<C>}ver` lives at most 1 h, so a client fetches it at each reconnect and hourly resync whatever `versions` shows. Under DESIGN-COMPUTE.md's authorization features (§7.9), the `core` state also names the features every gate serving the network implements, and each `core` request the features its sidecar's release implements, which api keeps per sidecar, unsigned, for the turn-on prompt alone (§2.8's api-7, `{scf_<network_id>}`; owner decisions 744, 750, 770, 775).
- **Late pages and retry waits (owner decision 299).** The client's push machine counts its inputs, each reset part and hint applied, and each `versions` refetch notes the count when it starts. A page whose refetch began before an input the machine has since applied takes only its rises: a durable topic it shows lower, or an open reset run it would end, sends the client to `versions` again, one more refetch at most, and a clock topic it shows lower waits for the next page; a page begun after every applied input keeps the rules above, its alarms and adopted falls included, so every alarm a timely page earns still comes and none comes from a page that was only late. A failed refetch waits out a backoff that doubles from `RetryMinInterval` to `RetryMaxInterval`: a reconnect, the connect generation's when its client connects again or the long-poll generation's first successful poll after a failure, ends a pending wait at once and refetches, being a changed input that connect's transport already paces, while every other ask (a `seq` gap, an abandoned reset run, an undecodable frame, a poll's incomplete reset) is kept and served when the wait ends, the next failure's wait doubling from where it stood.
- **Hints.** One script on the slot, like server/redis.go:955-958's conditional SET, writes `ver` (raising a field only if higher, so concurrent writers never lower one, and a raised clock's past the stored value as the registry below says), `hint` (`MAXLEN ~256`) and `n`, each key with `EXPIRE ... 3600 NX`, and returns the stream id, `tok` and `live` from the same slot for §18.7's wake step, which never shares a command with them. Versions stay exact: Redis's Lua keeps numbers as doubles, exact only below 2^53, and evs's push sequence is near 1.8 × 10^18 (§11.10), so every version is a canonical decimal string (digits only, no leading zero, at most 20) from the caller's `ARGV` to `ver` and the hint stream, never passed through `tonumber` or arithmetic: "higher" compares lengths, then, at equal length, the digits before the last 10 and the last 10 as two numbers, each exact; a raised clock's raise past a stored value, `core`'s, `sock`'s (owner decision 718), `mail`'s, `tls`'s or `gkm`'s, is `HINCRBY` by 1; and a stream id compares as its two integer parts, as server/model/subscription_redis_admission.go:192-207 keeps its counters as strings. Publishers parse each version with `strconv.ParseUint`, the wire carries it as uint64 (`PushHint`, `TopicVersion`), and the core holds it as uint64 on every build leg; a binding that shows one passes a decimal string, since syscall/js turns an int64 into a JS number. The listener (`__keyspace@0__:{scp_*}n`) sends `PushReset`, then `PushHint`s after the last stream id sent, coalescing a topic's hints over 100 ms: superseded ones keep their `seq` and lose their `hint` bytes. It sends each batch with connect's frame ack and, on the ack, raises `{scp_<C>}ack` to the batch's last stream id while `tok` exists (EX 3600).
- **Trigger rule (D-PROTO-12).** Production enables keyspace classes K, g, $, s and x only (xops/redis-set-notify-keyspace-events.sh:23; server/redis.go:929-930): HSET (h) and XADD (t) emit nothing, so the INCR ($) triggers, and its value is the `seq`. `EXPIRE NX` emits one g event per key generation, not one per write to every connect process (server/CPUOPT3.md Part E §4.8). §13's kill switch uses the same trigger.
- **Long-poll.** HTTP-only sandboxes poll `GET /sidecar/sync/poll?cursor=` from v0. Each poll holds at most 25 s and answers 200 `PollResponse` on a hint or after an empty hold, never 204, which carries no body; the hold fits the http block's 30 s `proxy_read_timeout` (warp/warpctl/config.go:1320) and the 15 min idle timeout of owner decision 34's `ssl_preread` stream hop (:1383). An ephemeral client's polls also refresh §18.8's liveness lease (D-SDK-17).

**Topic registry.** Only topics that gate access stay durable. A version comes from the owner's durable state, which never falls, a Postgres restore included (§19.10): `team`'s authorization log position, `dns`'s serial and `gkm:<group_id>`'s epoch and generation; or from a clock: api's for `core`, each writer's for `mail` and `tls`, gkm's, sockets' (§9.5), or, for evs's push sequence, the `TIME` of the Redis master that creates it (§11.10). The script never lowers a stored version, so a clock version falls only when Redis loses it and the next writer's clock trails the last one's by more than the time since (for evs, since the sequence's creation). A client takes such a fall, shown by a reset or a `versions` refetch, as a gap, never an alarm: it refetches the topic, checks what it fetches against its pins (I-16) and adopts the new value. §6.11 gives hint kinds. The config repo's `evs:` topic carries rules in real time (R-PROTO-5; owner decisions 5, 6). evs's subscription leases are server soft state in Redis, which holders re-create at their hourly resync (§11.10); hint and subscription semantics are unchanged for clients (owner decision 136).

```text
topic              owner            version
core               §5               api's clock in µs, which the script raises to the stored value plus one, by
                                    HINCRBY, when not above it, as gkm's
team               §7; §20 limits   the authorization log position n (§7.9); a limit change raises no n and
                                    reaches clients at the hourly resync
sock               §9               sockets' clock in ms, per client (§9.5), raised past the stored value by
                                    HINCRBY as mail's is, so a second hint in one ms reaches the client
                                    (owner decision 718)
mail               §14, §15         the writer's clock in ms, per client, raised past the stored value by
                                    HINCRBY as gkm's is, so mxedge, smtpedge and api may all write it; no
                                    durable sequence
tls                §13              the writer's clock in ms, per client, as mail's
dns                §12              zone serial, which a restore raises above every serial issued before
                                    it (§12.6); a sidecar refetches its zone through GET /dns/zone (§12.8)
gkm (per client)   §10              gkm's clock in µs, which the script raises to the stored value plus one,
                                    by HINCRBY, when not above it, so while Redis keeps that value, skew
                                    between gkm instances never makes a work hint (pending, wrap-pending,
                                    welcome, key-packages-low) stale
gkm:<group_id>     §10              epoch × 2^24 + generation, so a rotation without a commit raises it
evs:<repo_id>      §11              the repo's push sequence, which every commit on any ref raises by one,
                                    since heads are per ref: Redis soft state created at its master's TIME in
                                    µs × 1,000, a decimal string near 1.8 × 10^18 that no script turns into a
                                    number (§11.10), so a loss restarts it above every earlier value unless
                                    the new master's clock trails the creator's by more than the time since
                                    creation, less 1 µs per 1,000 commits; a skip or a fall sends the client
                                    to the window (§11.10)
```

**Security.**
- **Exposure.** ControlId pushes need no contract (server/controller/connect_controller.go:609-628), skip Required by construction (`ReceiveNoSession`, §6.3) and ride wss TLS (sdk/network_space.go:686); they carry topics, versions and server-held ids, never content.
- **Guard (D-PROTO-8).** Push types are accepted only when `source.IsControlSource()` and `peer.TransportType` is h1, h3, h3dns or h3dnspump (connect/transfer_route_manager.go:153-157), and nothing else from ControlId. P2P receive checks no source (connect/transport_p2p.go:1927-1990), but `TransportType` comes from the carrier (:2317-2318), so the guard holds until C3 lands.

### 6.9 Peer authentication and encryption

**Claims.** Source ids are platform-attested, as residents drop forwards not from their own client (server/connect/resident.go:4991-5002), and cryptographic once §6.4's check binds the Required session to an admitted identity. The HMAC'd contract's Network attests the same network, but ControlId and contract-free peers show it too (connect/transfer.go:17297-17303): check `IsControlSource()` first.

**Signatures (D-PROTO-7).** Anything other clients act on, or the server stores or relays, carries a typed `Signed`: evs heads and manifests (§11), config records (purpose `authority`, §7.9), bridge statements (`bridge`, §17.8), socket registrations (§9), slot deletions, records (§16) and approvals, generations (`gen-rotate`, §10.5), reader keys and wraps (`reader-key`, `reader-wrap`, §10.5), window delegations and share certificates (`window-delegation`, §17.9), directory cards and repo announcements (`directory`, §16.11), re-seed statements (`evs-reseed`, §11.6), group forms (`group-form`, §10.6), agent certificates (`agent-cert`, §5.5), TLS key attestations, members-device logins and link tokens (`tls-key`, `edge-login`, `tls-link`, §13.7, §13.8) and §5's binding, whose two signatures have the purposes `binding-client` and `binding-identity` (§5.4). DESIGN-COMPUTE.md adds three: `attach-origin`, an attach link's origin (`SIGNED_ATTACH_ORIGIN`, 0x1808; owner decision 755); `disclosure-ack`, an Owner's or Admin's acknowledgment of a disclosure for the network, by an approval-capable device's identity key (`SIGNED_DISCLOSURE_ACK`, 0x1809; owner decisions 765, 773); and `enclave-setup`, the statement by which an indexer incarnation's sponsor vouches for what its device installed over SSH (`SIGNED_ENCLAVE_SETUP`, 0x180A; owner decision 773), DESIGN-COMPUTE.md §7.10, §2.8 and §11.7 giving their bodies. An MLS credential's `identity_signature` covers the same signed bytes under purpose `mls-credential` (§10.4), and a presence key's own proof inside its `KeyRegister` under purpose `key-proof` (§7.9's record bytes). Verifiers check a `Signed` with `VerifySigned` against the type they expect, so `sidecar/device` verifies without linking `protocol` (§4.4), and parse a body only as the type its (purpose, type) registers in §6.11's `SignedType`, refusing any other or unknown type. Bytes on a verified Required session need no signature; MLS signs its own messages (§10). A statement whose check needs an authorization state carries that state in its typed body, never in `Signed`: a log statement's `StatementHeader.at` (§7.9), a GenRotate's `auth` and a late `KeyDelivery`'s `auth` and `time_ms` (§10.5).

```proto
// sidecar/protocol/bridge/signed.proto (§4.4), with SignedType (§6.11): VerifySigned's input
message Signed {
  bytes body = 1; bytes signer_id = 2; bytes key_id = 3; bytes signature = 4;
  WebAuthnEvidence webauthn = 5;   // a presence key's evidence: for Signed's own signature
                                   //   by a webauthn-es256 key, or, key_id set, §7.9's
                                   //   presence countersignature beside an identity key's
  uint32 type = 6;                 // SignedType (§6.11)
}  // signed bytes: "urnetwork-sidecar-v1/" || purpose || 0x00 || u32be(type) || body
message WebAuthnEvidence {
  bytes authenticator_data = 1; bytes client_data_json = 2;   // webauthn-es256 keys only
  bytes key_id = 3;              // countersignature: the presence key's KeyRegister key_id
  bytes signature = 4;           // countersignature: its DER ECDSA P-256 signature (§16.6)
  uint32 act_size = 5;           // m, the act's statements: 1 to 65,535
  uint32 act_index = 6;          // this statement's leaf, 0 to m - 1
  repeated bytes act_path = 7;   // its RFC 9162 §2.1.3 inclusion path, at most 16 hashes
}  // countersigned bytes: "urnetwork-sidecar-v1/presence-act" || 0x00 || signer_id ||
   //   u32be(act_size) || root, root being RFC 9162's MTH over the SHA-256 of each of the
   //   act's statements' signed bytes, in act order; "presence-act" is no §6.11 purpose
```

```go
// sidecar/protocol/bridge (§4.4). Refuses a type other than expectedType, then checks the signature over the
// signed bytes (for webauthn-es256, the evidence and its challenge); callers resolve key_id to its key record
// and apply §16.6's profile. Evidence must fit: without its key_id only for a webauthn-es256 signer, and with
// it, a countersignature, only beside an identity key's signature.
type SignedKeyAlg int // SignedKeyAlgEd25519, SignedKeyAlgEcdsaP256 (DER), SignedKeyAlgWebAuthnEs256
func VerifySigned(signed *Signed, purpose string, expectedType SignedType, keyAlg SignedKeyAlg, publicKey []byte) error
// VerifyPresenceCountersign checks signed.webauthn as §7.9's presence countersignature by the key its key_id
// names (keyAlg and publicKey from that key's KeyRegister): signed's leaf, its inclusion path to the act's root,
// then §16.6's countersign check over the countersigned bytes, UV set; the caller decides that one is required.
func VerifyPresenceCountersign(signed *Signed, purpose string, keyAlg SignedKeyAlg, publicKey []byte) error
```

- **Algorithm.** The key record that `key_id` names fixes it, never the message: Ed25519 for identity keys, agent subkeys and share keys (a host's pinned `BridgeShareKey`, a verified ShareCert's `signer_public_key`), ECDSA P-256 or WebAuthn ES256 for presence keys (DER signatures; §16.6's profiles, verified per use) registered through an I-8 channel. WebAuthn's challenge is the SHA-256 of the signed bytes, so it covers the type. A presence countersignature (§7.9's presence row; owner decisions 185, 187) runs the same profile over its act's countersigned bytes, whose Merkle leaves hash the act's statements' signed bytes, so each still covers its own type, and verifies with its one statement and that statement's inclusion path.
- **Signers.** Whatever the server stores or verifies is signed by a sidecar identity key (`signer_id` = `sidecar_id`), a presence key, a member's recovery key (`signer_id` = `member_id`, `key_id` = the raw 32-byte Ed25519 key, which `bridge.VerifyRecoverySigned` matches to the member row's `recovery_key_sha256`; §7.9), a Delegation's key (`signer_id` = `delegation_id`, `key_id` = the SHA-256 of its public key), which signs only its admissions or, for a forwarding Delegation, only its sidecar's `WindowDelegation`s (§7.9; owner decision 197), or a share key, never an agent subkey, so agent ids stay off the server: a share's pinned ShareKey signs only its ShareCerts, and the ShareSigner a ShareCert certifies only that share's link `WindowDelegation`s, each with `signer_id` = `share_id` and `key_id` = the SHA-256 of its public key (§17.9); subkeys sign only sealed provenance (§11), and the ClientKey only §5's binding. An identity key leaves `key_id` empty, and a verifier picks the path from the two lengths, never by trying keys: 16 and 0 a sidecar, 16 and 32 a member's recovery key, 32 and 32 a Delegation, so a `sidecar_id` chosen equal to a `member_id` confuses nothing. §16.6 fixes each approval evidence type's signer (owner decision 75).

**Encryption (D-PROTO-6).** Sidecar-owned clients, and edge platform clients toward sidecars, run `EncryptionModeRequired` (R-PROTO-11): held sends to a peer without a session surface as UNAVAILABLE (ENCRYPTION), and its plaintext is acked, then discarded (connect/transfer.go:17309-17335). The owner directive rules out Off and Opportunistic, which sends plaintext until a session forms, or forever (connect/transfer_encrypt.go:477-483), so no sidecar shares the sdk device client (owner decision 4). Relays hold a frame, its size and timing only in memory while forwarding it.

**Session recovery (owner decisions 691, 692, 693).** A client restarted under its kept connect identity, a sidecar generation's (§5.9's `connect_identity`), an edge's derived one (§13.6) or an sdk device's, presents the key, sequence certificate and provide keys it had, so peers' contracts to it stay valid, and connect's C21 recovers the per-peer session at once whichever side speaks first: a stale initiator drops its demoted epoch's handshake records before its new ClientHello, and the restarted responder answers each attempt once. A restarted daemon is reached in under a second by calls and streams, where it took about two minutes. connect then resends the peer's unacknowledged backlog under the recovery epoch, its oldest Pack first, which may carry a Hello, an open or a held write from before the restart: C22's report ends the peer's Hello (§6.4), a replayed Hello's answer prompts a fresh Hello at the peer (§6.4's Hello endings), and a replayed socket open names a listen the restart ended, so §9.6's admission refuses it at step 2. A ticketless sidecar-internal target may take a replayed open as a new stream, which its opener resets within a round trip.

### 6.10 Contracts and accounting

Same-network sidecar traffic uses Network, witnesses and remote search without a reach grant a Network contract of class `control` (§6.4), edges Service (C9) both ways, and cross-network shares FriendsAndFamily (owner decision 11); C13 seals every contract's subject, source network and class, whatever its mode (item 4, D-PROTO-19). Every byte is debited (owner decision 10): relayed same-network bytes from close reports (`CloseContract`'s byte counts, connect/protocol/transfer.proto:650-653), edge bytes by lease, shares from the dialer's escrow (§20.6). Neither mode CreateContract computes today fits (§8.3): Network grants allow-all egress, LAN and loopback included, and Public would list sidecars in VPN exits' egress index (server/model/egress_index.go:1308-1315). Contract rows keep today's retention (§2.8 connect-1): contracts expire within 60 min (server/model/subscription_contract_expiration.go:14); paid ones (shares) are reaped 7 days after payout and unpaid ones (Network, Service) at 300 days (server/model/subscription_model.go:47-52); close-report evidence goes after 35-91 days (server/db_contract_close_evidence.go:94).

**Remote search's contracts (owner decision 609).** A requester-indexer pair's contracts are accounted like any peer's: connect keeps no window ledger, withholds no report, reports no floor and moves no sequence at a window's end, no Hello marks the pair, and app hosts keep no pair warm and send no keepalive Ping. The fixed sizes that hide a search's pages from relays stay (§6.11, §11.14). api's retained contract rows and close reports therefore show when a phone searched through an indexer and how many 20 KiB exchanges it took, the same that and when evs-26 concedes for "search more", and never a query, hit or repo (§2.8's connect-5). This reverses owner decisions 176, 188 and 191, which had C19 account the pair in 55-minute windows at a 256 KiB floor, with a keepalive a minute in the foreground and a search that found its session lost re-establishing it at once.

#### 6.10.1 Service and share relationships

§6 owns the mechanism (D-PROTO-15), §20 the payer and escrow; items 1-3 are §4's C9, item 4 needs C13, and item 5 C18.

1. **Service = 6.** ProvideMode ends at 5 (connect/protocol/transfer.proto:354-361). C9 makes providers drop IP from Service sources and accept only subprotocol 21842 from them, with no escrow or payout (§20's leases bill the bytes), and settles replies as Service, as same-network replies settle as Network (server/controller/connect_controller.go:912-927). connect asks for such a reply as a plain non-companion contract in the reply direction, never as a companion (connect/ip.go:9393-9411); in a network with a head row §8.10's contract rule passes it as a reply once contract creation finds its origin, and sidecar RPC replies ride that rule.
2. **Who.** One end is a platform client in `urnetwork-edge` (its network id is `config/<env>/sidecar.yml`'s `urnetwork_edge`, §19.11), and the destination advertises Service: edges always, a sidecar only while it holds a `tls/` or `smtp/` registration, or while it holds a `ur/` stream (§13.6; owner decision 298): a sidecar that dials a `ur/` name holds Service from the ticket's open until its last `ur/` stream ends, as a listener holds it for its lease, with one provide frame at the first hold and one at the last release, so the edge's replies on that stream (StreamAccept, SmtpPreambleResult, the MX's TLS bytes, SmtpOutcome) get Service contracts and a sidecar that sends mail through `ur/smtpedge` without receiving any works. While held, edges get Service contracts to the sidecar only for its live `{svc_<sidecar>}` pairs, the inline handler admits from a Service source only stream frames, Ping, Pong and answers to the sidecar's own calls, and an edge's StreamOpen reaches only listeners the sidecar has. A connect resident whose first read of sidecar.yml failed, the file there but unreadable or unparsable with no earlier read to keep, knows no `urnetwork_edge` until its first good read, and meanwhile settles an edge end's contract by the ordinary rules, which may give Public or FriendsAndFamily where the destination advertises them, or Network between two clients in `urnetwork-edge`: a gap in D-PROTO-6 and D-PROTO-9 while a push is broken, recorded as accepted, since the edges are the platform's own processes and closing it would add a column to every CreateContract's relationship query, while the edge clients' `rev/` objects close on such a read (§9.8; owner decision 641).
3. **Authorization.** At Find, sockets records §9's pair as field `<dialer_client_id>` of `{svc_<listener_client_id>}`, expiring under §9.6's rule (HEXPIRE; Redis 8.10.2, xops/main/ansible/playbook-redis-clusters.yml:634): a `tls/` or `smtp/` pair at the lesser of the grant's remaining life and 15 min, renewed by its listener's accepted registration (owner decision 338), and a `ur/` pair at its service's grant length, 60 min by default and 125 min for `ur/smtpedge`. The pair is keyed by its non-edge end in every namespace (owner decision 298): a `ur/` Find, where the edge listens as `ur/<service>` and a sidecar dials (D-SOCK-11), writes field `<edge listener client_id>` of `{svc_<sidecar dialer client_id>}`, the roles swapped in the key and the ticket unchanged, so CreateContract's read is always field `<edge>` of `{svc_<sidecar>}` whichever end listens. Revocation and unlisten remove a `ur/` pair from the dialer's key; the edge's last unlisten does not reach it, so a `ur/` pair ends at its ttl. CreateContract issues Service only while the pair lives (one Redis read, no new PostgreSQL query), with a deadline at the earlier of the grant expiry and 60 min. Residents forward the contract under the contract-hole projection, keyed on client pairs (connect/CODESTYLE.md:108-109).
4. **Shares.** When the relationship is Public, the admins' signed id-only projection (§8) holds a share covering both subjects, and the destination is a marked sidecar client, CreateContract returns FriendsAndFamily, never for sdk device clients, which advertise FriendsAndFamily whenever they provide Public (sdk/device_local.go:4734-4744). In every mode (Network, Service, FriendsAndFamily) the contract signer fills `source_subject_client_id` from the source client's stored `network_client.acl_subject_client_id` (D-ACL-3), never a request field, and seals it with `source_network_id`, the contract class (`data` or `control`) and, for a window client, the subject's `WindowDelegation` (§17.9), copied unchanged (C13), so `Peer` and `EgressFlow` carry one sealed set whatever the mode.
5. **Egress.** Service sources get no IP. FriendsAndFamily sources carry owner decision 86's cross-network forwards and invites, reaching private destinations only through C18, a per-flow decision of C5's `EgressHook` on C13's sealed source network that passes only at sidecar-owned Required targets holding an explicit cross-network route grant (§8). C18 stays off in sdk providers, which keep treating FriendsAndFamily as Public (connect/ip_security.go:385-390, :574-576); §17.9 aliases foreign overlay addresses. A share's companion (return) contract inherits the forward contract's subject, source network and class and seals no `WindowDelegation`, which is the forward contract's alone (owner decision 301): a companion request carries none, the signer copies none and the server keeps no forward contract's delegation, and none is missed, since §17.9's verify row admits a native flow only when the delegation's `window_client_id` is the contract's own source, which on a companion is the replying provider. Only the dialer's network is escrowed, for both directions (owner decision 11); a cross-network share never normalizes to Network (item 1).

### 6.11 Message catalog index and codec conventions

Owners define messages; §6 assigns numbers, permanent once released. An RPC's result type is its request's value + 1 (HELLO_RESULT, PONG). Services 0x80-0xFF are unreleased experiments. Push kinds ride in `PushHint.hint`.

```proto
// sidecar/protocol/types.proto. Comments: owner; carrier.
enum MessageType {
  MESSAGE_TYPE_NONE = 0;
  HELLO = 0x0001; HELLO_RESULT = 0x0002; PING = 0x0003; PONG = 0x0004;        // §6; peer
  CANCEL = 0x0005; ERROR = 0x0006; HEAD_CHECK = 0x0007; HEAD_CHECK_RESULT = 0x0008;
  HEAD_CHECK_PROOF_REQUEST = 0x0009; HEAD_CHECK_PROOF = 0x000A;              // §6.4; peer RPC
  PUSH_RESET = 0x0101; PUSH_HINT = 0x0102;                                    // §6; ControlId -> client
  STREAM_OPEN = 0x0201; STREAM_ACCEPT = 0x0202; STREAM_REJECT = 0x0203;       // §6; peer
  STREAM_DATA = 0x0204; STREAM_WINDOW = 0x0205; STREAM_CLOSE = 0x0206; STREAM_RESET = 0x0207;
  SOCKET_HINT = 0x1001;                       // §9.5; push sock: {kind: revoked or drain, listen_id}
  // 0x11 §8: none; policy rides the config repo (owner decisions 5, 6)
  MEMBERSHIP_CHANGED = 0x1201; APPROVAL_REQUESTED = 0x1202;                   // §7; push team
  AUTHORITY_HEAD_CHANGED = 0x1203;
  GKM_HINT = 0x1301;                          // §10; push gkm, gkm:<group_id>
  EVS_HEAD_CHANGED = 0x1401;                  // §11; push evs:<repo_id>
  reserved 0x1402 to 0x1403;                  // withdrawn EvsHeadCheck: ref pins ride HeadCheck; never reused
  reserved "EVS_HEAD_CHECK", "EVS_HEAD_CHECK_RESULT";
  SEARCH = 0x1404; SEARCH_RESULT = 0x1405;    // §11.14; peer RPC, remote search (owner decision 175)
  EVIDENCE = 0x1406; EVIDENCE_RESULT = 0x1407; // DESIGN-COMPUTE.md §11.6, §11.10; peer RPC, a member's device
                                              // asking the indexer enclave for its evidence (owner decision 752)
  TLS_EDGE_OPEN = 0x1501; TLS_HINT = 0x1502;  // §13; StreamOpen metadata; push tls
  SMTP_PREAMBLE = 0x1601; SMTP_PREAMBLE_RESULT = 0x1602; SMTP_OUTCOME = 0x1603; // §14; stream to smtpedge, the
                                              // outcome a NO_REPLY envelope to the ticket's listener
  SMTP_STATUS = 0x1604;                       // §14; push mail
  SMTP_PROOF = 0x1605; SMTP_PROOF_RESULT = 0x1606;                            // §14; BDAT and DATA proofs, RPC to smtpedge, M9
  SMTP_HANDSHAKE = 0x1607; SMTP_HANDSHAKE_RESULT = 0x1608;                    // §14; TLS 1.3's disclosed SHTS, RPC to smtpedge, M9
  MAIL_INGRESS = 0x1701; MAIL_HINT = 0x1702;  // §15; StreamOpen metadata; push mail
  // 0x18 §16 MCP: none in v0 or v1; the directory's notices ride §11's hints (§16.11)
  // 0x19 §17: bridge rules ride the config repo (owner decision 5); listeners' live ask is DESIGN-COMPUTE.md's
  LISTENERS = 0x1901; LISTENERS_RESULT = 0x1902; // DESIGN-COMPUTE.md §26.8; peer RPC on the control class too
                                              // (owner decision 770)
  CORE_HINT = 0x1A01;                         // §5; push core
  DNS_ZONE_CHANGED = 0x1B01;                  // §12; push dns
}

// sidecar/protocol/bridge/signed.proto, beside Signed (§4.4), so sidecar/device reads it without protocol.
// Signed.type (§6.9): service << 8 | n, with MessageType's service bytes; names SIGNED_<MESSAGE>; one value
// per body message, added by its owner with the format that defines it; permanent once released. A verifier
// refuses 0, an unknown value, and any value its position does not expect; a heterogeneous list (deltas)
// maps each value to its parser and purpose.
enum SignedType {
  SIGNED_TYPE_NONE = 0;
  // 0x10xx §9: SIGNED_SOCKET_REGISTRATION 0x1001, SIGNED_SOCKET_TICKET 0x1002
  // 0x11xx §8 acl statements, GrantActivate: 0x1101 to 0x110F in §8.8's row order, then 0x1110
  //   ApprovalDelivery (§16.8; owner decision 447), which signed.proto reserves until its code, and 0x1111
  //   RepoPrefixRules
  // 0x12xx §7 config records and log statements: 0x1201 to 0x1215 in §7.9's row order
  // 0x13xx §10: SIGNED_GEN_ROTATE 0x1301, SIGNED_READER_KEY 0x1302, SIGNED_READER_WRAP 0x1303,
  //   SIGNED_DELEGATION_WRAP 0x1304, SIGNED_GROUP_FORM 0x1305 (purpose group-form), SIGNED_UR_MLS_CREDENTIAL
  //   0x1306 (purpose mls-credential; §10.4)
  // 0x14xx §11: SIGNED_EVS_PUSH 0x1401, SIGNED_EVS_RESEED 0x1402, SIGNED_EVS_PATH_MAP 0x1403,
  //   SIGNED_EVS_IMPORT 0x1404 (§11.6's four)
  // 0x15xx §13: SIGNED_TLS_KEY_ATTESTATION 0x1501 (purpose tls-key), SIGNED_TLS_EDGE_LOGIN 0x1502
  //   (edge-login), SIGNED_TLS_LINK 0x1503 (tls-link)
  // 0x16xx §14: SIGNED_SMTP_OUTBOX 0x1601 (purpose smtp-outbox), over §15.7's o/ entry, which signed.proto
  //   takes with the outbox's sender (owner decision 445); 0x17xx §15, 0x1Bxx §12
  // 0x1Axx §5: SIGNED_SIDECAR_BINDING 0x1A01 (purposes binding-client and binding-identity),
  //   SIGNED_AGENT_CERT 0x1A02 (purpose agent-cert)
  // 0x18xx §16 records, ApprovalDecision (§16.8); 0x1805 SIGNED_DIRECTORY_CARD, 0x1806 SIGNED_DIRECTORY_REPO
  //   (its body RepoAnnouncement), purpose directory (§16.11); DESIGN-COMPUTE.md's 0x1808
  //   SIGNED_ATTACH_ORIGIN (purpose attach-origin), 0x1809 SIGNED_DISCLOSURE_ACK (disclosure-ack) and 0x180A
  //   SIGNED_ENCLAVE_SETUP (enclave-setup), which signed.proto declares, 0x1807 left free
  //   (owner decisions 755, 765, 773)
  // 0x19xx §17: 17.8's statements 0x1901-0x1907 (purpose bridge), WindowDelegation 0x1908 and ShareCert
  //   0x1909 (window-delegation)
}
```

```text
edge codes, numbered here beside ErrorCode (6.5) and StreamRejectCode and StreamResetCode (6.7)
SmtpPreambleResult.code (§14)       UNSPECIFIED 0, OK 1, HALTED 2, QUOTA 3, DENIED 4, NO_MX 5, NO_TLS 6,
                                    TRY_LATER 7, KEYS 8
SmtpProofResult.code (§14)          UNSPECIFIED 0, OK 1, INVALID 2
SmtpHandshakeResult.code (§14)      UNSPECIFIED 0, OK 1, INVALID 2
SmtpStatus.kind (§14)               UNSPECIFIED 0, HALTED 1, QUOTA 2, CLEAR 3, in PushHint.hint on topic mail
TlsEdgeOpen (§13), MailIngress      no code of their own: the listener answers StreamAccept, or StreamReject
  (§15) streams                     with a StreamRejectCode, and ends with a StreamResetCode
zero                                every code but ErrorCode starts at UNSPECIFIED 0, which no sender sets; a
                                    receiver takes it as a protocol error, never as retry, drain or success:
                                    a reject as INVALID, a reset as PROTOCOL, and an edge result by resetting
                                    its stream with PROTOCOL
```

```text
Hello.features   bit n set: the sender implements n, in Hello and HelloResult alike; senders set only bits
                 they implement; receivers ignore unknown bits and grant or refuse nothing by a peer's bit,
                 each side deciding by its own state (§6.4's floor); a bit is permanent once released
0 serves remote  set by a sidecar that serves §11.14's remote search, a designated search indexer (§7.9);
  search v1      requesters ask only a peer that set it
1 asks remote    set by an app host toward each search indexer its remote-search mode lets it ask (§18.4); it
  searches       marks nothing, the pair's contracts being accounted like any peer's (§6.10; owner decision
                 609)
```

- **Files.** One proto3 `sidecar/protocol/<service>.proto` per service, generated by protoc-gen-go v1.36.11 as connect is (connect/protocol/transfer.pb.go:1-4), within sdk/build's v1.36.12 pin [R:sdk-clients]. What `sidecar/device` parses lives in `sidecar/protocol/bridge/*.proto` instead (§4.4; std and protobuf only): `Signed`, `WebAuthnEvidence` and `SignedType`; §7.9's `AuthPin`, `AuthEntry`, `ProjectionHeader`, `StatementHeader`, `Genesis` and every other record a device verifies against the anchor or applies between states, at least `SidecarRevoke`, `MemberRevoke`, `Suspend`, `Unsuspend`, `GrantRevoke` and §17.8's statements, `BridgeWithdraw` included; and §17's `BridgeState` (with `BridgeIdentity` and `BridgeShareKey`), `Pending`, `WindowDelegation` and `ShareCert`. `protocol`'s files, config.proto and acl.proto among them, import these and never redeclare them: both packages are `urnetwork.sidecar`, where a duplicate panics at init (§4.9).
- **Rules.** No `oneof` in envelope, stream or push messages or anything they carry (Q-TEST-6, closed by peer review), since protobuf-go allocates a wrapper per set oneof and hot-path decodes stay allocation-free; §22.5's lint walks the released descriptors from those roots, with an allowlist empty in v0. Others may use one. Hot fields use numbers 1-15.
- **Codecs.** v0 uses `connect.ProtoCodec`, which allocates per receive (connect/subprotocol.go:237-259). From M5, if §22 measures the cost worth removing, a pooled envelope codec, byte-identical to `proto.Marshal` like connect's wrapper (connect/subprotocol.go:138-227), implements `SubprotocolMessagePool` (:72-75), fuzzed by §22.

### 6.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| One public id, inner type (vs one id per service) | One check point; no connect change | Per-service stats in the sidecar | Chosen |
| Reserved id below 1024 | Network namespace | Unexported; invisible to queries | Rejected |
| Streams on one sequence | Today's API; credit isolates readers | Shared fate | Chosen, from M5 |
| Explicit lanes per stream | No cross-stream blocking | Off by default; starve without floors (connect/transfer.go:5978-5981) | Later (C7) |
| TCP over `connect.Tun` | Per-connection congestion control | Nested congestion control (RFC 9484 §10); ~20% overhead | §17 only |
| A quorum of witnesses | One colluding peer cannot vouch | Owner decision 129 chose any one admitted reader sidecar; a split defeats both | Rejected |
| Witnesses only under reach grants | No new contract class | From M4 any network's document, a Team's default one included, can leave sidecars unwitnessed | Rejected (D-PROTO-18) |
| A uvarint type in the signed bytes | 1-3 B shorter | Non-canonical varints let one statement sign two ways | Rejected: u32be |
| A contract class of its own for search | Policy could cut it | The gate marks which contracts carry search; a new class for C13 to seal | Rejected |
| The pair's Network contract, data or control | Works under every document; looks like HeadCheck at the gate | Policy cannot cut it (admins retire `search` instead) | Chosen (D-PROTO-21) |
| C19's windows: the marked pair's reports withheld to each 55-minute window's end at a 256 KiB floor, with a keepalive a minute in the foreground (owner decisions 176, 188) | Up to five pages a window read as none in api's rows | About 1.4k lines and 3k test lines in connect and 1.7k in sidecar, a sweep every connect merge waited on, 512 KiB of transfer balance a warm pair an hour in the foreground | Removed (owner decision 609): the pair's contracts are accounted like any peer's |

### 6.13 Decisions proposed

**D-PROTO-1 (proposed).** One public id, 21842, carries §6.5's envelope. *Why:* no connect change; one dispatcher.

**D-PROTO-2 (proposed).** Envelopes are capped at 4,080 B, with chunking (§6.5). *Why:* buffers stay pooled; connect does not fragment.

**D-PROTO-3 (proposed).** RPC follows §6.6; sidecar→server calls use HTTPS. *Why:* calls fail before the 60 s exit.

**D-PROTO-4 (proposed).** Streams follow §6.7 on one sequence per peer from M5, revisited if the TLS edge measures p99 shared-sequence stalls above 500 ms. *Why:* carrier blocking dominates; M1-M4 need only RPC and push.

**D-PROTO-5 (proposed).** Push follows §6.8, with wakes for wake-class hints a token holder's stack does not ack (§18.7; X8 (b); owner decisions 17, 88); the long-poll answers 200 `PollResponse`, and a reset applies only once complete. *Why:* state sync fits resident lifetimes.

**D-PROTO-6 (proposed).** Sidecar-owned clients run Required and provide Network, plus Service and FriendsAndFamily only per §6.10.1, never Public; edge platform clients run Required and relay-only toward sidecars, but for §6.10.1's accepted window while a sidecar.yml push is broken (owner decision 641). *Why:* the directive rules out Opportunistic; Public enters the egress index.

**D-PROTO-7 (proposed).** Statements others act on carry a typed `Signed` (§6.9), whose signed bytes name the message type. *Why:* transfer authentication proves nothing to third parties.

**D-PROTO-8 (proposed).** Push types are accepted only from ControlId on platform carriers, and nothing else from ControlId. *Why:* P2P can forge ControlId.

**D-PROTO-9 (proposed).** Cross-network grants and edge relationships are never minted as ProvideMode Network, but for §6.10.1's accepted window while a sidecar.yml push is broken (owner decision 641). *Why:* Network grants LAN and loopback egress.

**D-PROTO-10 (proposed).** Sidecar clients never request P2P streams, so pairs stay relay-only until C3 lands, P2P is tested and a network turns it on; a forcing peer can still move a pair (server/model/contract_stream_binding.go:78-93). Same-network P2P is built at M6 behind `SidecarProtocolSettings.EnablePeerP2p`, default off, and relay-only stays until a later owner call made on §22's P2P schedule and measurement (owner decision 296); before any network turns it on, §2.8's connect-2 and §2.10 say what a pair on P2P shows. *Why:* D-PROTO-8, not the carrier, is the control.

**D-PROTO-11 (proposed).** Package `urnetwork.sidecar`, protoc-gen-go v1.36.11, and `connect.ProtoCodec` until §22 justifies a pooled codec. *Why:* no registry or sdk-pin conflicts.

**D-PROTO-12 (proposed).** Hint writes and triggers follow §6.8, every version a canonical decimal string in Redis and its scripts, never a Lua number, and uint64 on the wire. *Why:* HSET and XADD emit nothing in production; concurrent writers would lower versions; Redis's Lua holds numbers as doubles, exact only below 2^53, so evs's push sequence, near 1.8 × 10^18, would round to a multiple of 256.

**D-PROTO-13 (proposed).** Peer sessions pass §6.4's identity check before streams or RPC. *Why:* first-contact key substitution (EX6); owner decision 3.

**D-PROTO-14 (proposed).** Sidecars compare pins by HeadCheck (D-PROTO-17) on §6.4's schedule, any admitted reader sidecar witnessing (owner decision 129), reconcile, and refuse lower or conflicting values; across a split, §2.8's bound does not hold. *Why:* withholding and rollback are otherwise invisible.

**D-PROTO-15 (proposed).** Edges use Service and shares FriendsAndFamily, reaching private destinations only through C18 (§6.10.1; owner decision 11). *Why:* no Network privilege, egress index, new PostgreSQL query or foreign packets in sdk providers' NATs.

**D-PROTO-16 (proposed).** Every limit, protocol and format limits included, is a field of §6.6's settings or of its owning component's settings object, with process-wide caps; only identifiers are named constants (§6.6's bounds; owner decision 297), and no security property is feature-gated (§6.4). *Why:* connect/CODESTYLE.md:142-145, whose exceptions narrow to identifiers; code and tests read one place; no downgrade by negotiation.

**D-PROTO-17 (proposed).** HeadCheck compares the auth pin, generations, ref heads, shared MLS epochs and vetoes, at most 16 of each a message and rotating, and reconciles a lower side; a device counts as a witness only a peer at its pin, neither revoked, parked nor suspended in its state, that sends neither `proven` nor `unverified`, and none while it holds an UNVERIFIED pin itself; proof of withholding or a FORK stops sealing at once and rides on as `proven`, and a higher pin that neither api nor its claimant proves is UNVERIFIED and rides on as `unverified` with its relay path, each receiver holding it until it reaches the pin or a sidecar on the path is revoked or parked (§6.4). *Why:* v0 must detect ref and generation forks, a peer that is merely behind proves nothing, and a writer that a chain of up to 8 HeadCheck hops links to a holder must stop, at `witness_bound_hours` when the server drops the proof or the gap is wider than the newest 64 KiB of entries a holder, phones included, keeps to serve it; the path ends a false pin's denial when its maker is revoked or parked, as FORK's ends at revocation.

**D-PROTO-18 (proposed).** Two admitted sidecars of one network, neither revoked, parked nor suspended (§8.10 governs), and only they, get a Network contract of class `control` with no reach grant, carrying only Hello, Ping, HeadCheck and HeadCheckProof, D-PROTO-21's SEARCH pair at a sidecar that serves remote search, and DESIGN-COMPUTE.md's LISTENERS pair, a peer RPC for listeners' live ask (owner decision 770); receivers refuse streams and other RPCs on it, and providers deny IP (§6.4, §8.10). *Why:* owner decision 129's witnesses need a path that policy cannot cut.

**D-PROTO-19 (proposed).** On every contract, whatever its mode, C13 seals the server-authenticated sidecar subject (the stored `acl_subject_client_id`), the source network, the contract class and the subject's `WindowDelegation`; a companion contract inherits its forward contract's subject, source network and class, and seals no `WindowDelegation`, which is the forward contract's alone (owner decision 301); the dialer's network alone is escrowed (§6.10.1). *Why:* grants key on the subject, and a client-asserted subject is forgeable; one set for every mode gives C5's hook and C18 the same fields; §17.9 verifies the delegation.

**D-PROTO-20 (proposed).** §6's codes are frozen enums whose 0 is UNSPECIFIED, a protocol error (ErrorCode keeps OK, never sent), the poll body is `PollResponse`, and a partial `PushReset` advances no applied version. *Why:* the wire freezes at M2, and a default-constructed code must never read as retry, drain or success.

**D-PROTO-21 (proposed).** `SEARCH` (0x1404) and `SEARCH_RESULT` (0x1405) carry §11.14's remote search, to a designated search indexer (owner decisions 175, 178), on the pair's Network contract: data where reach allows, otherwise the control class, whose receivers accept SEARCH only at a sidecar advertising Hello feature bit 0, and SEARCH_RESULT only as its reply. Search requests always carry `timeout_ms` 10,000, are never cancelled, and repeat by (search_id, page). DESIGN-COMPUTE.md's `EVIDENCE` (0x1406) and `EVIDENCE_RESULT` (0x1407) are the ask by which a member's device has the network's indexer enclave answer, on the device's own nonce, a quote or report with its public keys and B and, for an incarnation set up over SSH, its sponsor's setup statement, saying too whether its mail receiver and search service are up, which the device that ran its steps takes as its readiness (owner decisions 752, 773; DESIGN-COMPUTE.md §11.6, §11.10). *Why:* remote search must work under every policy document without a reach grant, and carries no IP. On the control class the gate sees what HeadCheck shows it, and the indexer's own evaluation authorizes each repo.

**D-PROTO-22 (withdrawn).** Superseded by owner decision 609: the remote-search pair's contracts are accounted like any peer's, with no windows, floor, withheld reports or keepalive.

### 6.14 Open questions

**Q-PROTO-1.** [X8] How do server services push to clients in real time? **Decided by owner 2026-11-03 (owner decision 17):** (b), ControlId-sourced hints (§6.8), amending SUBPROTOCOL.md decision 6 (connect/SUBPROTOCOL.md:372-373) so the control id may send subprotocol frames to clients, never receive them (C12), plus an HTTPS long-poll fallback in v0. *Residual:* none.

**Q-PROTO-2.** May a sidecar share the device's client (X10, §5)? **Decided by owner 2026-11-03 (owner decision 4):** no. Each sidecar owns a Required client (§5.5, Q-CORE-1), and no sidecar role runs in the iOS tunnel (owner decision 87). *Residual:* none.

**Q-PROTO-3.** Which provide modes carry edge and share traffic (cross-cutting, X11)? **Decided by owner 2026-11-03 (owner decision 11):** (b), Service (6, C9, M5) for edges, authorized by §9's Find-recorded pair, and FriendsAndFamily (2) with a sealed source network (C13) for shares (§6.10.1). *Residual:* none.

**Q-PROTO-4.** Cross-cutting (§2.8, §11.14, §20.6). Should connect keep remote search's byte totals per contract, which show roughly how many search pages ran in each contract hour? **Decided by owner 2026-11-05 (owner decision 176):** (b), connect change C19 (§4.6), hiding up to five pages an hour by rounding the marked pair's reports up to 128 KiB, at ~5 MiB a day for a phone foregrounded in 20 separate hours, against the free tier's 30 GiB daily grant (config/all/pro.yml:88-89); §2.8's connect-5 states what remains visible (options (a), disclosure alone, and (c), shorter contract retention, not taken). **Amended by owner 2026-11-06 (owner decision 188), after the meta review's F18:** rounding each report did not hide one page once background, checkpoints or contracts opened after idle exits put a page across a step, so C19 reports each §6.10 window, both directions, at a floor F = 256 KiB covering five exchanges and the pair's scheduled background at its maximum, F plus 128 KiB steps past it, withholding every report to the window's end, with a keepalive a minute while the app is in the foreground: 512 KiB a window, ~10 MiB a day for a phone foregrounded in 20 separate hours and at most 13.5 MiB a day a pair; the same windows at a 128 KiB floor, which covers only the routine schedule, and the claim narrowed to 128 KiB quantization were not taken. **Amended by owner 2026-11-06 (owner decision 191), after the meta review's checks:** a search that finds the pair's foreground session lost (120 s with no Pong) re-establishes it at once by its own Hello, whose contract and successor keep that search's time in connect's rows, as connect-5 discloses beside a failover's window; waiting for the keepalive's re-establishment, which can stall a search up to a minute after an outage at the indexer's end, was not taken. **Amended by owner 2026-11-17 (owner decision 609), after the complexity review:** C19's window accounting goes, with its floor, withheld reports, keepalive and warm pairs; the pair's contracts are accounted like any peer's, so api's rows show when a phone searched through an indexer and how many 20 KiB exchanges it took, the fixed sizes still hiding pages from relays; keeping both and deferring remote search were not taken. *Residual:* none.

### 6.15 Departures from PLAN.md

- **PLAN.md:82:** edges are platform clients in Service mode, not clients per served network (owner decisions 11, 59; §13.14, Q-TLS-5).

### 6.16 Interfaces

- **Provides:** `sidecar.Subprotocol` (§4.4's `envelope_`, `rpc_`, `stream_`, `push_` and `codec_` files) with `Call`, `Handle`, `OpenStream` (a `net.Conn` with `CloseWrite`), `Listen` and `Subscribe`; `SidecarPublisher` (`sidecar/pushservice`); typed `Signed`, `SignedType`, `VerifySigned` and `VerifyPresenceCountersign` (`protocol/bridge`, §4.4); `HeadCheck`, `HeadCheckProof`, `witnessed_at` and the control-contract message rule; `CallOptions.Edge`, `Subprotocol.SendEdge` and the edge role's `HandleNoReply`, by which a sidecar calls and sends to an edge with no Hello (§6.4; owner decision 624); the code, topic, Hello feature and message registries; `PollResponse`; §6.10's accounting, remote search's contracts among it, and §6.10.1's contract mechanism.
- **Consumes:** §5's Required client, identity key, binding and `GET /sidecar/identity/<sidecar_id>`; §7.9's authorization log (AuthPin, entries from api, RecoveryVeto), admissions, `IndexerSet` and `ServiceSettings.witness_bound_hours`; D-TRUST-10 (§2); §10.4's MLS pins and §10.5's `gen/`; §11.9's ref statements, §11.10's push sequences and §11.14's remote rules; §8's hook, local policy, signed projection and §8.10's control contracts; §9's tickets and Find-recorded pairs; §4's connect changes (C13's seals); §17.9's `WindowDelegation`; §20's payer and escrow; §18.7's wake trigger, §18.8's lease and §19's push sender.
- **Subprotocol messages:** §6.11's services 0x00 and 0x02 (peer↔peer) and 0x01 (ControlId→client), and service 0x14's SEARCH pair (peer→peer: an app host to a search indexer, §11.14).
- **API routes:** `GET /sidecar/sync/versions?cursor=` (200 `PollResponse`, paged), `GET /sidecar/sync/<topic>?since=`, which serves `core` alone (§6.8's sync routes), and `GET /sidecar/sync/poll?cursor=` (≤25 s; 200 `PollResponse`); `POST /sidecar/wake {sidecar_id}` (another admitted device of the caller's member, hourly at most; §18's content-free wake on `core`); `POST /sidecar/close` (an ephemeral page's best-effort unload beacon, reaping that client at once; D-SDK-17). All are in connect/api/bringyour.yml, Client class except `/sidecar/close`: `sendBeacon` sets no Authorization header and Workers lack it (https://www.w3.org/TR/beacon/), so the key-origin iframe document sends, as a text/plain body, a 128-bit close capability minted with the ephemeral client (§7.7, §18.8), which authorizes only that client's close; the route is Public, a credential of its own kind (server/api/route_authz.go:23-26).
- **Tables:** PostgreSQL: §18.8's `network_client_lease` (api; MG1), one row per ephemeral client. Its poll writes `seen_time` only when `SET {scp_<clientId>}hb 1 NX EX 300` sets or errs, so at most once per 300 s while Redis answers; no poll writes `network_client`, whose `auth_time` keeps `ConnectNetworkClient`'s hourly refresh (server/model/network_client_model.go:3625-3634); `/sidecar/close` matches `close_sha256`. Redis: `{scp_<clientId>}ver`, `hint` and `n` (owners write by script; residents and api read); §18.7's `{scp_<clientId>}live`, `tok` and `ack`, and `{wakeq_<shard>}` (owning services, evs included, write; §19's push sender reads); §18.8's `{scp_<clientId>}hb` (api); `{svc_<listenerClientId>}` (sockets writes; CreateContract reads); `{wake_<sidecarId>}` (api's hourly limit, TTL 1 h).
- **Services and config:** resident publishers in server/connect behind `EnableSidecarPush`; `config/<env>/sidecar.yml`'s `push` gate and `urnetwork_edge` key, the `urnetwork-edge` network's id (§19.11).
- **Assumptions about other sections:** §5.4's `SidecarSettings.ProtocolSettings` carries `SidecarProtocolSettings`, its `head_alarm` event §6.4's alarms, and its status `witnessed_at` and each UNVERIFIED pin held; §2.8's EX6 lasts until M2's admission check; §7.9's presence row says which statements carry `Signed.webauthn` as a countersignature, and §16.6's countersign row checks it (owner decisions 185, 187); §11.10 creates each repo's push sequence in Redis at its master's `TIME` in µs × 1,000, a decimal string no script turns into a Lua number, so a loss restarts it above its old values beyond the masters' clock skew; §12.6's restore raises the zone serial above every value issued before the restore, §7.9 keeps `team`'s log position, and every other topic's version is a clock, whose fall is a gap, so §19.10 needs no step for them; §4 lists `sidecar/pushservice` (owner decision 104), and §4.6's C13 and §17.6's `EgressFlow` seal the source network in every mode, with the class; connect accounts remote search's pair like any peer's, §4.6's C19 withdrawn (owner decision 609); §11.14 pads every search body as its sizes rule states; §7.9 and §17 declare what a device verifies in `protocol/bridge`, §7.9's retain row that every sidecar, phones included, keeps the newest 64 KiB of entries a HeadCheckProof serves, its cascade which sidecars are parked, and §17.9 the share keys' `signer_id` and `key_id` as §6.9 gives them; §8.10 issues control contracts from M4, with the contract gate (§8.19, §23.6); §9.6 takes `StreamRejectCode`'s numbers (retry 1 to quota 5); §18.7 defines the wake trigger; §7.7's ephemeral mint inserts the `network_client_lease` row, and §7.8's enroll and auth-client responses return its `close` capability once; §22.5 tests the long-poll, `team` hints at `acl_enforcing` device clients, stable code numbers, the zero rule and the partial-reset rule, and FS-17 a relayed proof (desktop holder, peer and writer, the writer-holder contracts dropped; again with a phone holder serving it from its newest 64 KiB, and the writer stops at once), a relayed `unverified` pin with that proof dropped and with a gap wider than the phone's kept entries (the phone answers NOT_FOUND, the peer sends `unverified` and counts for no one, and the writer stops at `witness_bound_hours`), an R-X-Y-W chain, a copy cleared by its relayer's revocation, and a parked peer that counts for no one; FS-125 keeps its number, held with C19's withdrawn windows (owner decision 609).

### 6.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| ControlId pushes forged over P2P | Low | High | Carrier guard; C3 in M1 |
| One stalled pack resets a peer's streams | Medium | Medium | Keepalive, reset codes, RPC retry |
| Redis load from fan-out and a pattern on every master | Medium | Medium | Class-$ trigger, `EXPIRE NX`, coalescing; §19 load test |
| Redis loss drops hints, subscription leases and evs push sequences | Low | Medium | Sequences restart above old values beyond the masters' clock skew, and clients take a jump or a clock version's fall as a gap and resync; holders re-create leases hourly (§11.10; owner decision 136) |
| Ack-and-discard hides misconfigured peers | Medium | Medium | App responses; ENCRYPTION reason |
| Edge or share contracts minted as Network, or FriendsAndFamily IP past its grant | Medium | High | D-PROTO-9; C18 per flow, off on sdk providers; §22 tests |
| First-contact key substitution in M1, before admissions | Low | Critical | C15 and Hello's check in M1; admissions from M2; EX6 (§2.8) |
| No witness for a writer: weekend CI, a lone cloud agent, an absent team | Medium | Medium | Agents witness too, over control contracts; alarm at 24 h; shared writes stop at `witness_bound_hours`, up to 168 h (owner decision 129) |
| A relaying server withholds a revocation and drops cross-split traffic; stale writers witness one another and keep sealing to the removed reader | Medium | High | A HeadCheck path from a holder, direct or within 8 hops through peers relaying `proven` or `unverified`, stops the writer: at once with a proof, at `witness_bound_hours` without one (dropped, or a gap wider than the newest 64 KiB of entries the holder keeps); each round includes peers of other members (§6.4); where no path crosses, owner decision 129's bound does not hold, as §2.8 states |
| Memory across hundreds of peers | Low | High | Per-process caps; mobile defaults |
| Relays time remote searches and count their pages, and api's rows show when a phone searched through an indexer and how many exchanges it took | High | Low | Fixed sizes hide each page's content and length; the rest is disclosed in §2.8's connect-5, as evs-26 discloses "search more" (owner decision 609) |

### 6.18 Phasing

- **v0 (M1, same network).** Hello with M1's identity check, RPC, chunking, typed `Signed`, the numbered codes, hint push, the long-poll fallback with `PollResponse` and §18.8's lease (MG1), `POST /sidecar/close`, and `connect.ProtoCodec`; C3, C12 and C15.
- **M2.** Hello checks admissions; scheduled HeadCheck over auth pins, generations, ref heads, MLS epochs and vetoes (§7, §10, §11), with the `proven` and `unverified` relays and owner decision 129's witness alarm and stop; the wire freezes.
- **M4.** C13's seals (D-PROTO-19), with §17's bridge; control contracts (D-PROTO-18) with §8.10's contract gate, since from then a network's document can cut every other witness path.
- **M5-M6.** Streams with §9's `tls/`, and the pooled codec if measured worthwhile; Service edges (C9, M5); FriendsAndFamily shares with C18 (M6); same-network P2P behind `EnablePeerP2p`, built at M6 and off by default (owner decision 296).
- **M8.** `POST /sidecar/wake`, wakes through §19's push sender for unacked hints (§18.7), and `team` hints to `acl_enforcing` device clients, with §18's mobile hosts (owner decision 88).
- **M10 (v1; owner decision 169).** The SEARCH pair, Hello's feature bits 0 and 1 and the control class's acceptance of SEARCH, app hosts asking from the later of M10's and M8's exits (§18), the pair's contracts accounted like any peer's (owner decision 609); their bytes freeze at M10's Gn-out, additive to M2's wire.
- **v1.** P2P for same-network sidecar pairs once C3 is tested, able to end relay-only at [a later owner call](DESIGN-DEFER.md#proto-peer-p2p) (owner decision 296).
- **Later.** [Logical lanes (C7)](DESIGN-DEFER.md#repo-c7-logical-lanes), [stream resume](DESIGN-DEFER.md#proto-stream-resume), and [hybrid-only TLS groups](DESIGN-DEFER.md#proto-hybrid-only-tls-groups).
- **Deferred.** DESIGN-DEFER.md holds an entry for each Later item, linked above, and for [this section's v1 set](DESIGN-DEFER.md#proto-v1) (owner decision 587).
