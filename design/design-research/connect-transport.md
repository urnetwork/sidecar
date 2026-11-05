# Fact sheet: connect's client/transfer layer as the sidecar substrate

Research for the sidecar design writers, 2026-11-03. Read-only survey of the working trees under `/Users/brien/urnetwork` (connect HEAD `49f285f1`). Code citations are `repo/path:LINE` relative to `/Users/brien/urnetwork`. Anything marked **inference:** is my reading, not a statement in code. Where a design note and the code disagree, the code is treated as correct and the disagreement is noted. The message repo and `connect/MESSAGEREVIEW.md` were left out as instructed.

---

## 1. Summary

1. A sidecar is an ordinary `connect.Client`. Its id must be the `client_id` claim of a client JWT minted by `POST /network/auth-client` (`connect/api.go:233-268`, `connect/jwt.go:7-52`). It attaches through `NewPlatformTransport*`, whose Auto mode prefers H1 WebSocket and falls back to H3 (`connect/transport.go:152-178`). Contracts are created out of band over HTTPS `POST /connect/control` (`connect/transfer_contract_manager.go:2399`, `server/api/api.go:345`).
2. Subprotocols are implemented in `connect/subprotocol.go`. They have 16-bit ids, and the public registration accepts only ids from 1024 up. Each id gets any number of raw listeners plus at most one typed codec. Handlers run inline and must not block. Sends to `ControlId` are refused, and there is a peer query. There is no fragmentation, and the per-registration size and provide-mode options described in SUBPROTOCOL.md §6 were not built.
3. The hard size limit is one transport message of **16 KiB**. The code says 16 KiB; SUBPROTOCOL.md says 8 KiB, and the code wins (`connect/transfer.go:1722-1724`). Measured per-pack overhead is about 107 B in plaintext and about 180 B when encrypted, plus about 1.1 KB on a pack that also carries a contract frame.
4. Delivery is reliable, ordered and deduplicated **per send sequence**. A sequence is keyed by destination, companion, force-stream, logical lane and encryption role/companion (`connect/transfer.go:5781-5796`). If an item goes 60 s without an ack, the whole sequence is torn down (`connect/transfer.go:904`, `:9595`). A transfer ack does not prove that the application received the data.
5. Backpressure: `Send` blocks by default. Receive callbacks run inline. On reliable carriers the client's single receive pump waits when a sequence queue is full. **inference:** one slow handler therefore stalls traffic from every peer.
6. **Same network:** contracts use the Network provide mode. No escrow is taken and no one pays, but the bytes are still recorded in contract close reports. **Different networks:** the relationship is always Public. That requires the destination to provide Public (escrowed from the sender's balance) or a Stream companion reply to an existing contract. Two ordinary consumer clients in different networks cannot talk today.
7. End-to-end encryption: per-peer TLS 1.3 sessions (X25519MLKEM768) seal the entire inner TransferFrame with AES-256-GCM. Residents still see the outer path ids, sizes, timing and role hints, and the platform mints every contract and receives its byte counts. Encryption is Off by default in connect; the sdk's provider client uses Opportunistic.
8. The only real-time server-to-client push today: the resident's internal client, whose id is `ControlId`, sends control frames to the user client when a Redis keyspace event fires. The client consumes them in a `ReceiveCallback` that checks `source.IsControlSource()`. This traffic needs no contract and is never e2e-encrypted.
9. A server-run "platform client" with its own client id is possible; the egress prober is a precedent. But it cannot reach user clients unless the server's contract relationship rules change.
10. connect has no client-to-client stream or socket abstraction. Two bases exist for building one: a multiplexed stream subprotocol over sequences with its own credit flow control, or `connect.Tun` (gVisor TCP) carrying IP packets as no-ack messages.

---

## 2. Facts with citations

### 2.1 Direct answers

**(a) The best way today to carry a reliable, bidirectional byte stream (TLS edge, abstract sockets), and what it costs**

- **Best option without changing connect:** a sidecar-owned stream-multiplexing subprotocol on one id of 1024 or higher.
  - Send it with `SendSubprotocolBytes` or `SendSubprotocolWithTimeout` on the default reliable lane (`connect/subprotocol.go:902-1008`).
  - The protocol needs OPEN/ACCEPT/DATA/WINDOW/FIN/RST messages, stream ids and byte offsets.
  - It must carry its own per-stream credit, in the style of SSH `SSH_MSG_CHANNEL_WINDOW_ADJUST` (RFC 4254 §5.2, https://www.rfc-editor.org/rfc/rfc4254.html#section-5.2) or QUIC `MAX_STREAM_DATA` (RFC 9000 §4.1, https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1). The reason: handlers cannot block (`connect/subprotocol.go:77-85`), so a receiver can only drop or queue, and dropping breaks a byte stream.
  - Any ack error must abort or resume the stream, because an ack timeout destroys the whole sequence (`connect/transfer.go:9550-9616`).
- **Cost: head-of-line blocking.** Every stream to one peer shares one ordered sequence, so one lost pack stalls all of them until it is resent. This is the failure RFC 9114 §1.1 describes for HTTP/2 over TCP: "a lost or reordered packet causes all active transactions to experience a stall" (https://www.rfc-editor.org/rfc/rfc9114.html#section-1.1).
  - Resend floors are 300 ms once an RTT is known and 2 s cold (`connect/transfer.go:883`, `:890`).
  - Fast retransmit starts after 3 selective acks (`connect/transfer.go:923`).
  - The only built-in mitigation is logical lanes 1..8 (§2.4), which are experimental and off by default.
- **Cost: flow control.** Transfer limits each sequence, not each stream.
  - The sender's resend queue is capped at 2 MiB, memory-scaled (`connect/transfer.go:961`).
  - The receiver advertises how much out-of-order data it can hold (`connect/protocol/transfer.proto:207-223`), defaulting to about 2.5 MiB (`connect/transfer.go:1099`).
  - Nothing reflects whether the application has consumed the data.
- **Cost: overhead.** Measured (§2.5):
  - About 180 B per encrypted pack: 4.4% at a 4 KiB payload, 2.2% at 8 KiB, 16% at 1.1 KB.
  - About 88 B per plaintext ack and about 160 B per encrypted ack (**inference** for the encrypted figure). Acks are coalesced (`connect/transfer.go:1076-1084`).
- **Cost: setup.** The first contact with a new peer needs:
  - one API round trip to create a contract;
  - a TLS 1.3 + ML-KEM handshake over transfer whose server flight is about 5 KB (`connect/transfer.go:1708-1711`);
  - a companion or Network contract for replies.
  After that, network-peer contracts start at 1 MiB and grow to 128 MiB, and a successor is prefetched at a fill fraction of 0.8 (`connect/transfer_contract_manager.go:354-356`, `connect/transfer.go:989`).
- **Cost: path.** Traffic is relayed client → resident → exchange → resident → client (`server/connect/resident.go:40-63`), unless a same-network P2P stream gets promoted (`server/connect/GLOSSARY.md:72-75`).
- **Alternative: real TCP over gVisor.** `connect.Tun` offers `DialContext` and `ListenTCP` (`connect/tun.go:1-13`, `:1335-1345`, `:1389`). Its IP packets can travel as no-ack subprotocol messages; the opts are passed through (`connect/subprotocol.go:986-1001`, `connect/transfer.go:1511`).
  - Gains: TCP flow and congestion control per connection, and no head-of-line blocking across connections.
  - Costs:
    - Nested congestion control. RFC 9484 §10 notes the tunnelled traffic "will incur at least two nested congestion controllers" (https://www.rfc-editor.org/rfc/rfc9484.html#section-10).
    - About 1.1–1.28 KB packets (`connect/ip.go:44`, `:54`) carry about 180 B connect overhead plus 40–60 B of IP/TCP headers. **inference:** roughly 20%.
    - gVisor memory per Tun.
    - Tun addresses come from a process-local allocator (`connect/tun.go:863-900`), so an addressing scheme has to be designed.
    - No-ack packs "may be dropped if [the] matching contract is not active" (`server/connect/GLOSSARY.md:126`).
  - **inference:** a natural fit for the "IP address and port forward" item, heavier than the mux for the TLS edge.

**(b) How a server-side service could push a message to a specific client in real time**

- **Existing mechanism.**
  1. Server state changes in Redis.
  2. `keyEventSubscriber` on every connect process dispatches the keyspace notification to listeners (`server/connect/session_notifications.go:27-35`, `server/connect/key_event_subscriber.go:140`, `:162`, `:185`).
  3. Only the process hosting that client's resident has a listener. The listener calls `Resident.sendListenerFrame` → `self.client.Send(frame, clientId)` (`server/connect/resident.go:4849-4860`). Existing pushes include network peers, stream hops, client close, `NetworkSessionsChanged` (`:4696-4806`) and `ResidentMigrate` (`:2105-2127`).
  4. The resident's internal client has id `ControlId` (`server/connect/resident.go:46-58`). `ControlId` needs no contract on either end (`connect/transfer_contract_manager.go:686-697`) and gets no encryption session (`connect/transfer_encrypt.go:3662-3686`).
  5. On the client, a callback added with `AddReceiveCallback` checks `source.IsControlSource()` and switches on `MessageType`. The pattern is shown in `sdk/device_local_provider.go:616-640`.
- **Using it for the sidecar needs server work.** The server must add a listener (per client or per network) and pick a frame type:
  - A new top-level `MessageType`. This changes connect; older clients ignore unknown types (`connect/protocol/frame.proto:63-71`).
  - A `MessageType_Subprotocol` frame with a sidecar id, sent from ControlId.
    - The client dispatches subprotocol frames from any source (`connect/subprotocol.go:590-651`), and `SendSubprotocolBytes` refuses ControlId only as a *destination* (`:994-996`). **inference:** this works today without changing connect.
    - It contradicts SUBPROTOCOL.md §8.6, which says "the control id speaks only the top-level protocol".
- **Semantics.**
  - Delivery is reliable only while the client is connected; the resident exists only for a live connection.
  - Listeners re-read full state when they register (`server/connect/resident.go:4768-4773`, `:4799-4805`). So pushes must be idempotent state sync (snapshot plus deltas, like `NetworkPeersReset`+`Update`), not durable messages.
  - In-band control *from* the client cannot carry replies; replies go through the HTTPS API (`server/connect/resident_controller.go:61-64`).
- **Platform-client alternative.** A server process runs `connect.Client` as a client of a platform-owned network; the precedent is the egress prober using `ByClientJwt` (`server/taskworker/work/provider_egress_probe_work.go:2070`).
  - Today it needs a Public relationship, which means escrow and requires the user client to provide Public. Alternatively it can reply on a companion contract after the user client contacts it first (§2.6).
  - Removing that requirement needs a server rule change, for example special-casing a service network the way `ControlId` is special-cased in `getProvideRelationshipDetails` (`server/controller/connect_controller.go:604-616`).

**(c) Limits a sidecar subprotocol must respect.** These are listed in §3.

### 2.2 Client identity, authentication, attaching to the platform

- **Constructors.** `NewClientWithDefaults` / `NewClient` / `NewClientWithTag(ctx, clientId, clientTag, clientOob OutOfBandControl, settings)` (`connect/transfer.go:2254-2283`). The client id is supplied by the caller.
- **Client id must match the JWT.** `ClientAuth.ClientId()` parses it from the JWT (`connect/transport.go:358-364`). The resident drops any forward whose source is not its own client (`server/connect/resident.go:4943-4954`). **inference:** a client constructed with a different id cannot send anything.
- **JWT claims.** `ByJwt` has `UserId`, `NetworkName`, `NetworkId`, `ClientId`, `SessionId` and `RootClientId` (`connect/jwt.go:7-14`). The client JWT is minted by `AuthNetworkClient{ClientId?, SourceClientId?, Description, DeviceSpec}`, which returns `by_client_jwt` (`connect/api.go:233-268`). Setting `SourceClientId` creates a *derived* client.
- **Network id.** The client itself never uses its network id; same-network status comes from the contract (§2.6).
- **Auth.** `ClientAuth{ClientInfo, StreamLeaseVersion, ByJwt, InstanceId, AppVersion, ProvideIntent}` (`connect/transport.go:348-364`). The server validates the live JWT state and parses `InstanceId` (`server/connect/transport_authentication.go:38-59`).
  - `InstanceId` identifies one running instance; a new value starts a newer generation for the same client id (`server/connect/GLOSSARY.md:59`).
  - **inference:** the sidecar must persist the instance id, as the examples require.
- **Out-of-band control.** `NewApiOutOfBandControl(ctx, clientStrategy, byJwt, apiUrl)` posts control packs to the API (`connect/transfer_oob_control.go:59-68`, `:105-200`). `SetByJwt` rotates the token (`:101-103`).
- **Identity key.** `ClientSettings.ClientKeySeed` should be persisted to keep the Ed25519 identity key stable (`connect/transfer.go:1658-1663`). `SkipClientKeyPublication` disables publication (`:1670-1676`).
- **Concurrent-client limit.**
  - The platform closes connections that exceed a network's limit, and the client then backs off (`connect/transport_client_limit.go:1-30`).
  - Only **top-level** clients count; derived clients do not, and enforcement may be dark (`server/model/peer_model.go:1520-1528`).
  - Declared provide intent exempts a client from the limit (`connect/transport_provide_intent.go:1-11`).
- **Network peer list.**
  - `PeerManager.NetworkPeers()` lists connected top-level clients of the same network with roles, principal, device name and provide modes, pushed in real time (`connect/transfer_peer_manager.go:27-60`, `:201-226`, `:301`).
  - Only top-level client-category peers receive it, and clients in the "isolated" ACL group do not (`server/connect/resident.go:4784-4790`).
  - Derived clients never appear in the list (`connect/transfer.go:17611-17617`).
- **Minimal bootstrap reference.** `sdk/sim_device.go:104-150` and `:221-229` show a full client built from connect calls only: strategy, OOB, `NewClient`, `SetProvideModesWithReturnTraffic`, `NewPlatformTransportWithTargetMode`.

### 2.3 Transports, including the in-process test transports

- **Platform transport modes.** Auto, `h1`, `h3`, `h3dns`, `h3dnspump`. Auto prefers H1, then H3, then the DNS-carried modes (`connect/transport.go:152-178`). Constructors are at `connect/transport.go:1702-1745`.
- **Framer limit.** The platform framer's maximum is `MinimumMessageLenLimit` because it must carry the encryption handshake (`connect/transport.go:911-914`). The server uses the same limit (`server/connect/transport.go:502`) and calls `ws.SetReadLimit(MaxMessageLen+4)` (`:1616`). With gorilla/websocket, exceeding that limit makes "the connection send a close message to the peer and return ErrReadLimit" (v1.5.3, published 2024-06-14, https://pkg.go.dev/github.com/gorilla/websocket#Conn.SetReadLimit). connect's framer rejects oversized writes with an error (`connect/message_framer.go:120-131`).
- **H3.** Small frames go in QUIC DATAGRAMs, with an initial payload of 1160 B and fragmentation; larger frames stay on the reliable QUIC stream (`connect/transport_h3_datagram.go:20-37`).
- **P2P.** WebRTC SCTP data channel (`MaxMessageSize` 64 KiB, `connect/transport_p2p_webrtc.go:863`) or the fast SRTP lane; browser builds keep the data channel (`connect/transport_p2p_fast_js.go:1-5`). P2P carries payload while the platform keeps control (`server/connect/GLOSSARY.md:72`). `P2pReceiveTransport.MatchesReceive` returns true for every path (`connect/transport_p2p.go:2345-2347`).
- **In-process test transports (exported).**
  - `NewSendGatewayTransport()` / `NewReceiveGatewayTransport()` with `Route = chan []byte` (`connect/transfer_route_manager.go:23`, `:3714`, `:3768`), installed via `client.RouteManager().UpdateTransport(t, []Route{ch})` (`:1174`).
  - `NewNoContractClientOob()` refuses all control (`connect/transfer_oob_control.go:258-281`).
  - `ContractManager().HandleControlFrame(ContractKey, frame)` injects a contract (`connect/transfer_contract_manager.go:1173`). `SignStoredContract` and `VerifyStoredContract` are exported (`:291-317`).
  - The test-only helpers `requireContractResult`, `newConditioner` and `applyTestEncryptionSettings` live in `connect/transfer_test.go:592`, `:660` and `:748`, so they cannot be imported. The working end-to-end pattern is `connect/subprotocol_transfer_test.go:17-120`.

### 2.4 Send and receive API and guarantees

- **Guarantees as stated in the header** (`connect/transfer.go:30-38`): eventual delivery up to timeout, in-order delivery, sender notification, mutual contract accounting, return traffic accounted to the sender, multiple routes.
- **Send.** `Send`, `SendWithTimeout(Detailed)`, `SendMulti*`, `SendMultiHop*` (`connect/transfer.go:3317-3365`, `:3656`, `:4228-4260`).
  - `timeout <0` blocks until admitted, `0` never waits, `>0` waits up to the bound (`:4082-4125`).
  - The frame's pool buffer is taken only on (true, nil) (`:3330-3335`).
- **Ack callback.** `AckFunction` runs inline on the send path, and blocking it is backpressure by design (`connect/transfer.go:78-81`).
- **Options.**
  - `NoAck()`, `CompanionContract()`, `ForceStream()`, `Ctx(ctx)` (`connect/transfer.go:1511`, `:1521`, `:1562`, `:1572`).
  - A received `Peer.TransferKey` passed back as an option reproduces the lane for a reply (`:591-603`, `:3928-3952`).
  - `TransferOptions{Ack, CompanionContract, ForceStream, NetworkPeer}` (`:1481-1505`).
  - No-ack packs may arrive out of order (`:1482-1485`).
- **Sequence identity.** `sendSequenceId{Destination, CompanionContract, ForceStream, LogicalLane, EncryptionRole, EncryptionCompanion}` (`connect/transfer.go:5781-5796`). Ordering holds only within one of these. **inference:** a reply sent with a companion key does not share ordering with the request.
- **Timers** (`connect/transfer.go:868-1010`):
  - `AckTimeout` 60 s. At timeout the sequence exits (`:9550-9616`) and every pending ack fails.
  - Send `IdleTimeout` 300 s; receive `IdleTimeout` 120 s and `GapTimeout` 60 s (`:1060-1062`).
  - `CreateContractTimeout` 30 s, `WriteTimeout` 15 s.
- **Receiver deduplicates** by sequence number (`connect/DESIGNNOTES.md:93-97`).
- **Logical lanes.** Lanes 1..8 hash IP five-tuples; lane 0 is control and legacy (`connect/transfer_logical_lane.go:1-37`). `LogicalDataLaneCount: 0`, so lanes are off by default (`connect/transfer.go:1010`). An explicit `TransferKey{LogicalLane:n}` bypasses the capability gate (`:5966-5975`).
- **Receive.**
  - `ReceiveFunction` "is invoked inline and must not block"; frames are borrowed (`connect/transfer.go:618-625`).
  - The client has one multi-route reader (`:4436`). For reliable carriers, `ReliablePackHandoffTimeout: -1` makes that reader wait until the sequence's queue (32 packs / 256 KiB) has room (`:1068`, `:1073`, `:14280-14285`, `:4975-4991`).
  - **inference:** a blocked handler therefore halts all inbound traffic on that carrier.
- **Multi-hop.** At most 8 intermediaries (`connect/connect.go:13-15`). Every intermediary must be an active client, and contract bytes are multiplied by hops+1 (`server/controller/connect_controller.go:1313-1330`).

### 2.5 Message size and overhead

- **Floor.** `MinimumMessageLenLimit()` returns **16 KiB**. The comment explains it was raised from 8 KiB after production captured a 9,124-byte carrier (`connect/transfer.go:1700-1724`). SUBPROTOCOL.md §1 still says 8 KiB at "transfer.go 1318" (`connect/SUBPROTOCOL.md:87-90`); the code wins. `examples/SUBPROTOCOLS.md:84` says 16 KiB.
- **No fragmentation.** There is none at the frame layer (`connect/SUBPROTOCOL.md:89-90`, `:374-375`).
- **Batching.** Packs batch at most 2 frames or `DefaultMtu` (1100 B) of payload; one oversized frame travels alone (`connect/transfer.go:1344-1345`, `:3453-3459`, `connect/ip.go:44`).
- **Contract-size panic.** A frame larger than about 0.8 × 128 MiB panics with "Message too large for contract" (`connect/transfer.go:10414-10419`).
- **Measured overhead.** Measured by marshalling `connect/protocol` types with protobuf v1.36.11 in a scratch program that is not in any repo:

  | Item | Size |
  |---|---|
  | Subprotocol wrapper | 3–6 B |
  | Single-frame plaintext TransferFrame overhead | 101–107 B |
  | Same, encrypted outer frame (`SealOuterFrame`: 12 B nonce + 16 B tag + outer path + hints, `connect/transfer_encrypt.go:338-362`) | 174–180 B |
  | Plaintext ack TransferFrame | 88 B |
  | Contract frame with one P-256 certificate | 1,123 B |

  **inference:** the worst-case payload in one message is about 16,384 − 180 − 1,123 ≈ 15 KB.
- **Pooling.** Message pool classes are 256 B, 2 KiB, 4 KiB and 8 KiB; anything larger is unpooled heap (`connect/message_pool.go:423-431`). The comment keeps "the ordinary H1 data class at 4 KiB" (`connect/transfer.go:1712-1714`).
- **Guidance in examples.** "Keep messages to a few KiB": URMS uses 4112 B and the protobuf example 4608 B. The sdk's companion RPC caps frames at 65535 B (`examples/SUBPROTOCOLS.md:84`, `sdk/subprotocol_rpc.go:12-15`).

### 2.6 Contracts, provide modes, server authorization, accounting

- **What a contract is.** A platform-signed `StoredContract{contract_id, transfer_byte_count, source_id, destination_id, stream_id, priority, provide_tls_certificate, destination_client_public_key, signature, roles, principal, expiration}`.
  - It is HMACed with the **destination's** provide secret for the mode (`connect/protocol/transfer.proto:563-645`, `connect/transfer_contract_manager.go:291-300`).
  - `roles` and `principal` are set only for Network contracts (`connect/protocol/transfer.proto:631-638`) and surface as `Peer.Roles` / `Peer.Principal` (`connect/transfer.go:608-617`, `:17287-17296`).
- **Who verifies.** The receiver verifies the HMAC against its own secret. The mode must be enabled, and while providing is paused only Stream and Network pass (`connect/transfer_contract_manager.go:1580-1606`, `connect/transfer.go:17503-17520`).
  - Clients send their provide secrets to the platform (`connect/transfer_contract_manager.go:1420-1480`, `server/controller/connect_controller.go:1568-1581`). **inference:** the platform can mint any relationship.
- **When a contract is needed.** It is needed for every peer except `ControlId` and the client itself, unless contracts are disabled by time (`connect/transfer_contract_manager.go:536-538`, `:686-697`, `:1635-1662`). Peers without a contract are labelled `ProvideMode_Network` (`connect/transfer.go:17297-17303`). The server forwards only with an active contract (`server/connect/resident.go:704`, `:5034-5043`).
- **ProvideMode values** (`connect/protocol/transfer.proto:354-361`):
  - None=0.
  - Network=1: same network.
  - FriendsAndFamily=2.
  - Public=3: anyone; enters the egress index (`server/model/egress_index.go:1315`).
  - Stream=4: return traffic; `SetProvideModesWithReturnTraffic` adds it (`connect/transfer_contract_manager.go:1483-1493`).
  - PublicStream=5: treated as public by the client (`:1023`, `:1386-1388`). The server model enum stops at Stream=4 (`server/model/network_client_model.go:73-78`).
- **The server-side check:** `controller.CreateContract` (`server/controller/connect_controller.go:748`), reached via `/connect/control`.
  1. The relationship is resolved by `GetProvideRelationshipDetails`. It starts at **Public** and becomes Network only if the two clients share a `network_id` or are the same client (`server/model/network_client_model.go:2258-2337`). `ControlId` is always Network (`server/controller/connect_controller.go:604-616`). **inference:** FriendsAndFamily is never computed as a relationship.
  2. The destination must be active (top-level or derived) (`server/controller/connect_controller.go:710-718`, `:878-896`).
  3. Non-companion requests use the relationship's mode if the destination advertises it, otherwise Stream as a companion fallback, otherwise `NoPermission` (`:734-746`, `:917-944`).
  4. Companion requests use Stream. When the pair is same-network and the destination advertises Network, a companion request is settled as Network instead (`:901-916`). A Stream companion needs an existing origin contract in the opposite direction (`:954-988`, `:1401-1440`).
  5. The destination's secret for that mode must exist (`:992-1012`). Both endpoints are rechecked as active when the contract is written (`:1299-1308`).
- **Answer: can A (network X) send to B (network Y)?** Only if B provides Public (an escrow from X's balance; `contractPayerNetworkId`, `server/controller/connect_controller.go:1230-1248`) or Stream, and in the Stream case only as a reply to a contract B opened to A. Provide modes, B's lifecycle and X's balance decide it.
- **Answer: can two clients of the same network talk free?** Yes. The destination must provide Network. The contract is created with `CreateContractNoEscrowWithExpiration` with `TrustedPriority` and no payer (`server/controller/connect_controller.go:1332-1355`, `server/model/subscription_model.go:2801-2841`). Bytes are still counted from close reports (`server/controller/connect_controller.go:58-62`) and in the block-users stat (`server/model/subscription_model.go:2832-2839`).
- **Contract sizes.** Server bounds are 1 MiB to 256 MiB (`server/controller/connect_controller.go:43-57`).

### 2.7 The subprotocol layer as built, compared with SUBPROTOCOL.md §8–10

- **Wire format.** `MessageType_Subprotocol=30`, `TransferSubprotocolsQuery=31`, `...QueryResult=32` (`connect/protocol/frame.proto:72-85`). The payload is `SubprotocolMessage{subprotocol_id=1, message_bytes=2}` (`connect/protocol/subprotocol.proto:12-31`). This is shape B, per §8.1. §10.1 calls the message `Subprotocol`; the code names it `SubprotocolMessage`.
- **API** (`connect/subprotocol.go`):
  - `SubprotocolId uint16`, `SubprotocolReservedLimit=1024` (`:46-50`).
  - `SubprotocolCodec[T]` (`:56-67`), `SubprotocolMessagePool[T]` (`:72-75`), `ProtoCodec` (`:237`).
  - `SubprotocolRawFunction` / `SubprotocolHandler[T]` (`:80-85`).
  - `AddSubprotocolRawCallback` (`:540`), `RegisterSubprotocol` (`:553`), `QuerySubprotocols` (`:754`), `RetainSubprotocolBytes` (`:812`), `SubprotocolStats` (`:821`), `WithSubprotocolCodec` (`:833`).
  - `SendSubprotocol` / `WithTimeout` / `MultiHop` / `Multi` (`:895-980`), `SendSubprotocolBytes` / `WithTimeout` (`:986-1008`).
- **Matches the design.**
  - Raw listeners run before the typed handler (`:640-650`).
  - Unregistered and decode failures are dropped and counted (`:627-636`).
  - Registration refuses id 0 and reserved ids. The reserved variants are **unexported** (`:545-560`).
  - Sends accept reserved ids (`:874`, `:997`).
  - Sends and queries to `ControlId` are refused (`:755`, `:903`, `:925`, `:951`, `:994`).
  - Dispatch runs before the generic callbacks (`connect/transfer.go:4262-4273`).
  - Query replies use the provider-ping path: Network for the same network, otherwise a Stream companion, zero timeout (`connect/subprotocol.go:665-711`).
- **Diverges from the design.**
  - §6's `SubprotocolOption`, `AcceptProvideModes` and `MaxMessageByteCount` do not exist; `RegisterSubprotocol` takes no options (`:553`). Handlers must check `peer.ProvideMode` and length themselves.
  - Query answers list only application ids, 1024 and up, on both ends (`:369-380`, `:676`, `:727`).
  - Stats are `Sent, SentByteCount, Received, ReceivedByteCount, DroppedUnregistered, DroppedDecode, MarshalOverrun, QueriesSent, QueriesAnswered, QueryReplyDrops, ReceivedById`, which differ from §10.5. There is no "dropped-oversized" counter from §7 (`:383-396`).
  - `SendSubprotocolBytes` always consumes the caller's slice (`defer MessagePoolReturn`, `:993`).
  - "The platform drops any that arrive" (§8.6) actually happens as an error, "Cannot handle oob control message", counted as a control failure (`server/controller/connect_controller.go:556-568`).
  - The client does not check the source of subprotocol frames (`connect/subprotocol.go:590-651`).
- **Users of the layer.** The sdk exposes raw listeners only: `DeviceLocal.EnableSubprotocol`. `SendSubprotocolBytes` copies the slice and sends with a blocking timeout (`sdk/device_local_subprotocol.go:85-93`, `:226-245`).

### 2.8 `subprotocol_rpc_message.go`

It is in **sdk**, not connect: `sdk/subprotocol_rpc_message.go:1-26`. It defines private gob structs (`subprotocolRpcRequest`/`Response`) for the sdk's `net/rpc` **companion-device bridge**. That bridge is `DeviceLocalRpc.Subprotocol`, with operations open, receive (polled, `Pending`), send, query and close (`sdk/subprotocol_rpc.go:95-227`). It lets a JS/TS or remote process use a native `DeviceLocal`'s subprotocols.
- Limits: 16 subscriptions, 65535 B per frame, a queue of 64 messages or 1 MiB (`:12-15`).
- It requires a provider-capable, non-hosted device (`:104-110`).
- It is not a peer-to-peer RPC layer.

### 2.9 Per-peer end-to-end encryption and what residents see

- **Session model.** One TLS session per peer pair (by destination mask), shared by its send and receive sequences. `EncryptedControl` handshake frames ride ordinary packs and are routed into the session (`connect/transfer_encrypt.go:31-60`, `connect/transfer.go:17305-17311`). They are also applied optimistically, out of order (`:4874-4950`).
- **Cipher.** TLS 1.3 with mutual auth, ephemeral certificates, and X25519MLKEM768 preferred (`connect/transfer_encrypt.go:384-421`). The exporter key feeds AES-256-GCM with **random 96-bit nonces** (`:284-312`).
  - NIST SP 800-38D §8.3 caps random-IV GCM at 2^32 invocations per key (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf, 2007).
  - Rekeying happens only on a new handshake epoch (`connect/transfer_encrypt.go:1376-1381`). I found no counter-based rekey.
- **What is sealed.** The entire inner TransferFrame: pack, frames, contract frame, sequence ids, inner path. The inner path is authenticated against the outer one (`connect/transfer.go:4668-4731`).
- **What the platform still sees.**
  - In plaintext: outer `TransferPath` (source, destination, stream ids), `session_role` and `session_companion` hints, sizes, timing (`connect/protocol/transfer.proto:37-60`).
  - Handshake packs and mirrored acks.
  - The platform authors every contract and receives close reports with byte counts.
- **Modes** (`connect/transfer_encrypt.go:473-497`):
  - Off is connect's default (`:786-788`).
  - Opportunistic sends plaintext until the session is up; `OpportunisticEstablishHold` narrows that window (`:590-607`). The sdk provider uses Opportunistic (`sdk/device_local_provider.go:251-258`).
  - Required refuses plaintext. A plaintext application frame received under Required is **acked and discarded** (`connect/transfer.go:17309-17335`).
- **Control-plane traffic is never encrypted** (`connect/transfer_encrypt.go:3662-3686`).
- **Identity.** Peer identity is anchored in the platform: the contract certificate, the Ed25519 key, `/key/<id>`, and signed history plus pins. The code states it "does not stop an operator that is malicious from a client's first contact" (`connect/transfer_key_history.go:22-26`, `connect/transfer_encrypt.go:683-712`).

### 2.10 Existing stream and socket abstractions

- None exists between clients. `vless_stream.go` is extender proxy framing, `stream_fast_path.go` is a prototype IP fast path (`connect/stream_fast_path.go:1-10`), and `FramedMessageConn` is the H1 carrier (`connect/framed_message_conn.go:31-35`).
- The sdk's `DialContext` and `DialTls*` are user-space egress sockets: gVisor `connect.Tun` feeding the provider data path (`sdk/socket.go:93-146`, `:197-240`). "Listener/server sockets are a future API" (`examples/go/socket/README.md:57`).
- `examples/SUBPROTOCOLS.md:293-301` prescribes application-level acks and correlation on (source, message_id).

---

## 3. Constraints the design must respect

1. Sidecar ids must be between 1024 and 65535. connect's reserved-id registration is unexported (`connect/subprotocol.go:545-560`), so ids below 1024 need a connect change. Each client allows one codec per id.
2. Every frame, including wrapper, pack, encryption and a possible contract frame, must fit in 16 KiB. **inference:** an oversized frame stalls or tears down the carrier (`connect/transfer.go:1700-1707`). Enforce a protocol maximum on both sides; ≤4–8 KiB keeps buffers pooled.
3. Handlers and raw callbacks are inline and must never block. Bytes are borrowed and must be copied or retained. Never send with a blocking timeout from a handler; the query reply uses timeout 0 (`connect/subprotocol.go:700-707`).
4. Ordering holds only within one send sequence (destination × lane keys). Ack failure or idle exit ends it, so streams must abort or resume on ack errors and tolerate a new sequence.
5. A transfer ack is not delivery to the application: under Required, data is acked and discarded, and old peers drop unknown types. End-to-end semantics need application acks.
6. A client cannot send subprotocol frames to `ControlId`. Server-bound sidecar traffic must go to a service client id or through the API.
7. Same-network delivery requires the destination to provide Network. Cross-network delivery needs a Public or companion contract with escrow, so the sidecar must not enable Public casually (egress index).
8. Encryption must be configured explicitly; connect defaults to Off. For confidentiality, use Required on both ends and expect no traffic until the session is up.
9. Peer authorization data is platform-signed (`roles`, `principal` only on Network contracts). The receive side cannot tell ControlId from same-network peers by `ProvideMode`; it must check `source.IsControlSource()`.
10. The sidecar may depend only on connect, so it must rebuild the bootstrap itself. The sdk patterns (`sdk/sim_device.go:104-229`) use connect only.
11. A top-level sidecar client counts toward the network's concurrent-client limit (when enforced). A derived one does not, but it is absent from peer lists.
12. Pushes from ControlId exist only while the client is connected. Design them as state sync, not as a mailbox.

## 4. Reusable pieces

- **Client:** `connect.NewClientWithTag`, `Client.RouteManager()`, `ContractManager()`, `PeerManager().NetworkPeers()`, `AddReceiveCallback`, `ClientKeyManager()`, `ReadyNotify()`, `CloseAndWait` (`connect/transfer.go:2277`, `:2491-2499`, `:3243`, `:4414`, `:2487`, `:2402`, `:5162`).
- **Attachment:** `NewClientStrategy` / `NewClientStrategyWithDefaults` (`connect/net_http.go:379`, `:446`), `NewApiOutOfBandControl` (`connect/transfer_oob_control.go:59`), `NewPlatformTransportWithTargetMode` + `ClientAuth` (`connect/transport.go:1738`, `:348`), `BringYourApi.AuthNetworkClientSync`, `GetClientKeySync` (`connect/api.go:270`, `:561`).
- **Provide:** `ContractManager.SetProvideModesWithReturnTraffic(map{ProvideMode_Network:true})` (`connect/transfer_contract_manager.go:1483`).
- **Subprotocol:** `RegisterSubprotocol`, `ProtoCodec`, `AddSubprotocolRawCallback`, `SendSubprotocol*`, `SendSubprotocolBytes(WithTimeout)`, `QuerySubprotocols`, `RetainSubprotocolBytes`, `SubprotocolStats` (§2.7).
- **Send options:** `NoAck()`, `CompanionContract()`, `ForceStream()`, `Ctx()`, `Peer.TransferKey` for replies, `TransferKey{LogicalLane}` (experimental).
- **Paths and control:** `TransferPath.IsControlSource()`, `ControlId` (`connect/connect.go:32`, `:117-119`), `ToFrame`/`FromFrame`, `MessagePoolGet`/`Return`/`Copy`.
- **Tests:** `NewSendGatewayTransport`, `NewReceiveGatewayTransport`, `NewNoContractClientOob`, `HandleControlFrame`, `SignStoredContract` (§2.3).
- **Byte streams:** `connect.CreateTun` (`connect/tun.go:859`), `Tun.ListenTCP`, `Tun.DialContext`, `Tun.Read/Write(Batch)`.
- **Server-side push pattern:** `keyEventSubscriber.Add*Listener` + `Resident.sendListenerFrame` (`server/connect/key_event_subscriber.go:140-185`, `server/connect/resident.go:4849-4860`).

## 5. Gaps, risks, surprises

- **Doc drift.** SUBPROTOCOL.md's 8 KiB floor, §6 options and §10.5 stats names are stale (§2.7). §8.6's "control id speaks only the top-level protocol" is not enforced on receive.
- **Consumer cross-network messaging is impossible today** without one side providing Public. A Public-providing sidecar would enter provider discovery (`server/model/egress_index.go:1315`); **inference** on the exact eligibility. The PLAN pricing ("all of these count towards transfer balance", `sidecar/PLAN.md:353`) is not implemented: Network-mode transfer has no payer.
- **No listener registry, accept handshake, fair scheduler or stream mux** exists anywhere for the PLAN's abstract sockets and TLS edge. The PLAN's "tls edge opens a client on a network" suggests the edge holds a client *inside* the listener's network, which would make the hop a free Network contract. That needs a server-side way to mint such clients. **inference.**
- **Cross-peer head-of-line blocking.** A blocking handler can stall the whole client's receive pump (§2.4) — **inference**, but it follows from `ReliablePackHandoffTimeout: -1`. Whatever TLS edge client multiplexes many listeners is the most exposed.
- **Spoofing risk to verify.** P2P receive transports accept any path (`connect/transport_p2p.go:2345-2347`), and no source filtering appears in the P2P transports (`connect/frame_protobuf.go:1997` is used only by the run loop). Whether a P2P peer could inject frames claiming `SourceId=ControlId` is unverified. Any design that authenticates pushes by `IsControlSource()` must check this.
- **Plaintext windows.** ControlId pushes are never e2e-encrypted (§2.9). Under Opportunistic mode the first frames to a new peer may be plaintext.
- **No counter-based AES-GCM rekey** for long-lived busy sequences, against the 2^32 random-IV limit. Low practical risk; **inference.**
- **Slice ownership.** `SendSubprotocolBytes` returns the caller's slice to the pool even on failure. A foreign slice whose capacity happens to equal a class size + 12 is interpreted through its trailing meta bytes (`connect/message_pool.go:325-350`, `:1242-1262`).
- **First-message latency** to every new peer: API contract round trip plus TLS handshake. The TLS edge should keep long-lived per-listener sequences.
- **Reserved MessageType block.** `connect/protocol/frame.proto:98-119` still reserves MessageType 1000–1003 for the beta message protocol being removed. A new top-level MessageType should avoid that block until cleanup lands.
- **Web worker build.** The extension's web worker means a js/wasm connect build. Browser builds exclude native datagram P2P (`connect/transport_p2p_fast_js.go:1-5`). **inference:** H3/UDP is unavailable there, and the sidecar there runs over H1 only.

## 6. Open questions for the owner

1. Should cross-network sidecar traffic (TLS edge → listener, sharing, SMTP edge) use a new server relationship rule (a no-escrow "service" relationship), per-network edge clients, or Public with escrow? Who pays?
2. For server-to-client pushes (EVS change notices, port-forward rules), is a ControlId-sourced subprotocol frame acceptable despite SUBPROTOCOL.md §8.6? Or should connect gain a sidecar MessageType, or an exported reserved-id registration (ids below 1024)?
3. Is a small connect change acceptable (exported reserved-id API, per-registration size and provide-mode filters, a source check), or must the sidecar live strictly on the current public API?
4. Should the sidecar always run `EncryptionModeRequired`, accepting no traffic to peers that cannot establish a session?
5. Should each harness sidecar be a top-level client (visible in peer lists, counts toward the limit) or a derived client of the device (hidden, exempt)?
6. Is head-of-line blocking across streams to the same peer acceptable for v1? If not, may the sidecar use explicit logical lanes, or should it carry TCP over `connect.Tun`?
7. Is the P2P path in scope for the TLS edge and same-network sockets, or relay-only for v1?
8. What delivery semantics should pushes have when the client is offline: state resync on reconnect only, or a durable per-client queue on the server?
