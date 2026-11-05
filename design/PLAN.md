
# SIDECAR


The implementation of sidecar will be split across the sidecar repo, where a new cli and components will be built, and the server repo, where horizontally scaled services to support those components will be added and integrated into the overall architecture, as well as enhancements to network/team client management and access control. The sidecar components will be exposed in sdk.

The structure of sidecar will be that it depends on connect, but not server or sdk. server and sdk will plan to import sidecar.

The basic struture of sidecar is

```
sidecar/
  go.mod # all service code goes in the root of the module named sidecar
  sidecar.go # the core Sidecar struct that holds an auhtenticated jwt, connect client, api, and encryption key
  protocol/
    # the sidecar subprotocol protobufs
  mcp/
    # stdio mcp server
  cli/
    main.go # cli that speaks stdio mcp by default

```


A network has a dns zone <me>.ur.network and owns all entries in the zone. 


The sdk will have a new sdk/sidecar.go Sidecar struct that imports the sidecar repo and exposes the key controls. This plan does not include the apps, but the sidecar will be used directly by the apps, and also run in the background in the extension as a web worker.


The initial goal for the sdk is to expose the features of the new services below and to integrate them where needed into the existing sdk device (e.g. ip addr, port forward) by introducing abstractions that the Sidecar struct implements.


# New services

The following services will be added vertically through sidecar to server.




# Encrypted Versioned Storage (evs)


Messaging Layer Security (MLS) for collaborative file security


In practical MLS file storage systems, Client-Side Lazy Re-wrapping using MLS Exporter Secrets is almost universal because it avoids introducing complex non-standard algebraic assumptions (like pairings) while keeping client egress low.


[I think in our git setup if a client detects a rewrap is needed it should send a new checkpoint of the file]


Each directory corresponds to a git repo. The entire dir is encrypted with one session key stored in GKM.

A connect client can subscribe/unsubscribe for changes to a dir and subpath, and get notified when there are any changes via a subprotocol message.

The storage service speaks git over https.

The git identity is forced to be the sidecar client id. The file paths are not encrypted with the session key, but the file contents are, following the git-crypt model. 

The file blobs are stored in minio in a new file cluster.

The storage should store diffs, with the clients sending the full file as a checkpoint every N commits on a file. If the git protocol does not support this, we will need to add our own extension. We want to add a custom API to read the head version of a file without having to clone the entire repo. The head verison will be the last checkpoint plus commits after that, all encrypted.



# Abstract socket listener

The ability for a client to publish to the server that it listens on an abstract "network:name" and for another client to make a connect to a single one of many client listening on that name, using a fair scheduler similar to to socker reuse on linux. 


# Access control

The ability to specify which clients, groups, and networks can reach another client, group, network, or abstract socket.



# DNS and TLS edge

Run ur.network as its own dns zone
load balancers forward *.ur.network to the tlsedge service
tls edge opens a client on a network and sends traffic to any listener using subprotocol. does a find listener and accept handshake. The TLS edge uses the abstract socket listeners to connect the edge connection to a client listening.

Certs are issued automatically for each listened TLS endpoint. ideally nginx lb would pass the tls unterminated to the tls edge so that the tls edge can do its own certificate termination.


# SMTP edge

allow N outgoing connects per day for free, more for pro networks. N for free is small.
Each encryopted connect must present the raw header with the Raw original headers showing the routing path, message ID, which is verified in the stream using a zk proof
Abuse reports against the message id halt sending for a day from that network.


ZK park allows TLS to go to destination, but first N bytes buffer. There is a byte header to the tcp connection that gives the plain text values that must appear in the first N bytes, similar to proxy protocol


All the entries DMARC abuse reports need to tie back to outgoing requests must be in the raw ZK header so that we can join the fields back to the network that sent it. I think message id and routing path are the main DMARC headers.




# Local Email server

SMTP server runs locally and terminates a public mail.<me>.ur.network . Writes incoming emails to encrypted storage. Uses SMTP edge for sending.


# Local MCP

Integrate with harness to ingest data into encrypted storage.



# IP Address and Port Forward (bridge)

Ability to store subnets assocaited with a client. When a packet is routed through a device with an ip destination, look up a client associated with that ip and send to that client instead of the default route.

Ability to map a destination ip and port to a new destination ip and port. When ip providing a packet from same network, look at port mappings and rewrite the destination ip and port based on rules.

The rules are stored on the server and the rules that affect each client are sent in real time to each client. The clients consult the local rules to make decisions.

















## MLS NOTES



Using MLS (RFC 9420) for encrypted file storage repurposes its continuous group key agreement protocol for multi-user access control. While MLS was designed for messaging, its $O(\log N)$ scaling and tree-based key derivation map cleanly to shared drives, folders, and collaborative vaults.

---

### How MLS Maps to File Storage

* **Access Control Lists (ACLs) as MLS Groups:** A bucket, folder, or file namespace is represented as an MLS group. Read/write participants are leaves in the tree.
* **Epoch-Bound Encryption Keys:** Instead of encrypting multi-gigabyte files directly with MLS handshake messages, MLS serves as the control plane. Each MLS epoch derives an `epoch_secret` and dedicated application secrets via HKDF. Files are encrypted with random file-encryption keys (FEKs) wrapped by the current epoch key (envelope encryption).
* **Revocation and Membership Churn:** Removing a collaborator traditionally requires re-encrypting entire directories (or managing brittle pairwise re-wrap queues). In MLS, removing a user triggers a standard commit that rotates node keys along the direct path to the root. The revoked user cannot compute epoch keys from epoch $E+1$ onward.

---

### Core Architectural Considerations

#### 1. The Delivery Service vs. Untrusted Storage

MLS relies on a centralized **Delivery Service (DS)** to enforce total ordering of epochs and resolve concurrent commit conflicts. In file storage:

* The object store (S3, Ceph, IPFS, or local disk) stores the encrypted blobs and epoch metadata.
* A sequencing authority (or metadata service) must sequence commits. If Alice revokes Bob while Charlie adds Dave, the sequencer determines which commit establishes epoch $E+1$.
* Without total ordering, tree state forks, breaking shared key derivation.

#### 2. Lazy vs. Active Re-encryption

When a user is removed:

* **Forward Secrecy for Storage:** The revoked user already has past data, but must not read new uploads. MLS handles this automatically by advancing epochs for new writes.
* **Revoking Past Access (Active vs. Lazy):** If you also want to revoke access to existing files they haven't yet downloaded, you must re-wrap the FEKs under epoch $E+1$. To avoid massive I/O overhead on large datasets, file systems typically use **lazy re-encryption**: re-wrap FEKs during epoch transitions, but only re-encrypt the underlying payload data when an authorized user next modifies or writes that specific file.

#### 3. Handling Offline Collaborators & State Bloat

MLS requires members to process commits sequentially to maintain tree state. If a collaborator goes offline for six months while thousands of file updates occur, they must replay the commit history to synchronize their leaf secret to the current root.

* **External PSKs / Tree Snapshots:** File storage implementations frequently use MLS **External Commits** or periodically export encrypted tree state snapshots to the storage layer, allowing catching up without replaying every epoch transition from epoch 0.

#### 4. Granularity: File vs. Folder Hierarchy

Mapping MLS groups to storage nodes requires a structural choice:

| Strategy | Architecture | Trade-offs |
| --- | --- | --- |
| **Coarse-Grained** (Per-Vault / Shared Drive) | One MLS group per shared folder or vault. All files inherit the epoch key. | Minimal MLS overhead; all members in the vault share read access. |
| **Fine-Grained** (Per-File / Per-Subfolder) | Independent MLS groups for distinct files or sub-trees. | Exact ACL parity with traditional POSIX/cloud IAM, but high state overhead and complex cross-tree sync. |

---

### Representative Pattern: Envelope Architecture

```text
+-----------------------------------------------------------+
|                        MLS Tree                           |
|       (Tracks membership, epochs, and root secrets)       |
+-----------------------------------------------------------+
                             │
                             ▼ (Derive via HKDF-Expand-Label)
               [Epoch E Key / Storage Exporter]
                             │
                             ▼ (Key Wrap)
         +───────────────────────────────────────+
         │ Encrypted File Key (Envelope Header)  │
         +───────────────────────────────────────+
                             │
                             ▼ (AES-256-GCM / ChaCha20-Poly1305)
         +───────────────────────────────────────+
         │        Encrypted File Payload         │
         │    (Stored in Blob/Object Storage)    │
         +───────────────────────────────────────+

```

Using the MLS `export` secret (defined in RFC 9420 §8.5) provides domain-separated symmetric key material derived from the epoch secret specifically for storage usage, preventing cross-protocol key reuse.









In a zero-knowledge or untrusted-storage threat model, the storage server/sequencer acts strictly as an oblivious blob store and ordering authority. It holds ciphertext and metadata, but possesses no group secrets, epoch keys, or plaintext File Encryption Keys (FEKs).

Because the server cannot decrypt or re-encrypt on its own, re-encryption relies on one of two paradigms: **client-driven re-wrapping** or **blinded proxy re-encryption (PRE)**.

---

### Pattern 1: Client-Driven Re-Wrapping (Standard Architecture)

In MLS-backed storage, the heavy payload data and the lightweight key metadata are split into two decoupled layers:

1. **Payload Layer:** The file data is encrypted with a random, single-use symmetric File Encryption Key ($FEK$) via AES-256-GCM or ChaCha20-Poly1305:

$$\text{Ciphertext} = \text{Enc}_{FEK}(\text{Data})$$


2. **Key Header (Envelope Layer):** The $FEK$ itself is encrypted using an epoch-specific key derived from the MLS root secret:

$$\text{Header} = \text{Enc}_{K_{\text{epoch}}}(FEK)$$



The client performing the eviction or update possesses the local tree state and the keys for both epochs ($E_{\text{old}}$ and $E_{\text{new}}$).

```text
[Untrusted Server / Cloud Storage]
  │
  │ 1. Download only Key Header (~48 bytes)
  ▼
[Active Client (Possesses Epoch E and E+1)]
  ├─ 1. Decrypt:  FEK = Dec(K_epoch_E, Header)
  └─ 2. Re-wrap:  Header' = Enc(K_epoch_E+1, FEK)
  │
  ▼ 2. Upload only new Key Header
[Untrusted Server]  <-- Payload untouched; revoked member locked out of Header'

```

#### How Active Re-encryption Works (Client-Driven)

When Bob is evicted at epoch $E \to E+1$, an online authorized member (e.g., Alice) processes the eviction:

1. **Metadata Re-wrap:** Alice fetches the small encrypted header for each target file, decrypts $FEK$ using $K_E$, re-encrypts $FEK$ under $K_{E+1}$, and uploads the updated header. The server simply replaces the metadata block.
2. **Payload Rotation (if revoking read access to cached/unseen data):** If Alice must guarantee that Bob cannot decrypt even the underlying blobs he hasn't yet fetched, Alice downloads the payload, generates $FEK_{\text{new}}$, re-encrypts the file data, re-wraps $FEK_{\text{new}}$ under $K_{E+1}$, and pushes both back to the server.

* *Cost:* Heavy bandwidth and compute overhead on the evicting client ($O(\text{data size})$).

#### How Lazy Re-encryption Works (Client-Driven)

To eliminate that bandwidth penalty during member churn:

1. **Immediate Header Cutoff:** Alice only re-wraps the $FEK$ under $K_{E+1}$ (or simply relies on epoch boundaries for all future files). The server replaces the header.
2. **Deferred Payload Rotation:** The existing payload remains encrypted under the original $FEK$. Because Bob was already in the group when that ciphertext was committed, he theoretically could have cached it anyway.
3. **Write-Triggered Rotation:** The next time *any* authorized member (Alice, Charlie, etc.) modifies or replaces that file under epoch $E+n$:
* The client generates a fresh $FEK_{\text{fresh}}$.
* The client encrypts the new data with $FEK_{\text{fresh}}$.
* The client wraps $FEK_{\text{fresh}}$ with $K_{E+n}$ and writes both to the storage node.



* *Result:* Zero bulk download/upload penalty at the moment of eviction. The heavy lifting is distributed lazily across natural write operations.

---

### Pattern 2: Cryptographic Proxy Re-Encryption (PRE)

If you do not want an active client downloading and re-wrapping metadata headers for millions of files, **Proxy Re-Encryption** delegates the transformation to the untrusted server without revealing plaintext.

```text
       [Alice (Client)]
              │
              │ Computes re-encryption key:
              │ rk_(E -> E+1)
              ▼
    [Untrusted Storage Server]
              │
   Applies: ReEncrypt(rk, Enc_E(FEK))
              │
              ▼
      Enc_(E+1)(FEK)
(Server learns ZERO plaintext FEK material)

```

1. **Re-Encryption Key Generation:** When evicting a member, an authorized client uses public-key or identity-based primitives (such as pairing-based cryptography or lattice-based schemes like Umbral/NuCypher) to compute a unidirectional re-encryption key:

$$rk_{E \to E+1}$$


2. **Blinded Evaluation:** The client sends only $rk_{E \to E+1}$ to the untrusted server.
3. **Server-Side Transformation:** The server evaluates the transformation function across all stored file headers:

$$\text{Header}_{E+1} = \text{ReEncrypt}(rk_{E \to E+1}, \text{Header}_E)$$


4. **Security Invariant:** The server converts ciphertexts from being decryptable by epoch $E$ keys to epoch $E+1$ keys, but at no point does the server possess the decryption key for either epoch or the underlying $FEK$.

---

### Comparison of Re-Encryption Models

| Dimension | Client-Side Lazy Re-wrap | Client-Side Active Re-wrap | Proxy Re-Encryption (PRE) |
| --- | --- | --- | --- |
| **Server Trust Model** | Zero knowledge (blind blob/key-value store) | Zero knowledge (blind blob/key-value store) | Semi-honest / Honest-but-curious |
| **Bandwidth on Eviction** | Minimal (header-only or zero) | High (downloads & uploads full files) | Minimal (transfers one small $rk$ key) |
| **Server Compute on Eviction** | Zero (metadata write only) | Zero | Moderate ($O(\text{files})$ pairing/point ops) |
| **Cryptographic Primitives** | Standard AEAD + HKDF (MLS native) | Standard AEAD + HKDF (MLS native) | Pairings (BLS12-381) or custom lattices |
| **Threat Profile** | Evicted user retains access to old, unmodified blobs | Evicted user loses read capability to un-cached blobs | Immediate cryptographic isolation across all past headers |

In practical MLS file storage systems, **Client-Side Lazy Re-wrapping** using MLS Exporter Secrets is almost universal because it avoids introducing complex non-standard algebraic assumptions (like pairings) while keeping client egress low.





In practical MLS file storage systems, Client-Side Lazy Re-wrapping using MLS Exporter Secrets is almost universal because it avoids introducing complex non-standard algebraic assumptions (like pairings) while keeping client egress low.


[I think in our git setup if a client detects a rewrap is needed it should send a new checkpoint of the file]







# Pricing notes 

Community
Pro
Team [$100/month+usage based overage]


[all of these count towards transfer balance]

Encrypted Storage   1GB, 20GB, 200GB
Send Emails/day       5   200 20000
DNS entries           5   200 2000
TLS edge              1   20  200
IP and port forward   [unlimited]
recurd                [all]


Team management including SSO [only team]
Custom domain   [only team]

















