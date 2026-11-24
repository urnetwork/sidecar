# Minimal SSH (client + server) and minimal git inside a Go program that also targets gomobile (iOS/Android) and GOOS=js/wasm

Research date: 2026-11-23. Version, release and advisory data were pulled on that date from the Go module proxy, the GitHub API, the OSV API and the files themselves. "As of 2026-11-23" applies to every repo metric below unless another date is given. Some facts come from local builds and runs on this Mac (darwin/arm64, Go 1.27.4). Those are marked **[local measurement]**, and the method is described under the first and fifth questions. Anything older than about 12 months is flagged as possibly superseded.

---

## Q1. Go SSH libraries: x/crypto/ssh, gliderlabs/ssh, charmbracelet/wish, and others. What does a minimal server need, how well maintained and secure are they, and how big?

### Takeaway
`golang.org/x/crypto/ssh` (v0.59.0, 2026-11-11) is the only foundation worth building on. It is actively patched, offers post-quantum key exchange first by default, and has full certificate support. But it is a protocol toolkit: you write the session, exec, pty, env, subsystem and forwarding plumbing yourself.

`gliderlabs/ssh` is a thin wrapper (about 1.7k lines) that handles that plumbing. It has had no commits since 2025-01. The live descendants are Charm's fork (`charm.land/ssh` v0.4.3, used by wish v2) and Tailscale's own fork (`github.com/tailscale/gliderssh`, pseudo-version dated 2026-10-26).

x/crypto/ssh's security record is busy, and most of it sits in authentication-callback semantics (more than 20 advisories since 2023, including 13 on 2026-05-22). Any build should pin x/crypto ≥ v0.56.0.

On linux/amd64, a stripped SSH client adds about 2.6 MB to a binary, and a full gliderlabs server with pty, sftp and port forwarding adds about 3.2 MB.

### Cited Findings

**golang.org/x/crypto/ssh: versions and features**
- Latest is v0.59.0, published 2026-11-11 ([Go module proxy](https://proxy.golang.org/golang.org/x/crypto/@latest)). `golang.org/x/term` v0.48.0 (2026-11-09) replaces the deprecated `x/crypto/ssh/terminal` for client raw mode ([proxy](https://proxy.golang.org/golang.org/x/term/@latest)).
- The package doc says it "implements an SSH client and server". It also says the package "does not fall under the stability promise of the Go language itself, so its API may be changed when pressing needs arise". It cites draft-miller-ssh-cert and draft-sfluhrer-ssh-mldsa, and documents a FIPS 140-3 mode that silently drops non-approved algorithms ([ssh/doc.go @ v0.59.0](https://github.com/golang/crypto/blob/v0.59.0/ssh/doc.go)).
- Key exchange: `mlkem768x25519-sha256` (hybrid post-quantum; comment: "supported from Go 1.24") is listed before `curve25519-sha256` in the default lists. The SHA-1 and group1 exchanges are named `InsecureKeyExchange...` ([ssh/common.go @ v0.59.0](https://github.com/golang/crypto/blob/v0.59.0/ssh/common.go)).
- ML-DSA user and host keys (`ssh-mldsa-44`, `-65`, `-87`) exist in v0.59.0 behind `//go:build go1.27 && !fips140v1.0`. There is a stub file for other builds ([ssh/keys.go](https://github.com/golang/crypto/blob/v0.59.0/ssh/keys.go), [ssh/mldsa.go](https://github.com/golang/crypto/blob/v0.59.0/ssh/mldsa.go)).
- `ServerConfig` has these hooks: `PublicKeyAuthAlgorithms`, `NoClientAuth`, `NoClientAuthCallback`, `MaxAuthTries`, `PasswordCallback`, `PublicKeyCallback`, `VerifiedPublicKeyCallback` (a newer callback that runs only after the key is proven), `KeyboardInteractiveCallback`, `AuthLogCallback`, `PreAuthConnCallback`, `ServerVersion`, `BannerCallback` and `GSSAPIWithMICConfig`. `Permissions` carries `CriticalOptions`, `Extensions` and `ExtraData` ([ssh/server.go @ v0.59.0](https://github.com/golang/crypto/blob/v0.59.0/ssh/server.go)).
- Client `Session` methods: `Setenv`, `RequestPty`, `RequestSubsystem`, `WindowChange`, `Signal`, `Start`, `Run`, `Output`, `CombinedOutput`, `Shell`, `Wait` and the std pipes ([ssh/session.go @ v0.59.0](https://github.com/golang/crypto/blob/v0.59.0/ssh/session.go)).
- The server side has no session handling built in. You accept `NewChannel`s and parse `exec`, `pty-req`, `env`, `shell`, `subsystem`, `window-change` and `signal` requests yourself, then send `exit-status`. These request names come from the SSH connection protocol ([RFC 4254](https://www.rfc-editor.org/rfc/rfc4254)). **[local measurement]** A working exec-only server took about 70 lines.
- Subpackages are `agent`, `knownhosts`, `terminal` (deprecated) and `test`. Non-test line counts at v0.59.0: ssh 12,802, agent 1,946, knownhosts 578 **[local measurement]** ([source tree](https://github.com/golang/crypto/tree/v0.59.0/ssh)).

**x/crypto/ssh security record (from OSV / Go vulndb, fetched 2026-11-23)**
- CVE-2023-48795 (Terrapin, a prefix-truncation attack) was fixed in v0.17.0 on 2023-12-18 ([GO-2023-2402](https://pkg.go.dev/vuln/GO-2023-2402)).
- CVE-2024-45337 (fixed in v0.31.0, 2024-12-11): misusing `PublicKeyCallback` could bypass authorization, because "A call to this function does not guarantee that the key offered is in fact used to authenticate" ([GO-2024-3321](https://pkg.go.dev/vuln/GO-2024-3321)).
- CVE-2025-22869: denial of service via a slow or incomplete key exchange, fixed in v0.35.0 (2025-02) ([GO-2025-3487](https://pkg.go.dev/vuln/GO-2025-3487)).
- CVE-2025-58181: unbounded memory use when parsing GSSAPI. CVE-2025-47914 and CVE-2025-47913: ssh/agent DoS bugs. Fixed in v0.43.0 to v0.45.0 (2025-11) ([GO-2025-4134](https://pkg.go.dev/vuln/GO-2025-4134), [GO-2025-4135](https://pkg.go.dev/vuln/GO-2025-4135), [GO-2025-4116](https://pkg.go.dev/vuln/GO-2025-4116)).
- On 2026-05-22 the Go team announced 13 x/crypto/ssh issues, all fixed in v0.52.0 ([golang-announce](https://groups.google.com/g/golang-announce/c/a082jnz-LvI)). They include:
  - Certificate restrictions such as force-command dropped when a callback returned `PartialSuccessError` with permissions (CVE-2026-39828, [GO-2026-5014](https://pkg.go.dev/vuln/GO-2026-5014)).
  - knownhosts not enforcing `@revoked` for a CA signature key (CVE-2026-42508, [GO-2026-5021](https://pkg.go.dev/vuln/GO-2026-5021)).
  - `VerifiedPublicKeyCallback` permissions skipping source-address enforcement (CVE-2026-46595, [GO-2026-5023](https://pkg.go.dev/vuln/GO-2026-5023)).
  - Agent destination-restriction constraints silently stripped when forwarding keys (CVE-2026-39832, [GO-2026-5006](https://pkg.go.dev/vuln/GO-2026-5006)).
  - A FIDO touch bypass, an infinite loop on large channel writes, a memory leak when rejecting channels, a server deadlock, and RSA/DSA parameter DoS ([OSV query, Go ecosystem, golang.org/x/crypto](https://osv.dev/list?ecosystem=Go&q=golang.org%2Fx%2Fcrypto)).
- CVE-2026-56854 (v0.55.0, 2026-08-28): the source-address critical option was not enforced for permissions returned by `PasswordCallback`, `KeyboardInteractiveCallback`, **`NoClientAuthCallback`** or GSSAPI callbacks ([GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303)). This matters directly to Tailscale-style "none" auth designs (see Q2).
- CVE-2026-78662 and CVE-2026-56855 (v0.56.0, 2026-09-02): DoS via deadlocked undecided or established channels ([GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354), [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355)).

**gliderlabs/ssh and its forks**
- `github.com/gliderlabs/ssh`: latest release v0.3.8 (2024-12-13), last push 2025-01-27, 67 open issues, BSD-3-Clause ([GitHub](https://github.com/gliderlabs/ssh), [proxy](https://proxy.golang.org/github.com/gliderlabs/ssh/@latest)). OSV lists no advisories for it ([OSV](https://osv.dev/list?ecosystem=Go&q=github.com%2Fgliderlabs%2Fssh)).
- v0.3.8 API: session `Handler`, `Pty()` with a window-change channel, `SubsystemHandlers`, `ChannelHandlers` (`DefaultSessionHandler`, `DirectTCPIPHandler`), `LocalPortForwardingCallback` and `ReversePortForwardingCallback`, `PublicKeyHandler`, and agent-forwarding helpers (`AgentRequested`, `NewAgentListener`, `ForwardAgentConnections`). Its session code normalizes `\n` to `\r\n` "when pty is accepted" ([agent.go](https://github.com/gliderlabs/ssh/blob/v0.3.8/agent.go), [server.go](https://github.com/gliderlabs/ssh/blob/v0.3.8/server.go), [session.go](https://github.com/gliderlabs/ssh/blob/v0.3.8/session.go)). Coder disables that "minimal PTY emulation (NL-to-CRNL)" ([agentssh.go](https://github.com/coder/coder/blob/main/agent/agentssh/agentssh.go)).
- About 1,709 non-test lines, so it is small enough to vendor and audit **[local measurement]** ([GitHub](https://github.com/gliderlabs/ssh)).
- `charmbracelet/ssh` is Charm's fork. It wraps x/crypto/ssh "with a higher-level API that feels like net/http" and imports as `charm.land/ssh`. Latest is v0.4.3 (2026-08-07), with 52 stars and 3 open issues ([GitHub](https://github.com/charmbracelet/ssh), [proxy](https://proxy.golang.org/github.com/charmbracelet/ssh/@latest)).
- `charmbracelet/wish` v2.0.5 was released 2026-10-01, with v2 starting mid-2026; v1 stopped at v1.4.7 (2025-03-25). It is MIT licensed with 5.6k stars ([GitHub](https://github.com/charmbracelet/wish), [proxy v2](https://proxy.golang.org/github.com/charmbracelet/wish/v2/@latest)). It is a middleware framework for SSH *apps* (TUI over SSH) rather than a shell server.
- Wish had an SCP path-traversal bug allowing arbitrary file read and write: CVE-2026-41589, fixed in 2.0.1 (2026-04-18) ([GHSA-xjvp-7243-rg9h](https://github.com/advisories/GHSA-xjvp-7243-rg9h)).
- Tailscale's `ssh/tailssh` now imports `gliderssh "github.com/tailscale/gliderssh"` together with `golang.org/x/crypto/ssh`. Its go.mod pins `github.com/tailscale/gliderssh v0.3.4-0.20261026144310-31f7cf365d3a`, `github.com/tailscale/golang-x-crypto` (2026-07-20), `pkg/sftp v1.13.11` and `creack/pty v1.1.24` ([tailssh.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go), [go.mod](https://github.com/tailscale/tailscale/blob/main/go.mod)).

**SFTP and pty**
- `github.com/pkg/sftp`: stable v1.13.12 (2026-10-23). v2 is still alpha: v2.0.0-alpha (2026-01-22) and alpha2 (2026-05-04). BSD-2-Clause, about 12.2k non-test lines **[local measurement]**, no OSV advisories ([GitHub releases](https://github.com/pkg/sftp/releases), [OSV](https://osv.dev/list?ecosystem=Go&q=github.com%2Fpkg%2Fsftp)). In gliderlabs it plugs in as `SubsystemHandlers["sftp"]` via `sftp.NewServer(sess)`. Tailscale serves SFTP in-process the same way ([tailssh.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)).
- `github.com/creack/pty` v1.1.24 (2024-10-31; possibly superseded only by unreleased commits, last push 2026-06-01), MIT ([GitHub](https://github.com/creack/pty)). **[local measurement]** It does not compile for js/wasm or wasip1 (`undefined: syscall.TIOCGWINSZ`), so server-side pty is a Unix-only feature.

**What a minimal server needs, and the risks**
- Agent forwarding. OpenSSH warns that it "should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the agent's Unix-domain socket) can access the local agent through the forwarded connection. An attacker cannot obtain key material from the agent, however they can perform operations on the keys that enable them to authenticate using the identities loaded into the agent" ([ssh_config(5) source](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)). Go's agent package also silently dropped destination-restriction constraints when forwarding until v0.52.0 ([GO-2026-5006](https://pkg.go.dev/vuln/GO-2026-5006)).
- Port forwarding: `direct-tcpip` channels handle local forwarding; the `tcpip-forward` and `cancel-tcpip-forward` global requests handle remote forwarding ([RFC 4254](https://www.rfc-editor.org/rfc/rfc4254)). Coder's agent allows both by default ("Allow local port forwarding all!") unless configured otherwise, and also handles `streamlocal-forward@openssh.com` and X11 ([agentssh.go](https://github.com/coder/coder/blob/main/agent/agentssh/agentssh.go)). Tailscale gates local and reverse forwarding and agent forwarding per policy action (`AllowLocalPortForwarding`, "agent forwarding revoked") ([tailssh.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)).

**Size [local measurement]**

Binaries built with `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"` on Go 1.27.4. Sizes are bytes, with `gzip -9` in parentheses.

| Program | linux/amd64 | android/arm64 | js/wasm | wasip1/wasm |
|---|---|---|---|---|
| hello | 1,507,488 | 1,769,766 | 2,453,276 (707,726) | 2,427,046 |
| x/crypto/ssh client (exec one command) | 4,157,600 | 4,391,206 | 7,115,999 (1,941,285) | 7,099,917 |
| x/crypto/ssh exec-only server | 4,309,152 | 4,522,278 | 7,319,998 (1,997,694) | 7,258,052 |
| gliderlabs server with pty, sftp and direct-tcpip | 4,698,272 | 4,915,494 | build fails (creack/pty) | build fails (creack/pty) |

- Module dependencies: the client and the exec server need only `golang.org/x/crypto`. The gliderlabs server adds `anmitsu/go-shlex`, `creack/pty`, `gliderlabs/ssh`, `kr/fs` and `pkg/sftp`.

#### Measurement method (SSH)
- I wrote four small programs: `hello`; an SSH client using `ssh.Dial` and `Session.CombinedOutput`; an exec-only server using `ssh.NewServerConn`, handling the `session` channel and the `exec` request, running `/bin/sh -c`, and replying with `exit-status`; and a gliderlabs server with a pty via creack/pty, an `sftp` subsystem via pkg/sftp, `DirectTCPIPHandler`, and a `PublicKeyHandler`.
- Each was built for darwin/arm64, linux/amd64, linux/arm64, android/arm64, ios/arm64, js/wasm and wasip1/wasm.
- Line counts exclude `_test.go`, `_examples` and `testdata`.

### Inferences
- For an auditable build, the smallest trustworthy stack is x/crypto/ssh plus about 300–600 lines of your own session code (exec, shell with pty, env allowlist, window-change, signal, exit-status, optional sftp). That beats depending on dormant gliderlabs. Vendoring gliderlabs' 1.7k lines, or tracking Charm's or Tailscale's fork, is the alternative.
- Pin x/crypto ≥ v0.56.0. Treat every authentication callback (`NoClientAuthCallback`, `PublicKeyCallback`) as security-critical. The 2024–2026 advisories cluster exactly there: permissions semantics, partial success, source-address enforcement.
- Disable agent forwarding outright. Sidecar identity comes from device keys, not ssh-agent, so forwarding only adds the risk OpenSSH describes and the recent Go constraint bug.
- Expose SFTP and port forwarding only behind explicit policy, as Tailscale does, never by default as Coder does.

### Gaps
- No public line-by-line security audit of gliderlabs/ssh or of Charm's fork was found. Absence of OSV entries is not evidence of safety for a dormant project.
- I did not check whether `github.com/tailscale/golang-x-crypto` is still used through a `replace` directive, nor what it patches.
- `gomobile bind` output sizes (an .xcframework or .aar with cgo) were not measured. Only package compilation for ios/arm64 was verified (see Q4).

---

## Q2. How does Tailscale SSH work, and what can be reused from Teleport, Smallstep, Fly and Coder when the transport is already an authenticated E2EE overlay? Is SSH's own crypto still needed, or is exec/shell over an authenticated stream enough?

### Takeaway
Overlay-authenticated systems keep the SSH *wire protocol* so that stock clients work: OpenSSH, scp/sftp, port forwarding, IDE remotes. But they **turn off SSH user authentication** and authorize by the overlay's peer identity:
- **Tailscale** accepts SSH auth method `none` and looks up the WireGuard peer with WhoIs.
- **Coder** sets `NoClientAuth: true` over its tailnet.

Fly and Teleport go the other way and mint short-lived OpenSSH certificates (Fly also tunnels over WireGuard). Kubernetes `exec` shows that a non-SSH, channel-multiplexed stream (WebSocket `v5.channel.k8s.io`) is enough when the client is your own code.

For an agent harness talking to sidecar-to-sidecar streams, "exec/shell over an authenticated stream" is sufficient. SSH framing earns its keep only where interoperability with standard SSH tools is wanted.

### Cited Findings

**Tailscale SSH: authentication and policy**
- Tailscale "authenticate[s] and encrypt[s] the connection over WireGuard, using Tailscale node keys". The server accepts SSH auth type `none`. It does not change `authorized_keys` or `sshd_config`. The server runs on Linux and macOS, needs v1.24+, and listens only on port 22 ([Tailscale SSH KB, last validated 2026-01-05](https://tailscale.com/kb/1193/tailscale-ssh)).
- Policy lives in the `ssh` section of the tailnet policy:
  - `action` is `accept` or `check`. `check` forces re-authentication with the identity provider (possibly MFA), with `checkPeriod` defaulting to 12 h (range 1 min to 168 h, or `always`).
  - `users` lists host accounts, including `autogroup:nonroot` and `localpart:*@domain`.
  - `acceptEnv` allowlists environment variable names (v1.76.0+).
  - Check rules are evaluated before accept rules.
  - Policy changes reach nodes in seconds, and revocation ends live sessions ("Access revoked") ([KB](https://tailscale.com/kb/1193/tailscale-ssh)).
- Limitations: any OS user on the client can connect, because no local key pair is used. The KB calls it a poor fit for multi-user clients or for hosts relying on `authorized_keys` command restrictions. Restarting `tailscaled` ends sessions ([KB](https://tailscale.com/kb/1193/tailscale-ssh)).

**Tailscale SSH: implementation**
- `tailssh` sets `NoClientAuth: true` ("required for the NoClientAuthCallback to run") and resolves identity with `WhoIs("tcp", src)` on the peer's tailnet address. Check mode is implemented as a `HoldAndDelegate` action URL that the server waits on during auth. Policy is re-checked mid-session, and a session ends if the rule changes from Accept to HoldAndDelegate or the recording obligation changes. Source comments mention clients "that get confused by successful replies to auth type 'none'" ([tailssh.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)).
- The server is compiled only for `(linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9`, so there is no SSH server on phones ([tailssh.go build tag](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)).

**Tailscale SSH: host keys**
- `tailscale set --ssh` generates a host key pair. The public key goes to the control plane, and clients get a Tailscale-managed `known_hosts` "created just in time", so plain `ssh host` works. Rotation is `tailscale up --ssh --force-reauth` ([KB](https://tailscale.com/kb/1193/tailscale-ssh)).
- In code, the system's OpenSSH host keys are used when readable; otherwise Tailscale generates its own rsa, ecdsa and ed25519 keys ([hostkeys.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/hostkeys.go)).

**Tailscale SSH: session recording**
- The destination node streams **terminal output only** ("No keystrokes are captured") in asciinema `.cast` format (newline-delimited JSON) to a tagged recorder node, end-to-end encrypted. Recordings land on disk or in S3 as `/dir/<stablenodeid>/<timestamp>.cast`.
- `enforceRecorder: false` fails open; `true` fails closed and ends live sessions when no recorder is reachable.
- The KB says Tailscale "no longer offers session recording through `tsrecorder`", with support for existing users ending August 2027, and points to "Tailscale PAM" ([session-recording KB, last validated 2026-01-05](https://tailscale.com/kb/1246/tailscale-ssh-session-recording)).

**Other systems**
- **Coder** workspace agent: gliderlabs/ssh with `ServerConfigCallback` returning `&gossh.ServerConfig{NoClientAuth: true}`. Authentication rests entirely on Coder's tailnet transport. sftp runs as a subsystem ([agentssh.go](https://github.com/coder/coder/blob/main/agent/agentssh/agentssh.go); Coder v2.39.4, 2026-11-16).
- **Fly.io** (2021-03-01; possibly superseded): `flyctl ssh console` uses "certificate-based SSH, running over gVisor user-mode TCP/IP, running over userland wireguard-go". The in-VM server, "Hallpass", is "a teeny, tiny, trivial SSH server in Go" built on x/crypto/ssh, and OpenSSH certificates with expiry give short-lived access ([Fly blog](https://fly.io/blog/ssh-and-user-mode-ip-wireguard/)). A forum reply said Hallpass did not support port forwarding ([Fly community](https://community.fly.io/t/incoming-ssh-support-for-instances/685)); this is old and unverified now.
- **Teleport**: "Certificate Authorities and short-lived certificates are the core of Teleport authentication". Every connection presents a CA-issued certificate, "short-lived certificates automatically expire, there is no need to revoke them", and hosts get certificates from the same Auth Service ([Teleport docs](https://goteleport.com/docs/reference/architecture/authentication/)). Latest release v18.11.10 (2026-11-16), AGPL-3.0 ([GitHub](https://github.com/gravitational/teleport)). Teleport had a remote authentication bypass, CVE-2025-49825 (2025-06) ([GHSA-8cqv-pj7f-pwpc](https://github.com/advisories/GHSA-8cqv-pj7f-pwpc)).
- **Smallstep** `step-ca` describes itself as "A private certificate authority (X.509 & SSH) & ACME server ... SSO for SSH". v0.30.2 (2026-03-23), Apache-2.0 ([GitHub](https://github.com/smallstep/certificates)).
- **Kubernetes exec/attach** dropped SSH and SPDY in favour of a WebSocket subprotocol, `v5.channel.k8s.io`. Channels are 0 stdin, 1 stdout, 2 stderr, 3 status/error, 4 resize, and v5 adds a CLOSE signal (255). kubectl uses WebSockets by default from v1.31 ([Kubernetes blog 2024-08-20](https://kubernetes.io/blog/2024/08/20/websockets-transition/)). KEP-4006 went alpha in 1.29 and beta in 1.31, targeting stable in 1.37 ([KEP-4006](https://www.kubernetes.dev/resources/keps/4006/)).

### Inferences
- When the stream is already mutually authenticated and E2EE between device keys, SSH's own key exchange and cipher add defense in depth but no new identity. Tailscale and Coder both accept that and keep SSH only for compatibility and for its well-understood channel, request and exit-status semantics.
- For an agent-only path (sidecar harness to enclave sidecar), a small framed protocol is easier to audit and to make cross-platform than SSH. The client needs no x/crypto/ssh (about 2.6–4.7 MB saved, see Q1/Q4), and there is no SSH auth state machine where the advisories cluster. It could look like this:
  - an `open{argv|shell, env-allowlist, pty{rows,cols}?}` message;
  - stdin, stdout and stderr channels;
  - resize and signal messages;
  - an `exit{code|signal}` message.
- Where a human wants OpenSSH, VS Code Remote-SSH or sftp, run an SSH server endpoint that is reachable only over the overlay. Use Tailscale's model: `NoClientAuthCallback` maps the overlay peer identity to a local user and policy. With x/crypto ≥ v0.55.0, source-address enforcement also covers `NoClientAuthCallback` (CVE-2026-56854). Alternatively, mint short-lived user certificates from device keys (Fly/Teleport model), so stock clients authenticate without a `~/.ssh` keypair.
- Reusable Tailscale patterns:
  - policy-driven `check` mode, re-authenticating before granting a session;
  - mid-session policy re-evaluation with forced termination;
  - fail-open or fail-closed session recording of output only, as asciinema casts;
  - an env-var allowlist (`acceptEnv`);
  - just-in-time `known_hosts` from a directory, instead of trust-on-first-use.
- For agents, recording structured exec transcripts (argv, exit code, stdout and stderr hashes) is more useful than terminal casts.

### Gaps
- Fly's current Hallpass behaviour (certificate TTL, port forwarding) was not verified against 2026 docs. The cited post is from 2021.
- "Tailscale PAM", the stated successor to tsrecorder, was not researched.
- No published threat analysis was found that compares SSH-in-WireGuard with plain exec-over-WireGuard.

---

## Q3. SSH certificates (OpenSSH CA format) for binding a host key to an attested identity, and alternatives to known_hosts

### Takeaway
The OpenSSH certificate format is now specified by an IETF draft. draft-miller-ssh-cert-06 (2025-11-10) has been replaced by the working-group draft draft-ietf-sshm-cert, and OpenSSH removed PROTOCOL.certkeys on 2025-05-05.

The format allows domain-qualified custom extensions. Unknown extensions must be ignored, while unknown critical options must cause rejection. So a CA, such as sidecar's network key, can sign host certificates carrying attestation metadata.

x/crypto/ssh gives you `CertChecker` (`IsHostAuthority`, `IsRevoked`, `HostKeyFallback`) and an arbitrary `HostKeyCallback`, so host verification can consult sidecar's own directory or attestation state with no `known_hosts` file. OpenSSH clients can be served with `@cert-authority` lines or a `KnownHostsCommand`.

### Cited Findings
- OpenSSH commit 928f8dcc1b (2025-05-05): "Now that there's an I-D for certificate keys, refer to that instead of the much more basic format description we had previously." The repo root now has PROTOCOL, PROTOCOL.agent, .key, .krl, .mux, .sshsig and .u2f, but no PROTOCOL.certkeys ([commit](https://github.com/openssh/openssh-portable/commit/928f8dcc1b), [repo](https://github.com/openssh/openssh-portable)).
- draft-miller-ssh-cert-06, "SSH Certificate Format" by D. Miller, published 2025-11-10 and replaced by draft-ietf-sshm-cert ([IETF datatracker](https://datatracker.ietf.org/doc/html/draft-miller-ssh-cert)):
  - Key types are `ssh-ed25519-cert` and others, "equivalent to" the vendor names such as `ssh-ed25519-cert-v01@openssh.com`.
  - Fields in order: key type, nonce (≥16 bytes), public key, serial (uint64), role (user=1, host=2), identifier, principals, valid after, valid before, critical options, extensions, reserved, signature key (the CA), signature.
  - Critical options for user certificates: `force-command`, `source-address`, `verify-required`. Extensions: `permit-agent-forwarding`, `permit-port-forwarding`, `permit-pty`, `permit-user-rc`, `permit-X11-forwarding`, `no-touch-required`.
  - Unknown critical option: the verifier "MUST refuse to accept the certificate". Unknown extension: it "MUST ignore it and continue processing".
  - Custom names follow RFC 4251 §4.2 domain-qualified naming (`name@domain`).
  - Host certificates have no defined options or extensions, and principals must match the name the client connected to.
  - The draft defines no revocation mechanism (it suggests serial or explicit lists) and does not specify how CA trust is established.
- x/crypto/ssh `CertChecker` fields: `SupportedCriticalOptions`, `IsUserAuthority`, `IsHostAuthority(auth, address)`, `Clock`, `UserKeyFallback`, `HostKeyFallback`, `IsRevoked`. `CertChecker.Authenticate` enforces `source-address` ([ssh/certs.go @ v0.59.0](https://github.com/golang/crypto/blob/v0.59.0/ssh/certs.go)).
- Go has had cert-specific bugs: dropped certificate restrictions (CVE-2026-39828) and an unenforced `@revoked` for CA keys in knownhosts (CVE-2026-42508), both fixed in v0.52.0 ([GO-2026-5014](https://pkg.go.dev/vuln/GO-2026-5014), [GO-2026-5021](https://pkg.go.dev/vuln/GO-2026-5021)).
- OpenSSH `known_hosts` supports the markers `@cert-authority` (trust a CA for matching hosts) and `@revoked` ([sshd(8) source](https://github.com/openssh/openssh-portable/blob/master/sshd.8); [man.openbsd.org/sshd](https://man.openbsd.org/sshd#SSH_KNOWN_HOSTS_FILE_FORMAT)).
- `KnownHostsCommand` "Specifies a command to use to obtain a list of host keys, in addition to those listed in UserKnownHostsFile and GlobalKnownHostsFile". It may write host-key lines in known_hosts format and is called several times per connection ([ssh_config(5) source](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)).
- Tailscale avoids trust-on-first-use by distributing host public keys through its control plane and generating `known_hosts` just in time ([Tailscale SSH KB](https://tailscale.com/kb/1193/tailscale-ssh)). Teleport issues host certificates from its Auth Service ([Teleport docs](https://goteleport.com/docs/reference/architecture/authentication/)).

### Inferences
- **Binding a host key to an attested enclave.** Have an enclave's sidecar generate its SSH host key inside the TEE. A network CA then issues a short-lived host certificate after verifying the TEE attestation, with:
  - principals = the enclave's stable sidecar ID or name;
  - a custom extension such as `attestation@<your-domain>` holding the quote digest or measurement;
  - a short validity period, avoiding revocation needs, as Teleport argues.

  Stock OpenSSH clients only need one `@cert-authority` line. They ignore the extension, which is safe per the draft. Sidecar's own Go client verifies the cert *and* the extension in `HostKeyCallback`.
- If the transport is already sidecar-authenticated, the simplest client check is `HostKeyCallback`: accept only the host key that sidecar's directory or attestation record binds to the peer's device identity. No `known_hosts` file is needed at all, and `KnownHostsCommand` can expose the same logic to OpenSSH.
- **User certificates for stock clients** (Fly/Teleport/Smallstep style). Minted from device keys, they can carry:
  - `permit-pty` and `permit-port-forwarding` granted selectively;
  - `force-command` for agent-only identities;
  - `source-address` pinned to the overlay address.

  Note the Go bugs above: pin x/crypto ≥ v0.56.0.

### Gaps
- The current revision, status and changes of draft-ietf-sshm-cert were not fetched.
- No published example was found of OpenSSH host certificates carrying TEE attestation extensions; this pattern looks novel.
- The OpenSSH version that introduced `KnownHostsCommand` was not re-verified.

---

## Q4. Client portability: what works in wasm (no raw sockets, no pty) and on iOS (no subprocesses), and terminal emulation (xterm.js, SwiftTerm, Termux) versus structured exec output for an agent

### Takeaway
The x/crypto/ssh client and go-git compile with `CGO_ENABLED=0` for android/arm64, js/wasm and (v6 go-git only) wasip1. ios/arm64 executables require cgo external linking, so iOS means `gomobile bind`, although the packages compile for ios/arm64.

The browser has no sockets: Go's `net` on js and wasip1 is a fake in-memory network, and `net/http` uses the Fetch API. An in-browser SSH client therefore needs a `net.Conn` tunnelled over WebSocket or WebTransport, or a userspace netstack over a relay, which is what Tailscale SSH Console does.

Server-side pty and subprocesses are unavailable on iOS and in wasm. Keep shells on the enclave side, and give the agent structured exec results rather than a terminal.

For humans: xterm.js 6.0 (web), SwiftTerm (Apple, now also wasm and headless), and Termux's Apache-2.0 terminal libraries (Android).

### Cited Findings
- **[local measurement]** On ios/arm64 with `CGO_ENABLED=0`, every program failed to link with "ios/arm64 requires external (cgo) linking, but cgo is not enabled". A package-only build of `golang.org/x/crypto/ssh`, `github.com/go-git/go-git/v5` and `go-billy/v5/memfs` for ios/arm64 succeeded. android/arm64, js/wasm and wasip1/wasm built for the SSH client and server (sizes in Q1).
- **Go's browser networking**: `net` on `js || wasip1` is "Fake networking for js/wasm and wasip1/wasm" ([net_fake.go](https://github.com/golang/go/blob/master/src/net/net_fake.go)). `net/http` on `js && wasm` exposes Fetch API options (mode, credentials, redirect) ([roundtrip_js.go](https://github.com/golang/go/blob/master/src/net/http/roundtrip_js.go)).
- **Prior art: Tailscale SSH Console** (blog 2022-10-27; possibly superseded in details). The browser becomes an ephemeral Tailscale node: the Tailscale client, WireGuard, gVisor's userspace netstack and an SSH client were ported to WebAssembly, the terminal is xterm.js, and all traffic goes through DERP relays. It is in beta and limited to admin roles ([Tailscale blog](https://tailscale.com/blog/ssh-console), [Tailscale SSH Console docs](https://tailscale.com/docs/features/tailscale-ssh/tailscale-ssh-console), [tsconnect](https://pkg.go.dev/tailscale.com/cmd/tsconnect)). A third-party reuse reports the Go wasm binary at about 32 MB ([search result, unverified](https://github.com/morpig/tailssh)).
- **iOS process limits**: ios_system's README says `system()` calls "are rejected at compile time" on iOS and that `execv` after `fork()` "is not possible in iOS". a-Shell emulates fork and exec through ios_system ([ios_system](https://github.com/holzschu/ios_system)). This matches Tailscale's tailssh build tag, which excludes ios and android ([tailssh.go](https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go)).
- **Terminal emulators**:
  - xterm.js 6.0.0 released 2025-12-22 (MIT, 21.4k stars) ([release](https://github.com/xtermjs/xterm.js/releases/tag/6.0.0)).
  - SwiftTerm v1.99.3 (2026-11-06, MIT): "Xterm/VT100 Terminal emulator library in Swift with AppKit, UIKit, WebAssembly, Web, headless frontends" ([GitHub](https://github.com/migueldeicaza/SwiftTerm)).
  - The Termux app is GPLv3-only, but its `terminal-view` and `terminal-emulator` libraries derive from Android-Terminal-Emulator under Apache 2.0 ([termux-app LICENSE.md](https://github.com/termux/termux-app/blob/master/LICENSE.md)). The last stable app release is v0.118.3 (2025-05-22).
- **Structured exec semantics are already in x/crypto/ssh**: `Session.Output`, `CombinedOutput`, `StdoutPipe`, `StderrPipe` and `Wait` with exit status ([session.go](https://github.com/golang/crypto/blob/v0.59.0/ssh/session.go)). Kubernetes uses separate stdout, stderr and status channels plus a resize channel ([Kubernetes blog](https://kubernetes.io/blog/2024/08/20/websockets-transition/)).

### Inferences
- **Browser**: carry sidecar's own authenticated stream over WebSocket or WebTransport and run either SSH (x/crypto/ssh on a WebSocket-backed `net.Conn`; about +4.7 MB raw or +1.2 MB gzip over a hello-world wasm) or the lighter exec protocol from Q2 on top. The wasm code needs no pty.
- **iOS and Android**: the same Go client code works through `gomobile bind`. Only client roles belong there. The gobind type restrictions (only basic types, byte slices, and structs or interfaces of them cross the boundary; see [gobind docs](https://pkg.go.dev/golang.org/x/mobile/cmd/gobind); not re-verified today) argue for a narrow API, for example `Exec(target, argv, stdin []byte) -> {code, stdout, stderr}` plus a streaming session object.
- **Agents**: no pty by default. Return `{exit_code, stdout, stderr, truncated, duration}` with explicit output caps, and offer a pty session only when a TUI program needs it. Separate stderr is lost under a pty, which is why `CombinedOutput` and pty modes are unsuitable for agents.
- **Humans**: xterm.js for web and wasm, SwiftTerm for iOS and macOS (MIT), Termux terminal-emulator for Android (Apache-2.0; avoid GPL app code).

### Gaps
- I did not build or measure a `gomobile bind` framework for iOS or Android (no gomobile or NDK in this environment).
- I did not test x/crypto/ssh over a WebSocket `net.Conn` in a real browser.
- Browser memory limits for Go wasm, which is a 32-bit address space, were not measured.

---

## Q5. go-git (github.com/go-git/go-git, v5 and v6): supported operations, in-memory storage for wasm and phones, large-repo performance, known gaps and bugs, license

### Takeaway
go-git stable is **v5.19.3**. **v6.0.0-beta.1** came out on 2026-10-04; both were released the same day, and v6 is what the README recommends.

It covers clone, fetch and push over smart HTTP (protocol v1 only), ssh, git and file transports, plus status, add (plain), commit, reset, rm, mv, branch, basic checkout, tag, log, show, unified diff, blame, grep, clean, sparse-checkout, shallow clone and submodules. **Merge is fast-forward only.** **Rebase, stash, revert and apply are missing.** Cherry-pick, SHA-256, partial-clone filters and linked worktrees are only partial and only in v6.

It is Apache-2.0 and pure Go, and it compiles to js/wasm (about 17.9–18.7 MB raw, about 4.4–4.6 MB gzip). v5 fails to build on wasip1; v6 builds.

Two big caveats:
1. Security churn: 11 advisories in 2026, mostly about hostile repositories or servers.
2. Memory: an in-memory clone used about 20x the packed repo size in RAM (2.1 GB for a 101 MB repo), and v6 beta was much slower in my file:// test.

So phones and browsers need shallow clones, file-backed storage, or a narrower custom transport and storage.

### Cited Findings

**Releases, maintenance and license**
- Releases: v5.19.3 (2026-10-04), v5.19.2 (2026-07-29); v6.0.0-beta.1 (2026-10-04), v6.0.0-alpha.5 (2026-07-29). 7.9k stars, 300 open issues, last push 2026-11-22, Apache-2.0 ([GitHub](https://github.com/go-git/go-git), [proxy v5](https://proxy.golang.org/github.com/go-git/go-git/v5/@latest), [proxy v6](https://proxy.golang.org/github.com/go-git/go-git/v6/@latest)).
- The README on main says `import "github.com/go-git/go-git/v6"`. It describes the project as "actively maintained by individual contributors, including several of the original authors", "backed by GitSight" and supported by Entire. It names Keybase, Gitea and Pulumi as users, and supports "in-memory filesystems, or custom implementations, thanks to the Storer interface" ([README](https://github.com/go-git/go-git/blob/main/README.md)).
- go-billy, the filesystem abstraction behind `memfs` and `osfs`: v5.9.2 (2026-10-02) and v6.0.0-beta.1 ([GitHub](https://github.com/go-git/go-billy)).

**Compatibility matrix (v6 on main, read 2026-11-23)**

Source: [COMPATIBILITY.md (main/v6)](https://github.com/go-git/go-git/blob/main/COMPATIBILITY.md).

- Supported:
  - `init`, `clone` (with `--depth`, `--single-branch`, `--recurse-submodules`; none, token, user+password or ssh auth)
  - `add`: "Plain add is supported. Any other flags aren't supported"
  - `status`, `commit`, `reset`, `rm`, `mv`, `branch`
  - `checkout`: "Basic usages"
  - `sparse-checkout`, `tag`
  - `fetch`, `push`, `remote`, `submodule` (no `deinit`)
  - `pull`: "Only supports merges where the merge can be resolved as a fast-forward"
  - `show`, `log`
  - `diff`: "Patch object with UnifiedDiff output representation"
  - `blame`, `grep`, `clean`
  - `repack` (`RepackObjects`), `git-verify-commit` and `git-verify-tag`
  - plumbing commands `cat-file`, `for-each-ref`, `hash-object`, `ls-files`, `ls-remote`, `rev-list`, `show-ref`, `symbolic-ref`
  - `gitignore`, `gitattributes`
- Partial:
  - `merge`: "Fast-forward only"
  - `cherry-pick`: "supports default merge strategy `--strategy=ort`"
  - `bisect` (via Log, ForEach and Checkout)
  - `worktree add/remove/list`: "Not all flags nor subcommands"
  - `daemon` (via go-git/cli)
  - `merge-base` (two commits only)
- Missing: `stash`, `rebase`, `revert`, `apply`, `am`, `format-patch`, `describe`, `reflog`, `gc`, `fsck`, `archive`, `bundle`, `notes`, `rev-parse`, `update-ref`, `write-tree`, `read-tree`, `check-ignore`, `lfs`, `mergetool`.
- Protocols and formats:
  - pack-protocol v1 ✅, **v2 ❌**
  - the index table lists v2 ✅ and v1/v3 ❌; v4 is not listed, although CVE-2026-33762 concerns decoding index v4
  - multi-pack-index ❌, cruft packs ❌
  - `thin-pack` ❌, `side-band`/`side-band-64k` partial, `report-status-v2` ❌
  - `object-format` ✅ with a SHA-256 example
  - `filter` partial: it can fetch with a filter and record the partial clone, but "go-git cannot fetch the withheld objects back on demand, so reading one fails rather than backfilling it"
- Transports: smart http(s), git, ssh and file ✅. Dumb HTTP is "Not supported, neither as a client nor when serving". "Custom ✅: All existing schemes can be replaced by custom implementations".

**v5 versus v6 differences** ([v5 COMPATIBILITY.md, releases/v5.x](https://github.com/go-git/go-git/blob/releases/v5.x/COMPATIBILITY.md) compared with main)

| Feature | v5 | v6 |
|---|---|---|
| SHA-256 `object-format` | ❌ | ✅ |
| partial-clone `filter` | ❌ | partial |
| `cherry-pick` | ❌ | partial |
| linked worktrees | ❌ | partial |
| `repack` | ❌ | ✅ |
| `multi_ack`, `multi_ack_detailed` | ❌ | ✅ |
| `file://` | partial: "this is not pure Golang. This shells out to the `git` binary" | pure Go ✅ |
| dumb-HTTP `update-server-info` | ✅ | ❌ (removed) |

- v6.0.0-beta.1 release notes include ([release notes](https://github.com/go-git/go-git/releases/tag/v6.0.0-beta.1)):
  - "transport, Remove dumb HTTP protocol support"
  - "Make sha1cd the default for Git object hashing"
  - "Record partial clones so git accepts a filtered fetch"
  - "Fix js wasm build" (#2406)
  - "Harden reference names across storage and transport"
  - "Validate delta ops before applying"
  - "Break cyclic delta chains instead of recursing"
  - "Compare origins when following redirects"
- **[local measurement]** The v6 API changed: `PushOptions` no longer has `Auth`. It now has `ClientOptions []client.Option`, along with `RemoteURL`, `ForceWithLease`, `Atomic`, `Quiet` and other fields ([options.go @ v6.0.0-beta.1](https://github.com/go-git/go-git/blob/v6.0.0-beta.1/options.go)).

**Security record (OSV / GHSA, fetched 2026-11-23)**
- 2023–2025:
  - CVE-2023-49568 (DoS) and CVE-2023-49569 (path traversal and RCE via malicious server replies), fixed in 5.11.0 ([GHSA-449p-3h89-pw88](https://github.com/advisories/GHSA-449p-3h89-pw88)).
  - CVE-2025-21613 (argument injection via the URL field, file transport) and CVE-2025-21614 (DoS), fixed in 5.13.0 (2025-01) ([GHSA-v725-9546-7q7m](https://github.com/advisories/GHSA-v725-9546-7q7m)).
- 2026, each fixed in the v5 version shown and in the matching v6 alpha:
  - CVE-2026-25934: improper integrity verification of `.idx`/`.pack`, fixed in 5.16.5 ([GHSA-37cx-329c-33x3](https://github.com/advisories/GHSA-37cx-329c-33x3))
  - CVE-2026-33762: panic decoding index v4 (5.17.1)
  - CVE-2026-34165: memory exhaustion via a crafted idx (5.17.1)
  - CVE-2026-41506: "Credential leak via cross-host redirect in smart HTTP transport" (5.18.0) ([GHSA-3xc5-wrhm-f963](https://github.com/advisories/GHSA-3xc5-wrhm-f963))
  - CVE-2026-45022: object parsing inconsistent with upstream Git (5.19.0)
  - CVE-2026-45571: "Crafted repositories may modify main and submodule .git directories" (5.19.1)
  - CVE-2026-45570: "Improper single-quote escaping in go-git SSH transport" (5.19.1)
  - GHSA-w5pp-99ch-qj29: malformed objects cause panic or exhaustion (5.19.1)
  - CVE-2026-71556: "Worktree operations may follow symlinks" (5.19.2) ([GHSA-hc8v-wwc9-vgxm](https://github.com/advisories/GHSA-hc8v-wwc9-vgxm))
  - CVE-2026-71557: "Malicious reference names may modify files outside the reference storage" (5.19.2) ([GHSA-qgq7-7hm3-q39j](https://github.com/advisories/GHSA-qgq7-7hm3-q39j))
- Full list: [OSV go-git](https://osv.dev/list?ecosystem=Go&q=github.com%2Fgo-git%2Fgo-git).

**Size, dependencies and portability [local measurement]**

Stripped, `CGO_ENABLED=0`, Go 1.27.4. The test program does an in-memory clone, add, status, commit, patch and log.

| Version | linux/amd64 | android/arm64 | js/wasm | wasip1/wasm |
|---|---|---|---|---|
| v5.19.3 | 9,830,560 | 10,289,446 | 17,879,258 (gzip 4,382,321) | **fails**: `worktree.go:747: undefined: isSymlinkWindowsNonAdmin` |
| v6.0.0-beta.1 | 10,166,432 | 10,551,590 | 18,684,004 (gzip 4,570,211) | 18,784,435 (builds) |

- Compared with hello-world, go-git adds about 8.3 MB on linux/amd64 and about 3.7 MB gzip in js/wasm.
- v5.19.3 pulls 19 modules: dario.cat/mergo, cloudflare/circl, cyphar/filepath-securejoin, emirpasic/gods, go-git/gcfg, go-billy/v5, golang/groupcache, jbenet/go-context, kevinburke/ssh_config, pjbgf/sha1cd, ProtonMail/go-crypto, sergi/go-diff, skeema/knownhosts, xanzy/ssh-agent, x/crypto, x/net, x/sys and gopkg.in/warnings.v0.
- v6.0.0-beta.1 pulls 13: circl, gods, gcfg/v2, go-billy/v6, ssh_config, sha1cd, ProtonMail/go-crypto, sergi/go-diff, x/crypto, x/net, x/sync and x/sys.
- Non-test, non-example line counts: v5.19.3 47,415; v6.0.0-beta.1 68,859; go-billy v5 5,022. The v6 count did not exclude `internal/test*` helper packages, so it may be slightly inflated.

**In-memory clone cost [local measurement]**

Single runs on this Mac. The setup is `memory.NewStorage()` plus `memfs`, a full-history clone from a local bare mirror over `file://`, then add one file, status, commit, patch and log.

| Repository | Client | Time | Memory | Status / commit |
|---|---|---|---|---|
| go-git (bare 14 MB, 4,191 commits, 791 files) | go-git v5.19.3 | 0.95 s | 274 MiB Go heap, 324 MB max RSS | 17 ms / 2 ms |
| go-git | go-git v6.0.0-beta.1 | 8.9 s | 842 MB max RSS | — |
| go-git | system `git clone` | 0.69 s | 38 MB RSS | — |
| tailscale (bare 101 MB, 11,794 commits, 3,163 files) | go-git v5.19.3 | 5.85 s | 1,592 MiB heap, 2.15 GB max RSS | 75 ms / 4 ms |
| tailscale | go-git v6.0.0-beta.1 | 64.6 s | 5.6 GiB HeapInuse, 2.48 GB max RSS | — |
| tailscale | system `git clone` | 3.47 s | 176 MB RSS | — |

- The v6 comparison is confounded. In v6, `file://` is pure Go ([COMPATIBILITY.md](https://github.com/go-git/go-git/blob/main/COMPATIBILITY.md)), so go-git also generated the pack server-side in-process, whereas v5 shells out to `git-upload-pack`. v6 also switched hashing to sha1cd by default (release notes above).
- HTTPS clones from github.com with go-git failed in this sandbox with "repository not found", although `git ls-remote` and `curl` to the same URL succeeded. I could not resolve this, so I did not take network numbers.

#### Measurement method (git)
- The program is `git.Clone(memory.NewStorage(), memfs.New(), &CloneOptions{URL, Depth, SingleBranch: true})`, then `fs.Create` a file, `Worktree.Add`, `Status`, `Commit`, `Commit.Parent(0).Patch`, and `Repository.Log` iteration. I wrote it once for v5 and once for v6 (only the import paths and the push auth field differ).
- Timings are wall clock. Memory is `runtime.MemStats` plus `/usr/bin/time -l` max RSS.

### Inferences
- For harness use cases (status, diff, log, show, add, commit, branch, switch, restore, blame, grep), go-git v5 or v6 covers about 80% of real usage. The gaps that matter to agents:
  - **3-way merge**: v6 has an ort-based merge engine via cherry-pick, so a non-fast-forward merge may be buildable on it, but it is not exposed as `merge`;
  - **rebase**;
  - **stash**;
  - **revert**;
  - **`rev-parse`-style revision syntax** (the Go API has `Repository.ResolveRevision`; [pkg.go.dev](https://pkg.go.dev/github.com/go-git/go-git/v5#Repository.ResolveRevision));
  - **path-limited and staged diffs** with git-identical output.

  These would have to be written in sidecar's layer.
- For sidecar's storage service, the two key extension points are go-git's **custom transport** registration and its **Storer interface**. Git pack traffic can run over sidecar's own authenticated stream instead of HTTP, avoiding CORS and Fetch API limits in the browser and reusing device-key auth. Objects could also live in an encrypted, versioned store rather than `.git` on disk.
- In-memory storage is unsuitable for anything but small repos on phones and in wasm. Full clones cost roughly 20x the pack size in RAM, and wasm32 tops out at 4 GiB. Prefer shallow (`Depth: 1`) or single-branch fetches and file-backed storage (osfs on phones; OPFS or IndexedDB-backed billy in the browser, which I did not test).
- Choose v6 if SHA-256, wasip1, partial clone or worktrees matter, accepting beta API churn (e.g. push auth moved to `ClientOptions`). Benchmark v6 over a network transport before committing, given the slow file:// result.
- Treat repository content as hostile even from your own service, since other writers and agents share it. Track go-git point releases closely: 2026 advisories arrived about monthly. Prefer an in-process implementation that never runs hooks or filters; go-git's matrix lists no hook support.

### Gaps
- I did not find a maintained public benchmark of go-git against git for large-repo status, diff or log. A gh issue search for performance issues returned nothing usable due to query errors.
- I did not measure network (smart HTTP) clone performance or memory with filesystem-backed storage.
- I did not verify whether go-git runs any hooks (no row exists in COMPATIBILITY.md).
- I did not investigate go-git's handling of SHA-256 repos in v5 beyond the matrix.

---

## Q6. Alternatives: libgit2/git2go (cgo), gitoxide (Rust), isomorphic-git (JS, browser), and their trade-offs for gomobile and wasm

### Takeaway
None of the alternatives beats pure-Go go-git for a single Go codebase that must also run in Go's js/wasm.
- **libgit2** is the most complete library (v1.9.7, with v2.0.0-rc.1 out on 2026-10-14). But it is C under GPLv2 with a linking exception, it needs cgo, so it cannot link into Go's js/wasm, and its Go binding **git2go is effectively abandoned** (v34.0.0 from 2022 tracks libgit2 1.5).
- **gitoxide** (Rust, MIT/Apache) is fast and active (gix v0.91.0, 2026-11-22), but its own status file still lists push, merge, rebase, stash and checkout orchestration as unfinished.
- **isomorphic-git** (MIT, v1.44.18, 2026-11-21) has the richest browser story: merge, stash, cherryPick, push. It has no rebase and needs CORS or a proxy, and it would mean a JS implementation alongside Go.
- **wasm-git** (libgit2 via Emscripten) is a browser-only option.

### Cited Findings
- **libgit2**: v1.9.7 and v1.8.7 (2026-08-13); v2.0.0-rc.1 (2026-10-14), "the first release candidate for libgit2 v2.0". 10.7k stars, 617 open issues ([releases](https://github.com/libgit2/libgit2/releases)). COPYING states GPL v2 only ("the only valid version of the GPL ... is ... v2") ([COPYING](https://github.com/libgit2/libgit2/blob/main/COPYING)). The well-known linking exception is in the same file but was not re-read today.
- **git2go**: last release v34.0.0 (2022-10-06), last push 2024-03-04. Its README maps git2go v34 to libgit2 1.5, with main "(will be v35)" ([GitHub](https://github.com/libgit2/git2go), [proxy](https://proxy.golang.org/github.com/libgit2/git2go/v34/@latest)).
- **gitoxide**: v0.62.0 and gix v0.91.0 (2026-11-22). License "MIT OR Apache-2.0", rust-version 1.95, 12.2k stars ([GitHub](https://github.com/GitoxideLabs/gitoxide), [Cargo.toml](https://github.com/GitoxideLabs/gitoxide/blob/main/Cargo.toml)). Its crate-status workflow overview ([crate-status.md](https://github.com/GitoxideLabs/gitoxide/blob/main/crate-status.md)):
  - checked: `commit` and low-level mutation; `status` and worktree-vs-index; `merge-base`, revision parsing and commit description; low-level checkout.
  - unchecked: `checkout`/`switch`/`restore`/`reset` orchestration; `merge`/`cherry-pick`/`revert`; `rebase`; `stash`/`am`/`apply`; "`push` and self-contained clone/fetch over `file://` and `ssh://`"; signed commits; client-side hooks.
- **isomorphic-git**: v1.44.18 (2026-11-21), MIT, npm unpacked size 5.1 MB ([npm registry](https://www.npmjs.com/package/isomorphic-git), [GitHub](https://github.com/isomorphic-git/isomorphic-git)).
  - Command index: abortMerge, add, addNote, addRemote, annotatedTag, branch, checkout, **cherryPick**, clone, commit, currentBranch, deleteBranch, deleteRef, deleteRemote, deleteTag, fastForward, fetch, findMergeBase, getRemoteInfo(2), indexPack, init, isIgnored, listBranches, listFiles, listRefs, listServerRefs, listTags, log, **merge**, packObjects, pull, **push**, readBlob, readCommit, readTree, remove, renameBranch, resetIndex, resolveRef, setConfig, **stash**, status, **statusMatrix**, tag, updateIndex, walk, writeBlob, writeCommit, writeTree. There is no rebase, no diff/patch porcelain, no blame and no grep ([docs/alphabetic.md](https://github.com/isomorphic-git/isomorphic-git/blob/main/docs/alphabetic.md)).
  - The quickstart says: "Since GitHub hasn't added CORS headers to the git clone endpoint yet, we have to use a proxy server" (`corsProxy: 'https://cors.isomorphic-git.org'`) ([guide-quickstart.md](https://github.com/isomorphic-git/isomorphic-git/blob/main/docs/guide-quickstart.md)).
  - Advisories published 2026-11-09, all fixed in 1.38.6: arbitrary file write via a directory symlink during checkout ([GHSA-9qw7-j9xw-fv9c](https://github.com/advisories/GHSA-9qw7-j9xw-fv9c)), path traversal via `..` tree entries, and DoS via circular symrefs ([OSV npm isomorphic-git](https://osv.dev/list?ecosystem=npm&q=isomorphic-git)).
- **wasm-git**: "GIT for nodejs and the browser using libgit2 compiled to WebAssembly with emscripten". v0.0.17 (2026-07-17), 854 stars ([GitHub](https://github.com/petersalomonsen/wasm-git)).
- **[local measurement]** Go's js/wasm and wasip1 builds above used `CGO_ENABLED=0`. Go has no cgo path into js/wasm, so a C library like libgit2 can only reach the browser as a separate Emscripten module (wasm-git), not linked into the Go wasm.

### Inferences
- **gomobile**: libgit2 through cgo is technically possible (gomobile already uses cgo) but adds cross-compiling C, OpenSSL or mbedTLS, and libssh2 for iOS and Android, plus GPL-with-exception compliance and a dead Go binding. That is the opposite of small and auditable.
- **gitoxide** would require a Rust staticlib through cgo on mobile and wasm-bindgen in the browser. That is two languages plus FFI, and the porcelain features agents need are still missing.
- **isomorphic-git** could make sense only if the browser harness is JS-native and you accept two git implementations with divergent behaviour. For a Go sidecar compiled to wasm, go-git keeps one codebase across server, phone and browser.
- Whichever library is chosen, 2026 brought symlink and path-traversal advisories in both go-git and isomorphic-git. Checkout into a real filesystem is the riskiest operation. An agent sandbox that only exposes files through sidecar's API, with no host filesystem, sidesteps most of these bugs.

### Gaps
- I did not compare memory or performance between isomorphic-git, gitoxide and go-git on the same repos.
- I did not check libgit2 2.0's API changes or whether a maintained Go binding for libgit2 2.x exists.

---

## Q7. Which git commands do coding agents actually use, and how do existing sandboxed agents expose git?

### Takeaway
I found no published per-subcommand tallies from agent trajectories. The primary-source harness prompts and tool surfaces converge on a small core:
- `status`, `diff` (`HEAD`, `--staged`, path-limited), `log -n N`, `show`;
- `add <specific paths>` (explicitly *not* `add -A` unprompted), `commit -m`;
- branch create and switch (`checkout`), `reset`/`restore` for undo;
- `worktree` for parallel sessions, which Claude Code relies on;
- remote operations (`push`, PRs via `gh`) gated behind approval.

Destructive commands (`reset --hard`, `checkout --`) are discouraged and interactive flags (`-i`) avoided. Hosted sandboxes either give a full VM or container with real git (Codex cloud, Daytona, Vercel Sandbox) or a structured git API (Daytona's git module, the MCP git server). Simulated shells like just-bash ship **no git**.

### Cited Findings

**What harness prompts and docs say**
- **OpenAI Codex prompt** (gpt_5_codex_prompt.md): "You may be in a dirty git worktree." "**NEVER** use destructive commands like `git reset --hard` or `git checkout --` unless specifically requested or approved by the user." It uses `git show` as its example of a command whose output the agent must summarize ([codex-rs/core/gpt_5_codex_prompt.md](https://github.com/openai/codex/blob/main/codex-rs/core/gpt_5_codex_prompt.md)).
- **Google Gemini CLI prompt snippets** ([packages/core/src/prompts/snippets.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/prompts/snippets.ts)). For commits:
  - "`git status` to ensure that all relevant files are tracked and staged, using `git add <file>...`"
  - "`git diff HEAD` to review all changes (including unstaged changes)"
  - "`git diff --staged` to review only staged changes"
  - "`git log -n 3` to review recent commit messages and match their style"
  - "Do not use `git add .` or `git add -A` unprompted"
  - "e.g. `git status && git diff HEAD && git log -n 3`"
- **Aider** ([docs](https://aider.chat/docs/git.html), [source](https://github.com/Aider-AI/aider/blob/main/aider/website/docs/git.md)):
  - auto-commits every edit with a descriptive message, and commits pre-existing dirty files first;
  - in-chat `/diff`, `/undo` ("undo and discard the last change"), `/commit` and `/git` (raw git);
  - skips hooks by default (`--no-verify`);
  - commit messages follow Conventional Commits, written by a "weak model".
- **Claude Code** best-practices docs (current page, read 2026-11-23) ([best practices](https://code.claude.com/docs/en/best-practices)):
  - with `gh` signed in, "Claude will open pull requests and read review comments";
  - permission examples `"ask": ["Bash(git push *)"]` and headless `--allowedTools "Read,Edit,Bash(git add *),Bash(git commit *)"`;
  - parallel sessions via `claude -w <name>` in a new **git worktree**, cleaned up with `git worktree remove` / `git worktree unlock`;
  - "/batch" gives each unit its own worktree and PR;
  - checkpoints "work alongside git rather than replacing it".
- **Trajectory research**: a 1,794-run CLI-agent study mentions a failing `git add -A` ([Failure as a Process, arXiv 2607.09510](https://arxiv.org/html/2607.09510v1)). A 143,209-trajectory study maps shell commands to semantic actions ([arXiv 2611.17440](https://arxiv.org/pdf/2611.17440)). Neither, as surfaced in search, reports git subcommand frequencies.

**How sandboxes and tools expose git**
- **MCP git reference server** (Python, GitPython) has 14 tools: `git_status`, `git_diff_unstaged`, `git_diff_staged`, `git_diff`, `git_commit`, `git_add`, `git_reset`, `git_log`, `git_create_branch`, `git_checkout`, `git_merge`, `git_show`, `git_branch` and `git_remote` ([src/git/README.md](https://github.com/modelcontextprotocol/servers/blob/main/src/git/README.md); servers release v2.5.0, 2026-11-18).
  - It warns: "Without `--repository`, the server reads and writes any Git repository the server process can reach."
  - It hardens against repository-supplied config: hooks off (`core.hooksPath` set to the null device), `core.fsmonitor=false`, filter and merge drivers emptied, `commit.gpgSign=false`, `submodule.recurse=false`, `core.pager=cat`, and index entries with `..` or absolute paths refused.
  - Advisories: CVE-2025-68143 (unrestricted `git_init`), CVE-2025-68144 (argument injection in `git_diff`/`git_checkout` allowing local file overwrite), CVE-2025-68145 (missing path validation with `--repository`), all 2025-12-17; CVE-2026-27735 (path traversal in `git_add`, 2026-02-26) ([GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59), [GHSA-vjqx-cfc4-9h6v](https://github.com/advisories/GHSA-vjqx-cfc4-9h6v)).
- **Daytona** sandboxes expose a structured git module: clone (optionally a branch), status (branch, changed files, ahead/behind), add (a file list or "."), commit (message plus author, returns a SHA), push and pull with username and PAT, branches list/create/switch/delete, and checkout of a branch or SHA. REST endpoints live under `/toolbox/{sandboxId}/git/...` ([Daytona git operations docs](https://www.daytona.io/docs/en/git-operations)).
- **OpenAI Codex cloud** starts a container and checks out the repo at a branch or SHA. Setup scripts have internet access, while agent internet is off by default (or allowlisted by domain and method), and "secrets are removed before the agent phase starts". Containers are cached up to 12 h, and changes are published as a GitHub PR ([Codex cloud environments](https://developers.openai.com/codex/cloud/environments), [agent internet](https://developers.openai.com/codex/cloud/agent-internet)).
- **Cloudflare Sandbox SDK 1.0**: "In 1.0, your own Durable Object starts the Container, and this package provides only file operations and bucket mounts". The 0.x `Sandbox` class ran commands ([sandbox-sdk README](https://github.com/cloudflare/sandbox-sdk)).
- **Vercel just-bash** v3.6.1 (2026-11-16, Apache-2.0 per its package) is "A simulated bash environment with virtual filesystem". Its supported commands span file operations, text tools including `rg`, `jq`, `sqlite3`, `yq`, gzip and tar, `curl`, and optional `python3` and `js-exec`, with **no `git`**. It is extensible with TypeScript `defineCommand` custom commands ([just-bash README](https://github.com/vercel-labs/just-bash/blob/main/packages/just-bash/README.md)). Vercel's bash-tool uses just-bash by default, with Vercel Sandbox (VM) for full binaries ([InfoQ 2026-01](https://www.infoq.com/news/2026/01/vercel-bash-tool)).

### Inferences
- **A "minimal git" that meets harness expectations should implement:**
  - `status` (`--porcelain`/`-s`), `diff` (worktree, `--staged`/`--cached`, `HEAD`, `A..B`, `-- <paths>`, `--stat`, `--name-only`), `log` (`-n`, `--oneline`, `-p`, `-- <path>`, `--format`), `show` (`<rev>`, `<rev>:<path>`, `--stat`);
  - `add <paths>`/`-A`, `rm`, `mv`, `commit -m` (multiple `-m`, `--amend`, `--allow-empty`);
  - `restore` (`--staged`, `--source`) and `checkout -- <path>`, `reset` (`--soft`/`--mixed`; `--hard` behind approval);
  - `branch` (list/create/delete), `switch`/`checkout -b`;
  - `rev-parse` (`HEAD`, `--abbrev-ref`, `--show-toplevel`), `ls-files`, `blame`, `grep`;
  - `merge` (fast-forward plus 3-way with conflict markers), `stash` (push/pop/list), `worktree` (add/list/remove);
  - `fetch`, `pull`, `push` against sidecar's storage service.

  go-git covers about two thirds directly. `stash`, 3-way `merge`, `restore`/`checkout -- path` parity, `rev-parse` syntax and output formatting must be added in sidecar's layer.
- Rebase (`-i` especially) and `cherry-pick` are rarer and interactive. Defer them or return a clear "unsupported" error. Prompts already steer agents away from `-i`.

### Gaps
- No quantitative frequency data exists for git subcommands in agent trajectories. A sidecar could gather it by logging which subcommands harnesses request.
- Claude Code's internal system-prompt git instructions are not public as a stable document. Only the docs above were cited.
- Vercel Sandbox's git source option and E2B's git API were not fetched.

---

## Q8. How should a minimal git CLI be exposed to an agent: a parser compatible with common invocations, or structured tool calls?

### Takeaway
Evidence favours **a git-CLI-compatible command surface implemented in-process**: a `git` command inside a simulated shell, or a single `git(argv)` tool, with strict argv parsing, a whitelist of subcommands and flags, explicit "unsupported" errors, and an optional `--json` or porcelain output.
- Harness prompts already speak git CLI.
- Vercel's bash-only agent beat its 17 specialized tools.
- just-bash shows the "simulated shell plus custom commands" pattern.

Structured tools are not automatically safer. The MCP git server shipped argument-injection and path-traversal CVEs and needed extensive hardening against repository-controlled config, hooks and filters. An in-process Go implementation with no real git binary removes the hook, filter and pager attack surface entirely.

### Cited Findings
- **Vercel** (Andrew Qu, 2025-12-22): its d0 text-to-SQL agent went from 17 specialized tools to essentially one bash command tool plus a filesystem in Vercel Sandbox. On 5 representative queries ([Vercel blog](https://vercel.com/blog/we-removed-80-percent-of-our-agents-tools)):
  - average time 274.8 s → 77.4 s (3.5x);
  - success 4/5 → 5/5;
  - tokens about 102k → 61k (−37%);
  - steps about 12 → 7 (−42%).

  The post says "Every tool is a choice you're making for the model" and "Grep is 50 years old and still does exactly what we need", with the caveat that "This only worked because our semantic layer was already good documentation". The sample is small and the domain is SQL, not git.
- **just-bash**: simulated bash with a virtual filesystem, extended via `defineCommand` custom commands that receive `env`, `stdin`, limits and `exec`. It ships no git ([README](https://github.com/vercel-labs/just-bash/blob/main/packages/just-bash/README.md)).
- **Harness prompts use git CLI syntax verbatim** (`git status && git diff HEAD && git log -n 3`; `git reset --hard` prohibitions; `Bash(git commit *)` permission patterns) ([Gemini CLI snippets](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/prompts/snippets.ts), [Codex prompt](https://github.com/openai/codex/blob/main/codex-rs/core/gpt_5_codex_prompt.md), [Claude Code docs](https://code.claude.com/docs/en/best-practices)).
- **Structured-tool pitfalls**: mcp-server-git argument injection in `git_diff` and `git_checkout` let callers overwrite local files (CVE-2025-68144). `git_add` allowed staging files outside the repository (CVE-2026-27735). Its README now documents repository-config neutralization: hooks, fsmonitor, filter and merge drivers, gpg signing, `branch.<name>.mergeOptions`, submodule recursion, pager ([README](https://github.com/modelcontextprotocol/servers/blob/main/src/git/README.md), [GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59)).
- **Structured APIs in hosted sandboxes**: Daytona's git module uses typed parameters (paths, message, author, credentials) and returns typed status and branch objects ([Daytona docs](https://www.daytona.io/docs/en/git-operations)).

### Inferences
- **Recommended shape.** One tool, `git`, taking `argv: string[]` and `cwd` within sidecar storage, returning `{exit_code, stdout, stderr}` exactly as git would print them, so models' priors hold. Behind it:
  1. a getopt-style parser per subcommand with a flag whitelist;
  2. no shelling out, no hooks, filters or pagers;
  3. paths confined to the repository root, with `--` handling and rejection of option-looking revisions;
  4. deterministic "git: '<flag>' is not supported by this git" messages so the model can adapt.

  Optionally accept `--json` on `status`, `log` and `diff --stat` for programmatic callers (UI, MCP clients).
- Expose the same command set as typed MCP tools (status, diff, log, show, add, commit, branch, switch, restore, merge, stash) only as thin wrappers over the same parser. That keeps one validation path and avoids the dual-surface drift that produced mcp-server-git's argument-injection bugs.
- Since the local harness has no shell, embedding `git` as a command in a just-bash-like simulated shell, with sidecar's `ssh`/exec as another command, gives agents familiar composition (`git diff | head`) without host access. This pattern needs no extra binaries in Go: in-process commands over a virtual filesystem backed by go-git's worktree or Storer.

### Gaps
- No controlled study was found comparing agent success rates for git specifically, CLI-string tools against typed git tools. The Vercel result concerns SQL and data exploration.
- I did not assess how well current models handle "unsupported flag" errors from partial git implementations.
