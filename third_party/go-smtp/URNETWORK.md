# Local go-smtp dependency

This directory is the source distribution of `github.com/emersion/go-smtp
v0.25.1` (module zip `h1:y6nzefT6PtFeMItFw97GX/ZCkVbh0rqSXG8b3ang8/w=`,
fetched through proxy.golang.org and checked against Go's checksum database),
except for the changes to `server.go`, `conn.go` and `parse.go` below, the
added `urnetwork_serve_conn_test.go`, `urnetwork_bdat_reset_test.go`,
`urnetwork_bare_postmaster_test.go` and this file, and the removed upstream `.github/`, `.build.yml` and `.gitignore` (upstream's
CI and repository settings). The upstream MIT license is kept in `LICENSE`. The module path
stays `github.com/emersion/go-smtp`, so a module replaces it here (QD-193,
RESOLUTIONS.md's plan-MAIL-go-smtp-fork).

v0.25.1 differs from v0.25.0, which DESIGN.md §15.3 read, only in the
client's recipient list across LMTP transactions. The server is the same.

## The first change: ServeConn

D-MAIL-3 needs a session on a connection whose STARTTLS exchange already
happened elsewhere: mxedge answers the plaintext EHLO and STARTTLS, and the
receiver or the platform listener ends TLS. After the handshake the client
speaks first (RFC 3207 section 4.2), so the server must not greet. Upstream
takes connections only through `Serve`, whose `handleConn` always calls
`greet()`, and a connection wrapped to hide that is no longer a `*tls.Conn`,
so `TLSConnectionState` fails and REQUIRETLS is never advertised.

`server.go` adds:

- `ServeConnOptions{AfterStartTls bool}`.
- `(*Server).ServeConn(c net.Conn, opts ServeConnOptions) error`, which serves
  one connection accepted elsewhere and returns when its session ends. Under
  the server's lock it checks that the server is not closed, counts the
  session in the wait group `Shutdown` waits on, and adds it to the
  connections `Close` closes, so either `Close` and `Shutdown` see it or it
  sees them and refuses with `ErrServerClosed`, closing `c` unwritten. With
  `AfterStartTls` it sends no greeting, and it refuses a `c` that is not a
  `*tls.Conn` with `ErrServeConnNotTls`, since a plain connection would then
  advertise STARTTLS to a client that ran it.
- `(*Server).ServeTlsConn(c *tls.Conn) error`, `ServeConn` with
  `AfterStartTls`. The sidecar root reaches the fork only through this method,
  by an interface assertion, because §4.9's release fixture builds the root
  with no replaces against upstream, where the assertion fails and the
  session refuses, closed (`sidecar/mail_smtp_serve.go`).

`handleConn` keeps its registration and now calls `serveConn(c, greet)`, which
is upstream's session loop with `c.greet()` behind `greet`. `Serve`'s
behavior does not change.

The names follow D-MAIL-3. An offer upstream would likely spell them
`AfterStartTLS` and `ServeTLSConn`, as go-smtp spells `TLSConfig`; offering it
is an outward action for the owner.

## The second change: a BDAT transfer cut short by a reset

Upstream runs a BDAT transfer's `Session.Data` on a goroutine of its own and
hands its result back on `c.dataResult`, which the goroutine reads from the
connection when it sends. A transfer cut short by RSET, a new MAIL or EHLO
leaves that goroutine running while the next BDAT assigns a new channel to the
same field, so the cut transfer's result can land on the next transaction's
channel and answer its LAST, and `reset` calls `Session.Reset` while the cut
`Data` still runs, so two transactions' `Data`, or `Reset` and a `Data`, run
at once. The race detector reports the field (MAIL-M7-14's receiver met it).

`conn.go` changes, each line marked `URNETWORK`:

- the goroutine sends on the channel it was started with, never on whatever
  `c.dataResult` names when it ends;
- `reset` takes the pipe and the channel under the lock, releases it, closes
  the pipe with `ErrDataReset` and waits for the cut transfer's result, outside
  the lock its `Session()` takes, before it resets anything else;
- LAST clears `c.dataResult` once it has taken the result, so the `reset` that
  follows waits for nothing.

`Close` is unchanged: `Server.Close` may call it while the connection's own
goroutine waits on the same channel at a LAST.

## The third change: RCPT's bare <Postmaster>

RFC 5321 section 4.5.1 says a server that delivers mail MUST take the
reserved mailbox postmaster as a case-insensitive local name, and that "the
special case of `RCPT TO:<Postmaster>` (with no domain specification), MUST be
supported"; section 4.1.1.3's grammar writes it as an alternative to RCPT's
path. Upstream's path parser needs an `@` after the local part, so it answers
`501 5.5.2` before a session sees the recipient (QD-921, owner decision 446).

`parse.go` changes, each marked `URNETWORK`:

- `parsePath`, which only RCPT calls, returns `postmaster` for a path that
  begins `<Postmaster>`, matched without regard to ASCII case, and leaves what
  follows the bracket for RCPT's parameters, as a path leaves it;
- any other path goes to upstream's `parsePath`, renamed `parseMailboxPath`;
- `parseReversePath` calls `parseMailboxPath`, so MAIL's reverse-path keeps
  upstream's rules and `MAIL FROM:<Postmaster>` still answers 501.

Only the bracketed name with nothing before its closing bracket matches:
`<Postmaster@>`, `<Postmasters>`, `Postmaster` without brackets,
`<"Postmaster">`, a source route before it and a name that folds to it only
under Unicode keep upstream's 501. A session gets the bare form as
`postmaster`, with no domain, and maps it to its own domain's postmaster
before its recipient rules: the platform listener to `postmaster@<root>`
(`sidecar/mxedgeservice/platform_session.go`), a receiver's session to
postmaster at the domain it serves (`sidecar/mail_session.go`). Against
upstream the parser never hands a session the bare form, so that mapping is
never reached and the sender gets upstream's 501.

The change is about ten lines and stands alone: it touches neither
`ServeConn` nor the BDAT change, so it can be offered upstream by itself,
which is an outward action for the owner.

## Tests

`urnetwork_serve_conn_test.go`, run with `go test -run Urnetwork ./` in this
directory, over `net.Pipe` with no sleeps:

- a handshaken connection gets no greeting, and EHLO's reply advertises
  REQUIRETLS and neither STARTTLS nor AUTH, for a backend without
  `AuthSession`;
- the session sees the `*tls.Conn`: STARTTLS is refused with 502 and
  `MAIL FROM:<...> REQUIRETLS` is taken;
- a connection whose handshake has not run gets it first, then no greeting;
- `Close` ends a live session, and closes its connection;
- `Shutdown` waits for a live session and returns once it ends;
- after `Close`, `ServeConn` refuses with `ErrServerClosed` and the client
  reads nothing;
- `AfterStartTls` on a plain connection refuses with `ErrServeConnNotTls`;
- without `AfterStartTls`, a connection is greeted as `Serve` greets it.

`urnetwork_bdat_reset_test.go`, the second change: RSET between BDAT chunks,
then a new transaction sent as one BDAT LAST, which must answer its own 250,
with `Reset` never running beside a `Data` and no two `Data` at once. Upstream's
`conn.go` fails it every run.

`urnetwork_bare_postmaster_test.go`, the third change: `RCPT TO:<Postmaster>`,
`<postmaster>` and `<POSTMASTER>` reach `Rcpt` as `postmaster`, and a full
address keeps its case; parameters after the bare form's bracket are parsed
as after any path; `<Postmaster@>`, `<Postmasters>`, `<other>` and the other
paths above with no domain still answer 501; `MAIL FROM:<Postmaster>` still
answers 501. Upstream's `parse.go` fails its two tests that take the bare
form.

Upstream's own tests run with `go test ./...` here and still pass.

## Who replaces it

Go does not inherit replacements, so each main module that links sidecar's
root repeats one:

- `sidecar/go.mod`: `./third_party/go-smtp`;
- `sidecar/cli`, `sidecar/smtpproof` and `sidecar/mlsinterop`:
  `../third_party/go-smtp`;
- server, sn and the four sdk modules: `../sidecar/third_party/go-smtp`, one
  level further up in the nested sdk modules.

`sidecar/check`'s hygiene rule fails a module whose replace is missing or
points elsewhere. Once upstream holds all three changes, delete this
directory, the replaces and the interface assertion in `mail_smtp_serve.go`.
The sessions' mapping of a bare postmaster stays, since upstream's parser then
hands them the bare form.
