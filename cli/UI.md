# ur's command line: what DESIGN.md adds

DESIGN.md cites `cli/UI.md` for ur's flags, and no checkout holds that file (question plan-CORE-cli-ui-missing,
QD-024). The owner's copy is to come in at `design/UI.md`, and its spellings win over anything here, each a one-line
rename behind `registerUrCommand`. Until it does, this file records the commands DESIGN.md says it adds to `cli/UI.md`,
in the spellings `ur` implements, one section a command, so `ur <command> -h` and this page agree.

## ur socket (§9.9)

Sockets live in the daemon, which stays up while it holds any (§5.8). Each command returns once the daemon holds what
it asked for.

```text
ur socket                               every socket the daemon holds, listens and dial forwards
ur socket listen <addr> <target>        listen on <addr>, forwarding each stream to <target>
ur socket dial <addr> [--listen=<local>]
ur socket ls [<net>]                    the network's names, unsealed on this device
ur socket drain <addr>                  drain the daemon's sockets on <addr>
```

- `<addr>` is `[<net>:]<name>` (§9.4). With no `<net>` it is the call's network: `.ur`'s, else the only one hosted.
- `listen`'s `<target>` is `[<ip>:]<port>`, 127.0.0.1 unless an address is given. While the target refuses, the listen
  keeps its lease and takes no tickets (`serving=false`), and the daemon dials the target again until it answers.
- An outward name, `tls/` or `smtp/`, passes §5.4's gate first. While a person's decision is awaited, `listen` prints
  `ur approve <id>` for another approval-capable device and exits 1; the listen runs once it is run again after the
  approval.
- `dial --listen=[<ip>:]<port>` is a local forward on every interface (0.0.0.0 and ::) unless `<ip>` is given, carrying
  raw bytes with no TLS-only rule (D-TRUST-8; owner decisions 84, 130). `ur status` lists it, LAN-exposed when it is.
- `dial` with no `--listen` relays stdin and stdout to one stream, for `ssh -o ProxyCommand='ur socket dial %h'`.
  Nothing of ur's own reaches stdout; a refusal goes to stderr. stdin's end closes the stream's half, and the far
  side's end ends the relay.
- `ls` pages `GET /socket/list` and opens each seal with the network's K_sock on this device. A seal that does not
  open is counted and never shown.
- `drain` drains each listen as §9.9's `Drain` does, ending at zero streams in flight or after 30 s, and stops a dial
  forward taking new local connections.

## ur share (§9.9, D-SOCK-16)

A link that `ur share get` redeems at most `--count` times before it expires, served while the sharing device's daemon
runs, which stays up while a share lives (§5.8). `ur status` says so.

```text
ur share                                every live share, its uses left and its expiry; never a link
ur share add <path> [--count=<n>] [--expires=<d>] [--network=<name>]
ur share get <link> <out>
ur share rm <token> [--network=<name>]
```

- `add` hashes the file, prints the link `<net>:share/<token>#<k>`, once, and then its uses and expiry. The fragment
  `k` carries the secret: it never reaches a server or a log.
- `--count` omitted is one use, `--count=0` unlimited until the expiry, `--count=n` n uses (QD-241).
- `--expires` takes a duration such as `36h` or whole days as `7d`: 24 h by default, at most 30 days (owner decision 74).
- `get` writes `<out>.part`, keeping the get's id beside it in `<out>.part.id` until it completes, so a get cut short
  resumes where it stopped and spends no second use. `<out>` must not exist. It refuses a sharer whose verified
  identity is not the link's.
- `rm` ends a share at once: its live streams reset and its link redeems nothing more.
