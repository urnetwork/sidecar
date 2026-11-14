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

## ur tun (§17.11)

The OS tun `ur-<instance>` for one network's bridge, on Linux and WSL2 at M4 (macOS and Windows at M6). It lives in
the daemon, as a socket does: each command returns once the daemon holds what it asked for, and the daemon stays up
while the bridge is on (§5.8).

```text
ur tun [--network=<name>]               bring the tun up over the network's bridge, and show what it carries
ur tun down                             end it, removing its routes
ur tun ip [<ip>] [--network=<name>]     show this host's overlay address and the block, or claim <ip>, or auto
```

- The daemon needs CAP_NET_ADMIN or root: `sudo setcap cap_net_admin=ep "$(command -v ur)"` grants it to the ur the
  daemon runs as. Without it `ur tun` says so, and `ur bridge` still works over the userspace stack.
- The tun carries the block, the granted prefixes and `<block>.0.53`, and under the egress mode `exits` the default
  route too, in a routing table of its own with wg-quick's rules (`lookup main suppress_prefixlength 0`, then
  `not fwmark <mark> lookup <table>`): the daemon's own connect sockets carry connect's egress mark, so its transport
  keeps the host's route (QD-800); IPv6, which the tun does not carry, keeps the host's route too. Where the host
  refuses it, a strict reverse path filter or a table or mark another program uses, `ur tun` says the exits are held
  and why, the host's other traffic keeps its route, and it tries again. The route, its rules and the mark come off
  when the mode leaves `exits` and when the tun ends.
- The network's names, `~<net>.<root>`, resolve through `<block>.0.53` by systemd-resolved, set for the tun's link.
  Where resolved is absent or refuses, `ur tun` prints the step to take.
- `ur tun` yields to an app's bridge: on a sidecar paired with an app whose VPN holds the block, it refuses, naming the
  interface.
- One network's tun an instance: `ur tun` for another network refuses until `ur tun down`. `down` is this file's
  spelling; §17.11 names none.
- `ip <ip>` must lie in the block's lower /17, outside `<block>.0.0/24`, and not end in .0 or .255 (§17.4); the first
  claim in the log wins. `ip auto` refuses until the check that no browser leaks an overlay address through WebRTC has
  passed (QD-424).

## ur bridge (§17.11)

The network's bridge from the terminal. It lives in the daemon, as `ur tun` does, and needs no tun and no root: a
forward dials over a userspace stack.

```text
ur bridge [--network=<name>]                       list addresses, private names, rules and forwards
ur bridge expose <ranges>... [--remap]             advertise this host's subnets; 0.0.0.0/0 alone is its exit
ur bridge expose :<port>[=<ip>:<port>] [--udp]     map a port of this host's overlay address
ur bridge forward <client>:<port>[:<local ip>]:<local port> [--listen=<ip>] [--udp]
                                                   listen locally and dial the client's port
ur bridge close <id> [--reset]                     end a forward, withdraw a rule or revoke a grant
ur bridge egress auto|<exit>[,<exit>]|tag:<t>|none set this device's default route
ur bridge block [cycle|<cidr>]                     show the network's block, or re-roll or choose it (admins)
```

- The listing shows pinned and unpinned counts, what the bridge waits on, a block another network on this host
  shares, and local addresses carved out of the block (§17.17). Rules and forwards are named by their ids.
- Without an active grant, `expose` and `forward` print `ur approve <id>` and wait, asking the daemon again until
  the decision lands; a wait that runs out exits 1 and the same command picks the decision up later (§16.6).
- A forward listens on every interface unless a local ip or `--listen` narrows it, and then serves every host that
  reaches the listener: it is listed LAN-exposed, here and in `ur status`, and the command warns. It carries its
  user's own protocol, so no TLS rule applies. It stops at its grant's expiry and when the grant is revoked.
- `egress` and `block` ask for a yes on the terminal first, and never run from MCP or a hook.
- `close` is this file's spelling; §17.11 names none. Closing a forward leaves its grant; `close <grant id>` revokes
  it. `<client>` is a sidecar's id until the daemon follows the network's config, then a private name or an overlay
  address too.
- Until the daemon follows a network's config, every `ur bridge` command answers that no bridge runs for the network.

## ur login --device (§5.6, §7.8; RFC 8628)

For a host with no browser, or one whose browser cannot reach a loopback redirect: the same single-use, user-owned
auth key of at most 5 minutes as `ur login`, got by the device authorization grant.

```text
ur login --device [--network=<name>] [--replace]
```

- ur prints a page to open on another device, the code to enter there, and a consent code. Approve only if the page
  shows that consent code: an agent can drive a browser, so consent stays code-matched.
- ur polls every 5 s, or the interval the issuer sets, slowing by 5 s each time it is asked to, and stops at the code's
  expiry, a denial, or 15 min. The token and its DPoP key are dropped before the daemon is reached; the daemon gets the
  key alone, and nothing ur prints holds the token or the device code.
- An issuer that offers no device sign-in is refused, naming it.
