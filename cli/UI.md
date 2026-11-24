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
ur socket listen <addr> <target> [--expires=<d>]
                                        listen on <addr>, forwarding each stream to <target>
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
- `--expires` is how long an outward name's grant lasts, a duration such as `36h` or whole days as `7d`, held to the
  requests rule's `maxExpiry`, which refuses a longer one, as `ur bridge public-tls --expires` is; omitted, the rule's
  `expiresDefault`, 1 h unless the document says otherwise (owner decision 687). Run the listen again after the
  approval with the same `--expires`, since another lifetime is another request. A name whose listen asks no grant,
  and a standing grant's, ask nothing of it: the first refuses it, the second passes whatever it asks.
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
ur share get - <out>                    the same, the link read from stdin
ur share rm <token> [--network=<name>]
```

- `add` hashes the file, prints the link `<net>:share/<token>#<k>`, once, and then its uses and expiry. The fragment
  `k` carries the secret: it never reaches a server or a log.
- `get -` reads the link from stdin, one line, as in `ur share get - <out> < link.txt`, so the link's reusable secret
  stays out of argv, `ps` and shell history (owner decision 336). When stdin is a terminal, the link is typed or
  pasted with echo off, as a pass is. A line that is empty, too long or no link is refused, and nothing repeats it.
  The plain form puts the link in argv: while the get runs another user of the host reads it through `ps` or
  `/proc/<pid>/cmdline`, and the shell keeps it in its history.
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
  keeps the host's route (QD-800); IPv6, which the tun does not carry, keeps the host's route too. This host's own
  interface, gateway and resolver addresses, which the bridge carves out of what it routes (§17.4), take a `throw`
  route each in that table, kept in step as they change, so they keep the host's route as well, and a resolver beyond
  the host's own networks still answers the host's lookups, outside the exits (QD-808). Where the host refuses it, a
  strict reverse path filter or a table or mark another program uses, `ur tun` says the exits are held and why, the
  host's other traffic keeps its route, and it tries again. The route, its throws, its rules and the mark come off
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
ur bridge invite <target>...                       share targets of this network with one other network (admins)
ur bridge accept-invite <code>                     accept another network's invite, aliasing its targets (admins)
ur bridge activate <share_id>                      show an accepted share, then activate it on a yes (admins)
```

- The listing shows pinned and unpinned counts, what the bridge waits on, a block another network on this host
  shares, and local addresses carved out of the block (§17.17). Rules and forwards are named by their ids.
- Without an active grant, `expose` and `forward` print `ur approve <id>` and wait, asking the daemon again until
  the decision lands; a wait that runs out exits 1 and the same command picks the decision up later (§16.6).
- A forward listens on every interface unless a local ip or `--listen` narrows it, and then serves every host that
  reaches the listener: it is listed LAN-exposed, here and in `ur status`, and the command warns. It carries its
  user's own protocol, so no TLS rule applies. It stops at its grant's expiry and when the grant is revoked.
- `egress` and `block` ask for a yes on the terminal first, and never run from MCP or a hook.
- A share takes three admins' acts (§17.9, v1), each asking on the terminal first and never run from MCP or a hook.
  `invite`'s target is `<host>=<cidr>[,tcp:<port>[-<port>]|,udp:<port>[-<port>]]`, the host by its id, private name
  or overlay address; it prints the share's id and the invite's code, shown once. `accept-invite <code>` prints each
  target's alias in this network's block and the ShareKey's fingerprint, or why there was no room.
- `activate <share_id>` is the inviting network's approving admin's, on a device that made the invite, and stays
  apart from the invite, since another admin may approve. It needs a terminal before it reads the share, and shows
  the share there, not on stdout: the network that accepted, each target with its host and its alias in that
  network's block, the ShareKey's fingerprint (its public key's SHA-256 in groups of four hex digits, which
  `accept-invite` printed on the other side, to compare) and both tables' SHA-256 and versions. Only on a yes does it
  activate, and only what was shown: a share that changed in between is refused, and the command shows it again when
  run again. A share not yet accepted, or refused, is shown and not asked about. The activation files the share's
  grant through the approval gate, so it may print `ur approve <id>` and wait as `expose` does. The owner named the
  command (QD-831); §17.11's table names only `invite` and `accept-invite` until the design carries it.
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

## ur id (§15.8)

A network's mail addresses, thin over the daemon's mail component. §15.8 gives `ur id create <name>`, `ur id
group-create [--private]` and `group-add`; the rest of these spellings and the flags are this file's until the owner's
copy lands.

```text
ur id create <name> [--network=<net>]                  <name>@<net>.<root>, into this member's mailbox
ur id group-create <name> [--private] [--network=<net>]
ur id group-add <group> <member_id> [--network=<net>]
ur id ls [--network=<net>]                             every address mailcfg holds, and whether a receiver takes it
ur id rm <name> [--network=<net>]
```

- `create` and `rm` are outward actions (I-8): each passes §5.4's gate first. While a person's decision is awaited the
  command prints `ur approve <id>` for another approval-capable device and exits 1; it runs once it is run again
  after the approval.
- `group-create` and `group-add` ask on /dev/tty first. A group's repo stores each message once. The signed creation
  marks the inbox and grants deposit to the devices that may run the network's receiver: a Team's mail indexers, or
  on a personal network the member's devices (QD-1177). Members join with `group-add` (§16.11).
- `ls` names an address whose creator's grant is gone as one no receiver takes, since a record outlives no grant.

## ur mail (§15.6, §15.15)

```text
ur mail enable [--network=<net>]    turns mail on: mailcfg, this member's mailbox, then POST /mail/enable
ur mail status [--network=<net>]    the network's mail status, this device's receiver, and the indexer prompt
ur mail recipients rm <alias> <recipient> [--network=<net>]
                                    removes an approved recipient of a sending alias (§15.10)
```

- With mail on, the daemon never idles out (§5.8), and `ur status` adds the same lines.
- Until a mail indexer stands, both print §15.6's prompt: a phone alone cannot reliably receive mail, and a desktop
  `ur daemon`, a NAS or a VPS is needed.
- A receiver whose listen waits on a person shows `ur approve <id>` for another approval-capable device.
- `recipients rm` asks on /dev/tty first, never through MCP: mail from `<alias>` to `<recipient>` then waits on a
  person again. The design names the command and no arguments, so the pair is this file's.

## ur admin settings (§7.9)

ServiceSettings' Settings fields, each network-wide and signed by an Owner's or Admin's device (owner decisions 302
and 305; QD-204). §7.9 names no command; this one is the owner's answer to question
service-settings-7-9-admin-settings-command (QD-1131), in the shape `ur admin directory` has.

```text
ur admin settings [--network=<name>]    the three as this device honors them
ur admin settings [--mail-strict=on|off] [--record-cost=on|off] [--record-required=on|off] [--network=<name>]
                                        sign the options given into the config head, after a yes on /dev/tty
```

- `mail_strict` is §15.4's `mail.strict`, off by default. `record_cost` says whether per-run cost totals go to the
  team record as well as each member's vault, on by default. `record_required` says whether each member's
  `ur install-harness` writes fail-closed hooks, off by default.
- The options given go into one Signed ServiceSettings, the head's other fields kept, through this device's config
  writer. The daemon refuses before anything is signed: a device that is no Owner's or Admin's, any call a person did
  not confirm, and a caller with a harness process among its ancestors. No MCP tool reaches it, so `record_required`
  is never set through MCP.
- Every member's `ur status` names `record_cost` in a Team, and `record_required` while it is set. A member's
  `ur install-harness` reads `record_required` from its running daemon and writes the fail-closed form while it is
  set; while it is set, the daemon reads a fail-open install as changed, so its runs taint until the install runs
  again.

## ur admin scopes (§7.9, §12.5, §13.8)

A Team scope's first binding, signed by an Owner's or Admin's device into ServiceSettings.team_scopes (QD-1163). §7.9
names no command; this one follows `ur admin settings`.

```text
ur admin scopes [list] [--network=<name>]
                                        the Team scopes the newest verified base holds
ur admin scopes add <label> (--member=<member_id> | --tag=<tag>) [--network=<name>]
                                        bind a label to a member or a tag, after a yes on /dev/tty
```

- A scope is the network's only once a verified base holds its binding: a head that declares it binds nothing until
  then, and a hostname, a grant naming a scope host or a directory answer never does.
- A label's first binding never changes, its retirement's included, and reassignment waits for its consent rule
  (DESIGN-DEFER.md): `add` refuses a label bound already, to the same owner as well, and an owner holding a label.
- The daemon refuses before anything is signed: a device that is no Owner's or Admin's, any call a person did not
  confirm, a caller with a harness process among its ancestors, a label §12.5 refuses a scope or §12.7 refuses an
  owner, a brand-confusable one, a client name, a host the policy publishes, a member the network does not hold and a
  tag the policy declares no owners of.

## ur admin members --after (§7.5, §7.8)

```text
ur admin members [list] [--after=<member_id>] [--device]
                                        a page of the team's members: the first, or the one past <member_id>
```

- One command a page (QD-1162): the page's admin token covers no query, so `--after` rides in the command's signed body,
  and each page takes its own consent in the browser. `ur acl push` reads pages the same way while a member its policy
  names is on none read yet, at most `AclMemberPageCount` (8), and sends no email of the policy's in any of them.
