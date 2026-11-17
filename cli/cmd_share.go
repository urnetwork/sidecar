// ur share (§9.9, D-SOCK-16, R-SOCK-10; SOCK-M5-15): a link that ur share get redeems at most --count times before
// its expiry, served while this device's daemon runs, which stays up while a share lives (§5.8).
//
//	ur share                                        every live share: remaining uses and expiry, never a link
//	ur share add <path> [--count=<n>] [--expires=<d>] [--network=<name>]
//	                                                hashes the file, prints <net>:share/<token>#<k>
//	ur share get <link> <out>                       redeems a link into <out>, resuming <out>.part
//	ur share get - <out>                            the same, the link read from stdin
//	ur share rm <token> [--network=<name>]          ends a share early, resetting its live streams
//
// This process draws the token and the 256-bit secret (sidecar.NewShareCredentials) and hashes the file, so the daemon's
// reply carries nothing secret and its control call does not wait on a large file's hash (§5.8: a request may carry a
// secret, a reply never does). The link is printed once, for the person; nothing logs it. --count omitted is one use,
// 0 unlimited until the expiry (QD-241); --expires takes Go's durations or whole days as <n>d, 24 h by default, and the
// daemon refuses more than 30 days.
//
// ur share get dials the share through the daemon's socket hello mode holding the link's sidecar_id, so the daemon's
// dial refuses before OPEN a listener whose verified Hello names another sidecar, within the sharer's network only, and
// runs the getter's half here (sidecar.SharePart). The link is an argument, as §9.9 writes it, so on a shared host
// another user reads it through ps or /proc/<pid>/cmdline while the get runs, and the shell keeps it in its history.
// `-` in its place keeps it out of all three (owner decision 336): the link is then one line of stdin or, when stdin
// is a terminal, a line typed or pasted on /dev/tty with echo off, as a pass is (tty.go), so it never shows on the
// screen either. A line that is empty, too long or no link is refused before anything is dialed or written, and no
// refusal repeats it (I-13). The line read is zeroed once it parses and the secret once the get ends; the parse's
// copy of the text is a string, which nothing can zero.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// What ur share get takes in place of <link> to read the link from stdin (owner decision 336).
const urShareLinkFromStdin = "-"

func init() {
	registerUrCommand(&urCommand{
		name: "share",
		usage: strings.Join([]string{
			"  ur share",
			"  ur share add <path> [--count=<n>] [--expires=<d>] [--network=<name>]",
			"  ur share get <link> <out>",
			"  ur share get " + urShareLinkFromStdin + " <out>",
			"  ur share rm <token> [--network=<name>]",
		}, "\n"),
		summary: "share a file by a link that redeems a set number of times before it expires",
		run:     runUrShare,
	})
}

// What a socket and share count says in ur status: the daemon stays up while any is held.
type urSocketsTarget interface {
	socketCounts() (sockets int, shares int)
}

// The daemon's sockets and live shares, for ur status.
func (self *urDaemonNetwork) socketCounts() (int, int) {
	if self.daemon == nil {
		return 0, 0
	}
	sockets := self.daemon.Sockets()
	return len(sockets.Local()), sockets.LiveShareCount()
}

func runUrShare(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	switch {
	case options["add"] == true:
		path, _ := options.String("<path>")
		count, _ := options.String("--count")
		expires, _ := options.String("--expires")
		return runUrShareAdd(ctx, cli, path, count, expires, network)
	case options["get"] == true:
		linkText, _ := options.String("<link>")
		out, _ := options.String("<out>")
		var link *sidecar.ShareLink
		var err error
		// a lone - matches both get lines, and docopt hands it to whichever comes first
		if options[urShareLinkFromStdin] == true || linkText == urShareLinkFromStdin {
			link, err = readUrShareLink(cli)
		} else {
			link, err = sidecar.ParseShareLink(linkText)
		}
		if err != nil {
			return err
		}
		return runUrShareGet(ctx, cli, link, out)
	case options["rm"] == true:
		token, _ := options.String("<token>")
		return runUrShareRemove(ctx, cli, token, network)
	}
	return runUrShareList(ctx, cli)
}

// --count: omitted is one use (QD-241), 0 unlimited until the expiry, n that many.
func parseUrShareCount(text string) (uint32, error) {
	if text == "" {
		return 1, nil
	}
	count, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, errors.New("--count takes a whole number, 0 for unlimited until the share expires")
	}
	return uint32(count), nil
}

// --expires: a Go duration such as 36h, or <n>d for whole days; empty for the daemon's default. The daemon holds it
// to 30 days.
func parseUrShareExpires(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	if days, isDays := strings.CutSuffix(text, "d"); isDays {
		count, err := strconv.ParseUint(days, 10, 16)
		if err != nil || count == 0 {
			return 0, errors.New("--expires takes a duration such as 36h, or whole days as 7d")
		}
		return time.Duration(count) * 24 * time.Hour, nil
	}
	expires, err := time.ParseDuration(text)
	if err != nil || expires <= 0 {
		return 0, errors.New("--expires takes a duration such as 36h, or whole days as 7d")
	}
	return expires, nil
}

// The file's size, modification time and SHA-256, refused when it changed while it was read.
func hashUrShareFile(path string, chunkByteCount int) (int64, int64, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return 0, 0, nil, err
	}
	if !before.Mode().IsRegular() {
		return 0, 0, nil, errors.New("ur share shares a regular file")
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, chunkByteCount)); err != nil {
		return 0, 0, nil, err
	}
	after, err := os.Stat(path)
	if err != nil {
		return 0, 0, nil, err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return 0, 0, nil, errors.New("the file changed while it was hashed: run ur share add again")
	}
	return before.Size(), before.ModTime().UnixNano(), hash.Sum(nil), nil
}

func runUrShareAdd(ctx context.Context, cli *urCli, path string, countText string, expiresText string, network string) error {
	uses, err := parseUrShareCount(countText)
	if err != nil {
		return err
	}
	expires, err := parseUrShareExpires(expiresText)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	settings := sidecar.DefaultSidecarSettings().Sockets.Share
	size, mtimeNanos, sum, err := hashUrShareFile(absolute, settings.ChunkByteCount)
	if err != nil {
		return err
	}
	token, secret := sidecar.NewShareCredentials()
	defer clear(secret)
	params := &sidecar.DaemonShareAddParams{
		Network:       network,
		Path:          absolute,
		Size:          size,
		MtimeNanos:    mtimeNanos,
		Sha256:        sum,
		Uses:          uses,
		ExpiresMillis: expires.Milliseconds(),
		Token:         token,
		Secret:        secret,
	}
	reply := &sidecar.DaemonShareAddReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodShareAdd, params, false, reply); err != nil {
		return err
	}
	cli.printf("%s\n", sidecar.FormatShareLink(reply.NetworkLabel, reply.Token, reply.SidecarId, secret))
	usesText := strconv.FormatUint(uint64(reply.Uses), 10)
	if reply.Uses == 0 {
		usesText = "unlimited"
	}
	cli.printf("uses: %s; expires %s\n", usesText, time.UnixMilli(reply.ExpireMillis).UTC().Format(time.RFC3339))
	cli.printf("served while this device's daemon runs, which stays up while the share lives: ur share rm %s ends it\n", reply.Token)
	return nil
}

// The link of `ur share get -`: one line of stdin or, when stdin is a terminal, one typed on /dev/tty with echo off,
// refused where /dev/tty does not open rather than read echoed. The line's ending and the blanks around the link are
// dropped. A line that is empty, longer than ShareLinkByteCount or no link is refused, and no refusal repeats what
// was read (I-13).
func readUrShareLink(cli *urCli) (*sidecar.ShareLink, error) {
	var line []byte
	if cli.stdinIsTerminal() {
		tty, err := cli.openTty()
		if err != nil {
			return nil, fmt.Errorf("stdin is a terminal, and a link typed there is read only from /dev/tty with echo off, which did not open (%w): pipe the link in instead", err)
		}
		defer tty.Close()
		fmt.Fprint(tty, "share link (not echoed): ")
		line, err = tty.readSecretLine()
		fmt.Fprint(tty, "\n")
		if err != nil {
			return nil, fmt.Errorf("no link was read from the terminal: %w", err)
		}
	} else {
		// ReadSlice answers a slice of the reader's own buffer, so zeroing the line zeroes the buffer's copy too
		reader := bufio.NewReaderSize(cli.stdin, cli.settings.ShareLinkByteCount+1)
		var err error
		line, err = reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			clear(line)
			return nil, errors.New("stdin's first line is longer than any share link")
		}
		if err != nil && !errors.Is(err, io.EOF) {
			clear(line)
			return nil, fmt.Errorf("no link was read from stdin: %w", err)
		}
	}
	defer clear(line)
	text := bytes.TrimSpace(line)
	if len(text) == 0 {
		return nil, errors.New("no link was read: ur share get - <out> takes one line, the link ur share add printed")
	}
	if cli.settings.ShareLinkByteCount < len(text) {
		return nil, errors.New("the line read is longer than any share link")
	}
	link, err := sidecar.ParseShareLink(string(text))
	if err != nil {
		// the parse's error repeats nothing of the text, and this names only the sentinel, so neither can
		return nil, fmt.Errorf("the line read is %w", sidecar.ErrShareLink)
	}
	return link, nil
}

// Redeems link into out. The secret is zeroed once the get ends.
func runUrShareGet(ctx context.Context, cli *urCli, link *sidecar.ShareLink, out string) error {
	defer clear(link.Secret)
	absolute, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	settings := sidecar.DefaultSidecarSettings().Sockets.Share
	part, err := sidecar.OpenSharePart(absolute, link.Token, settings.ChunkByteCount)
	if err != nil {
		return err
	}
	hello := cli.hello(sidecar.DaemonModeSocket)
	hello.Socket = link.Address()
	hello.SocketSidecarId = &link.SidecarId
	stream, closeSession, err := cli.openSocketSession(ctx, hello)
	if err != nil {
		part.Close()
		return err
	}
	defer closeSession()
	if err := part.Get(stream, link); err != nil {
		if errors.Is(err, sidecar.ErrShareMismatch) || errors.Is(err, sidecar.ErrShareRefused) {
			return fmt.Errorf("%w: ur share get again resumes it", err)
		}
		return err
	}
	cli.printf("got %s\n", out)
	return nil
}

func runUrShareRemove(ctx context.Context, cli *urCli, token string, network string) error {
	reply := &sidecar.DaemonShareRemoveReply{}
	params := &sidecar.DaemonShareRemoveParams{Network: network, Token: token}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodShareRemove, params, false, reply); err != nil {
		return err
	}
	cli.printf("removed: its streams reset and its link redeems nothing\n")
	return nil
}

func runUrShareList(ctx context.Context, cli *urCli) error {
	reply := &sidecar.DaemonShareListReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodShareList, nil, false, reply); err != nil {
		return err
	}
	if len(reply.Shares) == 0 {
		cli.printf("no live shares: ur share add makes one\n")
	}
	for _, share := range reply.Shares {
		remaining := strconv.Itoa(share.RemainingCount) + " uses left"
		if share.RemainingCount < 0 {
			remaining = "unlimited uses"
		}
		serving := "serving"
		if !share.Serving {
			serving = "not serving yet"
		}
		cli.printf("%s  %s, %s, expires %s, %s\n", share.Token, share.Path, remaining,
			time.UnixMilli(share.ExpireMillis).UTC().Format(time.RFC3339), serving)
	}
	for _, token := range reply.FailedTokens {
		cli.printf("warning: share %s does not read and serves nothing: ur share rm %s takes it away\n", token, token)
	}
	if 0 < len(reply.Shares) {
		cli.printf("the daemon stays up while a share lives\n")
	}
	return nil
}
