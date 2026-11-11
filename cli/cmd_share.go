// ur share (§9.9, D-SOCK-16, R-SOCK-10; SOCK-M5-15): a link that ur share get redeems at most --count times before
// its expiry, served while this device's daemon runs, which stays up while a share lives (§5.8).
//
//	ur share                                        every live share: remaining uses and expiry, never a link
//	ur share add <path> [--count=<n>] [--expires=<d>] [--network=<name>]
//	                                                hashes the file, prints <net>:share/<token>#<k>
//	ur share get <link> <out>                       redeems a link into <out>, resuming <out>.part
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
// another user's ps can read it while the get runs.

package main

import (
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

func init() {
	registerUrCommand(&urCommand{
		name: "share",
		usage: strings.Join([]string{
			"  ur share",
			"  ur share add <path> [--count=<n>] [--expires=<d>] [--network=<name>]",
			"  ur share get <link> <out>",
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
		link, _ := options.String("<link>")
		out, _ := options.String("<out>")
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

func runUrShareGet(ctx context.Context, cli *urCli, linkText string, out string) error {
	link, err := sidecar.ParseShareLink(linkText)
	if err != nil {
		return err
	}
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
