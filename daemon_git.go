//go:build !js && !ios && !android && !sdk_mobile_bind

// git mode (§5.8, §11.11, CORE-M2-08): after a hello of {mode: git, version, repo: <net>/<repo>, service}, the session
// carries raw pkt-line bytes for one repo of that network's Sidecar, the daemon running the system git-upload-pack or
// git-receive-pack behind its hooks. git-remote-ur pipes git's stdio to it (§4.10), so only a same-uid process
// reaches it, through the daemon's peer check. The hello already refused any service but those two and any repo not
// of the <net>/<repo> form (daemon_hello.go).
//
// This file resolves <net> and hands the session to the git service, EVS1-M2-38's EvsClient.ServeGit, which ur daemon
// registers (C-16: the seam is declared here and the service registers on it). <net> is a label or alias by §12's
// rule among the networks the daemon hosts, never a legacy network_name, which another network may later hold
// (D-DNS-2). The mode selects a protocol, never a privilege (D-CORE-9): a git session reaches no control method, since
// its bytes go to the git service and never to the JSON-RPC dispatcher, and it signs nothing a person must confirm.
//
// A session that cannot be served is refused in git's own protocol, an ERR pkt-line, which git shows as a remote
// error. The line names the reason and nothing the caller sent.

package sidecar

import (
	"context"
	"errors"
	"io"
	"strings"
)

// The refusal a git session gets before its service runs.
var ErrDaemonGitRefused = errors.New("git session refused")

// One git session past its hello, as the git service serves it.
type DaemonGitSession struct {
	Hello *DaemonHello
	// The network <net> named, and its Sidecar.
	NetworkId Id
	Sidecar   *Sidecar
	// <repo>: a display name from the config repo, or id:<repo_id> (§11.11). The service resolves it.
	Repo string
	// git-upload-pack or git-receive-pack.
	Service string
	// The session's raw pkt-line bytes, both ways.
	Stream io.ReadWriter
}

// Serves one git session on its Sidecar's repo, returning when the session ends: EVS1-M2-38's EvsClient.ServeGit.
type DaemonGitService func(ctx context.Context, session *DaemonGitSession) error

// The git mode's handler on daemon: <net> resolves among the networks daemon hosts and the session goes to service.
// A nil service refuses every session, as does a <net> naming no hosted network.
func NewDaemonGitMode(daemon *Daemon, service DaemonGitService) DaemonModeHandler {
	return func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
		network, repo, found := strings.Cut(hello.Repo, "/")
		if !found || hello.Mode != DaemonModeGit {
			return refuseDaemonGit(stream, "ur: not a git session")
		}
		networkId, err := daemon.resolveNetworkName(network, false, false)
		if err != nil {
			return refuseDaemonGit(stream, "ur: "+err.Error())
		}
		sidecar, ok := daemon.SidecarForNetwork(networkId)
		if !ok {
			return refuseDaemonGit(stream, "ur: that network is not hosted here")
		}
		if service == nil {
			return refuseDaemonGit(stream, "ur: git is not served by this daemon yet")
		}
		return service(ctx, &DaemonGitSession{
			Hello:     hello,
			NetworkId: networkId,
			Sidecar:   sidecar,
			Repo:      repo,
			Service:   hello.Service,
			Stream:    stream,
		})
	}
}

// Writes git's ERR pkt-line with message and answers ErrDaemonGitRefused.
func refuseDaemonGit(stream io.Writer, message string) error {
	line, err := EvsPktLine{Kind: EvsPktLineData, Payload: []byte("ERR " + message + "\n")}.Encode()
	if err == nil {
		stream.Write(line)
	}
	return ErrDaemonGitRefused
}
