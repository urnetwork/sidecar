//go:build !js && !ios && !android && !sdk_mobile_bind

// Pairing over the daemon's sockets (§5.8's pair and Pairing rows, §5.9's socket row; owner decisions 4, 87;
// CORE-M8-02).
//
//	method     pair: the app's own control call, no person act, its one param the child's jwt, which the app minted
//	           under its device client and gives up here; its reply is the network and the generation bound, never a
//	           token (I-7). A host picks the Sidecar that takes it: the hosted one of the token's network, else its
//	           unenrolled one, as an enrollment does (CORE-M6-01)
//	app group  a sandboxed macOS app reaches the daemon through a short-named socket in each app-group container ur
//	           claims, 6BGU69Q742.group.network.ur and the direct build's 6BGU69Q742.group.com.bringyour.urnetwork
//	           (QD-345), served as the main socket is: the same peer check, hello and protocol, so it opens nothing
//	           the main socket does not. ServeAppGroupSockets listens in each container that exists, on macOS only
//	           (daemon_socket_appgroup_darwin.go), and stops with the daemon
//
// The socket's name: ur for the default instance, else u and the first 7 hex of SHA-256 of the instance's name, so a
// container path and the name fit sun_path's 104 bytes (§5.9). A path that would not fit is passed over, logged. The
// name is DaemonAppGroupSocketName's, in daemon_client.go, since a sandboxed app's remote backend dials by it too.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
)

// The pairing method.
const DaemonMethodPair = "pair"

// pair's params.
type DaemonPairParams struct {
	// The child's token, which the app minted and gives up: the daemon keeps it in the network's keychain.
	ChildJwt string `json:"child_jwt"`
}

// pair's reply: no token.
type DaemonPairReply struct {
	NetworkId  Id    `json:"network_id"`
	Generation int64 `json:"generation"`
}

// What a pairing reaches: a host's choice of the Sidecar that takes the child, which pairs it and answers.
type DaemonPairTarget interface {
	PairChild(ctx context.Context, childJwt string) (*DaemonPairReply, error)
}

// The network a child's token names, read without verifying it, for a host choosing the Sidecar that takes it: false
// for a token naming none.
func DaemonPairNetwork(childJwt string) (Id, bool) {
	networkId, _, ok := sidecarJwtClient(childJwt)
	return networkId, ok
}

// The pair method over target.
func DaemonPairMethod(target DaemonPairTarget) *DaemonMethod {
	return &DaemonMethod{
		Name: DaemonMethodPair,
		Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
			params := &DaemonPairParams{}
			if len(call.Params) == 0 || json.Unmarshal(call.Params, params) != nil || params.ChildJwt == "" {
				return nil, errors.New("pair takes the child's token")
			}
			testHookSecret("by_client_jwt", []byte(params.ChildJwt))
			reply, err := target.PairChild(ctx, params.ChildJwt)
			params.ChildJwt = ""
			return reply, err
		},
	}
}

// The app-group socket paths a sandboxed app of this platform pairs through, for instance under home: macOS's, which
// daemon_socket_appgroup_darwin.go sets, one a container that exists and whose path fits sun_path; none elsewhere.
var daemonAppGroupSocketPathsOf = func(instance string, home string) []string {
	return nil
}

// The app-group socket paths for instance under home (see daemonAppGroupSocketPathsOf).
func DaemonAppGroupSocketPaths(instance string, home string) []string {
	return daemonAppGroupSocketPathsOf(instance, home)
}

// Listens on each app-group socket of the daemon's instance (DaemonAppGroupSocketPaths), and on
// SidecarLocalSettings.AppGroupSocketPath where a host sets one, and serves their sessions as Run serves the main
// socket's, until the daemon closes. A listener that cannot open is logged and passed over: the main socket serves on.
// Answers the paths it listens on.
func (self *Daemon) ServeAppGroupSockets() []string {
	paths := DaemonAppGroupSocketPaths(self.settings.Instance, self.home())
	if extra := self.settings.Local.AppGroupSocketPath; extra != "" && !slices.Contains(paths, extra) {
		paths = append(paths, extra)
	}
	listening := []string{}
	for _, path := range paths {
		listener, err := listenDaemon(path)
		if err != nil {
			// the error names the path, which names the user's home: never logged (I-13)
			self.log.Warningf("[daemon]an app-group socket did not open")
			continue
		}
		listening = append(listening, path)
		go self.serveAppGroup(listener)
	}
	return listening
}

// Accepts on one app-group listener until the daemon closes, each session through the main socket's serve.
func (self *Daemon) serveAppGroup(listener net.Listener) {
	stop := context.AfterFunc(self.ctx, func() {
		listener.Close()
	})
	defer stop()
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if self.ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			self.log.Warningf("[daemon]an app-group socket stopped")
			return
		}
		if !self.openSession(conn) {
			conn.Close()
			return
		}
		go self.serve(conn)
	}
}
