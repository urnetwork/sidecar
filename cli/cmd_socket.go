// ur socket (§9.9, R-SOCK-8; SOCK-M5-14): the daemon's sockets, which live in the daemon and keep it up while they do
// (§5.8), so each command returns once the daemon holds what it asked for.
//
//	ur socket                               every socket the daemon holds: listens and dial forwards
//	ur socket listen <addr> <target>        a listen forwarding each stream to [<ip>:]<port>, 127.0.0.1 unless an ip
//	                                        is given; serving is off while the target refuses; an outward name
//	                                        (tls/, smtp/) waiting on a person prints ur approve <id>
//	ur socket dial <addr> --listen=<local>  a local forward on [<ip>:]<port>, every interface unless an ip is given,
//	                                        raw bytes with no TLS-only rule (D-TRUST-8; owner decisions 84, 130)
//	ur socket dial <addr>                   stdin and stdout relayed to one stream, for ssh -o ProxyCommand, through
//	                                        the daemon's socket hello mode (SOCK.md reading 13)
//	ur socket ls [<net>]                    the network's names, unsealed on this device (GET /socket/list)
//	ur socket drain <addr>                  drains the daemon's sockets on the address
//
// The relay writes nothing of its own to stdout: past the daemon's status line stdout carries the stream's bytes
// alone, so ssh reads only the far side, and a refusal goes to stderr. Its stdin's end is a FIN, the far side's answer
// still arriving, and the far side's end ends the relay. Nothing here logs an address or a name (I-13). The daemon's
// socket and share methods register from here (C-21), and the daemon's shares resume with them.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name: "socket",
		usage: strings.Join([]string{
			"  ur socket",
			"  ur socket listen <addr> <target>",
			"  ur socket dial <addr> [--listen=<local>]",
			"  ur socket ls [<net>]",
			"  ur socket drain <addr>",
		}, "\n"),
		summary: "listen on, dial, list and drain the network's sockets",
		run:     runUrSocket,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urSocketMethods)
}

// The daemon's socket and share methods (daemon_socket.go, socket_share.go), over a target that hosts its networks.
// Registered once the daemon hosts its networks, which is when the shares their records hold resume serving (§9.9).
func urSocketMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.daemon == nil {
		return nil
	}
	sockets := network.daemon.Sockets()
	sockets.Resume()
	return sockets.Methods()
}

// The <net> an address names, which the call's network argument carries so a daemon of several networks picks its
// Sidecar; empty for none, which §5.8's rule resolves.
func urSocketAddressNetwork(address string) (string, error) {
	parsed, err := sidecar.ParseSocketAddress(address)
	if err != nil {
		return "", errors.New("the address is not [<net>:]<name>")
	}
	return parsed.NetworkLabel, nil
}

func runUrSocket(ctx context.Context, cli *urCli, options docopt.Opts) error {
	address, _ := options.String("<addr>")
	switch {
	case options["listen"] == true:
		target, _ := options.String("<target>")
		return runUrSocketListen(ctx, cli, address, target)
	case options["dial"] == true:
		if local, _ := options.String("--listen"); local != "" {
			return runUrSocketDialForward(ctx, cli, address, local)
		}
		return runUrSocketRelay(ctx, cli, address)
	case options["ls"] == true:
		network, _ := options.String("<net>")
		return runUrSocketList(ctx, cli, network)
	case options["drain"] == true:
		return runUrSocketDrain(ctx, cli, address)
	}
	return runUrSocketLocal(ctx, cli)
}

// One socket the daemon holds, as a line.
func formatUrSocketStatus(status *sidecar.DaemonSocketStatus) string {
	state := "serving"
	switch {
	case status.Draining:
		state = "draining"
	case !status.Serving:
		state = "not serving: the local target refuses"
	}
	switch status.Kind {
	case sidecar.DaemonSocketKindDial:
		exposure := "loopback only"
		if status.LanExposed {
			exposure = "LAN-exposed"
		}
		return fmt.Sprintf("dial    %s from %s (%s), %d in flight", status.Name, strings.Join(status.LocalAddresses, ", "), exposure, status.Inflight)
	}
	return fmt.Sprintf("listen  %s to %s (%s), %d in flight", status.Name, status.Target, state, status.Inflight)
}

func runUrSocketListen(ctx context.Context, cli *urCli, address string, target string) error {
	network, err := urSocketAddressNetwork(address)
	if err != nil {
		return err
	}
	reply := &sidecar.DaemonSocketListenReply{}
	params := &sidecar.DaemonSocketListenParams{Network: network, Address: address, Target: target}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSocketListen, params, false, reply); err != nil {
		return err
	}
	if reply.ApprovalId != nil {
		cli.printf("approval pending: run ur approve %s on another approval-capable device, then run this listen again\n", reply.ApprovalId)
		return &urExitError{code: urExitFailed, err: errors.New("the listen waits on that approval")}
	}
	if reply.Status != nil {
		cli.printf("%s\n", formatUrSocketStatus(reply.Status))
	}
	cli.printf("the daemon holds the listen, and stays up while it does: ur socket drain %s ends it\n", address)
	return nil
}

func runUrSocketDialForward(ctx context.Context, cli *urCli, address string, local string) error {
	network, err := urSocketAddressNetwork(address)
	if err != nil {
		return err
	}
	status := &sidecar.DaemonSocketStatus{}
	params := &sidecar.DaemonSocketDialParams{Network: network, Address: address, Listen: local}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSocketDial, params, false, status); err != nil {
		return err
	}
	cli.printf("%s\n", formatUrSocketStatus(status))
	if status.LanExposed {
		cli.printf("warning: hosts on the LAN can reach this forward, which carries raw bytes; --listen=127.0.0.1:<port> keeps it on this host\n")
	}
	cli.printf("the daemon holds the forward, and stays up while it does: ur socket drain %s ends it\n", address)
	return nil
}

// stdin and stdout relayed to one stream to address, through the daemon's socket hello mode.
func runUrSocketRelay(ctx context.Context, cli *urCli, address string) error {
	if _, err := urSocketAddressNetwork(address); err != nil {
		return err
	}
	hello := cli.hello(sidecar.DaemonModeSocket)
	hello.Socket = address
	stream, closeSession, err := cli.openSocketSession(ctx, hello)
	if err != nil {
		return err
	}
	defer closeSession()
	return cli.relaySocket(stream)
}

// A socket session past its status line: the daemon's dial answered ok, or its refusal as §9.9's error.
func (self *urCli) socketSession(ctx context.Context, hello *sidecar.DaemonHello) (sidecar.DaemonSessionStream, func(), error) {
	client, err := self.connectDaemon(ctx, hello, nil)
	if err != nil {
		return nil, nil, err
	}
	stream := client.Stream()
	if err := sidecar.ReadDaemonSocketSessionAnswer(stream, int(sidecar.DefaultDaemonClientSettings().HelloByteCount)); err != nil {
		client.Close()
		return nil, nil, err
	}
	return stream, func() { client.Close() }, nil
}

// Copies stdin to stream and stream to stdout: stdin's end closes the stream's half, and the stream's end ends the
// relay, whatever stdin does.
func (self *urCli) relaySocket(stream sidecar.DaemonSessionStream) error {
	go func() {
		if _, err := io.Copy(stream, self.stdin); err == nil {
			stream.CloseWrite()
		}
	}()
	_, err := io.Copy(self.stdout, stream)
	return err
}

func runUrSocketList(ctx context.Context, cli *urCli, network string) error {
	reply := &sidecar.DaemonSocketListReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSocketList, &sidecar.DaemonSocketListParams{Network: network}, false, reply); err != nil {
		return err
	}
	for _, name := range reply.Names {
		if name.Local {
			cli.printf("%s  (this daemon listens)\n", name.Name)
		} else {
			cli.printf("%s\n", name.Name)
		}
	}
	if 0 < reply.DroppedCount {
		cli.printf("%d sealed names did not open on this device and are not shown\n", reply.DroppedCount)
	}
	if !reply.Complete {
		code := "the listing stopped at its page bound"
		if reply.Error != nil {
			code = "a page was refused: " + string(reply.Error.Code)
		}
		cli.printf("warning: the listing is incomplete, %s\n", code)
	}
	return nil
}

func runUrSocketDrain(ctx context.Context, cli *urCli, address string) error {
	network, err := urSocketAddressNetwork(address)
	if err != nil {
		return err
	}
	reply := &sidecar.DaemonSocketDrainReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSocketDrain, &sidecar.DaemonSocketDrainParams{Network: network, Address: address}, false, reply); err != nil {
		return err
	}
	cli.printf("draining %d: each ends once its streams do, or at the drain's timeout\n", reply.DrainedCount)
	return nil
}

func runUrSocketLocal(ctx context.Context, cli *urCli) error {
	reply := &sidecar.DaemonSocketLocalReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSocketLocal, nil, false, reply); err != nil {
		return err
	}
	if len(reply.Sockets) == 0 {
		cli.printf("no sockets: ur socket listen and ur socket dial --listen make them\n")
		return nil
	}
	for _, status := range reply.Sockets {
		cli.printf("%s\n", formatUrSocketStatus(status))
	}
	cli.printf("the daemon stays up while it holds a socket\n")
	return nil
}
