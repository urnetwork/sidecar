// ur bridge public-tls (§13.10; TLS-M5-23): publishes a local port at a host name of the network over TLS that ends on
// this device. The publish lives in the daemon, as a socket does, so the command returns once the daemon serves it.
//
//	ur bridge public-tls <host>:[<local ip>:]<local port>
//	                                          publishes the target, 127.0.0.1 unless a local ip is given, on port 443
//	                                          unless --port names 8443, 8883 or 5671; --audience members (the default),
//	                                          members-device, link or public; --tcp for a raw stream, with --audience
//	                                          public or link; --alpn=<id>[,<id>] the ALPN ids served; --expires how long
//	                                          the grant lasts; --proxy-protocol to have the target sent PROXY v2
//	ur bridge public-tls --stop <host>        ends the publish and revokes the grant its approval activated
//	ur bridge public-tls --status             lists this device's publishes, its certificates and its CT watch
//
// Without an active approved grant the command prints the approval prompt and waits, asking the daemon again until the
// decision lands or the wait runs out (§16.6), as expose and forward do. On a publish it prints the URL, for a raw
// link the client-certificate file's path, the expiry, the audience and "passthrough: key on this device". --stop and
// --status are a reading: §13.10 names no spelling for ending or listing a publish, and tls_unpublish is --stop's MCP
// twin. --stop revokes the subject's own grant, which needs no confirmation (§8.8), as ur bridge close's does.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// ur bridge public-tls's usage lines, which ur bridge's usage carries.
var urBridgePublicTlsUsage = []string{
	"  ur bridge public-tls <publish> [--port=<port>] [--expires=<duration>] [--audience=<audience>] [--alpn=<ids>] [--tcp] [--proxy-protocol] [--network=<name>]",
	"  ur bridge public-tls --stop <host> [--port=<port>] [--network=<name>]",
	"  ur bridge public-tls --status [--network=<name>]",
}

// A command line ur bridge public-tls cannot take.
var errUrBridgePublicTlsUsage = errors.New("ur bridge public-tls <host>:[<local ip>:]<local port>: see ur bridge --help")

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urTlsMethods)
}

// The root's tls methods, over a target that hosts Sidecars.
func urTlsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonTlsMethods()
}

// --port: absent is 0, which the daemon reads as 443.
func parseUrBridgePublicTlsPort(text string) (int, error) {
	if text == "" {
		return 0, nil
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return 0, &urExitError{code: urExitUsage, err: errUrBridgePublicTlsUsage}
	}
	return int(port), nil
}

// <host>:[<local ip>:]<local port> and the flags as the daemon's params. The daemon checks the host's grammar, the
// port's list and the audience: here only the shape is read.
func parseUrBridgePublicTls(publish string, port string, expires string, audience string, alpn string, tcp bool, proxyProtocol bool) (*sidecar.DaemonTlsPublishParams, error) {
	usage := &urExitError{code: urExitUsage, err: errUrBridgePublicTlsUsage}
	host, target, ok := strings.Cut(publish, ":")
	if !ok || host == "" || target == "" {
		return nil, usage
	}
	// the local port is the last component, and a number
	_, localPort, found := cutLast(target, ":")
	if !found {
		localPort = target
	}
	if number, err := strconv.ParseUint(localPort, 10, 16); err != nil || number == 0 {
		return nil, usage
	}
	params := &sidecar.DaemonTlsPublishParams{
		Host:          host,
		Target:        target,
		Audience:      audience,
		Tcp:           tcp,
		ProxyProtocol: proxyProtocol,
	}
	var err error
	if params.Port, err = parseUrBridgePublicTlsPort(port); err != nil {
		return nil, err
	}
	if expires != "" {
		duration, err := time.ParseDuration(expires)
		if err != nil || duration <= 0 {
			return nil, usage
		}
		params.ExpiresMs = duration.Milliseconds()
	}
	if alpn != "" {
		for _, id := range strings.Split(alpn, ",") {
			if id == "" {
				return nil, usage
			}
			params.Alpn = append(params.Alpn, id)
		}
	}
	return params, nil
}

// text around its last sep.
func cutLast(text string, sep string) (string, string, bool) {
	index := strings.LastIndex(text, sep)
	if index < 0 {
		return text, "", false
	}
	return text[:index], text[index+len(sep):], true
}

func runUrBridgePublicTls(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	port, _ := options.String("--port")
	if status, _ := options.Bool("--status"); status {
		return runUrBridgePublicTlsStatus(ctx, cli, network)
	}
	if stop, _ := options.Bool("--stop"); stop {
		host, _ := options.String("<host>")
		number, err := parseUrBridgePublicTlsPort(port)
		if err != nil {
			return err
		}
		return runUrBridgePublicTlsStop(ctx, cli, &sidecar.DaemonTlsUnpublishParams{Network: network, Host: host, Port: number})
	}
	publish, _ := options.String("<publish>")
	expires, _ := options.String("--expires")
	audience, _ := options.String("--audience")
	alpn, _ := options.String("--alpn")
	tcp, _ := options.Bool("--tcp")
	proxyProtocol, _ := options.Bool("--proxy-protocol")
	params, err := parseUrBridgePublicTls(publish, port, expires, audience, alpn, tcp, proxyProtocol)
	if err != nil {
		return err
	}
	params.Network = network
	return runUrBridgePublicTlsPublish(ctx, cli, params)
}

// Calls tls.publish, and while it answers an approval to wait on, prints the prompt once and asks again each
// ApprovalPollInterval until the decision lands or ApprovalWaitTimeout has passed (§16.6). The gate answers a
// decided use from its record, so asking again files nothing twice.
func callUrBridgePublicTls(ctx context.Context, cli *urCli, params *sidecar.DaemonTlsPublishParams) (*sidecar.DaemonTlsPublishStatus, error) {
	settings := urBridgeCommandSettings
	waited := time.Duration(0)
	prompted := false
	for {
		reply := &sidecar.DaemonTlsPublishReply{}
		if err := cli.callDaemon(ctx, sidecar.DaemonMethodTlsPublish, params, false, reply); err != nil {
			return nil, err
		}
		if reply.ApprovalId == nil {
			if reply.Publish == nil {
				return nil, errors.New("the daemon answered no publish")
			}
			return reply.Publish, nil
		}
		if !prompted {
			cli.printf("approval pending: run ur approve %s on an approval-capable device; waiting\n", reply.ApprovalId)
			prompted = true
		}
		if settings.ApprovalWaitTimeout <= waited {
			return nil, &urExitError{code: urExitFailed, err: fmt.Errorf("approval %s is still pending: run this again once it is decided", reply.ApprovalId)}
		}
		if err := urBridgeWait(ctx, settings.ApprovalPollInterval); err != nil {
			return nil, err
		}
		waited += max(settings.ApprovalPollInterval, time.Millisecond)
	}
}

// §13.10 step 4's lines for one publish.
func printUrBridgePublicTls(cli *urCli, publish *sidecar.DaemonTlsPublishStatus) {
	cli.printf("published  %s\n", publish.Url)
	if publish.ClientCertificateFile != "" {
		cli.printf("client certificate and key  %s\n", publish.ClientCertificateFile)
	}
	if 0 < publish.ExpiresMs {
		cli.printf("expires    %s\n", time.UnixMilli(publish.ExpiresMs).UTC().Format(time.RFC3339))
	} else {
		cli.printf("expires    with its standing grant\n")
	}
	cli.printf("audience   %s\n", publish.Audience)
	cli.printf("%s\n", publish.Passthrough)
	if !publish.Serving {
		cli.printf("warning: nothing answers on the local port yet; visitors are refused until it does\n")
	}
}

func runUrBridgePublicTlsPublish(ctx context.Context, cli *urCli, params *sidecar.DaemonTlsPublishParams) error {
	publish, err := callUrBridgePublicTls(ctx, cli, params)
	if err != nil {
		return err
	}
	printUrBridgePublicTls(cli, publish)
	cli.printf("ur bridge public-tls --stop %s ends it\n", params.Host)
	return nil
}

func runUrBridgePublicTlsStop(ctx context.Context, cli *urCli, params *sidecar.DaemonTlsUnpublishParams) error {
	if params.Host == "" {
		return &urExitError{code: urExitUsage, err: errUrBridgePublicTlsUsage}
	}
	reply := &sidecar.DaemonTlsUnpublishReply{}
	// the subject's own filing, which needs no confirmation (§8.8), as ur bridge close's is
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodTlsUnpublish, params, false, reply); err != nil {
		return err
	}
	if !reply.Unpublished {
		return &urExitError{code: urExitFailed, err: fmt.Errorf("this device does not publish %s", params.Host)}
	}
	cli.printf("unpublished  %s; its grant is revoked\n", params.Host)
	return nil
}

func runUrBridgePublicTlsStatus(ctx context.Context, cli *urCli, network string) error {
	reply := &sidecar.DaemonTlsStatusReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodTlsStatus, &sidecar.DaemonTlsStatusParams{Network: network}, false, reply); err != nil {
		return err
	}
	if len(reply.Publishes) == 0 {
		cli.printf("no publishes\n")
	}
	for _, publish := range reply.Publishes {
		printUrBridgePublicTls(cli, publish)
	}
	for _, certificate := range reply.Certificates {
		name := certificate.CustomHost
		if name == "" {
			name = "network"
		}
		presented := ""
		if certificate.Presented {
			presented = ", presented"
		}
		cli.printf("certificate  %s  %s  %s until %s%s\n", certificate.CertId, name, certificate.State,
			time.UnixMilli(certificate.NotAfterMs).UTC().Format(time.RFC3339), presented)
	}
	if reply.CtWatchDegraded {
		cli.printf("CT watch degraded\n")
	}
	return nil
}
