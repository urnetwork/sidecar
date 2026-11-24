// ur support (DESIGN-COMPUTE §28.4, §15.1): URnetwork's support conversation and the support log.
//
//	ur support logs [--sent=<id>] [--json]
//	    the support log's bundle as the next message would carry it, or as the one sent with an item did, rendered
//	    whole (§28.7, FB's ur feedback preview), printed only to the terminal
//
// The support log is content-free by construction (support_log.go), and still no agent reads a bundle (§28.7, I-7):
// the daemon builds one only for a control caller with no harness process among its ancestors, and ur prints it on
// /dev/tty, never to stdout, which an agent's shell would read. The daemon's ring lives under <state>/support-log,
// opened when the daemon starts (startUrSupportLog), and every Sidecar the daemon hosts writes through it.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur support calls.
const (
	urMethodSupportLogs = "support.logs"
)

// What support.logs refuses to a caller under a harness: a bundle is the person's to read, never an agent's (§28.7).
var errUrSupportUnderHarness = errors.New("the support log's bundle is shown to a person at a terminal, never under a harness (§28.7)")

func init() {
	registerUrCommand(&urCommand{
		name:    "support",
		usage:   "  ur support logs [--sent=<id>] [--json]",
		summary: "URnetwork's support conversation, and the support log's bundle",
		run:     runUrSupport,
	})
}

// support.logs' params.
type urSupportLogsParams struct {
	// the item whose sent bundle to show, empty for the next message's
	Sent string `json:"sent,omitempty"`
}

// support.logs' reply: the bundle's manifest and its document, which ur renders.
type urSupportLogsReply struct {
	Manifest *sidecar.SupportLogManifest       `json:"manifest"`
	Document *sidecar.SupportLogBundleDocument `json:"document"`
}

// Opens the daemon's ring under <state>/support-log, sets it as every hosted Sidecar's (settings is the one each
// starts with), records the daemon's start and registers support.logs. An ephemeral daemon keeps no ring and writes
// nothing. The answer records the daemon's stop, with why and how long it ran, and closes the ring: the daemon's last
// act.
func startUrSupportLog(daemon *sidecar.Daemon, stateDirectory string, settings *sidecar.SidecarSettings, ephemeral bool,
	autoSpawned bool, log sidecar.Logger) (func(reason sidecar.SupportLogStopReason), error) {
	if ephemeral {
		return func(reason sidecar.SupportLogStopReason) {}, nil
	}
	clock := settings.ClockOrReal()
	supportLog, err := sidecar.OpenSupportLog(&sidecar.SupportLogArgs{
		Directory: sidecar.SupportLogDirectory(stateDirectory),
		Settings:  settings.Support,
		Clock:     clock,
		Log:       log,
	})
	if err != nil {
		// the daemon runs without one: the support log is never a reason to stop work (§28.14)
		log.Warningf("[ur]no support log: %s", err)
		return func(reason sidecar.SupportLogStopReason) {}, nil
	}
	settings.SupportLog = supportLog
	started := clock.Now()
	supportLog.Event(sidecar.SupportLogCodeDaemonStarted, sidecar.SupportLogFieldRelease(sidecar.Version), sidecar.SupportLogFieldAutoSpawned(autoSpawned))
	for _, method := range urSupportMethods(daemon, supportLog) {
		if err := daemon.RegisterMethod(method); err != nil {
			supportLog.Close()
			return nil, err
		}
	}
	return func(reason sidecar.SupportLogStopReason) {
		supportLog.Event(sidecar.SupportLogCodeDaemonStopped, sidecar.SupportLogFieldStopReason(reason), sidecar.SupportLogFieldUptime(clock.Now().Sub(started)))
		supportLog.Close()
	}, nil
}

// Why the daemon stopped, from how Run returned: an error, the context a signal cancels, an auto-spawned daemon's idle
// exit, or a close.
func urSupportStopReason(ctx context.Context, err error, autoSpawned bool) sidecar.SupportLogStopReason {
	switch {
	case err != nil:
		return sidecar.SupportLogStopReasonFailed
	case ctx.Err() != nil:
		return sidecar.SupportLogStopReasonSignal
	case autoSpawned:
		return sidecar.SupportLogStopReasonIdle
	}
	return sidecar.SupportLogStopReasonClosed
}

// Whether the call's process has a harness process of a hosted network's runs among its ancestors. True too where the
// daemon cannot name the caller, the closed reading (record_disclose_ancestor.go).
func urSupportUnderHarness(ctx context.Context, daemon *sidecar.Daemon, call *sidecar.DaemonCall) bool {
	if call.Hello == nil || call.Hello.PeerPid <= 0 {
		return true
	}
	for _, hosted := range daemon.Sidecars() {
		if hosted.Sidecar.HarnessAncestor(ctx, int(call.Hello.PeerPid)) {
			return true
		}
	}
	return false
}

// What this ur says of itself in a bundle's header.
func urSupportLogHost() *sidecar.SupportLogBundleHost {
	return &sidecar.SupportLogBundleHost{Version: sidecar.Version, GatewayVersion: sidecar.Version}
}

// The support methods over the daemon's ring.
func urSupportMethods(daemon *sidecar.Daemon, supportLog *sidecar.SupportLog) []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodSupportLogs,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urSupportLogsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if urSupportUnderHarness(ctx, daemon, call) {
					return nil, errUrSupportUnderHarness
				}
				if params.Sent != "" {
					// the support client keeps each sent bundle 7 days (§28.7), which arrives with the client (M13b)
					return nil, fmt.Errorf("no bundle sent with item %s is kept on this device", params.Sent)
				}
				bundle, err := supportLog.Bundle(&sidecar.SupportLogBundleArgs{Host: urSupportLogHost()})
				if err != nil {
					return nil, err
				}
				return &urSupportLogsReply{Manifest: bundle.Manifest, Document: bundle.Document}, nil
			},
		},
	}
}

func runUrSupport(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case options["logs"] == true:
		jsonOutput, _ := options.Bool("--json")
		params := &urSupportLogsParams{Sent: urOptionString(options, "--sent")}
		// a bundle goes to the person's terminal alone, so nothing is fetched where none is open
		tty, err := cli.openTty()
		if err != nil {
			return fmt.Errorf("%w: %w", errUrNoTty, err)
		}
		defer tty.Close()
		reply := &urSupportLogsReply{}
		if err := cli.callDaemon(ctx, urMethodSupportLogs, params, false, reply); err != nil {
			return err
		}
		if jsonOutput {
			encoder := json.NewEncoder(tty)
			encoder.SetIndent("", "  ")
			return encoder.Encode(reply)
		}
		renderUrSupportLogs(tty, reply)
		return nil
	}
	return errors.New("ur support: no such form")
}

// A bundle as a person reads it: its header, then one line an event, oldest first.
func renderUrSupportLogs(out io.Writer, reply *urSupportLogsReply) {
	document := reply.Document
	if document == nil || document.Header == nil {
		fmt.Fprintln(out, "no bundle")
		return
	}
	header := document.Header
	at := func(seconds int64) string {
		if seconds == 0 {
			return "-"
		}
		return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
	}
	orNone := func(text string) string {
		if text == "" {
			return "-"
		}
		return text
	}
	fmt.Fprintf(out, "support log bundle: %d events, %s to %s, %d bytes compressed, registry %d\n",
		header.Events, at(header.First), at(header.Last), urSupportByteCount(reply.Manifest), header.Registry)
	fmt.Fprintf(out, "ur %s (%s), %s/%s, harness %s, gateway %s\n",
		orNone(header.Version), orNone(header.Channel), header.Os, header.Arch, orNone(header.HarnessVersion), orNone(header.GatewayVersion))
	if 0 < header.Omitted {
		fmt.Fprintf(out, "%d older events left out to fit the bundle's bound\n", header.Omitted)
	}
	fmt.Fprintln(out, "this is everything the bundle holds; it holds no text of yours, and no agent reads it")
	for _, event := range document.Events {
		names := make([]string, 0, len(event.Fields))
		for name := range event.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		fields := make([]string, 0, len(names))
		for _, name := range names {
			fields = append(fields, fmt.Sprintf("%s=%v", name, event.Fields[name]))
		}
		fmt.Fprintf(out, "%s  %-9s %s.%s  %s\n", at(event.T), event.Severity, event.Component, event.Code, strings.Join(fields, " "))
	}
}

// The manifest's byte count, 0 with none.
func urSupportByteCount(manifest *sidecar.SupportLogManifest) int64 {
	if manifest == nil {
		return 0
	}
	return manifest.ByteCount
}
