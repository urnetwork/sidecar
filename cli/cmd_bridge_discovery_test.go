// ur bridge devices, share, unshare and discovery parse as §17.11's rows write them, and print what the daemon lists.

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func TestUrBridgeDiscoveryCommandsParse(t *testing.T) {
	parse := func(args ...string) docopt.Opts {
		t.Helper()
		command := urCommands[args[0]]
		parser := &docopt.Parser{HelpHandler: docopt.NoHelpHandler, SkipHelpFlags: true}
		options, err := parser.ParseArgs("Usage:\n"+command.usage+"\n", args, "")
		if err != nil {
			t.Fatalf("%v does not parse: %v", args, err)
		}
		return options
	}
	if options := parse("bridge", "devices", "--json", "--network=acme"); options["devices"] != true || options["--json"] != true {
		t.Errorf("devices: %v", options)
	}
	if options := parse("bridge", "share", "synthetic-phone"); options["share"] != true || options["<device>"] != "synthetic-phone" {
		t.Errorf("share: %v", options)
	}
	if options := parse("bridge", "unshare", "synthetic-phone"); options["unshare"] != true {
		t.Errorf("unshare: %v", options)
	}
	for _, args := range [][]string{{"off"}, {"on"}, {"hide", "445"}, {"unhide", "51820/udp"}, {"proxy", "off"}} {
		options := parse(append([]string{"bridge", "discovery"}, args...)...)
		if options["discovery"] != true || options["<setting>"] != args[0] {
			t.Errorf("discovery %v: %v", args, options)
		}
	}
	// the existing forms still parse
	if options := parse("bridge", "expose", ":5432"); options["expose"] != true {
		t.Errorf("expose: %v", options)
	}
}

// The listing names each device's share, why a service is withheld, what is published and what each host gives.
func TestUrBridgeDevicesPrints(t *testing.T) {
	stdout := &bytes.Buffer{}
	cli := &urCli{stdout: stdout}
	printUrBridgeDevices(cli, &sidecar.DaemonBridgeDevicesReply{
		Notice: sidecar.BridgeDiscoveryOwnNotice,
		Own:    true,
		Lan: []*sidecar.DaemonBridgeLanDevice{{
			HostLabel: "synthetic-phone", Address: "192.168.80.5", Share: "moved",
			Services: []*sidecar.DaemonBridgeInstance{{Name: "Synthetic Phone", Service: "_remotepairing._tcp", Port: 49152, Withheld: "share moved"}},
		}},
		Published: []*sidecar.DaemonBridgeInstance{{Name: "Host Files", Service: "_smb._tcp", Address: "100.80.1.2", Port: 445}},
		Remote:    []*sidecar.DaemonBridgeRemoteHost{{Name: "host-b", DroppedCount: 2}},
	})
	text := stdout.String()
	for _, want := range []string{"ur bridge discovery off", "synthetic-phone 192.168.80.5, moved", "share it again", "published  Host Files _smb._tcp 100.80.1.2:445", "2 instances dropped"} {
		if !strings.Contains(text, want) {
			t.Errorf("the listing lacks %q:\n%s", want, text)
		}
	}
}
