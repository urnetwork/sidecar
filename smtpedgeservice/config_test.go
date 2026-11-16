// smtpedge.yml as the edge block reads it (SMTP-M9-20): HELO names under helo_domain, the block's mark for a
// sending address that names none, and the engine's own refusals kept.

package smtpedgeservice_test

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/smtpedgeservice"
)

const testSmtpEdgeConfig = `
root: root.example
report_host: rpt.report.example
helo_domain: out.report.example
sending_addresses:
  - {address: 192.0.2.10, helo: o1.out.report.example}
  - {address: 192.0.2.11, helo: o2.out.report.example, fwmark: 7}
router_interfaces: [203.0.113.25]
router_lan: 10.0.0.25:2525
loop_allowlist: [loop.example]
`

func TestSmtpEdgeConfigLoadsTheBlocksFile(t *testing.T) {
	config, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(testSmtpEdgeConfig), 3)
	if err != nil {
		t.Fatal(err)
	}
	addresses := config.Settings.SendingAddresses
	if len(addresses) != 2 || addresses[0].Fwmark != 3 || addresses[1].Fwmark != 7 {
		t.Fatalf("addresses %+v", addresses)
	}
	if len(config.Settings.RouterInterfaces) != 1 || config.Settings.RouterLanAddress.Port() != 2525 || config.Settings.LoopAllowlist[0] != "loop.example" {
		t.Fatalf("settings %+v", config.Settings)
	}
}

// A HELO name outside helo_domain is refused, as is a file with none, and the engine's refusals still hold.
func TestSmtpEdgeConfigRefusesAHeloOutsideItsDomain(t *testing.T) {
	for _, data := range []string{
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 192.0.2.10, helo: o1.out.other.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 192.0.2.10, helo: out.report.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nsending_addresses: [{address: 192.0.2.10, helo: o1.out.report.example}]\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nrouter_lan: 10.0.0.25:0\n",
		"root: root.example\nreport_host: rpt.report.example\nhelo_domain: out.report.example\nsending_addresses: [{address: 2001:db8::1, helo: o1.out.report.example}]\n",
	} {
		if _, err := smtpedgeservice.LoadSmtpEdgeConfig([]byte(data), 0); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("%q: %v", data, err)
		}
	}
}
