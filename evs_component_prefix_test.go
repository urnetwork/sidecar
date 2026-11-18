//go:build !sidecar_http && !ios_extension

// QD-1032's switch at the evs component (acl_prefix_dark_test.go has the client's): NewEvsComponent installs the dark
// defaults where no composition installed a judge, and keeps the judge a composition installed.

package sidecar

import (
	"testing"
)

// NewEvsComponent installs the dark defaults on a client no composition gave a judge, and keeps the judge a composition
// installed, its settings with it.
func TestEvsComponentKeepsTheCompositionsPrefixSettings(t *testing.T) {
	world := newEvsTestWorld(t)
	bare := world.reader(t, evsTestId("bare reader"))
	if bare.client.installedPrefixJudge() != nil || bare.client.PrefixRulesEnabled() {
		t.Fatal("a client no composition enabled holds a judge, or runs the rules")
	}
	NewEvsComponent(bare.client)
	if bare.client.installedPrefixJudge() == nil || bare.client.PrefixRulesEnabled() {
		t.Fatal("the component's defaults")
	}
	composed := world.reader(t, evsTestId("composed reader"))
	composed.client.EnablePrefixRules(&EvsPrefixRulesArgs{Settings: testAclPrefixSettingsOn(), Repair: true})
	installed := composed.client.installedPrefixJudge()
	NewEvsComponent(composed.client)
	if composed.client.installedPrefixJudge() != installed || !composed.client.PrefixRulesEnabled() || !installed.args.Repair {
		t.Fatal("the component replaced the composition's judge")
	}
}
