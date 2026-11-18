// QD-1032's switch over the authorization log (acl_prefix_settings.go's Enabled; acl_statement.go's
// configAclPrefixRulesDark): the launch configuration keeps the client-checked prefix write rules dark, and a log
// running it refuses every RepoPrefixRules at its position as a type whose rule this release does not carry, the
// statement's number kept, the refusal the same for every signer and body, and the log going on; a new device starting
// at a base whose tail_verdicts gave a set effect, as a log running the rules would, folds no set either. The rules' own
// tests run the log with the switch on (config_state_test.go's testConfigLogSettings).
//
// On every leg: nothing here reads evs.

package sidecar

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The prefix rules' settings with the rules on: what their own tests run under, so the code does not rot while launch
// keeps it dark (QD-1032).
func testAclPrefixSettingsOn() *AclPrefixSettings {
	settings := DefaultAclPrefixSettings()
	settings.Enabled = true
	return settings
}

// The log's settings at launch: the defaults, logged nowhere.
func testConfigLaunchLogSettings() *ConfigLogSettings {
	settings := DefaultConfigLogSettings()
	settings.Log = NewNoopLogger()
	return settings
}

// The launch configuration: the defaults keep the rules dark, in the prefix settings themselves, in a log's settings,
// and in a state whose log names none.
func TestAclPrefixRulesAreDarkInTheLaunchSettings(t *testing.T) {
	if DefaultAclPrefixSettings().Enabled {
		t.Error("DefaultAclPrefixSettings runs the prefix rules")
	}
	logSettings := DefaultConfigLogSettings()
	if logSettings.AclPrefix == nil || logSettings.AclPrefix.Enabled {
		t.Errorf("DefaultConfigLogSettings' prefix settings: %+v", logSettings.AclPrefix)
	}
	if (&ConfigState{}).aclPrefixSettings().Enabled {
		t.Error("a state whose log names no settings runs the prefix rules")
	}
	if !testAclPrefixSettingsOn().Enabled {
		t.Error("the rules' tests run them dark")
	}
}

// A log at the launch settings refuses a RepoPrefixRules at its position, ErrConfigRuleMissing naming the deferral, for
// a repo admin and a stranger alike; the repo's rows gain no set; the log goes on, the next statement taking effect at
// the next position; and a reader restored from what it retains, and a rows-only gate, reach the same verdict and rows.
// The same statement in a log running the rules takes effect.
func TestConfigLogRefusesRepoPrefixRulesAtLaunch(t *testing.T) {
	launch := testConfigLaunchLogSettings()
	net := newTestConfigNetWith(t, "launch network", launch)
	stranger := net.admitMemberDevice("launch stranger")
	repoId := net.createGeneralRepo("launch repo")
	for _, signer := range []testConfigDevice{net.owner, stranger} {
		verdict := net.post(signer, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, net.prefixRules(repoId))
		if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRuleMissing) || !errors.Is(verdict.Refusal, ErrConfigRefused) ||
			!strings.Contains(verdict.Refusal.Error(), "QD-1032") {
			t.Fatalf("a set at launch: %v", verdict.Refusal)
		}
		if verdict.Pin.GetVersion() != net.n || verdict.SignedType != bridge.SignedType_SIGNED_REPO_PREFIX_RULES {
			t.Fatalf("the refusal at %d, the tip %d, of %s", verdict.Pin.GetVersion(), net.n, verdict.SignedType)
		}
	}
	refusedAt := net.n
	if rows := aclTestPrefixRows(aclTestLogRows(t, net.log), repoId); len(rows) != 0 {
		t.Fatalf("the rows hold %v", rows)
	}
	next := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
		Header: net.header(), RepoId: repoId.Bytes(), SidecarId: stranger.sidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
	})
	if next.Pin.GetVersion() != refusedAt+1 {
		t.Fatalf("the next statement at %d, after a refusal at %d", next.Pin.GetVersion(), refusedAt)
	}

	retained := net.log.Retained()
	restored, err := RestoreConfigLog(launch, retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := RestoreConfigLogRowsOnly(launch, retained, net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, reader := range []*ConfigLog{restored, gate} {
		if kept := reader.keptEntry(refusedAt); kept == nil || kept.verdict.Accepted() || !errors.Is(kept.verdict.Refusal, ErrConfigRuleMissing) {
			t.Errorf("reader %d's verdict at %d: %+v", i, refusedAt, kept)
		}
		if rows := aclTestPrefixRows(aclTestLogRows(t, reader), repoId); len(rows) != 0 {
			t.Errorf("reader %d's rows hold %v", i, rows)
		}
	}

	ruled := newTestConfigNet(t)
	ruledRepoId := ruled.createGeneralRepo("launch repo")
	if verdict := ruled.post(ruled.owner, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, ruled.prefixRules(ruledRepoId)); !verdict.Accepted() {
		t.Fatalf("a set in a log running the rules: %v", verdict.Refusal)
	}
}

// A base whose tail_verdicts carry a set's effect, as a writer running the rules folds it: a device that starts at that
// base at the launch settings re-applies the tail by its bits, and the set's effect ends there, so its rows gain no set,
// while the long-running reader that ran the rules holds it.
func TestConfigLogFoldsNoSetFromABasesTailAtLaunch(t *testing.T) {
	net := newTestConfigNet(t)
	repoId := net.createGeneralRepo("tail repo")
	beforeSets := net.n
	at := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, net.prefixRules(repoId)).Pin.GetVersion()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after the set"))
	net.fold(net.owner, beforeSets, net.log.State().Base().GetConfigVersion()+1)
	if rows := aclTestPrefixRows(aclTestLogRows(t, net.log), repoId); len(rows) != 1 || rows[0].GetAt() != at {
		t.Fatalf("the reader running the rules holds %v", rows)
	}

	launch := testConfigLaunchLogSettings()
	retained := net.log.Retained()
	device, err := RestoreConfigLog(launch, retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := RestoreConfigLogRowsOnly(launch, retained, net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, reader := range []*ConfigLog{device, gate} {
		if rows := aclTestPrefixRows(aclTestLogRows(t, reader), repoId); len(rows) != 0 {
			t.Errorf("reader %d at the launch settings holds %v", i, rows)
		}
	}
}
