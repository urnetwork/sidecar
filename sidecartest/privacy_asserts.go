// §22.7's assert block as a registry (TEST-M2-10; R-TEST-3, D-TEST-5, I-18, I-20): one row per clause,
// the gates it must pass at and the tasks that own it. Gn-out's "§22's privacy assertions pass" reads
// Missing at its gate, so a clause that fell between planners shows as missing rather than passing
// unseen. privacy_asserts_test.go holds the rows to the design's own text: a clause §22.7 adds, or one
// it drops, fails there until a row follows it.
//
// A registration ties one test to a row, by its repository, package and name, so the test may live
// anywhere, the root and server included, and the gate tool (server/local/sidecar-gate) runs it by name.
// Registrations are package-level vars in this package's non-test files, so every binary that links
// sidecartest sees all of them, as sidecartest/fault does for its builders. This checks coverage, not
// truth: the owning test still has to fail on its mutant.
//
// Safe for concurrent use.

package sidecartest

import (
	"fmt"
	"slices"
	"sync"
)

// One clause of §22.7's assert block.
type PrivacyAssert struct {
	// A short name for the clause, used to register against it.
	Id string
	// The clause's opening words, verbatim from §22.7, which identify it in the design's text.
	Opening string
	// Where the clause must pass: Mn-out at milestone n's exit review, every gate listed.
	Gates []string
	// The tasks whose tests show the clause.
	Owners []string
}

// The test that shows a clause, as the gate tool runs it: go test -run '^Name$' Package in Repo.
type PrivacyAssertTest struct {
	// sidecar or server.
	Repo string
	// The package's import path.
	Package string
	// The top-level test function.
	Name string
	// Build tags the test needs, comma-separated as go test's -tags takes them.
	Tags string
}

// The package and test, as a gate report names it.
func (self *PrivacyAssertTest) String() string {
	name := self.Package + "." + self.Name
	if self.Tags != "" {
		name += " (-tags " + self.Tags + ")"
	}
	return name
}

// §22.7's assert block, clause by clause, in the design's order.
func privacyAssertRows() []*PrivacyAssert {
	return []*PrivacyAssert{
		{
			Id:      "stored-commits",
			Opening: "every stored commit but an external commit parses as PrivateMessage",
			Gates:   []string{"M2-out"},
			Owners:  []string{"TEST-M2-09"},
		},
		{
			Id:      "store-writes",
			Opening: "evs and gkm touch no Postgres and write Redis only in",
			Gates:   []string{"M2-out"},
			Owners:  []string{"TEST-M2-09"},
		},
		{
			Id:      "gate-view",
			Opening: "a gate's view holds no run id, agent id, recipient or preview",
			Gates:   []string{"M3-out"},
			Owners:  []string{"MCP-M3-03", "ACL-M4-04"},
		},
		{
			Id:      "wake-payloads",
			Opening: "wake payloads carry only a topic class and version",
			Gates:   []string{"M8-out"},
			Owners:  []string{"SDK-M8-10"},
		},
		{
			Id:      "private-names",
			Opening: "a private name gets A or NODATA on the device for every qtype",
			Gates:   []string{"M4-out"},
			Owners:  []string{"BRIDGE-M4-14"},
		},
		{
			Id:      "synthesized-dmarc",
			Opening: "synthesized DMARC records carry no ruf, no fo and no rua into <root>",
			Gates:   []string{"M5-out"},
			Owners:  []string{"DNS-M5-11"},
		},
		{
			Id:      "unsealed-peer",
			Opening: "a bridge flow from an unsealed peer is denied",
			Gates:   []string{"M4-out"},
			Owners:  []string{"BRIDGE-M4-22", "BRIDGE-M8-01"},
		},
		{
			Id:      "public-exits",
			Opening: "after C6a, public exits refuse 100.64/10 and RFC 1918 destinations",
			Gates:   []string{"M4-out"},
			Owners:  []string{"BRIDGE-M4-22", "BRIDGE-M4-03"},
		},
		{
			Id:      "friends-and-family",
			Opening: "a FriendsAndFamily flow reaches only its share's targets",
			Gates:   []string{"M6-out"},
			Owners:  []string{"BRIDGE-M6-08"},
		},
		{
			Id:      "flow-pins",
			Opening: "a TCP flow idle 300-600 s keeps its link across a withdraw",
			Gates:   []string{"M4-out"},
			Owners:  []string{"BRIDGE-M4-22"},
		},
		{
			Id:      "certificates",
			Opening: "no certificate whose key URnetwork holds names *.<root> or *.<net>.<root>",
			Gates:   []string{"M5-out", "M6-out"},
			Owners:  []string{"TLS-M5-25", "TLS-M6-03"},
		},
		{
			Id:      "mx-scope",
			Opening: "SNI mx.<scope>.<net>.<root> reaches only that scope's receivers",
			Gates:   []string{"M8-out"},
			Owners:  []string{"MAIL-M8-09"},
		},
		{
			Id:      "strict-mode",
			Opening: "in strict mode receivers refuse spliced sessions for URnetwork-zone MX hosts",
			Gates:   []string{"M7-out"},
			Owners:  []string{"MAIL-M7-27"},
		},
		{
			Id:      "splices",
			Opening: "tlsedge and mxedge splices are byte-identical",
			Gates:   []string{"M7-out"},
			Owners:  []string{"TLS-M5-25", "MAIL-M7-27"},
		},
		{
			Id:      "mail-labels",
			Opening: "mail is \"validated\" only under REQUIRETLS",
			Gates:   []string{"M7-out"},
			Owners:  []string{"MAIL-M7-10", "MAIL-M7-27"},
		},
		{
			Id:      "mta-sts-claims",
			Opening: "no UI or API claims MTA-STS protection for mail to a burner domain",
			Gates:   []string{"M7-out"},
			Owners:  []string{"MAIL-M7-10"},
		},
		{
			Id:      "query-canaries",
			Opening: "no query canary in CC1, CC3 or CC4",
			Gates:   []string{"M10-out"},
			Owners:  []string{"SEARCH-M10-39"},
		},
		{
			Id:      "directory-plaintext",
			Opening: "the directory's plaintext, decrypted with a member's keys, holds no canary",
			Gates:   []string{"M6-out"},
			Owners:  []string{"RECORD-M6-26"},
		},
		{
			Id:      "shards-dbreach",
			Opening: "every shard, bucket and all, is sealed at a Padmé size",
			Gates:   []string{"M10-out"},
			Owners:  []string{"TEST-M10-03"},
		},
		{
			Id:      "request-traces",
			Opening: "two different queries from equal sync states",
			Gates:   []string{"M10-out"},
			Owners:  []string{"TEST-M10-02"},
		},
	}
}

// The rows and what is registered against them.
type PrivacyAsserts struct {
	rows []*PrivacyAssert

	stateLock sync.Mutex
	// assert id to its tests, in registration order
	assertIdTests map[string][]*PrivacyAssertTest
}

// A registry of §22.7's rows with nothing registered.
func NewPrivacyAsserts() *PrivacyAsserts {
	return &PrivacyAsserts{
		rows:          privacyAssertRows(),
		assertIdTests: map[string][]*PrivacyAssertTest{},
	}
}

var defaultPrivacyAsserts = sync.OnceValue(NewPrivacyAsserts)

// The registry every registration in this package goes to, which a gate sweep reads.
func DefaultPrivacyAsserts() *PrivacyAsserts {
	return defaultPrivacyAsserts()
}

// Every row, in the design's order.
func (self *PrivacyAsserts) Rows() []*PrivacyAssert {
	return slices.Clone(self.rows)
}

// The row with id, or nil.
func (self *PrivacyAsserts) Row(assertId string) *PrivacyAssert {
	for _, row := range self.rows {
		if row.Id == assertId {
			return row
		}
	}
	return nil
}

// Ties test to a row. A row this registry does not hold, a test with no package or name, and the same
// test registered twice to one row each fail.
func (self *PrivacyAsserts) Register(assertId string, test *PrivacyAssertTest) error {
	if test == nil || test.Package == "" || test.Name == "" || test.Repo == "" {
		return fmt.Errorf("register %s: a test needs its repo, package and name", assertId)
	}
	if self.Row(assertId) == nil {
		return fmt.Errorf("register %s: §22.7's assert block has no row %q", test, assertId)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, other := range self.assertIdTests[assertId] {
		if *other == *test {
			return fmt.Errorf("register %s: %s is registered to it already", assertId, test)
		}
	}
	registered := *test
	self.assertIdTests[assertId] = append(self.assertIdTests[assertId], &registered)
	return nil
}

// The tests registered to a row, in registration order.
func (self *PrivacyAsserts) Tests(assertId string) []*PrivacyAssertTest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tests := []*PrivacyAssertTest{}
	for _, test := range self.assertIdTests[assertId] {
		copied := *test
		tests = append(tests, &copied)
	}
	return tests
}

// The rows that must pass at gate and that no test is registered to, in the design's order. Missing is
// never pass: a gate reports each of these missing.
func (self *PrivacyAsserts) Missing(gate string) []*PrivacyAssert {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	missing := []*PrivacyAssert{}
	for _, row := range self.rows {
		if slices.Contains(row.Gates, gate) && len(self.assertIdTests[row.Id]) == 0 {
			missing = append(missing, row)
		}
	}
	return missing
}

// Ties test to a row of the default registry. It runs from a package-level var, so a row this registry
// does not hold panics, and a test binary that cannot link its registrations does not pass:
//
//	var _ = RegisterPrivacyAssert("store-writes", &PrivacyAssertTest{Repo: "server", Package: ..., Name: ...})
func RegisterPrivacyAssert(assertId string, test *PrivacyAssertTest) *PrivacyAssertTest {
	if err := DefaultPrivacyAsserts().Register(assertId, test); err != nil {
		panic(err)
	}
	return test
}
