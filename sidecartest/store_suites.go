// D-TEST-2's rule as a list: each fake here that stands for a store server implements, and the suite
// that holds the fake and the store to one contract. T2 runs each suite on its fake, and server's T3 runs
// it on the real store (sidecart3.RunSuites), so an engine built against the fake keeps holding on what
// production runs.
//
// What counts as a store fake: a fake of ServiceHost.Blobs, Redis or Quota, every Fake<Name>Store, and
// FakeApi as the config log's sequencer. TestEveryStoreFakeHasASuite reads this package's source and
// fails a Fake<Name>Store added without a suite here, so a store fake cannot ship with nothing holding it
// to the real store.

package sidecartest

import (
	"slices"
)

// One conformance suite and the fakes it holds to their store's contract.
type StoreSuite struct {
	// The suite's entry, as a caller names it: "blobsuite.Run", "RunSocketStoreSuite".
	Name string
	// The fakes it runs on at T2, by type name.
	Fakes []string
	// What implements the store on server, for a reader: the T3 side runs the suite on it.
	Store string
}

// Every store suite, in the order a T3 run reports them.
func StoreSuites() []*StoreSuite {
	return []*StoreSuite{
		{Name: "blobsuite.Run", Fakes: []string{"FakeBlobs"}, Store: "server.FileClusters"},
		{Name: "redissuite.Run", Fakes: []string{"FakeRedis"}, Store: "sidecarhost.Redis"},
		{Name: "quotasuite.Run", Fakes: []string{"FakeQuota"}, Store: "ServiceHost.Quota on server's quota host"},
		{Name: "RunPushStoreSuite", Fakes: []string{"FakeRedis"}, Store: "model.SidecarPushRedis"},
		{Name: "RunSocketStoreSuite", Fakes: []string{"FakeSocketStore"}, Store: "model.SocketStore"},
		{Name: "RunDnsStoreSuite", Fakes: []string{"FakeDnsStore"}, Store: "dnshost.Store"},
		{Name: "RunDnsRestoreStoreSuite", Fakes: []string{"FakeDnsRestoreStore"}, Store: "dnshost.RestoreStore"},
		{Name: "RunCertsStoreSuite", Fakes: []string{"FakeCertsStore"}, Store: "model.NewCertsStore"},
		{Name: "RunTlsEdgeStoreSuite", Fakes: []string{"FakeTlsEdgeStore"}, Store: "model.NewTlsEdgeStore"},
		{Name: "RunMxEdgeStoreSuite", Fakes: []string{"FakeMxEdgeStore"}, Store: "model.MxEdgeStore"},
		{Name: "RunSmtpEdgeStoreSuite", Fakes: []string{"FakeSmtpEdgeStore"}, Store: "server's SmtpEdgeStore"},
		{Name: "RunConfigLogStoreSuite", Fakes: []string{"FakeApi"}, Store: "model's config log sequencer"},
	}
}

// Every fake that stands for a store server implements: what D-TEST-2 asks a suite of.
func StoreFakes() []string {
	return []string{
		"FakeBlobs",
		"FakeRedis",
		"FakeQuota",
		"FakeSocketStore",
		"FakeDnsStore",
		"FakeDnsRestoreStore",
		"FakeCertsStore",
		"FakeTlsEdgeStore",
		"FakeMxEdgeStore",
		"FakeSmtpEdgeStore",
		"FakeApi",
	}
}

// What breaks D-TEST-2 in suites against fakes: a store fake no suite runs on, and a suite naming a fake
// that is not a store's or naming none. Empty when every store fake has its suite.
func StoreSuiteProblems(suites []*StoreSuite, fakes []string) []string {
	problems := []string{}
	for _, fake := range fakes {
		suited := slices.ContainsFunc(suites, func(suite *StoreSuite) bool {
			return slices.Contains(suite.Fakes, fake)
		})
		if !suited {
			problems = append(problems, fake+" stands for a store and no suite holds it to the real one (D-TEST-2)")
		}
	}
	for _, suite := range suites {
		if len(suite.Fakes) == 0 {
			problems = append(problems, suite.Name+" names no fake it runs on at T2")
		}
		for _, fake := range suite.Fakes {
			if !slices.Contains(fakes, fake) {
				problems = append(problems, suite.Name+" names "+fake+", which stands for no store")
			}
		}
	}
	return problems
}
