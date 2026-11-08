package dnsservice_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// A block served over HTTP, and an edge following it through NewDnsFeedHttp.
type testHttpFeed struct {
	api    *testApi
	server *httptest.Server
	edge   *testEdge
	loop   *dnsservice.FeedLoop
}

func newTestHttpFeed(t testing.TB) *testHttpFeed {
	t.Helper()
	api := newTestApi(t, nil)
	api.settings.Rrl.ResponsesPerSecond = 1000
	server := httptest.NewServer(api.api.Handler())
	t.Cleanup(server.Close)
	edge := newTestEdge(t, api.settings)
	feed, err := dnsservice.NewDnsFeedHttp(server.URL, apiTestBearers[dnsservice.DnsCallerEdge], server.Client(), api.settings)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := dnsservice.NewFeedLoop(t.Context(), edge.host.ServiceHost(), api.settings, &dnsservice.FeedLoopDeps{
		Feed:              feed,
		Edge:              edge.edge,
		Zsk:               edge.keys.zsk,
		Anchors:           map[string][]*dns.DNSKEY{edgeTestRoot: edge.keys.anchors},
		SnapshotDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loop.Close)
	return &testHttpFeed{api: api, server: server, edge: edge, loop: loop}
}

// An edge follows the block over HTTP end to end: the first poll's rows, then each write the block's
// hold wakes for, signed and served.
func TestFeedLoopFollowsTheBlockOverHttp(t *testing.T) {
	feed := newTestHttpFeed(t)
	awaitServed(t, feed.edge, 1)
	serial := feed.api.write(t, "over-http")
	awaitServed(t, feed.edge, serial)
	if texts := edgeTxt(t, feed.edge, "over-http"); !slices.Equal(texts, []string{"over-http"}) {
		t.Errorf("served %v", texts)
	}
}

// Across a restore over HTTP: the block answers reload, the edge streams the snapshot whole and posts
// its diff back.
func TestFeedLoopReloadsAndPostsItsDiffOverHttp(t *testing.T) {
	feed := newTestHttpFeed(t)
	awaitServed(t, feed.edge, 1)
	dump, err := feed.api.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	lost := feed.api.write(t, "lost")
	awaitServed(t, feed.edge, lost)
	if err := feed.api.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	feed.api.store.LoadDump(edgeTestRoot, dump)
	restoreSerial, err := feed.api.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), lost)
	if err != nil {
		t.Fatal(err)
	}
	awaitServed(t, feed.edge, restoreSerial)
	var diffs []*dnsservice.DnsReloadDiff
	advanceUntil(t, feed.edge.clock, feed.loop, "a diff over HTTP", func() bool {
		diffs, err = feed.api.store.ReloadDiffs(t.Context(), edgeTestRoot)
		return err == nil && len(diffs) != 0
	})
	if len(diffs) != 1 || diffs[0].ReplacedSerial != lost || diffs[0].Serial != restoreSerial {
		t.Errorf("diffs %v", diffs)
	}
}

// The client sends its bearer and only that; a block that refuses it is an error that names no bearer.
func TestDnsFeedHttpSendsItsBearerAndNothingElse(t *testing.T) {
	api := newTestApi(t, nil)
	server := httptest.NewServer(api.api.Handler())
	defer server.Close()
	wrong, err := dnsservice.NewDnsFeedHttp(server.URL, apiTestBearers[dnsservice.DnsCallerCerts], server.Client(), api.settings)
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrong.Journal(t.Context(), edgeTestRoot, 0)
	if !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
		t.Errorf("certs' bearer on the feed: %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), apiTestBearers[dnsservice.DnsCallerCerts]) || strings.Contains(err.Error(), apiTestBearers[dnsservice.DnsCallerEdge])) {
		t.Error("an error names a bearer")
	}
	if _, err := wrong.Snapshot(t.Context(), edgeTestRoot); !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
		t.Errorf("snapshot: %v", err)
	}
	if err := wrong.ReloadDiff(t.Context(), &dnsservice.DnsReloadDiff{Root: edgeTestRoot, ReplacedSerial: 1, Serial: 2}); !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
		t.Errorf("reload-diff: %v", err)
	}
	right, err := dnsservice.NewDnsFeedHttp(server.URL, apiTestBearers[dnsservice.DnsCallerEdge], server.Client(), api.settings)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := right.Journal(t.Context(), edgeTestRoot, 0)
	if err != nil || len(answer.Rows) != 1 {
		t.Errorf("the edge's bearer: %v %v", answer, err)
	}
	for _, baseUrl := range []string{"", "not a url", "/relative"} {
		if _, err := dnsservice.NewDnsFeedHttp(baseUrl, apiTestBearers[dnsservice.DnsCallerEdge], http.DefaultClient, api.settings); !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
			t.Errorf("%q: %v", baseUrl, err)
		}
	}
	if _, err := dnsservice.NewDnsFeedHttp(server.URL, "", http.DefaultClient, api.settings); !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
		t.Errorf("no bearer: %v", err)
	}
}
