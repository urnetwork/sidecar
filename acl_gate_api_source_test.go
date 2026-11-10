//go:build !sidecar_http && !ios_extension

// AclGateApiSource against a fake api over a test network's log: a cold start and a later run read page by page, a
// cache over the source reaches the log's pin, the bearer rides every request and a source with none sends nothing,
// rows are held to their hash, and an answer past its bound, a page that says more and moves nothing, or an entry api
// forged is refused, the cache's state kept.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fake api serving one test network's published log on the two gate routes, a page of pageCount entries at a time,
// to requests carrying bearer.
type aclGateApiTestServer struct {
	t         *testing.T
	stateLock sync.Mutex
	net       *testConfigNet
	entries   [][]byte
	pageCount int
	bearer    string
	paths     []string
	// rewrites a projection page before it is sent
	rewrite func(page *sidecarConfigProjectionReply)
	// a body sent in place of each answer
	body []byte
}

func newAclGateApiTestServer(t *testing.T, net *testConfigNet) (*aclGateApiTestServer, *httptest.Server) {
	self := &aclGateApiTestServer{t: t, net: net, entries: net.entries, pageCount: 2, bearer: "synthetic-gate-bearer"}
	server := httptest.NewServer(self)
	t.Cleanup(server.Close)
	return self, server
}

// Publishes the network's log as it stands.
func (self *aclGateApiTestServer) publish() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = self.net.entries
}

// The paths requested, in order.
func (self *aclGateApiTestServer) requested() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.paths...)
}

func (self *aclGateApiTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.paths = append(self.paths, r.URL.Path)
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+self.bearer {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if self.body != nil {
		w.Write(self.body)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, AclGateApiProjectionPath):
		networkId, err := ParseId(strings.TrimPrefix(r.URL.Path, AclGateApiProjectionPath))
		after, afterErr := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if err != nil || afterErr != nil || networkId != self.net.networkId {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		page := &sidecarConfigProjectionReply{Entries: [][]byte{}, Rows: [][]byte{}}
		if after == 0 {
			page.Genesis = self.net.signedGenesis
		}
		from := min(after, uint64(len(self.entries)))
		through := min(from+uint64(self.pageCount), uint64(len(self.entries)))
		page.More = through < uint64(len(self.entries))
		for _, entryBytes := range self.entries[from:through] {
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				self.t.Error(err)
				return
			}
			chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
			if err != nil {
				self.t.Error(err)
				return
			}
			page.Entries = append(page.Entries, entryBytes)
			page.Tip = &sidecarConfigPinReply{N: entry.GetN(), Chain: chain[:]}
		}
		if self.rewrite != nil {
			self.rewrite(page)
		}
		body, err := json.Marshal(page)
		if err != nil {
			self.t.Error(err)
			return
		}
		w.Write(body)
	case strings.HasPrefix(r.URL.Path, AclGateApiRowsPath):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, AclGateApiRowsPath), "/")
		if len(parts) != 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		networkId, err := ParseId(parts[0])
		rowsSha256, hashErr := hex.DecodeString(parts[1])
		if err != nil || hashErr != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rows, err := self.net.source.Rows(networkId, rowsSha256)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(rows)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A source over the fake api with its bearer.
func newAclGateApiTestSource(t *testing.T, api *aclGateApiTestServer, server *httptest.Server, settings *AclGateApiSettings) *AclGateApiSource {
	t.Helper()
	source, err := NewAclGateApiSource(server.URL+"/", server.Client(), func() (string, error) { return api.bearer, nil }, settings)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// A cache over the api source reads a cold start page by page and later runs after its pin, reaching the log's.
func TestAclGateApiSourceLoadsALog(t *testing.T) {
	net := newTestConfigNet(t)
	for i := range 4 {
		net.admitMemberDevice("api source " + strconv.Itoa(i))
	}
	api, server := newAclGateApiTestServer(t, net)
	source := newAclGateApiTestSource(t, api, server, nil)

	genesis, err := source.Genesis(t.Context(), net.networkId)
	if err != nil || !bytes.Equal(genesis, net.signedGenesis) {
		t.Fatalf("genesis: %v", err)
	}
	entries, err := source.Entries(t.Context(), net.networkId, nil)
	if err != nil || len(entries) != len(net.entries) {
		t.Fatalf("a cold start's entries: %d of %d, %v", len(entries), len(net.entries), err)
	}

	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the cold load: %v", load.err)
	}
	moved := net.admitMemberDevice("after the cold load")
	api.publish()
	before := len(api.requested())
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the run after: %v", load.err)
	}
	snapshot, _ := cache.State(net.networkId)
	if snapshot.Config.SidecarRow(moved.sidecarId) == nil {
		t.Error("the run's admission is not in the state")
	}
	for _, path := range api.requested()[before:] {
		if !strings.HasPrefix(path, AclGateApiProjectionPath+net.networkId.String()) {
			t.Errorf("the run read %s", path)
		}
	}
}

// Every request carries the bearer; a source with none sends nothing; rows are held to their hash.
func TestAclGateApiSourceCredentialAndRows(t *testing.T) {
	net := newTestConfigNet(t)
	api, server := newAclGateApiTestServer(t, net)

	for _, credential := range []func() (string, error){
		nil,
		func() (string, error) { return "", nil },
		func() (string, error) { return "", errors.New("secret_files unreadable") },
	} {
		source, err := NewAclGateApiSource(server.URL, server.Client(), credential, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.Entries(t.Context(), net.networkId, nil); !errors.Is(err, ErrAclGateApiNoCredential) {
			t.Errorf("no credential: %v", err)
		}
	}
	if paths := api.requested(); len(paths) != 0 {
		t.Fatalf("a source with no credential sent %v", paths)
	}
	wrong, err := NewAclGateApiSource(server.URL, server.Client(), func() (string, error) { return "another bearer", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Entries(t.Context(), net.networkId, nil); err == nil || strings.Contains(err.Error(), "another bearer") {
		t.Errorf("a refused bearer: %v", err)
	}

	source := newAclGateApiTestSource(t, api, server, nil)
	base := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.entries[0], base); err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	header := &bridge.ProjectionHeader{}
	if err := proto.Unmarshal(base.GetBody(), signed); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(signed.GetBody(), header); err != nil {
		t.Fatal(err)
	}
	rows, err := source.Rows(t.Context(), net.networkId, header.GetRowsSha256())
	if sum := sha256.Sum256(rows); err != nil || hex.EncodeToString(sum[:]) != hex.EncodeToString(header.GetRowsSha256()) {
		t.Fatalf("base 1's rows: %v", err)
	}
	if _, err := source.Rows(t.Context(), net.networkId, make([]byte, sha256.Size)); !errors.Is(err, ErrBlobNotFound) {
		t.Errorf("rows api does not have: %v", err)
	}
	api.body = []byte("rows that hash to another")
	if _, err := source.Rows(t.Context(), net.networkId, header.GetRowsSha256()); !errors.Is(err, ErrAclGateApiReply) {
		t.Errorf("rows of another hash: %v", err)
	}
	if _, err := NewAclGateApiSource("not a url", nil, nil, nil); err == nil {
		t.Error("a base that is no url")
	}
}

// Answers that do not hold fail the read: one past its bound, a page that says more and moves nothing, bytes that do
// not decode; and an entry api forged reaches the cache, which refuses the run and keeps its state.
func TestAclGateApiSourceRefusesWhatDoesNotHold(t *testing.T) {
	net := newTestConfigNet(t)
	for i := range 3 {
		net.admitMemberDevice("refused " + strconv.Itoa(i))
	}
	api, server := newAclGateApiTestServer(t, net)

	bounded := DefaultAclGateApiSettings()
	bounded.PageMaxByteCount = 64
	if _, err := newAclGateApiTestSource(t, api, server, bounded).Entries(t.Context(), net.networkId, nil); !errors.Is(err, ErrAclGateApiReply) {
		t.Errorf("a page past its bound: %v", err)
	}
	source := newAclGateApiTestSource(t, api, server, nil)
	api.rewrite = func(page *sidecarConfigProjectionReply) {
		page.Entries, page.More = [][]byte{}, true
	}
	if _, err := source.Entries(t.Context(), net.networkId, nil); !errors.Is(err, ErrAclGateApiReply) {
		t.Errorf("more with no progress: %v", err)
	}
	api.rewrite = nil
	api.body = []byte("{")
	if _, err := source.Entries(t.Context(), net.networkId, nil); !errors.Is(err, ErrAclGateApiReply) {
		t.Errorf("a page that does not decode: %v", err)
	}
	api.body = nil

	settings := DefaultAclGateSettings()
	settings.FailureBackoff = 0
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), settings)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	held, _ := cache.State(net.networkId)
	net.admitMemberDevice("after the forgery")
	api.publish()
	api.rewrite = func(page *sidecarConfigProjectionReply) {
		for i, entryBytes := range page.Entries {
			forged := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, forged); err != nil {
				t.Error(err)
				return
			}
			forged.TimeMs += 1
			page.Entries[i] = testConfigMarshal(t, forged)
		}
	}
	cache.Changed(net.networkId)
	load := aclGateTestNextLoad(t, loads)
	if snapshot, _ := cache.State(net.networkId); !errors.Is(load.err, ErrConfigRunRefused) || snapshot != held || cache.Stats().AlarmCount != 1 {
		t.Errorf("a forged run: %v, alarms %d", load.err, cache.Stats().AlarmCount)
	}
}
