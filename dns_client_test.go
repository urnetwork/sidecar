//go:build !ios_extension

package sidecar

// DnsClient (DNS-M5-21), T2 on a fake dns block: the zone cached until a hint above its version or the hourly
// resync, a stale hint ignored, the label table fed; a decision's write whose answer was lost answers the stored
// result on its retry with one commit; a compare-and-swap conflict and a QuotaRefusal surfaced whole; a Lookup
// re-presenting a stored action reads done; and no error names the token.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A SidecarStore in memory, every leg's.
type testDnsMemoryStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

func newTestDnsMemoryStore() *testDnsMemoryStore {
	return &testDnsMemoryStore{files: map[string][]byte{}}
}

func (self *testDnsMemoryStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(value))), nil
}

type testDnsMemoryWriter struct {
	store  *testDnsMemoryStore
	name   string
	buffer bytes.Buffer
}

func (self *testDnsMemoryWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *testDnsMemoryWriter) Commit() error {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *testDnsMemoryWriter) Close() error {
	return nil
}

func (self *testDnsMemoryStore) Create(name string) (SidecarStoreWriter, error) {
	return &testDnsMemoryWriter{store: self, name: name}, nil
}

func (self *testDnsMemoryStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

func (self *testDnsMemoryStore) List(prefix string) ([]SidecarStoreEntry, error) {
	return nil, errors.New("not listed")
}

func (self *testDnsMemoryStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

// A visibly synthetic bearer, which no error may repeat.
const testDnsClientToken = "synthetic-dns-token-never-in-errors"

// The dns block in memory: GET /dns/zone answers zone, POST /dns/records answers by its refusal or commits, keyed by
// Idempotency-Key, and may lose the first answer of a key.
type testDnsBlock struct {
	stateLock  sync.Mutex
	zone       *DnsZone
	zoneCount  int
	fetched    chan int
	refusal    *DnsApiError
	commits    map[string][]byte
	loseFirst  bool
	lost       map[string]bool
	writeCount int
	requests   []*DnsRecordsRequest
	bearers    []string
}

func newTestDnsBlock(zone *DnsZone) *testDnsBlock {
	return &testDnsBlock{zone: zone, fetched: make(chan int, 16), commits: map[string][]byte{}, lost: map[string]bool{}}
}

func (self *testDnsBlock) RoundTrip(request *http.Request) (*http.Response, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.bearers = append(self.bearers, request.Header.Get("Authorization"))
	respond := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == DnsZonePath:
		self.zoneCount += 1
		select {
		case self.fetched <- self.zoneCount:
		default:
		}
		body, _ := json.Marshal(self.zone)
		return respond(http.StatusOK, body)
	case request.Method == http.MethodPost && request.URL.Path == DnsRecordsPath:
		body, _ := io.ReadAll(request.Body)
		recordsRequest := &DnsRecordsRequest{}
		if err := json.Unmarshal(body, recordsRequest); err != nil {
			return respond(http.StatusBadRequest, nil)
		}
		self.requests = append(self.requests, recordsRequest)
		if self.refusal != nil {
			return respond(self.refusal.Status, mustJson(self.refusal.HttpErrorResultBody()))
		}
		key := request.Header.Get(DnsIdempotencyKeyHeader)
		if answer, ok := self.commits[key]; ok && key != "" {
			return respond(http.StatusOK, answer)
		}
		self.writeCount += 1
		self.zone.Version += 1
		answer := mustJson(&DnsRecordsAnswer{Version: self.zone.Version})
		if key != "" {
			self.commits[key] = answer
			if self.loseFirst && !self.lost[key] {
				self.lost[key] = true
				return nil, errors.New("connection reset after the commit")
			}
		}
		return respond(http.StatusOK, answer)
	}
	return respond(http.StatusNotFound, nil)
}

func mustJson(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func (self *testDnsBlock) setZoneVersion(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.zone.Version = version
}

func (self *testDnsBlock) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.zoneCount, self.writeCount
}

func newTestDnsClient(t *testing.T, block *testDnsBlock, clock Clock, networkId Id) *DnsClient {
	t.Helper()
	settings := DefaultDnsClientSettings()
	settings.HintRefetchMinInterval = 0
	client, err := NewDnsClient(&DnsClientArgs{
		DnsUrl:    "https://dns.test.example",
		Transport: block,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return testDnsClientToken, nil
		},
		NetworkId: networkId,
		Settings:  settings,
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func testDnsClientZone(networkId Id, version uint64) *DnsZone {
	return &DnsZone{
		NetworkId: networkId,
		Root:      "root.example.",
		Label:     "lbl0000001",
		Version:   version,
		RecordSets: []DnsZoneRecordSet{
			{Name: "shop.lbl0000001.root.example.", Type: "A", Ttl: 60, Kind: "edge"},
		},
	}
}

// The zone is fetched once and served from the cache; a hint at or below its version is ignored, one above it
// refetches on the client's loop, and the next Zone answers the new version with no fetch of its own; the label
// table holds the zone's label.
func TestDnsClientZoneFollowsHints(t *testing.T) {
	networkId := NewId()
	block := newTestDnsBlock(testDnsClientZone(networkId, 7))
	clock := newTokenTestClock()
	client := newTestDnsClient(t, block, clock, networkId)
	labels, err := OpenNetworkLabelTable(newTestDnsMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	client.FeedLabels(labels)
	var callback PushNoticeFunction
	err = client.SubscribeHints(context.Background(), func(topic string, function PushNoticeFunction) (func(), error) {
		if topic != PushTopicDns {
			t.Errorf("topic %s", topic)
		}
		callback = function
		return func() {}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		zone, err := client.Zone(context.Background())
		if err != nil || zone.Version != 7 {
			t.Fatalf("zone %+v %v", zone, err)
		}
	}
	if zones, _ := block.counts(); zones != 1 {
		t.Fatalf("%d fetches", zones)
	}
	if networkIdOf, kind, err := labels.ResolveNetworkLabel("root.example", "lbl0000001", false); err != nil || networkIdOf != networkId || kind != NetworkLabelKindLabel {
		t.Fatalf("the label table: %v %s %v", networkIdOf, kind, err)
	}
	<-block.fetched
	callback(PushNotice{Topic: PushTopicDns, Version: 7, Kind: uint32(protocol.MessageType_DNS_ZONE_CHANGED)})
	callback(PushNotice{Topic: PushTopicDns, Version: 5, Kind: uint32(protocol.MessageType_DNS_ZONE_CHANGED)})
	if zone, err := client.Zone(context.Background()); err != nil || zone.Version != 7 {
		t.Fatalf("after stale hints: %+v %v", zone, err)
	}
	if zones, _ := block.counts(); zones != 1 {
		t.Fatalf("a stale hint fetched: %d", zones)
	}
	block.setZoneVersion(9)
	callback(PushNotice{Topic: PushTopicDns, Version: 9, Kind: uint32(protocol.MessageType_DNS_ZONE_CHANGED)})
	if count := <-block.fetched; count != 2 {
		t.Fatalf("fetch %d", count)
	}
	// the loop's fetch lands before Zone reads: wait for the cache to hold it
	for {
		version, changed := client.WatchVersion()
		if version == 9 {
			break
		}
		<-changed
	}
	if zone, err := client.Zone(context.Background()); err != nil || zone.Version != 9 {
		t.Fatalf("after the hint: %+v %v", zone, err)
	}
	if zones, _ := block.counts(); zones != 2 {
		t.Fatalf("%d fetches", zones)
	}
}

// With no hint the zone is fetched again once ResyncInterval has passed (§6.8's hourly resync).
func TestDnsClientZoneResyncs(t *testing.T) {
	networkId := NewId()
	block := newTestDnsBlock(testDnsClientZone(networkId, 3))
	clock := newTokenTestClock()
	client := newTestDnsClient(t, block, clock, networkId)
	if _, err := client.Zone(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(DefaultDnsClientSettings().ResyncInterval - time.Second)
	if _, err := client.Zone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if zones, _ := block.counts(); zones != 1 {
		t.Fatalf("%d fetches before the hour", zones)
	}
	clock.Advance(time.Second)
	if _, err := client.Zone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if zones, _ := block.counts(); zones != 2 {
		t.Fatalf("%d fetches after the hour", zones)
	}
}

// A dns_set action of value at owner.
func testDnsClientAction(t *testing.T, owner string, value string) *StoredCanonicalAction {
	t.Helper()
	action, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), DnsName: owner, DnsType: "A", DnsValue: value, DnsTtl: 300})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// A decision's write whose answer was lost after the block committed: the effect leaves the use uncertain, and its
// retry under the same key reads the stored answer, byte for byte, with one commit. Lookup re-presenting the stored
// action reads done.
func TestDnsClientRetryAfterALostAnswerReadsTheStoredResult(t *testing.T) {
	networkId := NewId()
	block := newTestDnsBlock(testDnsClientZone(networkId, 3))
	block.loseFirst = true
	client := newTestDnsClient(t, block, nil, networkId)
	action := testDnsClientAction(t, "shop.lbl0000001.root.example.", "11.22.33.44")
	approvalId := NewId()
	effectKey := ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	ctx := withApprovalSpend(context.Background(), &ApprovalSpend{ApprovalId: approvalId, Decisions: [][]byte{[]byte("synthetic decision")}, Action: action.Bytes})
	effect := client.RecordEffect(action.Bytes, nil)
	if _, err := effect.Run(ctx, effectKey[:]); err == nil || errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("a lost answer: %v", err)
	}
	answer, err := effect.Run(ctx, effectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, writes := block.counts(); writes != 1 {
		t.Fatalf("%d commits", writes)
	}
	outcome, err := client.Lookup(ctx, action.Bytes, effectKey[:])
	if err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, answer) {
		t.Fatalf("lookup %+v %v", outcome, err)
	}
	last := block.requests[len(block.requests)-1]
	if last.Approval == nil || !bytes.Equal(last.Approval.Action, action.Bytes) || last.Approval.Template != nil ||
		len(last.Upserts) != 1 || last.Upserts[0].Values[0] != "11.22.33.44" || last.Upserts[0].Ttl != 300 {
		t.Fatalf("the request %+v", last)
	}
	key := block.bearers[len(block.bearers)-1]
	if key != "Bearer "+testDnsClientToken {
		t.Fatalf("bearer %q", key)
	}
	if _, ok := block.commits[base64.RawURLEncoding.EncodeToString(effectKey[:])]; !ok {
		t.Fatalf("no commit under the effect key")
	}
}

// A refusal surfaces as the block said it: a compare-and-swap conflict by its code, a limit's QuotaRefusal whole; a
// decision's refusal says the request wrote nothing; and no error names the token.
func TestDnsClientSurfacesRefusals(t *testing.T) {
	networkId := NewId()
	cases := []*DnsApiError{
		{Status: http.StatusConflict, Code: DnsApiCodeVersionConflict, Message: "the zone is at a newer version"},
		NewDnsQuotaError(&QuotaRefusal{LimitKey: "dns_entries", Limit: 5, Used: 5, Upgrade: true}),
		NewDnsQuotaError(&QuotaRefusal{LimitKey: "dns_changes_per_hour", Limit: 60, Used: 60, RetryAfterMs: 1000}),
		{Status: http.StatusForbidden, Code: DnsApiCodeRefused, Message: "no grant"},
	}
	for _, refusal := range cases {
		block := newTestDnsBlock(testDnsClientZone(networkId, 3))
		block.refusal = refusal
		client := newTestDnsClient(t, block, nil, networkId)
		version := uint64(2)
		_, err := client.SetRecord(context.Background(), &DnsRecordUpsert{Name: "shop.lbl0000001.root.example.", Type: "A", Values: []string{"11.22.33.44"}}, &version)
		apiError := &DnsApiError{}
		if !errors.As(err, &apiError) || apiError.Status != refusal.Status || apiError.Code != refusal.Code {
			t.Errorf("%s: %v", refusal.Code, err)
			continue
		}
		if refusal.Refusal != nil && (apiError.Refusal == nil || *apiError.Refusal != *refusal.Refusal) {
			t.Errorf("%s: refusal %+v, want %+v", refusal.Code, apiError.Refusal, refusal.Refusal)
		}
		if strings.Contains(err.Error(), testDnsClientToken) {
			t.Errorf("%s: the error names the token", refusal.Code)
		}
		action := testDnsClientAction(t, "shop.lbl0000001.root.example.", "11.22.33.44")
		if _, err := client.RecordEffect(action.Bytes, nil).Run(context.Background(), nil); !errors.Is(err, ErrSidecarEffectNotDone) || strings.Contains(err.Error(), testDnsClientToken) {
			t.Errorf("%s: the effect: %v", refusal.Code, err)
		}
	}
}
