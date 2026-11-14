//go:build !ios_extension

// A sidecar's client of its network's zone (DNS-M5-21; R-DNS-2, D-DNS-2, I-8; plan-DNS-sidecar-zone-read): the dns
// block's GET /dns/zone and POST /dns/records on dns.bringyour.com, by a service token of aud dns from the caller's
// ServiceToken, on every leg but the ios_extension legs, with no connect import, over SidecarApi's transport.
//
//   - Zone answers GET /dns/zone: the label, the alias, the version and the caller's view of the RRsets, cached
//     until a DNS_ZONE_CHANGED hint above its version or ResyncInterval since the fetch (§6.8's hourly resync,
//     dns_hint.go), and fed to DNS-M2-01's NetworkLabelTable where one is given. TLS-M5-18 and TLS-M6-05 read the
//     label and host readiness here.
//   - SetRecord and DeleteRecord write one RRset under a standing grant. SetRecordEffect and DeleteRecordEffect are
//     §16.5's dns_set and dns_delete as SidecarEffects that Sidecar.Authorize runs (plan-MCP-effect-seam): with an
//     empty effect key a standing grant's write, else the decision the use spends, from the context, with its action
//     and Idempotency-Key: <effect_key>, so a retry after a lost answer reads the stored result. Lookup re-presents
//     a stored action under its key, so a restart reconciles a reserved use with no caller alive; the sidecar
//     registers it for both kinds (RegisterDnsEffectLookups).
//   - A refusal is a *DnsApiError, a limit's QuotaRefusal kept whole. Under a decision a refusal proves no effect
//     only at a use's first presentation (§16.6), which the gate judges; the effect says only that this request
//     wrote nothing (ErrSidecarEffectNotDone).
//
// The token goes only into the request's Authorization header, never a url, an error or a log (I-7), and an error
// names the route and never a body. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Tunables of the client.
type DnsClientSettings struct {
	// One request's deadline, the token's exchange included.
	RequestTimeout time.Duration
	// The most bytes an answer may hold: a zone of every RRset §12.7's caps allow, many times over.
	ReplyMaxByteCount int64
	// How long Zone serves its cached zone with no hint above it: §6.8's hourly resync.
	ResyncInterval time.Duration
	// The least time between two refetches hints ask for, so a burst of hints costs one fetch.
	HintRefetchMinInterval time.Duration
}

// §6.8's hourly resync, a request's 30 s and an answer's 4 MiB.
func DefaultDnsClientSettings() *DnsClientSettings {
	return &DnsClientSettings{
		RequestTimeout:         30 * time.Second,
		ReplyMaxByteCount:      4 * 1024 * 1024,
		ResyncInterval:         time.Hour,
		HintRefetchMinInterval: time.Second,
	}
}

// A service token for an audience url with scopes, Sidecar.ServiceToken's shape: for an in-process caller only.
type DnsServiceTokenFunction func(ctx context.Context, resource string, scopes []string) (string, error)

// An answer that does not hold the route's form. Never read as a refusal.
var ErrDnsClientReply = errors.New("dns client: reply invalid")

// What NewDnsClient takes.
type DnsClientArgs struct {
	// SidecarSettings.DnsUrl: absolute, no trailing slash.
	DnsUrl string
	// SidecarApi's transport.
	Transport http.RoundTripper
	// Sidecar.ServiceToken.
	ServiceToken DnsServiceTokenFunction
	// The network whose zone this is.
	NetworkId Id
	// nil takes the defaults.
	Settings *DnsClientSettings
	// nil is real time.
	Clock Clock
}

// The client. See the file header.
type DnsClient struct {
	baseUrl      string
	transport    http.RoundTripper
	serviceToken DnsServiceTokenFunction
	networkId    Id
	settings     *DnsClientSettings
	clock        Clock

	// the held zone's version, which a caller may wait on
	version *MonitorValue[uint64]

	stateLock sync.Mutex
	zone      *DnsZone
	fetchTime time.Time
	// a hint above the cached version arrived, or a resync notice: the next Zone fetches
	stale bool
	// the label table each fetch feeds, and its root
	labels *NetworkLabelTable
	hints  *dnsHints
}

// A client of the dns block at args.DnsUrl for args.NetworkId's zone.
func NewDnsClient(args *DnsClientArgs) (*DnsClient, error) {
	switch {
	case args == nil:
		return nil, fmt.Errorf("%w: no dns client args", errInvalidSettings)
	case args.Transport == nil || args.ServiceToken == nil || args.NetworkId == (Id{}):
		return nil, fmt.Errorf("%w: a dns client needs its transport, service token and network", errInvalidSettings)
	}
	if err := checkServiceUrl("DnsUrl", args.DnsUrl, "http", "https"); err != nil {
		return nil, err
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDnsClientSettings()
	}
	return &DnsClient{
		baseUrl:      args.DnsUrl,
		transport:    args.Transport,
		serviceToken: args.ServiceToken,
		networkId:    args.NetworkId,
		settings:     settings,
		clock:        clockOrReal(args.Clock),
		version:      NewMonitorValue[uint64](0),
	}, nil
}

// Feeds every zone fetched from now on to labels, DNS-M2-01's table, under the zone's root.
func (self *DnsClient) FeedLabels(labels *NetworkLabelTable) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.labels = labels
}

// One request to the block: its answer's body for a 2xx, a *DnsApiError for a refusal, or the transport's error.
func (self *DnsClient) do(ctx context.Context, route string, method string, path string, body []byte, header http.Header) ([]byte, error) {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.RequestTimeout, cancel)
	defer stop()
	token, err := self.serviceToken(callCtx, self.baseUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("dns %s: no service token: %w", route, err)
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(callCtx, method, self.baseUrl+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("dns %s: a request that does not build", route)
	}
	for name, values := range header {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("dns %s: %w", route, err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ReplyMaxByteCount+1))
	if err != nil || self.settings.ReplyMaxByteCount < int64(len(answer)) {
		return nil, fmt.Errorf("%w: %s: an answer cut short or past its bound", ErrDnsClientReply, route)
	}
	if response.StatusCode/100 == 2 {
		return answer, nil
	}
	retryAfter := time.Duration(0)
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && 0 < seconds {
		retryAfter = time.Duration(seconds) * time.Second
	}
	return nil, ParseDnsApiError(response.StatusCode, answer, retryAfter)
}

// GET /dns/zone now, kept and fed to the label table.
func (self *DnsClient) fetchZone(ctx context.Context) (*DnsZone, error) {
	answer, err := self.do(ctx, "GET "+DnsZonePath, http.MethodGet, DnsZonePath, nil, nil)
	if err != nil {
		return nil, err
	}
	zone := &DnsZone{}
	if err := json.Unmarshal(answer, zone); err != nil || zone.NetworkId != self.networkId || zone.Label == "" || zone.Root == "" {
		return nil, fmt.Errorf("%w: GET %s", ErrDnsClientReply, DnsZonePath)
	}
	var labels *NetworkLabelTable
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// a fetch that lost a race to a newer one keeps the newer
		if self.zone == nil || self.zone.Version <= zone.Version {
			self.zone = zone
			self.fetchTime = self.clock.Now()
			self.stale = false
			self.version.Set(zone.Version)
		}
		labels = self.labels
	}()
	if labels != nil {
		if err := labels.SetZoneLabel(zone); err != nil {
			return nil, err
		}
	}
	return cloneDnsZone(zone), nil
}

// A copy that shares nothing with zone.
func cloneDnsZone(zone *DnsZone) *DnsZone {
	copied := *zone
	copied.RecordSets = make([]DnsZoneRecordSet, 0, len(zone.RecordSets))
	for _, recordSet := range zone.RecordSets {
		recordSet.Values = append([]string{}, recordSet.Values...)
		copied.RecordSets = append(copied.RecordSets, recordSet)
	}
	return &copied
}

// The zone as GET /dns/zone answers this sidecar: the cached one while no hint above its version came and less
// than ResyncInterval has passed since it was fetched, else a fetch now.
func (self *DnsClient) Zone(ctx context.Context) (*DnsZone, error) {
	cached := func() *DnsZone {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.zone == nil || self.stale || !self.clock.Now().Before(self.fetchTime.Add(self.settings.ResyncInterval)) {
			return nil
		}
		return cloneDnsZone(self.zone)
	}()
	if cached != nil {
		return cached, nil
	}
	return self.fetchZone(ctx)
}

// The version of the zone held, zero before any fetch.
func (self *DnsClient) Version() uint64 {
	return self.version.Value()
}

// The version of the zone held and a channel that closes when it changes, so a caller waits for a hint's refetch
// with no sleep.
func (self *DnsClient) WatchVersion() (uint64, chan struct{}) {
	return self.version.Get()
}

// POST /dns/records with request, under the decision of approval with effectKey when one is set. Marks the cache
// stale on success, since the write moved the zone.
func (self *DnsClient) write(ctx context.Context, request *DnsRecordsRequest, effectKey []byte) ([]byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("dns POST %s: a body that does not marshal", DnsRecordsPath)
	}
	header := http.Header{}
	if len(effectKey) != 0 {
		header.Set(DnsIdempotencyKeyHeader, base64.RawURLEncoding.EncodeToString(effectKey))
	}
	answer, err := self.do(ctx, "POST "+DnsRecordsPath, http.MethodPost, DnsRecordsPath, body, header)
	if err != nil {
		return nil, err
	}
	parsed := &DnsRecordsAnswer{}
	if err := json.Unmarshal(answer, parsed); err != nil {
		return nil, fmt.Errorf("%w: POST %s", ErrDnsClientReply, DnsRecordsPath)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stale = true
	}()
	return answer, nil
}

// Replaces one RRset under a standing grant: §12.8's write of one upsert, compare-and-swapped on expectVersion when
// it is set.
func (self *DnsClient) SetRecord(ctx context.Context, upsert *DnsRecordUpsert, expectVersion *uint64) (*DnsRecordsAnswer, error) {
	answer, err := self.write(ctx, &DnsRecordsRequest{ExpectVersion: expectVersion, Upserts: []DnsRecordUpsert{*upsert}}, nil)
	if err != nil {
		return nil, err
	}
	return parseDnsRecordsAnswer(answer)
}

// Removes one RRset under a standing grant, compare-and-swapped on expectVersion when it is set.
func (self *DnsClient) DeleteRecord(ctx context.Context, recordDelete *DnsRecordDelete, expectVersion *uint64) (*DnsRecordsAnswer, error) {
	answer, err := self.write(ctx, &DnsRecordsRequest{ExpectVersion: expectVersion, Deletes: []DnsRecordDelete{*recordDelete}}, nil)
	if err != nil {
		return nil, err
	}
	return parseDnsRecordsAnswer(answer)
}

// A write's answer, or ErrDnsClientReply for one that is not the route's.
func parseDnsRecordsAnswer(answer []byte) (*DnsRecordsAnswer, error) {
	parsed := &DnsRecordsAnswer{}
	if err := json.Unmarshal(answer, parsed); err != nil {
		return nil, fmt.Errorf("%w: POST %s", ErrDnsClientReply, DnsRecordsPath)
	}
	return parsed, nil
}

// The write a stored dns_set or dns_delete action names: one RRset with its one value, or one delete, as reading 12
// binds a decision to (§12.8).
func dnsRecordsRequestOfAction(canonical []byte) (*DnsRecordsRequest, error) {
	action, err := ParseStoredCanonicalAction(canonical)
	if err != nil {
		return nil, err
	}
	switch SidecarActionKind(action.Action.GetKind()) {
	case SidecarActionDnsSet:
		return &DnsRecordsRequest{Upserts: []DnsRecordUpsert{{
			Name:   action.Action.GetDnsName(),
			Type:   action.Action.GetDnsType(),
			Ttl:    action.Action.GetDnsTtl(),
			Values: []string{action.Action.GetDnsValue()},
		}}}, nil
	case SidecarActionDnsDelete:
		return &DnsRecordsRequest{Deletes: []DnsRecordDelete{{
			Name: action.Action.GetDnsName(),
			Type: action.Action.GetDnsType(),
		}}}, nil
	}
	return nil, fmt.Errorf("%w: a kind that is no dns write", ErrSidecarActionInvalid)
}

// The approval a use's write carries: the decisions its spend holds, the use's own action, and the template the
// decisions hash when that is not the action. False under a standing grant.
func dnsRecordsApprovalOf(ctx context.Context, canonical []byte) (*DnsRecordsApproval, bool) {
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok {
		return nil, false
	}
	approval := &DnsRecordsApproval{Decisions: spend.Decisions, Action: canonical}
	if !bytes.Equal(spend.Action, canonical) {
		approval.Template = spend.Action
	}
	return approval, true
}

// §16.5's dns_set or dns_delete as the SidecarEffect Sidecar.Authorize runs (plan-MCP-effect-seam).
type DnsRecordEffect struct {
	client *DnsClient
	// the use's CanonicalAction as stored
	canonical     []byte
	expectVersion *uint64
}

// The effect of a dns_set or dns_delete whose action is canonical, as stored, compare-and-swapped on expectVersion
// when it is set.
func (self *DnsClient) RecordEffect(canonical []byte, expectVersion *uint64) *DnsRecordEffect {
	return &DnsRecordEffect{client: self, canonical: append([]byte{}, canonical...), expectVersion: expectVersion}
}

// The write, idempotent per effectKey through the server's use row: under a standing grant, effectKey empty, the
// write alone; under a decision, the spend's decisions with the action and Idempotency-Key. A refusal wraps
// ErrSidecarEffectNotDone, since this request wrote nothing; a transport failure or a 503 leaves the use uncertain.
func (self *DnsRecordEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	request, err := dnsRecordsRequestOfAction(self.canonical)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	request.ExpectVersion = self.expectVersion
	if len(effectKey) != 0 {
		approval, ok := dnsRecordsApprovalOf(ctx, self.canonical)
		if !ok {
			return nil, fmt.Errorf("%w: a use's key with no spend", ErrSidecarEffectNotDone)
		}
		request.Approval = approval
	}
	answer, err := self.client.write(ctx, request, effectKey)
	if err != nil {
		var apiError *DnsApiError
		if errors.As(err, &apiError) && apiError.Status/100 == 4 {
			return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, apiError)
		}
		return nil, err
	}
	return answer, nil
}

// A kind's Lookup for dns_set and dns_delete: re-presents the stored action under its effect key with the spend on
// the context, which the server answers from the use's row once it committed. done with the answer as the effect's
// reference; anything else leaves the use uncertain, since only the gate knows a first presentation.
func (self *DnsClient) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	request, err := dnsRecordsRequestOfAction(canonical)
	if err != nil {
		return nil, err
	}
	if len(effectKey) == 0 {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	approval, ok := dnsRecordsApprovalOf(ctx, canonical)
	if !ok {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	request.Approval = approval
	answer, err := self.write(ctx, request, effectKey)
	if err != nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: err}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: answer}, nil
}

// Registers client's Lookup for dns_set and dns_delete on sidecar's gate; the answer removes both.
func RegisterDnsEffectLookups(sidecar *Sidecar, client *DnsClient) func() {
	removeSet := sidecar.RegisterEffectLookup(SidecarActionDnsSet, client.Lookup)
	removeDelete := sidecar.RegisterEffectLookup(SidecarActionDnsDelete, client.Lookup)
	return func() {
		removeSet()
		removeDelete()
	}
}

// The network's DnsClient, built once over the sidecar's settings, transport and ServiceToken: nil with an error
// before the network is known or with no dns url. Its label table and hint subscription are the daemon's to attach
// (FeedLabels, SubscribeHints).
func (self *Sidecar) Dns() (*DnsClient, error) {
	self.dns.stateLock.Lock()
	defer self.dns.stateLock.Unlock()
	if client, ok := self.dns.client.(*DnsClient); ok {
		return client, nil
	}
	networkId := self.knownNetworkId()
	if networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	if self.sidecarApi == nil {
		return nil, errors.New("dns client: no api")
	}
	client, err := NewDnsClient(&DnsClientArgs{
		DnsUrl:       self.settings.DnsUrl,
		Transport:    self.sidecarApi.Transport(),
		ServiceToken: self.ServiceToken,
		NetworkId:    *networkId,
		Clock:        self.settings.ClockOrReal(),
	})
	if err != nil {
		return nil, err
	}
	self.dns.client = client
	return client, nil
}

// A DnsClient is what the Sidecar holds as its own (sidecar_types.go's sidecarDns).
func (self *DnsClient) isSidecarDnsClient() {}

// Attaches watch, whose last pass SidecarStatus reports as "zone watch degraded"; nil detaches it.
func (self *Sidecar) SetDnsWatch(watch *DnsWatch) {
	self.dns.stateLock.Lock()
	defer self.dns.stateLock.Unlock()
	if watch == nil {
		self.dns.watch = nil
		return
	}
	self.dns.watch = watch
}
