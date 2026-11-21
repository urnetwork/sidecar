// The tls/ namespace on the engine: §13.9's ValidateListen (TLS-M5-22; R-TLS-5, R-TLS-6, R-TLS-9, D-TLS-1, D-TLS-9,
// D-TLS-13, I-8, I-14; QD-107, QD-188, QD-807), the owner hook §9.4 runs on each tls/<port>/<host> entry of a
// registration page once the entry has passed the kill set, its listen grant and its claim, on the page's view S
// (registrations.go). Each row of §13.9's refusal table, with the two QD-107 and QD-188 add, is one check, run
// cheapest first, and every refusal is the same refusal (ErrSocketListenRefused, which the page answers denied, or
// revoked for an entry that held a lease):
//
//	shape     a canonical tls/<port>/<host> entry, its app mode http or raw (§9.5)
//	client    URnetwork-run (D-TLS-1): no sidecar, which neither a platform client nor §18's hosted device holds
//	          (SOCK.md reading 7, D-SDK-12), or a sidecar bound to a hosted device (TlsListenFacts.HostedSidecarIds)
//	port      other than TlsNamespaceSettings.Ports, 443, 8443, 8883 and 5671 (R-TLS-9)
//	host      mta-sts but on §13.9's system publish, below; a scope host, <label>.<scope>, whose scope the
//	          projection does not hold or, in a member scope, whose sidecar is no consented device of the scope's
//	          member (TLS-M6-03; Q-TLS-3, owner decision 126), as SetScopeConsent's source answers, every scope host
//	          refused while the hooks hold none; a host §13.5 maps to no listener of the network's: one §12.7's
//	          owner table keeps for the platform (b, mx, mail, mta-sts), a word-number label or one of the
//	          network's scope labels, all of which ScreenHost denies whatever else the facts say, a scope host's
//	          label screened alone
//	grant     no active approved publish grant for the host bound to this name, the view's (§8.10, I-8); an app
//	          mode other than the grant's app_mode; raw under an audience other than public or link; a raw link
//	          whose grant holds no 32-byte link_spki_sha256 (§13.7, D-TLS-13). The gates report audience and pin and
//	          judge neither, so this is the one place a raw grant's shape is refused (§8.10)
//	network   no network_verified (§21.7, QD-107), or a suspended standing, which publishes nothing (§21.7)
//	time box  a grant with no expiry, or more remaining life than its cap: 24 h on probation or restricted, 7 d at
//	          Community unless its tier fell less than §20.7's 14 days ago; Pro and Team hold standing names
//	screen    ScreenHost denies the host, or sends it to review with no screen_allow (§21.6, QD-188, QD-807)
//	cert      the sidecar holds no unexpired certificate row naming the host (TlsListenFacts.Certified), a scope
//	          host its scope's pair and every other host the network's pair, except an acme-tls/1-only registration,
//	          a TLS-ALPN-01 responder, before its first order
//
// An entry that passes is then narrowed (DESIGN-DETAILS 17.2.10, TLS-M6-08): of its certified names the hook keeps only
// those its sidecar holds an unexpired custom_issued row for, mapped to the name's owner, or an unexpired certificate
// naming a certified alias's pair, which every owner of the zone reaches as <owner>.<alias>.<root> (TLS-M6-03), past
// now plus CertifiedMargin (TlsListenFacts.CustomCertified), and of its ACME names only those whose claim the account's lock
// holds for that sidecar at that sequence (AcmeClaims). A dropped name never refuses the entry, since a listener must
// not lose its network names over a custom one, but an acme-tls/1-only entry left with no ACME name is refused. The
// engine stores the entry as the hook left it. An ACME name whose claim is above the one the facts hold reads the
// facts again, synchronously and at most once a FactsRereadInterval a sidecar, so a new claim is not held up by the
// cache. A list past its count is the engine's malformed entry (registrations.go). Until TLS-M6-05's model reads the
// two maps every listed name is dropped: the closed direction.
//
// §13.9's system publish, tls/443/mta-sts (TLS-M8-02, §15.5, D-MAIL-4), keeps lines of its own and no other name takes
// them, tls/8443/mta-sts and the like refused: it admits only a receiver, whose approved smtp/25/mx listen grant the
// engine asked in the name's place (system_publish.go, the check's Listen), registering app mode http, whose sidecar
// holds an unexpired certificate row for the network's pair, in a network with network_verified and a mail_network
// row, and not suspended. It has no tls/ grant of its own, so no publish grant is read and no time box applies, and it
// takes no tls_endpoints unit; its host is the platform's, so no screen runs. Its grant's end ends the publish: the
// next heartbeat's listen verdict refuses before this hook is asked.
//
// The facts past the view come through TlsListenFactsSource, read off the registration path, since §9.5 runs this per
// heartbeat (plan-SOCK-gate-data): a network's facts are asked for at its first entry and again once they are
// FactsRefreshInterval old, read by FactsLoadWorkerCount workers of the hooks' own, and a failed read keeps the last
// facts serving. A network whose facts this process has never loaded answers ErrSocketListenUnavailable, so the
// client retries and keeps what it held, and an unknown fact refuses, never passes. A check answers from memory and
// never waits on the source.
//
// FirstListen and LastUnlisten follow nothing: §9.4's seams have no tls/ consumer. Nothing here logs a name (I-13).
// Safe for concurrent use.

package socketsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Identifiers the tls/ namespace reads: the ALPN id of a TLS-ALPN-01 responder (RFC 8737), the host only §13.9's
// system publish takes, and §20.5's tier names as QuotaLimits.Tier gives them.
const (
	tlsNamespaceAlpnAcme      = "acme-tls/1"
	tlsNamespaceSystemHost    = "mta-sts"
	tlsNamespaceApexHost      = "@"
	tlsNamespaceTierCommunity = "free"
	tlsNamespaceTierPro       = "pro"
	tlsNamespaceTierTeam      = "team"
	tlsNamespaceNamePrefix    = "tls/"
)

// The tls/ namespace's tunables (§13.9, plan-SOCK-gate-data).
type TlsNamespaceSettings struct {
	// The ports a tls/ name may name: the lb's permanent ports to tlsedge (R-TLS-9; owner decisions 68, 121).
	Ports []string
	// The most a publish grant may have left in a network at Community: §13.9's 7 days.
	CommunityPublishMaxLifetime time.Duration
	// The most on probation or restricted: §21.7's 24 hours.
	ProbationPublishMaxLifetime time.Duration
	// How old a network's facts grow before a check asks for a fresh read: plan-SOCK-gate-data's 60 s. Positive.
	FactsRefreshInterval time.Duration
	// How long after a failed read the next may start, so a source that is down is not asked at every entry.
	// Positive.
	FactsRetryInterval time.Duration
	// The longest one read waits on the source. Positive.
	FactsReadTimeout time.Duration
	// Reads running at once, each on a worker of the hooks' own. Positive.
	FactsLoadWorkerCount int
	// Reads waiting for a worker; past it a check asks again at its next entry. Positive.
	FactsLoadQueueCount int
	// The most networks whose facts are held; past it the network read longest ago goes first. Positive.
	FactsMaxNetworkCount int
	// The most screen verdicts held per network between reads of its facts; past it a verdict is computed and not
	// held. Positive.
	ScreenVerdictMaxCount int
	// How long before a custom certificate's not_after the hook stops keeping its name certified (17.2.10): the
	// front's CertifiedMargin, so listener and hook share one default. Not negative.
	CertifiedMargin time.Duration
	// The least time between two of one sidecar's synchronous reads for a claim above the facts' (17.2.10's "once a
	// page a sidecar"). Positive.
	FactsRereadInterval time.Duration
}

// §13.9's numbers and plan-SOCK-gate-data's refresh.
func DefaultTlsNamespaceSettings() *TlsNamespaceSettings {
	return &TlsNamespaceSettings{
		Ports:                       []string{"443", "8443", "8883", "5671"},
		CommunityPublishMaxLifetime: 7 * 24 * time.Hour,
		ProbationPublishMaxLifetime: 24 * time.Hour,
		FactsRefreshInterval:        60 * time.Second,
		FactsRetryInterval:          5 * time.Second,
		FactsReadTimeout:            10 * time.Second,
		FactsLoadWorkerCount:        4,
		FactsLoadQueueCount:         1024,
		FactsMaxNetworkCount:        100_000,
		ScreenVerdictMaxCount:       1024,
		CertifiedMargin:             sidecar.DefaultTlsFrontSettings().CertifiedMargin,
		FactsRereadInterval:         1 * time.Second,
	}
}

// Whether the settings can serve. A refusal names the field.
func (self *TlsNamespaceSettings) Validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: no tls/ settings", ErrSocketsSettingsRefused)
	case len(self.Ports) == 0:
		return fmt.Errorf("%w: tls.ports", ErrSocketsSettingsRefused)
	case self.CommunityPublishMaxLifetime <= 0:
		return fmt.Errorf("%w: tls.community_publish_max_lifetime", ErrSocketsSettingsRefused)
	case self.ProbationPublishMaxLifetime <= 0:
		return fmt.Errorf("%w: tls.probation_publish_max_lifetime", ErrSocketsSettingsRefused)
	case self.FactsRefreshInterval <= 0:
		return fmt.Errorf("%w: tls.facts_refresh_interval", ErrSocketsSettingsRefused)
	case self.FactsRetryInterval <= 0:
		return fmt.Errorf("%w: tls.facts_retry_interval", ErrSocketsSettingsRefused)
	case self.FactsReadTimeout <= 0:
		return fmt.Errorf("%w: tls.facts_read_timeout", ErrSocketsSettingsRefused)
	case self.FactsLoadWorkerCount <= 0:
		return fmt.Errorf("%w: tls.facts_load_worker_count", ErrSocketsSettingsRefused)
	case self.FactsLoadQueueCount <= 0:
		return fmt.Errorf("%w: tls.facts_load_queue_count", ErrSocketsSettingsRefused)
	case self.FactsMaxNetworkCount <= 0:
		return fmt.Errorf("%w: tls.facts_max_network_count", ErrSocketsSettingsRefused)
	case self.ScreenVerdictMaxCount <= 0:
		return fmt.Errorf("%w: tls.screen_verdict_max_count", ErrSocketsSettingsRefused)
	case self.CertifiedMargin < 0:
		return fmt.Errorf("%w: tls.certified_margin", ErrSocketsSettingsRefused)
	case self.FactsRereadInterval <= 0:
		return fmt.Errorf("%w: tls.facts_reread_interval", ErrSocketsSettingsRefused)
	}
	for _, port := range self.Ports {
		if name, namespace, err := sidecar.ParseSocketName(tlsNamespaceNamePrefix + port + "/www"); err != nil ||
			namespace != sidecar.SocketNamespaceTls || name != tlsNamespaceNamePrefix+port+"/www" {
			return fmt.Errorf("%w: tls.ports: a port no tls/ name takes", ErrSocketsSettingsRefused)
		}
	}
	return nil
}

// What ValidateListen reads of a network beyond its projection (§13.9; plan-SOCK-gate-data's listen facts; QD-107,
// QD-188): server state the hooks keep in memory, read off the registration path by TlsListenFactsSource. They only
// take away, since a server originates only denials (I-4): nothing here allows what the network's signed grants do
// not. Once a source hands facts to the hooks they are never changed, so a check reads them with no lock.
type TlsListenFacts struct {
	// network_verified (§21.7): a payment method, or the owner's verified phone or email.
	Verified bool `json:"verified"`
	// §21.7's standing. One this build does not know refuses every entry (sidecar.AbuseStanding.Known).
	Standing sidecar.AbuseStanding `json:"standing"`
	// §20.5's tier as QuotaLimits.Tier names it: "free" (Community), "pro" or "team". Any other refuses.
	Tier string `json:"tier"`
	// The end of §20.7's 14 days from the network's leaving Pro or Team, through which it keeps its standing grants
	// (QD-107); zero when its tier did not fall.
	StandingGrantsEndTime time.Time `json:"standing_grants_end_time,omitzero"`
	// Whether the network has a mail_network row (§15.15), which §13.9's system publish needs.
	MailNetwork bool `json:"mail_network"`
	// The network's live certificates: its issued network_tls_cert rows not past not_after (cert-1), by what they
	// name.
	Certs []*TlsListenCert `json:"certs,omitempty"`
	// The sidecars bound to a client URnetwork runs, §18's hosted devices and their children, which no tls/ listener
	// may be (D-TLS-1). Empty in every network but one a hosted device was admitted to by mistake.
	HostedSidecarIds []connect.Id `json:"hosted_sidecar_ids,omitempty"`
	// What ScreenHost reads of the network beside its standing (§21.6): its verified domains (§7.6), its Team scope
	// labels, and the hosts a reviewer allowed it (abuse_action screen_allow, ABUSE-M5-08's model).
	VerifiedDomains    []string `json:"verified_domains,omitempty"`
	ScopeLabels        []string `json:"scope_labels,omitempty"`
	ScreenAllowedHosts []string `json:"screen_allowed_hosts,omitempty"`
	// 17.2.10's CustomCertified, for every sidecar and owner of the network: each custom_issued row whose custom host is
	// active and mapped to the owner, with its not_after, and TLS-M6-03's certified aliases. Empty until TLS-M6-05's
	// model reads them.
	CustomCertified []*TlsListenCustomName `json:"custom_certified,omitempty"`
	// 17.2.10's AcmeClaims, for every sidecar and owner: each account whose lock the sidecar holds, purpose order,
	// unlapsed, for a row of a custom host mapped to the owner, by its claim sequence. Empty until TLS-M6-05's model
	// reads them.
	AcmeClaims []*TlsListenAcmeClaim `json:"acme_claims,omitempty"`
}

// A custom host or alias a sidecar holds a certificate for, on the owner its host maps to (17.2.10).
type TlsListenCustomName struct {
	SidecarId connect.Id `json:"sidecar_id"`
	// The host segment of tls/<port>/<owner>, or TlsListenCustomNameAnyOwner for a certified alias.
	Owner string `json:"owner"`
	// A custom host, or a certified alias's zone, <alias>.<root>.
	Name     string    `json:"name"`
	NotAfter time.Time `json:"not_after"`
}

// The Owner of a certified alias (TLS-M6-03): its certificate names the alias's pair, {*.<alias>.<root>,
// <alias>.<root>}, so every one-label owner <host> of the network's zone is reached under it as <host>.<alias>.<root>,
// and @ as the zone itself; a scope host rides no alias's pair. An identifier, not a host.
const TlsListenCustomNameAnyOwner = "*"

// A custom host whose account lock a sidecar holds to order, on the owner the host maps to, with the claim's sequence
// (17.2.6, 17.2.10).
type TlsListenAcmeClaim struct {
	SidecarId connect.Id `json:"sidecar_id"`
	Owner     string     `json:"owner"`
	Name      string     `json:"name"`
	ClaimSeq  uint64     `json:"claim_seq"`
}

// CustomCertified for the entry's sidecar and owner: each name with its latest not_after, a certified alias's as the
// name owner takes under it.
func (self *TlsListenFacts) customCertified(sidecarId connect.Id, owner string) map[string]time.Time {
	nameNotAfters := map[string]time.Time{}
	for _, custom := range self.CustomCertified {
		if custom == nil || custom.SidecarId != sidecarId {
			continue
		}
		name := custom.Name
		switch custom.Owner {
		case owner:
		case TlsListenCustomNameAnyOwner:
			if strings.Contains(owner, ".") {
				continue
			}
			if owner != tlsNamespaceApexHost {
				name = owner + "." + custom.Name
			}
		default:
			continue
		}
		if notAfter, found := nameNotAfters[name]; !found || notAfter.Before(custom.NotAfter) {
			nameNotAfters[name] = custom.NotAfter
		}
	}
	return nameNotAfters
}

// AcmeClaims for the entry's sidecar and owner: each name with its claim's sequence, the highest where two are held.
func (self *TlsListenFacts) acmeClaims(sidecarId connect.Id, owner string) map[string]uint64 {
	nameClaimSeqs := map[string]uint64{}
	for _, claim := range self.AcmeClaims {
		if claim == nil || claim.SidecarId != sidecarId || claim.Owner != owner {
			continue
		}
		nameClaimSeqs[claim.Name] = max(nameClaimSeqs[claim.Name], claim.ClaimSeq)
	}
	return nameClaimSeqs
}

// One live certificate row as ValidateListen reads it: whose it is, until when, and what it names.
type TlsListenCert struct {
	SidecarId connect.Id `json:"sidecar_id"`
	NotAfter  time.Time  `json:"not_after"`
	// Whether it names the network's own pair, {*.<net>.<root>, <net>.<root>} (§13.8), which @ and every one-label
	// host ride.
	NetworkPair bool `json:"network_pair,omitempty"`
	// The Team scopes whose pair, {*.<scope>.<net>.<root>, <scope>.<net>.<root>}, it names.
	ScopePairs []string `json:"scope_pairs,omitempty"`
}

// Whether the sidecar holds a certificate row naming host that is unexpired at now: §13.9's cert line, as the one
// function it reads, which TLS-M6-03's scopes and TLS-M6-08's custom names extend. @ and a one-label host ride the
// network's pair, a scope host <label>.<scope> its scope's.
func (self *TlsListenFacts) Certified(sidecarId connect.Id, host string, now time.Time) bool {
	_, scope, scoped := strings.Cut(host, ".")
	for _, cert := range self.Certs {
		if cert == nil || cert.SidecarId != sidecarId || !now.Before(cert.NotAfter) {
			continue
		}
		if scoped {
			if slices.Contains(cert.ScopePairs, scope) {
				return true
			}
		} else if cert.NetworkPair {
			return true
		}
	}
	return false
}

// Whether the sidecar is bound to a client URnetwork runs (D-TLS-1).
func (self *TlsListenFacts) hosted(sidecarId connect.Id) bool {
	return slices.Contains(self.HostedSidecarIds, sidecarId)
}

// Whether the network takes probation's limits: on probation, or restricted (§21.7).
func (self *TlsListenFacts) probation() bool {
	return self.Standing == sidecar.AbuseStandingProbation || self.Standing == sidecar.AbuseStandingRestricted
}

// ScreenHost's facts for host in this network.
func (self *TlsListenFacts) screenFacts(host string) *sidecar.ScreenFacts {
	return &sidecar.ScreenFacts{
		VerifiedDomains: self.VerifiedDomains,
		Probation:       self.probation(),
		ReviewAllowed:   slices.Contains(self.ScreenAllowedHosts, host),
		ScopeLabels:     self.ScopeLabels,
	}
}

// Where ValidateListen's facts come from, read off the registration path: model.GetTlsListenFacts in a process that
// holds Postgres, and api's GET /internal/gate/listen-facts/<network_id> in one that does not (plan-SOCK-gate-data).
// An error keeps the last facts serving, and a network the source cannot read stays undecided. Safe for concurrent
// use.
type TlsListenFactsSource interface {
	// The network's facts as they stand now. The hooks never change what it returns.
	ListenFacts(ctx context.Context, networkId connect.Id) (*TlsListenFacts, error)
}

// A function as a TlsListenFactsSource.
type TlsListenFactsFunc func(ctx context.Context, networkId connect.Id) (*TlsListenFacts, error)

// See TlsListenFactsSource.
func (self TlsListenFactsFunc) ListenFacts(ctx context.Context, networkId connect.Id) (*TlsListenFacts, error) {
	return self(ctx, networkId)
}

// One network's facts as the hooks hold them.
type tlsListenFactsEntry struct {
	// nil until a read succeeds.
	facts *TlsListenFacts
	// When the read that gave facts began.
	loadTime time.Time
	// A read is asked for or running.
	loading bool
	// When the last read failed, zero once one succeeds after it.
	failTime time.Time
	// When a check last read the entry, which eviction orders by.
	readTime time.Time
	// ScreenHost's verdict by host, under facts, dropped with each read.
	hostScreenVerdicts map[string]sidecar.ScreenVerdict
}

// tls/'s hooks. NewTlsNamespaceHooks makes them; register them with SocketsService.RegisterNamespace under
// sidecar.SocketNamespaceTls.
type TlsNamespaceHooks struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *TlsNamespaceSettings
	source   TlsListenFactsSource
	clock    sidecar.Clock
	loads    chan connect.Id
	// Reads finished, failed ones included, so a test waits for one to land.
	loadCount *sidecar.MonitorValue[uint64]
	group     sync.WaitGroup

	stateLock      sync.Mutex
	networkEntries map[connect.Id]*tlsListenFactsEntry
	// When each (network, sidecar) last read its facts again for a claim above theirs.
	sidecarRereadTimes map[tlsListenRereadKey]time.Time
	// Where a scope host's scope and consent are read (SetScopeConsent); nil refuses every scope host.
	scopes SocketScopeConsent
}

// Who a synchronous read is rationed to.
type tlsListenRereadKey struct {
	networkId connect.Id
	sidecarId connect.Id
}

var _ SocketNamespaceHooks = (*TlsNamespaceHooks)(nil)

// tls/'s hooks on source and clock, nil being real time, with settings, nil being the defaults, their workers running
// until ctx ends or Close. A source must be given: a host with none leaves tls/ unregistered, which refuses every
// entry.
func NewTlsNamespaceHooks(ctx context.Context, source TlsListenFactsSource, clock sidecar.Clock, settings *TlsNamespaceSettings) (*TlsNamespaceHooks, error) {
	if source == nil {
		return nil, errors.New("tls/ opens only with a listen facts source")
	}
	if settings == nil {
		settings = DefaultTlsNamespaceSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &TlsNamespaceHooks{
		ctx:                cancelCtx,
		cancel:             cancel,
		settings:           settings,
		source:             source,
		clock:              clock,
		loads:              make(chan connect.Id, settings.FactsLoadQueueCount),
		loadCount:          sidecar.NewMonitorValue[uint64](0),
		networkEntries:     map[connect.Id]*tlsListenFactsEntry{},
		sidecarRereadTimes: map[tlsListenRereadKey]time.Time{},
	}
	self.group.Add(settings.FactsLoadWorkerCount)
	for range settings.FactsLoadWorkerCount {
		go self.run()
	}
	return self, nil
}

// Stops the workers and waits for them. A check after Close reads only what was loaded.
func (self *TlsNamespaceHooks) Close() {
	self.cancel()
	self.group.Wait()
}

// Reads finished, failed ones included, and a channel that closes at the next.
func (self *TlsNamespaceHooks) Loads() (count uint64, changed chan struct{}) {
	return self.loadCount.Get()
}

// Reads the network's facts now, on ctx and at most FactsReadTimeout, and holds them as a worker's read would: what a
// host warming a network, or a test, calls. A failed read keeps the last facts.
func (self *TlsNamespaceHooks) LoadFacts(ctx context.Context, networkId connect.Id) error {
	return self.load(ctx, networkId)
}

// One worker: reads the networks checks asked for, one at a time.
func (self *TlsNamespaceHooks) run() {
	defer self.group.Done()
	for {
		select {
		case <-self.ctx.Done():
			return
		case networkId := <-self.loads:
			self.load(self.ctx, networkId)
		}
	}
}

// Reads the network's facts on ctx and holds them, unless a read that began later already landed. A failure keeps the
// last facts and holds the next read off for FactsRetryInterval.
func (self *TlsNamespaceHooks) load(ctx context.Context, networkId connect.Id) error {
	readCtx, cancel := context.WithTimeout(ctx, self.settings.FactsReadTimeout)
	defer cancel()
	startTime := self.clock.Now()
	testHookBarrier("sockets.tls.facts.read.before", networkId.String())
	facts, err := self.source.ListenFacts(readCtx, networkId)
	testHookBarrier("sockets.tls.facts.read.after", networkId.String())
	if err == nil && facts == nil {
		err = errors.New("the listen facts source answered nothing")
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkEntries[networkId]
		if entry == nil {
			if err != nil {
				return
			}
			entry = &tlsListenFactsEntry{readTime: startTime}
			self.addEntryWithLock(networkId, entry)
		}
		entry.loading = false
		switch {
		case err != nil:
			entry.failTime = self.clock.Now()
		case entry.facts == nil || !startTime.Before(entry.loadTime):
			entry.facts = facts
			entry.loadTime = startTime
			entry.failTime = time.Time{}
			entry.hostScreenVerdicts = nil
		}
	}()
	self.loadCount.Update(func(count uint64) uint64 {
		return count + 1
	})
	return err
}

// Adds entry for the network, first evicting the entry read longest ago that no read is running for, while the hooks
// hold FactsMaxNetworkCount networks.
func (self *TlsNamespaceHooks) addEntryWithLock(networkId connect.Id, entry *tlsListenFactsEntry) {
	for self.settings.FactsMaxNetworkCount <= len(self.networkEntries) {
		var oldestNetworkId connect.Id
		var oldest *tlsListenFactsEntry
		for candidateNetworkId, candidate := range self.networkEntries {
			if candidate.loading {
				continue
			}
			if oldest == nil || candidate.readTime.Before(oldest.readTime) {
				oldestNetworkId, oldest = candidateNetworkId, candidate
			}
		}
		if oldest == nil {
			break
		}
		delete(self.networkEntries, oldestNetworkId)
	}
	self.networkEntries[networkId] = entry
}

// Reads the mail enablement row from the same cached facts as TLS. A cold network
// asks the worker for a read and keeps its registration pending until the row is known.
func (self *TlsNamespaceHooks) MailEnabled(ctx context.Context, networkId connect.Id) (bool, error) {
	facts, loaded := self.facts(networkId, self.clock.Now())
	if !loaded {
		return false, ErrSocketListenUnavailable
	}
	return facts.MailNetwork, nil
}

// The network's facts at now, false while none have loaded. Asks a worker for a read when the network has none or
// its facts are FactsRefreshInterval old, unless a read is asked for already or the last failed within
// FactsRetryInterval. Never waits on the source.
func (self *TlsNamespaceHooks) facts(networkId connect.Id, now time.Time) (*TlsListenFacts, bool) {
	var facts *TlsListenFacts
	ask := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkEntries[networkId]
		if entry == nil {
			entry = &tlsListenFactsEntry{}
			self.addEntryWithLock(networkId, entry)
		}
		entry.readTime = now
		facts = entry.facts
		due := facts == nil || self.settings.FactsRefreshInterval <= now.Sub(entry.loadTime)
		retry := entry.failTime.IsZero() || self.settings.FactsRetryInterval <= now.Sub(entry.failTime)
		if due && retry && !entry.loading {
			entry.loading = true
			ask = true
		}
	}()
	if ask {
		select {
		case self.loads <- networkId:
		default:
			// every worker is behind: the next check asks again
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if entry := self.networkEntries[networkId]; entry != nil {
					entry.loading = false
				}
			}()
		}
	}
	return facts, facts != nil
}

// ScreenHost's verdict on host under the network's facts, held until the facts are read again.
func (self *TlsNamespaceHooks) screen(networkId connect.Id, facts *TlsListenFacts, host string) sidecar.ScreenVerdict {
	verdict, held := func() (sidecar.ScreenVerdict, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkEntries[networkId]
		if entry == nil || entry.facts != facts {
			return sidecar.ScreenVerdictDeny, false
		}
		verdict, held := entry.hostScreenVerdicts[host]
		return verdict, held
	}()
	if held {
		return verdict
	}
	verdict = sidecar.ScreenHost(host, facts.screenFacts(host))
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkEntries[networkId]
		if entry == nil || entry.facts != facts {
			return
		}
		if entry.hostScreenVerdicts == nil {
			entry.hostScreenVerdicts = map[string]sidecar.ScreenVerdict{}
		}
		if len(entry.hostScreenVerdicts) < self.settings.ScreenVerdictMaxCount {
			entry.hostScreenVerdicts[host] = verdict
		}
	}()
	return verdict
}

// A refusal of the entry. Its reason names no host or network (I-13).
func tlsListenRefused(reason string) error {
	return fmt.Errorf("%w: %s", ErrSocketListenRefused, reason)
}

// The port and host of a canonical tls/<port>/<host> name, false for any other.
func tlsListenNameParts(name string) (port string, host string, ok bool) {
	canonical, namespace, err := sidecar.ParseSocketName(name)
	if err != nil || namespace != sidecar.SocketNamespaceTls || canonical != name {
		return "", "", false
	}
	segments := strings.Split(name, "/")
	if len(segments) != 3 {
		return "", "", false
	}
	return segments[1], segments[2], true
}

// Whether the registration answers only TLS-ALPN-01 (RFC 8737): its one ALPN id is acme-tls/1.
func tlsAcmeOnlyRegistration(registration *sidecar.SocketRegistration) bool {
	return len(registration.Alpn) == 1 && registration.Alpn[0] == tlsNamespaceAlpnAcme
}

// Whether grant's shape lets a registration in appMode take it (§13.7, §13.9, D-TLS-13): the registration's mode is
// the grant's app_mode, and raw only under public or link, a raw link only with its 32-byte pin. Unspecified reads as
// §8.4's defaults, members and http.
func tlsPublishGrantShapeAllows(grant *sidecar.AclPublishGrant, appMode string) bool {
	audience := grant.Audience
	if audience == protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED {
		audience = protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	}
	mode := grant.AppMode
	if mode == protocol.AclAppMode_ACL_APP_MODE_UNSPECIFIED {
		mode = protocol.AclAppMode_ACL_APP_MODE_HTTP
	}
	switch appMode {
	case socketDefaultTlsAppMode:
		return mode == protocol.AclAppMode_ACL_APP_MODE_HTTP
	case socketRawTlsAppMode:
		if mode != protocol.AclAppMode_ACL_APP_MODE_RAW {
			return false
		}
		switch audience {
		case protocol.AclAudience_ACL_AUDIENCE_PUBLIC:
			return true
		case protocol.AclAudience_ACL_AUDIENCE_LINK:
			return len(grant.LinkSpkiSha256) == sha256.Size
		}
	}
	return false
}

// The most a publish grant may have left at now in a network of facts, and whether anything caps it (§13.9, QD-107):
// ProbationPublishMaxLifetime on probation or restricted, CommunityPublishMaxLifetime at Community once §20.7's 14
// days from a fall from Pro or Team have run, nothing for Pro and Team. ok is false for a suspended network, which
// publishes nothing, and for a standing or tier this build does not read.
func (self *TlsNamespaceHooks) publishLifetimeCap(facts *TlsListenFacts, now time.Time) (lifetimeCap time.Duration, capped bool, ok bool) {
	switch facts.Standing {
	case sidecar.AbuseStandingProbation, sidecar.AbuseStandingRestricted:
		return self.settings.ProbationPublishMaxLifetime, true, true
	case sidecar.AbuseStandingStandard, sidecar.AbuseStandingTrusted:
	default:
		return 0, false, false
	}
	switch facts.Tier {
	case tlsNamespaceTierPro, tlsNamespaceTierTeam:
		return 0, false, true
	case tlsNamespaceTierCommunity:
		if now.Before(facts.StandingGrantsEndTime) {
			return 0, false, true
		}
		return self.settings.CommunityPublishMaxLifetime, true, true
	}
	return 0, false, false
}

// See SocketNamespaceHooks: §13.9's table, as the file's header lists it.
func (self *TlsNamespaceHooks) ValidateListen(ctx context.Context, check *SocketListenCheck) error {
	if check == nil || check.Namespace != sidecar.SocketNamespaceTls || check.Registration == nil {
		return tlsListenRefused("not a tls/ entry")
	}
	port, host, ok := tlsListenNameParts(check.Name)
	if !ok {
		return tlsListenRefused("not a tls/<port>/<host> name")
	}
	appMode := check.Registration.AppMode
	if appMode != socketDefaultTlsAppMode && appMode != socketRawTlsAppMode {
		return tlsListenRefused("no tls/ app mode")
	}
	// client: a URnetwork-run client holds no sidecar (D-TLS-1)
	if check.SidecarId == nil || *check.SidecarId == (connect.Id{}) {
		return tlsListenRefused("a URnetwork-run client")
	}
	sidecarId := *check.SidecarId
	// port
	if !slices.Contains(self.settings.Ports, port) {
		return tlsListenRefused("a port tlsedge does not serve")
	}
	// host
	if host == tlsNamespaceSystemHost {
		// §13.9's system publish keeps lines of its own, and no other port takes the host
		if check.Name != sidecar.SocketSystemPublishName {
			return tlsListenRefused("the system host on another port")
		}
		return self.validateSystemPublish(check, sidecarId)
	}
	screenHost, scope, scoped := strings.Cut(host, ".")
	if !scoped {
		screenHost = host
	} else if err := self.consentScope(check.NetworkId, scope, sidecarId); err != nil {
		return err
	}
	// grant, on the page's view
	if check.View == nil {
		return tlsListenRefused("no view")
	}
	now := self.clock.Now()
	request := &SocketGateRequest{
		NetworkId:       check.NetworkId,
		CallerClientId:  check.ListenerClientId,
		CallerNetworkId: check.NetworkId,
		SubjectClientId: check.ListenerClientId,
		SidecarId:       &sidecarId,
		Name:            check.Name,
	}
	grant := check.View.PublishGrant(request, appMode, now)
	if grant == nil {
		return tlsListenRefused("no publish grant")
	}
	if !tlsPublishGrantShapeAllows(grant, appMode) {
		return tlsListenRefused("a publish grant of another shape")
	}
	// what the projection does not hold
	facts, loaded := self.facts(check.NetworkId, now)
	if !loaded {
		return fmt.Errorf("%w: no listen facts yet", ErrSocketListenUnavailable)
	}
	if facts.hosted(sidecarId) {
		return tlsListenRefused("a URnetwork-run client")
	}
	if !facts.Verified {
		return tlsListenRefused("an unverified network")
	}
	// time box
	lifetimeCap, capped, known := self.publishLifetimeCap(facts, now)
	if !known {
		return tlsListenRefused("no publishing in the network's standing or tier")
	}
	if capped && (grant.ExpiresMs <= 0 || lifetimeCap < time.UnixMilli(grant.ExpiresMs).Sub(now)) {
		return tlsListenRefused("a publish grant past its time box")
	}
	// screen: the apex is the network's label or alias, screened when it was drawn or claimed
	if host != tlsNamespaceApexHost && self.screen(check.NetworkId, facts, screenHost) != sidecar.ScreenVerdictAllow {
		return tlsListenRefused("a host the screen does not allow")
	}
	// cert
	acmeOnly := tlsAcmeOnlyRegistration(check.Registration)
	if !acmeOnly && !facts.Certified(sidecarId, host, now) {
		return tlsListenRefused("no unexpired certificate")
	}
	// 17.2.10's narrowing, which refuses only an acme-only entry left with no claim
	certifiedNames, acmeNames := self.narrow(ctx, check, sidecarId, host, facts, now)
	if acmeOnly && len(acmeNames) == 0 {
		return tlsListenRefused("an acme-tls/1-only registration holding no claim")
	}
	check.Registration.CertifiedNames, check.Registration.AcmeNames = certifiedNames, acmeNames
	return nil
}

// Gives the hooks the source a scope host's scope and consent are read from (TLS-M6-03): the sockets gate, which reads
// the network's Team scopes from its verified projection (SocketProjectionGate, SOCK-M6-01). nil, or never set,
// refuses every scope host.
func (self *TlsNamespaceHooks) SetScopeConsent(scopes SocketScopeConsent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.scopes = scopes
}

// Whether a scope host's scope stands in the network and, in a member scope, sidecarId is one of the member's
// consented devices (Q-TLS-3, owner decision 126): nil, a refusal, or ErrSocketListenUnavailable while the source
// cannot decide yet.
func (self *TlsNamespaceHooks) consentScope(networkId connect.Id, scope string, sidecarId connect.Id) error {
	scopes := func() SocketScopeConsent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.scopes
	}()
	if scopes == nil {
		return tlsListenRefused("a scope host with no scope source")
	}
	err := scopes.ConsentListen(networkId, scope, &sidecarId)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrSocketListenUnavailable):
		return err
	}
	return tlsListenRefused("a scope the projection does not hold, or a device its member did not consent")
}

// 17.2.10's narrowing of the entry's two lists for sidecarId on owner: the certified names facts certify past now plus
// CertifiedMargin, and the ACME names whose claim facts hold at that very sequence. A claim above the one facts hold
// reads the facts again first, at most once a FactsRereadInterval a sidecar; a failed read narrows on what is held.
// Names keep the entry's order, and an empty list is nil.
func (self *TlsNamespaceHooks) narrow(ctx context.Context, check *SocketListenCheck, sidecarId connect.Id, owner string, facts *TlsListenFacts, now time.Time) ([]string, []*sidecar.SocketAcmeName) {
	registration := check.Registration
	if len(registration.CertifiedNames) == 0 && len(registration.AcmeNames) == 0 {
		return nil, nil
	}
	acmeClaims := facts.acmeClaims(sidecarId, owner)
	ahead := slices.ContainsFunc(registration.AcmeNames, func(acmeName *sidecar.SocketAcmeName) bool {
		return acmeName != nil && acmeClaims[acmeName.Name] < acmeName.ClaimSeq
	})
	if ahead && self.takeReread(check.NetworkId, sidecarId, now) {
		if err := self.load(ctx, check.NetworkId); err == nil {
			if fresh, loaded := self.loadedFacts(check.NetworkId); loaded {
				facts = fresh
				acmeClaims = facts.acmeClaims(sidecarId, owner)
			}
		}
	}
	customCertified := facts.customCertified(sidecarId, owner)
	var certifiedNames []string
	for _, name := range registration.CertifiedNames {
		if notAfter, found := customCertified[name]; found && now.Add(self.settings.CertifiedMargin).Before(notAfter) {
			certifiedNames = append(certifiedNames, name)
		}
	}
	var acmeNames []*sidecar.SocketAcmeName
	for _, acmeName := range registration.AcmeNames {
		if claimSeq, found := acmeClaims[acmeName.Name]; found && claimSeq == acmeName.ClaimSeq {
			acmeNames = append(acmeNames, &sidecar.SocketAcmeName{Name: acmeName.Name, ClaimSeq: acmeName.ClaimSeq})
		}
	}
	return certifiedNames, acmeNames
}

// Whether the sidecar may read its network's facts again now, noting it if so: once a FactsRereadInterval.
func (self *TlsNamespaceHooks) takeReread(networkId connect.Id, sidecarId connect.Id, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := tlsListenRereadKey{networkId: networkId, sidecarId: sidecarId}
	if lastTime, found := self.sidecarRereadTimes[key]; found && now.Sub(lastTime) < self.settings.FactsRereadInterval {
		return false
	}
	// the rationing is soft state: past the networks' bound it starts again, which lets each sidecar one read more
	if self.settings.FactsMaxNetworkCount <= len(self.sidecarRereadTimes) {
		self.sidecarRereadTimes = map[tlsListenRereadKey]time.Time{}
	}
	self.sidecarRereadTimes[key] = now
	return true
}

// The network's facts as held now, asking nothing.
func (self *TlsNamespaceHooks) loadedFacts(networkId connect.Id) (*TlsListenFacts, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry := self.networkEntries[networkId]
	if entry == nil || entry.facts == nil {
		return nil, false
	}
	return entry.facts, true
}

// §13.9's system publish lines, as the file's header lists them, for a sidecar's tls/443/mta-sts entry.
func (self *TlsNamespaceHooks) validateSystemPublish(check *SocketListenCheck, sidecarId connect.Id) error {
	if check.Listen == nil || !check.Listen.Allowed {
		return tlsListenRefused("no receiver's listen grant")
	}
	if check.Registration.AppMode != socketDefaultTlsAppMode {
		return tlsListenRefused("the system publish serves http")
	}
	now := self.clock.Now()
	facts, loaded := self.facts(check.NetworkId, now)
	if !loaded {
		return fmt.Errorf("%w: no listen facts yet", ErrSocketListenUnavailable)
	}
	switch {
	case facts.hosted(sidecarId):
		return tlsListenRefused("a URnetwork-run client")
	case !facts.Standing.Known() || facts.Standing == sidecar.AbuseStandingSuspended:
		return tlsListenRefused("no publishing in the network's standing")
	case !facts.Verified:
		return tlsListenRefused("an unverified network")
	case !facts.MailNetwork:
		return tlsListenRefused("a network with no mail")
	case !facts.Certified(sidecarId, tlsNamespaceApexHost, now):
		// @ rides the network's pair, which mta-sts.<net>.<root> does too
		return tlsListenRefused("no unexpired certificate for the network's pair")
	}
	// no custom name or claim rides the system publish
	check.Registration.CertifiedNames, check.Registration.AcmeNames = nil, nil
	return nil
}

// See SocketNamespaceHooks: nothing follows a tls/ name's first listener.
func (self *TlsNamespaceHooks) FirstListen(networkId connect.Id, name string) {}

// See SocketNamespaceHooks: nothing follows a tls/ name's last listener.
func (self *TlsNamespaceHooks) LastUnlisten(networkId connect.Id, name string) {}
