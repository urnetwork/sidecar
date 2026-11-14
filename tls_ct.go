//go:build !sidecar_http && !ios_extension

// D-TLS-8's CT watch (TLS-M5-24; R-TLS-8, D-TRUST-6, I-4): URnetwork can always pass DNS-01 in its own zones (§2.8
// EX1), so detection is the remaining control against a certificate nobody on the network asked for. A listening
// sidecar reads two CT sources for its zone, its aliases and its custom hosts about every 6 hours, jittered, and
// reads each logged certificate back against the network's rows (GET /tls/certs) and its own verified config.
//
// A logged certificate is known when some row is a certificate for exactly its key and its names, and that row's
// attestation verifies here, under the identity key verified config pins for the row's sidecar: the rows are a
// server's answer, so a row alone proves nothing. It alarms (ct_alarm) when
//
//   - no such row attests it (unattested): a certificate no device asked for, a test certificate included;
//   - or every identity that attests it was first pinned under CtIdentityPinMinAge, 24 hours, before the certificate
//     was issued (recent_identity): a device admitted just in time to ask.
//
// Which rows are certificates. issued and revoking; revoked, expired and failed while the row still holds its chain;
// custom_issued and custom_revoking (DESIGN-DETAILS 17.7). A network row still queued or ordering counts by its
// attestation, since a CA logs a precertificate before certs learns the order finished. custom_queued and
// custom_ordering are no certificate yet, so a certificate logged for a custom host on a key only they hold alarms,
// which is what catches a removed holder of the account key (17.5). A state this build does not know is no
// certificate.
//
// A precertificate and its certificate, and one certificate seen by both sources, are one: certificates compare by
// their key and names alone. Two sources disagreeing is no alarm by itself; each certificate either source shows is
// judged.
//
// A source failing, or the rows, the names or verified config not being there to read, marks the watch degraded,
// "CT watch degraded" in SidecarStatus, and never alarms: a pass with nothing to judge by judges nothing. A
// certificate past its validity is not judged, since its row may be gone.
//
// The watch keeps its own file in the tls component's store: each source's cursor a domain, the certificates it has
// found known, which stay known after their rows are deleted, and the alarms standing. Each pass judges the standing
// alarms again, so one whose row arrives late is withdrawn. An alarm's event is raised once a process. Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// The watch's file in the tls component's store, and its format.
const (
	tlsCtStateFileName = "ct.json"
	tlsCtStateFormat   = 1
)

// The identity keys verified config pins, as the watch asks for them. Safe for concurrent use.
type TlsCtIdentities interface {
	// The identity public key pinned for sidecarId, revoked tombstones included; nil for a sidecar the state never
	// admitted.
	IdentityPublicKey(sidecarId Id) []byte
	// Whether sidecarId's identity key was first pinned at or after at.
	PinnedSince(sidecarId Id, at time.Time) bool
}

// The identities of authority's verified state. A sidecar's key is first pinned by the entry that admitted it, and
// that entry's time is the log's, read through ProposedSince.
type tlsCtAuthorityIdentities struct {
	authority SidecarAuthority
}

// The identities the watch reads from authority, nil for none.
func NewTlsCtAuthorityIdentities(authority SidecarAuthority) TlsCtIdentities {
	if authority == nil {
		return nil
	}
	return &tlsCtAuthorityIdentities{authority: authority}
}

// See TlsCtIdentities.
func (self *tlsCtAuthorityIdentities) IdentityPublicKey(sidecarId Id) []byte {
	admission := self.authority.Admission(sidecarId)
	if admission == nil || admission.Row == nil {
		return nil
	}
	return admission.Row.GetIdentityPublicKey()
}

// See TlsCtIdentities. An identity the state does not hold counts as pinned just now.
func (self *tlsCtAuthorityIdentities) PinnedSince(sidecarId Id, at time.Time) bool {
	admission := self.authority.Admission(sidecarId)
	if admission == nil || admission.Row == nil {
		return true
	}
	n, _, ok := self.authority.ProposedSince(at)
	// with no entry timed at or after at, every pin is older
	return ok && n <= admission.Row.GetAdmittedAt()
}

// One standing alarm.
type TlsCtAlarm struct {
	Reason SidecarCtAlarm `json:"reason"`
	// The source that showed the certificate first.
	Source     string    `json:"source"`
	SpkiSha256 []byte    `json:"spki_sha256"`
	DnsNames   []string  `json:"dns_names"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	// recent_identity: the newest-pinned identity that attested it.
	SidecarId *Id `json:"sidecar_id,omitempty"`
	// When this device first saw it.
	SeenTime time.Time `json:"seen_time"`
}

// A certificate the watch found known, kept until it expires.
type tlsCtKnownEntry struct {
	Key      string    `json:"key"`
	NotAfter time.Time `json:"not_after"`
}

// The watch's file.
type tlsCtStateFile struct {
	Format int `json:"format"`
	// "<source> <domain>" to the source's cursor.
	Cursors map[string]string  `json:"cursors,omitempty"`
	Known   []*tlsCtKnownEntry `json:"known,omitempty"`
	Alarms  []*TlsCtAlarm      `json:"alarms,omitempty"`
}

// What the watch says of itself.
type TlsCtWatchStatus struct {
	// The last pass could not read a source, the rows, the names or verified config: "CT watch degraded".
	Degraded bool
	// When the last pass ended. Zero before any.
	PassTime time.Time
	// The alarms standing.
	Alarms []*TlsCtAlarm
}

// What the watch takes.
type TlsCtWatchArgs struct {
	NetworkId Id
	// The CT sources: TlsCtClient.Sources.
	Sources []TlsCtSource
	// GET /tls/certs.
	Rows func(ctx context.Context) (*TlsCertsResult, error)
	// The network's root, label, aliases and custom hosts, as the certificate manager reads them.
	Names func(ctx context.Context) (*TlsCertNames, error)
	// Verified config's identities now, nil while this device follows no verified state.
	Identities func() TlsCtIdentities
	// Whether this sidecar listens on a published name now. nil watches always.
	Listening func() bool
	// The tls component's directory.
	Store SidecarStore
	// ct_alarm's events. nil drops them.
	Event SidecarEventFunction
	// CtWatch* and CtIdentityPinMinAge. nil takes the defaults.
	Settings *SidecarTlsSettings
	// nil is real time.
	Clock Clock
	// A random number in [0, n), for the jitter. nil is math/rand's.
	Rand func(n int64) int64
	Log  Logger
}

// The watch. See the file header.
type tlsCtWatch struct {
	networkId  Id
	sources    []TlsCtSource
	rows       func(ctx context.Context) (*TlsCertsResult, error)
	names      func(ctx context.Context) (*TlsCertNames, error)
	identities func() TlsCtIdentities
	listening  func() bool
	store      SidecarStore
	event      SidecarEventFunction
	settings   *SidecarTlsSettings
	clock      Clock
	rand       func(n int64) int64
	log        Logger

	cancel context.CancelFunc
	done   chan struct{}

	// one pass at a time
	passLock sync.Mutex

	stateLock sync.Mutex
	status    TlsCtWatchStatus
	// the alarms whose event this process raised, by certificate key
	raised map[string]bool
}

// A watch over args, its passes running under ctx until Close.
func newTlsCtWatch(ctx context.Context, args *TlsCtWatchArgs) (*tlsCtWatch, error) {
	if args == nil || len(args.Sources) == 0 || args.Rows == nil || args.Names == nil || args.Identities == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: a ct watch needs its sources, rows, names, identities and store", errInvalidSettings)
	}
	if args.NetworkId == (Id{}) {
		return nil, fmt.Errorf("%w: a ct watch needs its network", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarTlsSettings()
	}
	if settings.CtWatchInterval <= 0 || settings.CtWatchJitter < 0 || settings.CtWatchInterval <= settings.CtWatchJitter {
		return nil, fmt.Errorf("%w: a ct watch's interval is past its jitter", errInvalidSettings)
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	random := args.Rand
	if random == nil {
		random = rand.Int64N
	}
	runCtx, cancel := context.WithCancel(ctx)
	self := &tlsCtWatch{
		networkId:  args.NetworkId,
		sources:    slices.Clone(args.Sources),
		rows:       args.Rows,
		names:      args.Names,
		identities: args.Identities,
		listening:  args.Listening,
		store:      args.Store,
		event:      args.Event,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		rand:       random,
		log:        log,
		cancel:     cancel,
		done:       make(chan struct{}),
		raised:     map[string]bool{},
	}
	go self.run(runCtx)
	return self, nil
}

// Ends the passes and waits for the one running.
func (self *tlsCtWatch) Close() {
	self.cancel()
	<-self.done
}

// The watch's own view.
func (self *tlsCtWatch) Status() TlsCtWatchStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := self.status
	status.Alarms = slices.Clone(self.status.Alarms)
	return status
}

// Whether the last pass was degraded: SidecarStatus's "CT watch degraded".
func (self *tlsCtWatch) Degraded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.status.Degraded
}

// How long until the next pass: CtWatchInterval, moved by up to CtWatchJitter either way.
func (self *tlsCtWatch) nextWait() time.Duration {
	wait := self.settings.CtWatchInterval
	if 0 < self.settings.CtWatchJitter {
		wait += time.Duration(self.rand(int64(2*self.settings.CtWatchJitter))) - self.settings.CtWatchJitter
	}
	return wait
}

// Runs a pass about every CtWatchInterval, jittered, until ctx ends.
func (self *tlsCtWatch) run(ctx context.Context) {
	defer close(self.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.nextWait()):
		}
		self.Pass(ctx)
	}
}

// The watch's file, empty when there is none. One that does not decode is a failure, never an empty state, since
// an empty state forgets every certificate found known.
func (self *tlsCtWatch) readState() (*tlsCtStateFile, error) {
	state := &tlsCtStateFile{Format: tlsCtStateFormat, Cursors: map[string]string{}}
	reader, err := self.store.Open(tlsCtStateFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	encoded, readErr := io.ReadAll(io.LimitReader(reader, int64(self.settings.CtStateMaxByteCount)+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	if self.settings.CtStateMaxByteCount < len(encoded) {
		return nil, fmt.Errorf("%w: the ct watch's state is past its bound", ErrSidecarStoreFailed)
	}
	if err := json.Unmarshal(encoded, state); err != nil || state.Format != tlsCtStateFormat {
		return nil, fmt.Errorf("%w: the ct watch's state does not decode", ErrSidecarStoreFailed)
	}
	if state.Cursors == nil {
		state.Cursors = map[string]string{}
	}
	return state, nil
}

// Writes the watch's file.
func (self *tlsCtWatch) writeState(state *tlsCtStateFile) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: the ct watch's state does not encode", ErrSidecarStoreFailed)
	}
	if self.settings.CtStateMaxByteCount < len(encoded) {
		return fmt.Errorf("%w: the ct watch's state is past its bound", ErrSidecarStoreFailed)
	}
	writer, err := self.store.Create(tlsCtStateFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// What certificates compare by: the key and the names, so a precertificate and its certificate are one.
func tlsCtCertificateKey(spkiSha256 []byte, dnsNames []string) string {
	digest := sha256.New()
	digest.Write(spkiSha256)
	for _, name := range dnsNames {
		digest.Write([]byte{0})
		digest.Write([]byte(name))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// Whether a row in state is a certificate the watch reads a logged one back against (see the file header).
func tlsCtRowIsCertificate(row *TlsCertRecord) bool {
	switch row.State {
	case TlsCertStateIssued, TlsCertStateRevoking, TlsCertStateCustomIssued, TlsCertStateCustomRevoking:
		return true
	case TlsCertStateQueued, TlsCertStateOrdering:
		return true
	case TlsCertStateRevoked, TlsCertStateExpired, TlsCertStateFailed:
		return 0 < len(row.Chain)
	default:
		// custom_queued and custom_ordering are no certificate yet, and neither is a state from a later build
		return false
	}
}

// The domains a pass asks the sources about: the network's zone, each alias's, and each custom host.
func tlsCtDomains(names *TlsCertNames) []string {
	domains := []string{}
	if names.Root != "" {
		for _, label := range append([]string{names.Label}, names.Aliases...) {
			if label != "" {
				domains = append(domains, label+"."+names.Root)
			}
		}
	}
	domains = append(domains, names.CustomHosts...)
	slices.Sort(domains)
	return slices.Compact(domains)
}

// One logged certificate's verdict against the rows: nil when a row attests it under an identity pinned long enough,
// else its alarm.
func (self *tlsCtWatch) judge(certificate *TlsCtAlarm, rows []*TlsCertRecord, identities TlsCtIdentities) *TlsCtAlarm {
	alarm := *certificate
	alarm.Reason = SidecarCtAlarmUnattested
	alarm.SidecarId = nil
	if len(certificate.SpkiSha256) != sha256.Size {
		return &alarm
	}
	spkiSha256 := [sha256.Size]byte(certificate.SpkiSha256)
	identifierSetSha256, err := TlsIdentifierSetHash(certificate.DnsNames)
	if err != nil {
		// names that form no identifier set, which no attestation covers
		return &alarm
	}
	pinnedBefore := certificate.NotBefore.Add(-self.settings.CtIdentityPinMinAge)
	for _, row := range rows {
		if row == nil || row.NetworkId != self.networkId || !tlsCtRowIsCertificate(row) {
			continue
		}
		if !bytes.Equal(row.SpkiSha256, spkiSha256[:]) || !bytes.Equal(row.IdentifierSetSha256, identifierSetSha256[:]) {
			continue
		}
		identityPublicKey := identities.IdentityPublicKey(row.SidecarId)
		if len(identityPublicKey) == 0 {
			continue
		}
		// the row is a server's answer: the attestation is verified here, against the logged key and names
		_, err := VerifyTlsKeyAttestation(row.Attestation, identityPublicKey, self.networkId, row.SidecarId, spkiSha256, identifierSetSha256)
		if err != nil {
			continue
		}
		if !identities.PinnedSince(row.SidecarId, pinnedBefore) {
			return nil
		}
		sidecarId := row.SidecarId
		alarm.Reason = SidecarCtAlarmRecentIdentity
		alarm.SidecarId = &sidecarId
	}
	return &alarm
}

// Runs one pass now and answers how many alarms stand. A sidecar that is not listening watches nothing.
func (self *tlsCtWatch) Pass(ctx context.Context) int {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	now := self.clock.Now()
	if self.listening != nil && !self.listening() {
		self.endPass(now, false, nil)
		return 0
	}
	degraded := func(reason string) int {
		if self.log.V(1).Enabled() {
			self.log.V(1).Info("ct watch degraded", "reason", reason)
		}
		standing := self.endPass(now, true, nil)
		return standing
	}
	state, err := self.readState()
	if err != nil {
		return degraded("state")
	}
	names, err := self.names(ctx)
	if err != nil || names == nil {
		return degraded("names")
	}
	identities := self.identities()
	if identities == nil {
		return degraded("config")
	}
	result, err := self.rows(ctx)
	if err != nil || result == nil {
		return degraded("rows")
	}
	rows := slices.Concat(result.Certs, result.QueuedCsrs)

	// what the sources logged past each cursor, and the alarms standing, judged again
	sourceFailed := false
	candidates := map[string]*TlsCtAlarm{}
	order := []string{}
	add := func(candidate *TlsCtAlarm) {
		key := tlsCtCertificateKey(candidate.SpkiSha256, candidate.DnsNames)
		if _, ok := candidates[key]; !ok {
			candidates[key] = candidate
			order = append(order, key)
		}
	}
	for _, alarm := range state.Alarms {
		add(alarm)
	}
	cursors := map[string]string{}
	for _, domain := range tlsCtDomains(names) {
		for _, source := range self.sources {
			cursorKey := source.Name() + " " + domain
			certificates, next, err := source.Issuances(ctx, domain, state.Cursors[cursorKey])
			if err != nil {
				sourceFailed = true
				continue
			}
			cursors[cursorKey] = next
			for _, certificate := range certificates {
				add(&TlsCtAlarm{
					Source:     certificate.Source,
					SpkiSha256: certificate.SpkiSha256[:],
					DnsNames:   certificate.DnsNames,
					NotBefore:  certificate.NotBefore,
					NotAfter:   certificate.NotAfter,
					SeenTime:   now,
				})
			}
		}
	}
	if ctx.Err() != nil {
		return degraded("ended")
	}

	known := map[string]time.Time{}
	for _, entry := range state.Known {
		if now.Before(entry.NotAfter) {
			known[entry.Key] = entry.NotAfter
		}
	}
	alarms := []*TlsCtAlarm{}
	for _, key := range order {
		candidate := candidates[key]
		if _, ok := known[key]; ok || !now.Before(candidate.NotAfter) {
			continue
		}
		if alarm := self.judge(candidate, rows, identities); alarm != nil {
			alarms = append(alarms, alarm)
		} else {
			known[key] = candidate.NotAfter
		}
	}

	next := &tlsCtStateFile{Format: tlsCtStateFormat, Cursors: state.Cursors, Alarms: alarms}
	for cursorKey, cursor := range cursors {
		next.Cursors[cursorKey] = cursor
	}
	for key, notAfter := range known {
		next.Known = append(next.Known, &tlsCtKnownEntry{Key: key, NotAfter: notAfter})
	}
	slices.SortFunc(next.Known, func(a *tlsCtKnownEntry, b *tlsCtKnownEntry) int {
		// the soonest to expire first, which is what a full list drops
		if order := a.NotAfter.Compare(b.NotAfter); order != 0 {
			return order
		}
		return bytes.Compare([]byte(a.Key), []byte(b.Key))
	})
	if self.settings.CtKnownMaxCount < len(next.Known) {
		next.Known = next.Known[len(next.Known)-self.settings.CtKnownMaxCount:]
	}
	// the verdicts are written before any is reported, so a restart neither loses an alarm nor moves a cursor past
	// a certificate it did not judge
	if err := self.writeState(next); err != nil {
		return degraded("state")
	}
	return self.endPass(now, sourceFailed, alarms)
}

// Ends a pass: its status, and an event for each alarm this process has not raised. alarms nil leaves the standing
// ones as they were. Answers how many stand.
func (self *tlsCtWatch) endPass(now time.Time, degraded bool, alarms []*TlsCtAlarm) int {
	raise, standing := func() ([]*TlsCtAlarm, int) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.status.Degraded = degraded
		self.status.PassTime = now
		raise := []*TlsCtAlarm{}
		if alarms != nil {
			self.status.Alarms = alarms
			for _, alarm := range alarms {
				// a certificate whose reason changed is told again
				key := tlsCtCertificateKey(alarm.SpkiSha256, alarm.DnsNames) + " " + string(alarm.Reason)
				if !self.raised[key] {
					self.raised[key] = true
					raise = append(raise, alarm)
				}
			}
		}
		return raise, len(self.status.Alarms)
	}()
	if self.event != nil {
		for _, alarm := range raise {
			self.event(SidecarEvent{Kind: SidecarEventCtAlarm, CtAlarm: alarm.Reason, SidecarId: alarm.SidecarId})
		}
	}
	return standing
}

// Attaches watch, whose last pass SidecarStatus reports as "CT watch degraded"; nil detaches it.
func (self *Sidecar) setTlsCtWatch(watch sidecarCtWatch) {
	self.tlsCt.stateLock.Lock()
	defer self.tlsCt.stateLock.Unlock()
	self.tlsCt.watch = watch
}
