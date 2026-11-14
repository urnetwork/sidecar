//go:build !sidecar_http && !ios_extension

// The device's certificate manager (TLS-M5-18; R-TLS-3, D-TLS-6, D-TLS-7, I-4, I-14, R-TRUST-4): it orders the
// certificate for this device's own key and its network's identifier set through certs' CSR proxy, keeps the chains in
// the tls component's store, and answers Sidecar.TlsDeviceCertificate from them. The key stays in the keychain: this
// file reaches it only as a crypto.Signer, for the CSR and for §12.8's reclaim, and no ACME client is imported here or
// reachable from here, so no mobile build carries one (D-TLS-7).
//
// What it does, each pass (Sync), from GET /tls/certs and its own state:
//
//   - reads its rows' states. A certificate is presented only while its row reads issued (a custom host's,
//     custom_issued), so a revoked one stops serving at once, and a state this build does not know is no certificate
//     (§13.8). A server's word here only ever takes a certificate away, which I-4 lets a server say.
//   - installs chains its rows hold: a leaf on a key this device holds, naming exactly the set the device computed,
//     each certificate signed by the next. The set comes from TlsIdentifierSet over what the names source gives, never
//     from a row.
//   - keeps the network's certificate once a person asked for one (EnsureTlsCertificate): a live local chain whose
//     row is gone, as after a restore, is ordered again with `replaces` (plan reading 7), and a key due for rotation
//     gets a pending successor whose order names the old certificate in `replaces`. The old certificate serves until
//     the successor's chain installs, and that install promotes the key.
//   - for each custom host the names source says this device may serve (DESIGN-DETAILS 17.2.5), queues one CSR naming
//     exactly that host when it has no open row of its own and no live certificate, installs chains from its
//     custom_issued rows, keeps a predecessor until it expires and presents the newest whose row is custom_issued.
//     The ordering is a desktop's (TLS-M6-05); this file only queues.
//
// A network certificate never answers for a custom host and a custom certificate never for a network name: each is
// chosen by its own names, and a custom leaf names exactly one host.
//
// The state file holds chains and open orders, which are public values (cert-1), and no key. One pass runs at a time,
// and no state lock is held across the keychain, the store or the api. Errors and logs name no host, label or id's
// owner (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The file in the tls component's store that holds the installed chains and open orders.
const tlsCertStateFileName = "certs.json"

// The state file's format.
const tlsCertStateFormat = 1

// What a retry's backoff is keyed by for the network's own certificate; a custom host's key is its name.
const tlsCertNetworkTarget = ""

var (
	// No certs audience is configured (SidecarTlsSettings.CertsResource), so nothing is ordered.
	ErrTlsCertsUnconfigured = errors.New("tls certificates: no certs audience configured")
	// No client generation is attached, so no route can be called.
	ErrTlsCertsOffline = errors.New("tls certificates: offline")
	// The order ended without a certificate: failed, or in a state this build does not know.
	ErrTlsCertOrderFailed = errors.New("tls certificate order failed")
	// A chain that cannot be installed: it does not parse, is not signed link by link, is on a key this device does
	// not hold, names something other than the set asked for, or is past its validity.
	ErrTlsCertChain = errors.New("tls certificate chain refused")
	// No issued certificate covers the names: none was ordered, it has not issued yet, or it expired or was revoked.
	// Publishing stops here; only local services fall back to the self-signed leaf.
	ErrTlsNoIssuedCertificate = errors.New("tls: no issued certificate")
	// The manager has closed.
	ErrTlsCertManagerClosed = errors.New("tls certificate manager closed")
	// A chain past its validity: refused as any other, and passed over without a report where a row merely still
	// lists a lapsed chain.
	errTlsCertChainExpired = fmt.Errorf("%w: past its validity", ErrTlsCertChain)
)

// §13.15's certificate routes as the manager calls them, which *SidecarApi answers (tls_api_client.go).
type TlsCertApi interface {
	TlsCertOrder(ctx context.Context, serviceToken string, args *TlsCertOrderArgs) (*TlsCertOrderResult, error)
	TlsCertOrderStatus(ctx context.Context, serviceToken string, certId Id) (*TlsCertOrderStatus, error)
	TlsCerts(ctx context.Context) (*TlsCertsResult, error)
	TlsCertRevoke(ctx context.Context, args *TlsCertRevokeArgs) error
}

// The device key as the manager reaches it: the keychain's record through the Sidecar's lock (tls_self_signed.go).
// Nothing here answers a private key.
type TlsCertKeys interface {
	// The key serving now, made on first use, and the successor a rotation set, nil when none is pending.
	TlsKeys() (current *TlsDeviceKey, pending *TlsDeviceKey, err error)
	// Sets a pending successor for reason, or answers the one pending.
	RotateTlsKey(reason TlsKeyRotationReason) (pending *TlsDeviceKey, err error)
	// Makes the pending key with this SPKI hash the current one, dropping the key it replaces.
	PromoteTlsKey(spkiSha256 [sha256.Size]byte) error
}

// What the device's own view of its network gives a certificate: the parts of §13.8's set, and the custom hosts this
// device may serve. The label and root are the zone's (DnsClient.Zone); the scope and the grants behind CustomHosts
// are verified config's. The set is computed here from these parts, never read from a certificate row.
type TlsCertNames struct {
	// The user root, canonical, with no final dot.
	Root string
	// The network's label.
	Label string
	// A Team scope's label, when this device holds only a scope's set (TLS-M6-03). Empty for none.
	Scope string
	// The network's live aliases.
	Aliases []string
	// Each active custom host mapped to an owner on one of whose tls/ names this device holds an active approved
	// publish grant (17.2.5's test): canonical names under no URnetwork root.
	CustomHosts []string
	// URnetwork's other roots, which no custom host may sit under. Root is always one.
	OtherRoots []string
}

// What NewTlsCertManager takes.
type TlsCertManagerArgs struct {
	NetworkId Id
	SidecarId Id
	// SidecarSettings.Tls. nil takes the defaults, which order nothing, having no certs audience.
	Settings *SidecarTlsSettings
	Keys     TlsCertKeys
	// Sidecar.Sign, for the key's attestation.
	Sign TlsKeyAttestationSignFunction
	// Sidecar.ServiceToken, for aud certs.
	ServiceToken func(ctx context.Context, resource string, scopes []string) (string, error)
	// The device's view of its network's names. An error skips whatever needs the names, and revocations still apply.
	Names func(ctx context.Context) (*TlsCertNames, error)
	// The tls component's sealed directory.
	Store SidecarStore
	// nil is real time.
	Clock Clock
	// nil is the default logger.
	Log Logger
}

// One installed certificate, as Sidecar.TlsCertificates lists it. Public values only.
type TlsCertificateInfo struct {
	CertId Id
	// The leaf's DNS names, sorted.
	Names []string
	// The custom host it serves. Empty for the network's own certificate.
	CustomHost string
	NotBefore  time.Time
	NotAfter   time.Time
	SpkiSha256 [sha256.Size]byte
	// Its row's state as last read. Empty when no row named it at the last read.
	State TlsCertState
	// Whether it answers TlsDeviceCertificate for its names now.
	Presented bool
}

// A custom host's certificate as the front presents it (TLS-M6-08).
type TlsCustomCertificate struct {
	Host        string
	Certificate *tls.Certificate
}

// An installed chain. The json fields are the state file's; the rest is read back from the chain at load.
type tlsCertEntry struct {
	CertId     Id       `json:"cert_id"`
	CustomHost string   `json:"custom_host,omitempty"`
	Chain      [][]byte `json:"chain"`
	// The row's state as last read: issued or custom_issued at install.
	State TlsCertState `json:"state,omitempty"`
	// No row named it at the last read: a restore behind it (plan reading 7).
	RowLost bool `json:"row_lost,omitempty"`

	leaf       *x509.Certificate
	spkiSha256 [sha256.Size]byte
}

// An order placed and not yet ended.
type tlsCertOrderEntry struct {
	CertId              Id     `json:"cert_id"`
	CustomHost          string `json:"custom_host,omitempty"`
	SpkiSha256          []byte `json:"spki_sha256"`
	IdentifierSetSha256 []byte `json:"identifier_set_sha256"`
}

// A revocation owed to POST /tls/cert-revoke: a suspected key's predecessor, once its successor serves.
type tlsCertRevokeEntry struct {
	CertId        Id   `json:"cert_id"`
	KeyCompromise bool `json:"key_compromise,omitempty"`
}

// The state file.
type tlsCertStateFile struct {
	Format int `json:"format"`
	// A person asked for the network's certificate, so the pass keeps it.
	Wanted  bool                  `json:"wanted,omitempty"`
	Certs   []*tlsCertEntry       `json:"certs,omitempty"`
	Orders  []*tlsCertOrderEntry  `json:"orders,omitempty"`
	Revokes []*tlsCertRevokeEntry `json:"revokes,omitempty"`
}

// When the background pass may try a target again, and the wait its next failure sets.
type tlsCertRetry struct {
	nextTime time.Time
	wait     time.Duration
}

// The manager. See the file header.
type TlsCertManager struct {
	networkId    Id
	sidecarId    Id
	settings     *SidecarTlsSettings
	keys         TlsCertKeys
	sign         TlsKeyAttestationSignFunction
	serviceToken func(ctx context.Context, resource string, scopes []string) (string, error)
	names        func(ctx context.Context) (*TlsCertNames, error)
	store        SidecarStore
	clock        Clock
	log          Logger

	ctx    context.Context
	cancel context.CancelFunc
	// one pass at a time: a sync, an order's placing, or a status read with its install
	passLock chan struct{}
	// raised when the installed custom chains or what they present change: an install, an expiry, a revocation
	customVersion *MonitorValue[uint64]
	// a hint, a resync notice or a new generation asks for a pass
	wake chan struct{}

	stateLock sync.Mutex
	api       TlsCertApi
	loaded    bool
	state     *tlsCertStateFile
	// the keys as last read from the keychain
	currentKey *TlsDeviceKey
	pendingKey *TlsDeviceKey
	// by target: tlsCertNetworkTarget or a custom host
	targetRetries map[string]*tlsCertRetry
}

// A manager whose pass runs until Close or ctx ends, attached to no api yet. Nothing is read from the store or the
// keychain until the first pass or question.
func NewTlsCertManager(ctx context.Context, args *TlsCertManagerArgs) (*TlsCertManager, error) {
	switch {
	case args == nil:
		return nil, fmt.Errorf("%w: no tls certificate manager args", errInvalidSettings)
	case args.NetworkId == (Id{}) || args.SidecarId == (Id{}):
		return nil, fmt.Errorf("%w: a tls certificate manager needs its network and sidecar", errInvalidSettings)
	case args.Keys == nil || args.Sign == nil || args.ServiceToken == nil || args.Names == nil || args.Store == nil:
		return nil, fmt.Errorf("%w: a tls certificate manager needs its keys, sign, service token, names and store", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarTlsSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	managerCtx, cancel := context.WithCancel(ctx)
	manager := &TlsCertManager{
		networkId:     args.NetworkId,
		sidecarId:     args.SidecarId,
		settings:      settings,
		keys:          args.Keys,
		sign:          args.Sign,
		serviceToken:  args.ServiceToken,
		names:         args.Names,
		store:         args.Store,
		clock:         clock,
		log:           loggerOrDefault(args.Log),
		ctx:           managerCtx,
		cancel:        cancel,
		passLock:      make(chan struct{}, 1),
		customVersion: NewMonitorValue[uint64](0),
		wake:          make(chan struct{}, 1),
		state:         &tlsCertStateFile{Format: tlsCertStateFormat},
		targetRetries: map[string]*tlsCertRetry{},
	}
	go manager.run()
	return manager, nil
}

// Ends the pass. What is installed stays in the store.
func (self *TlsCertManager) Close() {
	self.cancel()
}

// Attaches api, one generation's, and asks for a pass; nil detaches it, and every route answers ErrTlsCertsOffline
// until the next.
func (self *TlsCertManager) SetApi(api TlsCertApi) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.api = api
	}()
	if api != nil {
		self.requestPass()
	}
}

// A notice on topic tls: a TlsHint or a resync. Either way the rows are read again, since a hint is never
// authoritative. Never blocks, so it may run on the push's goroutine.
func (self *TlsCertManager) Hint(notice PushNotice) {
	self.requestPass()
}

// Asks the run loop for a pass, without waiting. A request already standing covers this one.
func (self *TlsCertManager) requestPass() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The pass loop: a pass at each hint, at CertResyncInterval with none, and when an installed certificate reaches its
// expiry, with at least CertHintMinInterval between two.
func (self *TlsCertManager) run() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-self.clock.After(self.nextPassWait()):
		}
		if err := self.Sync(self.ctx); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[tls]certificate pass: %s\n", tlsCertErrorText(err))
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.CertHintMinInterval):
		}
	}
}

// How long the loop waits with no hint: the resync, or less when an installed certificate expires sooner.
func (self *TlsCertManager) nextPassWait() time.Duration {
	wait := self.settings.CertResyncInterval
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entry := range self.state.Certs {
		if entry.leaf == nil {
			continue
		}
		if untilExpiry := entry.leaf.NotAfter.Sub(now); 0 < untilExpiry && untilExpiry < wait {
			wait = untilExpiry
		}
	}
	return wait
}

// An error's text for a log: a refusal's route and status, and for anything else its kind, never a name.
func tlsCertErrorText(err error) string {
	var apiErr *SidecarApiError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("%s refused with %d %s", apiErr.Route, apiErr.Status, apiErr.Code)
	}
	for _, known := range []error{
		ErrTlsCertsUnconfigured, ErrTlsCertsOffline, ErrTlsCertOrderFailed, ErrTlsCertChain, ErrTlsNoIssuedCertificate,
		ErrTlsIdentifierSet, ErrSidecarStoreLocked, ErrSidecarStoreFailed, context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "failed"
}

// Takes the pass lock, or answers ctx's or the manager's end.
func (self *TlsCertManager) acquirePass(ctx context.Context) error {
	select {
	case self.passLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-self.ctx.Done():
		return ErrTlsCertManagerClosed
	}
}

// Gives the pass lock back.
func (self *TlsCertManager) releasePass() {
	<-self.passLock
}

// The attached api, or ErrTlsCertsOffline.
func (self *TlsCertManager) currentApi() (TlsCertApi, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.api == nil {
		return nil, ErrTlsCertsOffline
	}
	return self.api, nil
}

// Reads the chain back into its leaf and key hash. An entry whose chain no longer parses is no certificate.
func (self *tlsCertEntry) parse() error {
	if len(self.Chain) == 0 {
		return ErrTlsCertChain
	}
	leaf, err := x509.ParseCertificate(self.Chain[0])
	if err != nil {
		return ErrTlsCertChain
	}
	self.leaf = leaf
	self.spkiSha256 = sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return nil
}

// Loads the state file once, with the pass lock held or before any pass. Nothing stored is an empty state; a file
// that does not decode is a failure and never absence (D-CORE-15), so nothing is written over it.
func (self *TlsCertManager) loadWithPass() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	state := &tlsCertStateFile{Format: tlsCertStateFormat}
	reader, err := self.store.Open(tlsCertStateFileName)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return err
	default:
		encoded, readErr := io.ReadAll(io.LimitReader(reader, int64(self.settings.CertStateMaxByteCount)+1))
		closeErr := reader.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if self.settings.CertStateMaxByteCount < len(encoded) {
			return fmt.Errorf("%w: the tls certificate state is past its bound", ErrSidecarStoreFailed)
		}
		if err := json.Unmarshal(encoded, state); err != nil || state.Format != tlsCertStateFormat {
			return fmt.Errorf("%w: the tls certificate state does not decode", ErrSidecarStoreFailed)
		}
		// an entry whose chain does not parse is dropped: a chain is public and its row gives it again
		state.Certs = slices.DeleteFunc(state.Certs, func(entry *tlsCertEntry) bool {
			return entry == nil || entry.parse() != nil
		})
		state.Orders = slices.DeleteFunc(state.Orders, func(order *tlsCertOrderEntry) bool {
			return order == nil
		})
		state.Revokes = slices.DeleteFunc(state.Revokes, func(revoke *tlsCertRevokeEntry) bool {
			return revoke == nil
		})
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
	self.loaded = true
	return nil
}

// Writes the state file, with the pass lock held. Past CertStateMaxByteCount nothing is written and the caller's
// change is refused.
func (self *TlsCertManager) persistWithPass() error {
	encoded, err := func() ([]byte, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return json.Marshal(self.state)
	}()
	if err != nil {
		return fmt.Errorf("%w: the tls certificate state does not encode", ErrSidecarStoreFailed)
	}
	if self.settings.CertStateMaxByteCount < len(encoded) {
		return fmt.Errorf("%w: the tls certificate state is past its bound", ErrSidecarStoreFailed)
	}
	writer, err := self.store.Create(tlsCertStateFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Reads the keys from the keychain and keeps them for the handshakes, with the pass lock held.
func (self *TlsCertManager) refreshKeysWithPass() (*TlsDeviceKey, *TlsDeviceKey, error) {
	current, pending, err := self.keys.TlsKeys()
	if err != nil {
		return nil, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.currentKey = current
	self.pendingKey = pending
	return current, pending, nil
}

// The held key whose SPKI hashes to spkiSha256, nil when this device holds none.
func (self *TlsCertManager) heldKeyWithLock(spkiSha256 [sha256.Size]byte) *TlsDeviceKey {
	if self.currentKey != nil && self.currentKey.SpkiSha256() == spkiSha256 {
		return self.currentKey
	}
	if self.pendingKey != nil && self.pendingKey.SpkiSha256() == spkiSha256 {
		return self.pendingKey
	}
	return nil
}

// Whether entry answers for its names at now: its row reads issued, or custom_issued for a custom host, it is inside
// its validity, and its key is the one serving. Any other state, a lost custom row included, is no certificate.
func (self *TlsCertManager) presentedWithLock(entry *tlsCertEntry, now time.Time) bool {
	if entry.leaf == nil || now.Before(entry.leaf.NotBefore) || !now.Before(entry.leaf.NotAfter) {
		return false
	}
	if self.currentKey == nil || self.currentKey.SpkiSha256() != entry.spkiSha256 {
		return false
	}
	if entry.CustomHost != "" {
		return entry.State == TlsCertStateCustomIssued && !entry.RowLost
	}
	return entry.State == TlsCertStateIssued
}

// Whether a network leaf answers for every name: each a name the leaf lists, or one a listed wildcard covers.
func tlsLeafCoversNames(leaf *x509.Certificate, names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if slices.Contains(leaf.DNSNames, name) {
			continue
		}
		if strings.HasPrefix(name, "*.") || leaf.VerifyHostname(name) != nil {
			return false
		}
	}
	return true
}

// The newest presented entry answering names at now, nil for none. A custom host's entry answers only that one
// name, and the network's never answers a custom host's, since its leaf lists none.
func (self *TlsCertManager) selectWithLock(names []string, now time.Time) *tlsCertEntry {
	var selected *tlsCertEntry
	for _, entry := range self.state.Certs {
		if !self.presentedWithLock(entry, now) {
			continue
		}
		if entry.CustomHost != "" {
			if len(names) != 1 || names[0] != entry.CustomHost {
				continue
			}
		} else if !tlsLeafCoversNames(entry.leaf, names) {
			continue
		}
		if selected == nil || selected.leaf.NotBefore.Before(entry.leaf.NotBefore) {
			selected = entry
		}
	}
	return selected
}

// The certificate crypto/tls presents for entry, on the device key, which signs and is never read.
func (self *TlsCertManager) certificateWithLock(entry *tlsCertEntry) *tls.Certificate {
	key := self.heldKeyWithLock(entry.spkiSha256)
	if key == nil {
		return nil
	}
	return &tls.Certificate{Certificate: slices.Clone(entry.Chain), PrivateKey: key, Leaf: entry.leaf}
}

// See TlsCertificateSource. From memory once the state and keys have been read; before that it reads them, and a
// store or keychain that will not answer is no certificate, which falls back to the self-signed leaf.
func (self *TlsCertManager) IssuedTlsCertificate(names []string, now time.Time) *tls.Certificate {
	ready := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded && self.currentKey != nil
	}()
	if !ready {
		if err := self.acquirePass(self.ctx); err != nil {
			return nil
		}
		err := self.loadWithPass()
		if err == nil {
			_, _, err = self.refreshKeysWithPass()
		}
		self.releasePass()
		if err != nil {
			return nil
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry := self.selectWithLock(names, now)
	if entry == nil {
		return nil
	}
	return self.certificateWithLock(entry)
}

// The issued certificate answering names, or ErrTlsNoIssuedCertificate: what a publish presents, which never falls
// back to the self-signed leaf.
func (self *TlsCertManager) PublishCertificate(names []string) (*tls.Certificate, error) {
	canonicalNames, err := tlsCertificateNames(names)
	if err != nil {
		return nil, err
	}
	certificate := self.IssuedTlsCertificate(canonicalNames, self.clock.Now())
	if certificate == nil {
		return nil, ErrTlsNoIssuedCertificate
	}
	return certificate, nil
}

// Every installed certificate, the network's first, then by host and validity.
func (self *TlsCertManager) Certificates() []*TlsCertificateInfo {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	infos := make([]*TlsCertificateInfo, 0, len(self.state.Certs))
	for _, entry := range self.state.Certs {
		if entry.leaf == nil {
			continue
		}
		state := entry.State
		if entry.RowLost {
			state = ""
		}
		infos = append(infos, &TlsCertificateInfo{
			CertId:     entry.CertId,
			Names:      slices.Sorted(slices.Values(entry.leaf.DNSNames)),
			CustomHost: entry.CustomHost,
			NotBefore:  entry.leaf.NotBefore,
			NotAfter:   entry.leaf.NotAfter,
			SpkiSha256: entry.spkiSha256,
			State:      state,
			Presented:  self.presentedWithLock(entry, now),
		})
	}
	slices.SortStableFunc(infos, func(a *TlsCertificateInfo, b *TlsCertificateInfo) int {
		if a.CustomHost != b.CustomHost {
			return strings.Compare(a.CustomHost, b.CustomHost)
		}
		return a.NotBefore.Compare(b.NotBefore)
	})
	return infos
}

// The certificate each custom host presents now, by host: what TLS-M6-08's front lists under its registration.
func (self *TlsCertManager) CustomCertificates() []*TlsCustomCertificate {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hosts := []string{}
	for _, entry := range self.state.Certs {
		if entry.CustomHost != "" && !slices.Contains(hosts, entry.CustomHost) {
			hosts = append(hosts, entry.CustomHost)
		}
	}
	slices.Sort(hosts)
	certificates := []*TlsCustomCertificate{}
	for _, host := range hosts {
		entry := self.selectWithLock([]string{host}, now)
		if entry == nil {
			continue
		}
		if certificate := self.certificateWithLock(entry); certificate != nil {
			certificates = append(certificates, &TlsCustomCertificate{Host: host, Certificate: certificate})
		}
	}
	return certificates
}

// A count raised at each change to what the custom hosts present, and a channel that closes at the next: an install,
// an expiry or a revocation. A reader asks CustomCertificates again when it closes.
func (self *TlsCertManager) WatchCustomCertificates() (uint64, chan struct{}) {
	return self.customVersion.Get()
}

// RFC 9773's certificate id of leaf, which an order names in `replaces`: base64url of the authority key identifier,
// a dot, and base64url of the serial's DER content octets. Empty for a leaf with no authority key identifier, which
// no ARI server knows.
func tlsAriCertificateId(leaf *x509.Certificate) string {
	if leaf == nil || len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil {
		return ""
	}
	serialDer, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil {
		return ""
	}
	var serial asn1.RawValue
	if _, err := asn1.Unmarshal(serialDer, &serial); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial.Bytes)
}

// Checks chain as a certificate for key and exactly identifierSet at now, and answers its entry. Each certificate
// must be signed by the next, the leaf must be on key, and its names must be the set and nothing else. It checks no
// trust root: which CAs may issue is CAA's and the CT watch's to hold (D-TLS-8), and a visitor's own.
func (self *TlsCertManager) checkChain(chain [][]byte, key *TlsDeviceKey, identifierSet []string, now time.Time) (*tlsCertEntry, error) {
	if len(chain) == 0 || self.settings.CertChainMaxCount < len(chain) {
		return nil, fmt.Errorf("%w: its length", ErrTlsCertChain)
	}
	certificates := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: it does not parse", ErrTlsCertChain)
		}
		certificates = append(certificates, certificate)
	}
	for index := 0; index+1 < len(certificates); index += 1 {
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return nil, fmt.Errorf("%w: a link is not signed by the next", ErrTlsCertChain)
		}
	}
	leaf := certificates[0]
	if sha256.Sum256(leaf.RawSubjectPublicKeyInfo) != key.SpkiSha256() {
		return nil, fmt.Errorf("%w: another key", ErrTlsCertChain)
	}
	if 0 < len(leaf.IPAddresses) || 0 < len(leaf.EmailAddresses) || 0 < len(leaf.URIs) {
		return nil, fmt.Errorf("%w: other kinds of name", ErrTlsCertChain)
	}
	leafNames := slices.Sorted(slices.Values(leaf.DNSNames))
	if !slices.Equal(leafNames, slices.Sorted(slices.Values(identifierSet))) {
		return nil, fmt.Errorf("%w: other names", ErrTlsCertChain)
	}
	if !now.Before(leaf.NotAfter) {
		return nil, errTlsCertChainExpired
	}
	entry := &tlsCertEntry{Chain: chain}
	if err := entry.parse(); err != nil {
		return nil, err
	}
	return entry, nil
}

// Installs chain as certId's certificate for key and identifierSet, a custom host's when customHost names one, with
// the pass lock held: checks it, writes it, and, when it is the network's on the pending key, promotes that key, which
// drops the key it replaces and every chain on it. Installing an id already installed changes nothing. Answers
// whether anything changed.
func (self *TlsCertManager) installWithPass(certId Id, chain [][]byte, key *TlsDeviceKey, identifierSet []string, customHost string, state TlsCertState) (bool, error) {
	now := self.clock.Now()
	installed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.ContainsFunc(self.state.Certs, func(entry *tlsCertEntry) bool {
			return entry.CertId == certId
		})
	}()
	if installed {
		return false, nil
	}
	entry, err := self.checkChain(chain, key, identifierSet, now)
	if err != nil {
		return false, err
	}
	entry.CertId = certId
	entry.CustomHost = customHost
	entry.State = state
	testHookBarrier("tls.cert_install.before", "")
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state.Certs = append(self.state.Certs, entry)
		self.state.Orders = slices.DeleteFunc(self.state.Orders, func(order *tlsCertOrderEntry) bool {
			return order.CertId == certId
		})
	}()
	if err := self.persistWithPass(); err != nil {
		// nothing serves a chain the store did not take: a restart would not have it
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.state.Certs = slices.DeleteFunc(self.state.Certs, func(other *tlsCertEntry) bool {
				return other == entry
			})
		}()
		return false, err
	}
	testHookBarrier("tls.cert_install.after", "")
	if customHost != "" {
		self.customVersion.Update(func(version uint64) uint64 { return version + 1 })
	}
	if err := self.promoteWithPass(); err != nil {
		return true, err
	}
	return true, nil
}

// Promotes the pending key once the network's certificate on it is installed and its row reads issued, with the pass
// lock held: the swap of a rotation, with no gap, since the old certificate served until this write. Then drops
// every chain and order on a key this device no longer holds, and owes the predecessor's revocation when the
// rotation was for suspicion (§13.8). Run after each install and at each pass, so a kill between the store's write
// and the keychain's is finished by the next.
func (self *TlsCertManager) promoteWithPass() error {
	now := self.clock.Now()
	var successor *tlsCertEntry
	var pending *TlsDeviceKey
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending = self.pendingKey
		if pending == nil {
			return
		}
		for _, entry := range self.state.Certs {
			if entry.CustomHost == "" && entry.State == TlsCertStateIssued && entry.spkiSha256 == pending.SpkiSha256() &&
				!now.Before(entry.leaf.NotBefore) && now.Before(entry.leaf.NotAfter) {
				successor = entry
			}
		}
	}()
	if successor == nil {
		return nil
	}
	testHookBarrier("tls.cert_promote.before", "")
	if err := self.keys.PromoteTlsKey(pending.SpkiSha256()); err != nil && !errors.Is(err, ErrTlsDeviceKeyNotPending) {
		return err
	}
	testHookBarrier("tls.cert_promote.after", "")
	if _, _, err := self.refreshKeysWithPass(); err != nil {
		return err
	}
	customChanged := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range self.state.Certs {
			if self.heldKeyWithLock(entry.spkiSha256) != nil {
				continue
			}
			if entry.CustomHost != "" {
				customChanged = true
			} else if pending.Reason() == TlsKeyRotationSuspicion && entry.State == TlsCertStateIssued {
				self.state.Revokes = append(self.state.Revokes, &tlsCertRevokeEntry{CertId: entry.CertId, KeyCompromise: true})
			}
		}
		self.state.Certs = slices.DeleteFunc(self.state.Certs, func(entry *tlsCertEntry) bool {
			return self.heldKeyWithLock(entry.spkiSha256) == nil
		})
		self.state.Orders = slices.DeleteFunc(self.state.Orders, func(order *tlsCertOrderEntry) bool {
			return len(order.SpkiSha256) != sha256.Size || self.heldKeyWithLock([sha256.Size]byte(order.SpkiSha256)) == nil
		})
	}()
	if customChanged {
		self.customVersion.Update(func(version uint64) uint64 { return version + 1 })
	}
	return self.persistWithPass()
}

// The network's set and its hash from names.
func tlsCertNetworkSet(names *TlsCertNames) ([]string, [sha256.Size]byte, error) {
	identifierSet, err := TlsIdentifierSet(names.Root, names.Label, names.Scope, names.Aliases)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	identifierSetSha256, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return identifierSet, identifierSetSha256, nil
}

// One custom host's set and its hash, refused for a host under a URnetwork root.
func tlsCertCustomSet(names *TlsCertNames, host string) ([]string, [sha256.Size]byte, error) {
	roots := append([]string{names.Root}, names.OtherRoots...)
	identifierSet, err := TlsCustomIdentifierSet(host, roots)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	identifierSetSha256, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return identifierSet, identifierSetSha256, nil
}

// Places one order with the pass lock held: a CSR on key for exactly identifierSet, the identity key's attestation
// of that key and set, and a service token for aud certs. The order is kept before this returns, so a restart asks
// after it and places no second one. replaces is RFC 9773's id of the certificate it takes over from, empty for none
// and always empty for a custom host, whose predecessor the server names.
func (self *TlsCertManager) placeOrderWithPass(ctx context.Context, key *TlsDeviceKey, identifierSet []string, customHost string, replaces string) (*tlsCertOrderEntry, error) {
	if self.settings.CertsResource == "" {
		return nil, ErrTlsCertsUnconfigured
	}
	api, err := self.currentApi()
	if err != nil {
		return nil, err
	}
	identifierSetSha256, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the device key is not P-256", ErrTlsCertChain)
	}
	csr, err := x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{
		DNSNames:           slices.Sorted(slices.Values(identifierSet)),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, errors.New("tls certificate order: the request does not build")
	}
	spkiSha256 := key.SpkiSha256()
	attestation, err := SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           self.networkId[:],
		SidecarId:           self.sidecarId[:],
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
		IssueTimeMillis:     uint64(self.clock.Now().UnixMilli()),
	}, self.sign)
	if err != nil {
		return nil, err
	}
	serviceToken, err := self.serviceToken(ctx, self.settings.CertsResource, nil)
	if err != nil {
		return nil, err
	}
	result, err := api.TlsCertOrder(ctx, serviceToken, &TlsCertOrderArgs{Csr: csr, Attestation: attestation, Replaces: replaces})
	if err != nil {
		return nil, err
	}
	order := &tlsCertOrderEntry{
		CertId:              result.CertId,
		CustomHost:          customHost,
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state.Orders = slices.DeleteFunc(self.state.Orders, func(other *tlsCertOrderEntry) bool {
			return other.CertId == order.CertId
		})
		self.state.Orders = append(self.state.Orders, order)
	}()
	if err := self.persistWithPass(); err != nil {
		return nil, err
	}
	return order, nil
}

// The open order for a key, set and host, nil for none.
func (self *TlsCertManager) openOrder(spkiSha256 [sha256.Size]byte, identifierSetSha256 [sha256.Size]byte, customHost string) *tlsCertOrderEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, order := range self.state.Orders {
		if order.CustomHost == customHost && bytes.Equal(order.SpkiSha256, spkiSha256[:]) && bytes.Equal(order.IdentifierSetSha256, identifierSetSha256[:]) {
			return order
		}
	}
	return nil
}

// Forgets order: it ended, or its row is gone.
func (self *TlsCertManager) dropOrderWithPass(certId Id) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state.Orders = slices.DeleteFunc(self.state.Orders, func(order *tlsCertOrderEntry) bool {
			return order.CertId == certId
		})
	}()
	return self.persistWithPass()
}

// RFC 9773's id of the certificate a new network order takes over from: the newest installed network chain that is
// still inside its validity and was not revoked, whatever key it is on. Empty for none.
func (self *TlsCertManager) networkReplaces(now time.Time) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var predecessor *tlsCertEntry
	for _, entry := range self.state.Certs {
		if entry.CustomHost != "" || entry.State != TlsCertStateIssued || !now.Before(entry.leaf.NotAfter) {
			continue
		}
		if predecessor == nil || predecessor.leaf.NotBefore.Before(entry.leaf.NotBefore) {
			predecessor = entry
		}
	}
	if predecessor == nil {
		return ""
	}
	return tlsAriCertificateId(predecessor.leaf)
}

// The network's certificate on this device's key (§13.8, §13.10's step 3): the installed one when it is live on the
// key that should serve, else an order through certs' CSR proxy, followed at GET /tls/cert-order/<id> by its
// retry_after until it issues, fails, or ctx ends. A rotation's pending key is the one ordered for, with `replaces`,
// and the certificate on the old key serves until that chain installs. Asking once makes the background pass keep
// the certificate from then on. Refusals: ErrTlsCertsUnconfigured, ErrTlsCertsOffline, certs' own as a
// *SidecarApiError, ErrTlsCertOrderFailed, ErrTlsCertChain for a chain that does not check.
func (self *TlsCertManager) EnsureTlsCertificate(ctx context.Context) (*tls.Certificate, error) {
	names, err := self.names(ctx)
	if err != nil {
		return nil, err
	}
	identifierSet, identifierSetSha256, err := tlsCertNetworkSet(names)
	if err != nil {
		return nil, err
	}
	var order *tlsCertOrderEntry
	var orderKey *TlsDeviceKey
	certificate, err := func() (*tls.Certificate, error) {
		if err := self.acquirePass(ctx); err != nil {
			return nil, err
		}
		defer self.releasePass()
		if err := self.loadWithPass(); err != nil {
			return nil, err
		}
		current, pending, err := self.refreshKeysWithPass()
		if err != nil {
			return nil, err
		}
		wantedChanged := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.state.Wanted {
				return false
			}
			self.state.Wanted = true
			return true
		}()
		if wantedChanged {
			if err := self.persistWithPass(); err != nil {
				return nil, err
			}
		}
		orderKey = current
		if pending != nil {
			orderKey = pending
		} else if certificate := self.IssuedTlsCertificate(identifierSet, self.clock.Now()); certificate != nil {
			return certificate, nil
		}
		order = self.openOrder(orderKey.SpkiSha256(), identifierSetSha256, "")
		if order == nil {
			order, err = self.placeOrderWithPass(ctx, orderKey, identifierSet, "", self.networkReplaces(self.clock.Now()))
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	}()
	if err != nil || certificate != nil {
		return certificate, err
	}
	for {
		wait, done, err := self.stepOrder(ctx, order, orderKey, identifierSet)
		if err != nil {
			return nil, err
		}
		if done {
			certificate := self.IssuedTlsCertificate(identifierSet, self.clock.Now())
			if certificate == nil {
				return nil, ErrTlsNoIssuedCertificate
			}
			return certificate, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.ctx.Done():
			return nil, ErrTlsCertManagerClosed
		case <-self.clock.After(wait):
		}
	}
}

// One read of order's status: installs its chain when it issued, answering done; drops it and answers
// ErrTlsCertOrderFailed when it ended any other way or reads as a state this build does not know; else answers how
// long to wait, the server's retry_after held to the settings' bounds.
func (self *TlsCertManager) stepOrder(ctx context.Context, order *tlsCertOrderEntry, key *TlsDeviceKey, identifierSet []string) (time.Duration, bool, error) {
	if err := self.acquirePass(ctx); err != nil {
		return 0, false, err
	}
	defer self.releasePass()
	api, err := self.currentApi()
	if err != nil {
		return 0, false, err
	}
	serviceToken, err := self.serviceToken(ctx, self.settings.CertsResource, nil)
	if err != nil {
		return 0, false, err
	}
	status, err := api.TlsCertOrderStatus(ctx, serviceToken, order.CertId)
	if err != nil {
		var apiErr *SidecarApiError
		if errors.As(err, &apiErr) && apiErr.Status == 404 {
			// the row is gone, as after a restore: the next call orders again
			if dropErr := self.dropOrderWithPass(order.CertId); dropErr != nil {
				return 0, false, dropErr
			}
			return 0, false, fmt.Errorf("%w: its row is gone", ErrTlsCertOrderFailed)
		}
		return 0, false, err
	}
	switch status.State {
	case TlsCertStateIssued:
		if len(status.Chain) == 0 {
			// issued with its chain still to come: ask again
			break
		}
		if _, err := self.installWithPass(order.CertId, status.Chain, key, identifierSet, order.CustomHost, TlsCertStateIssued); err != nil {
			if errors.Is(err, ErrTlsCertChain) {
				if dropErr := self.dropOrderWithPass(order.CertId); dropErr != nil {
					return 0, false, dropErr
				}
			}
			return 0, false, err
		}
		return 0, true, nil
	case TlsCertStateQueued, TlsCertStateOrdering, TlsCertStateWaitingDns:
	default:
		if err := self.dropOrderWithPass(order.CertId); err != nil {
			return 0, false, err
		}
		return 0, false, ErrTlsCertOrderFailed
	}
	wait := time.Duration(status.RetryAfterMs) * time.Millisecond
	if wait <= 0 {
		wait = self.settings.CertOrderPollInterval
	}
	wait = max(wait, self.settings.CertOrderPollMinInterval)
	wait = min(wait, self.settings.CertOrderPollMaxInterval)
	return wait, false, nil
}

// Whether the background pass may try target at now.
func (self *TlsCertManager) retryDue(target string, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	retry, ok := self.targetRetries[target]
	return !ok || !now.Before(retry.nextTime)
}

// Records target's attempt: a success forgets its backoff, a failure doubles it within the settings' bounds.
func (self *TlsCertManager) retryNote(target string, now time.Time, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err == nil {
		delete(self.targetRetries, target)
		return
	}
	retry, ok := self.targetRetries[target]
	if !ok {
		retry = &tlsCertRetry{}
		self.targetRetries[target] = retry
	}
	retry.wait = min(max(2*retry.wait, self.settings.CertRetryMinInterval), self.settings.CertRetryMaxInterval)
	retry.nextTime = now.Add(retry.wait)
}

// Whether record is this sidecar's own row of this network.
func (self *TlsCertManager) ownRow(record *TlsCertRecord) bool {
	return record != nil && record.NetworkId == self.networkId && record.SidecarId == self.sidecarId
}

// GET /tls/certs through the generation attached now: the network's rows as the server answers them, unjudged, which
// D-TLS-8's CT watch reads logged certificates back against. ErrTlsCertsOffline with no generation attached.
func (self *TlsCertManager) Rows(ctx context.Context) (*TlsCertsResult, error) {
	api, err := self.currentApi()
	if err != nil {
		return nil, err
	}
	return api.TlsCerts(ctx)
}

// One pass. See the file header. The first error is answered once the rest of the pass has run, so a names source
// that will not answer still lets a revocation take a certificate away.
func (self *TlsCertManager) Sync(ctx context.Context) error {
	if err := self.acquirePass(ctx); err != nil {
		return err
	}
	defer self.releasePass()
	if err := self.loadWithPass(); err != nil {
		return err
	}
	current, pending, err := self.refreshKeysWithPass()
	if err != nil {
		return err
	}
	api, err := self.currentApi()
	if err != nil {
		// with no rows to read, what time alone decides still applies
		return errors.Join(err, self.expireWithPass())
	}
	result, err := api.TlsCerts(ctx)
	if err != nil {
		return errors.Join(err, self.expireWithPass())
	}
	ownRows := map[Id]*TlsCertRecord{}
	for _, records := range [][]*TlsCertRecord{result.Certs, result.QueuedCsrs} {
		for _, record := range records {
			if self.ownRow(record) {
				ownRows[record.CertId] = record
			}
		}
	}
	now := self.clock.Now()
	var passErr error
	note := func(err error) {
		if err != nil && passErr == nil {
			passErr = err
		}
	}

	// the rows' states, which only ever take a certificate away here
	changed, customChanged := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		changed := false
		customChanged := false
		for _, entry := range self.state.Certs {
			state := entry.State
			rowLost := true
			if row, ok := ownRows[entry.CertId]; ok {
				state = row.State
				rowLost = false
			}
			if state == entry.State && rowLost == entry.RowLost {
				continue
			}
			before := self.presentedWithLock(entry, now)
			entry.State = state
			entry.RowLost = rowLost
			changed = true
			if entry.CustomHost != "" && before != self.presentedWithLock(entry, now) {
				customChanged = true
			}
		}
		return changed, customChanged
	}()
	if changed {
		note(self.persistWithPass())
	}
	if customChanged {
		self.customVersion.Update(func(version uint64) uint64 { return version + 1 })
	}
	note(self.expireWithPass())

	// orders whose rows ended or are gone
	endedOrderIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		endedOrderIds := []Id{}
		for _, order := range self.state.Orders {
			row, ok := ownRows[order.CertId]
			if !ok {
				endedOrderIds = append(endedOrderIds, order.CertId)
				continue
			}
			switch row.State {
			case TlsCertStateQueued, TlsCertStateOrdering, TlsCertStateWaitingDns, TlsCertStateIssued,
				TlsCertStateCustomQueued, TlsCertStateCustomOrdering, TlsCertStateCustomIssued:
			default:
				endedOrderIds = append(endedOrderIds, order.CertId)
			}
		}
		return endedOrderIds
	}()
	for _, certId := range endedOrderIds {
		note(self.dropOrderWithPass(certId))
	}

	note(self.revokeOwedWithPass(ctx, api, ownRows))

	names, err := self.names(ctx)
	if err != nil {
		return errors.Join(passErr, err)
	}
	networkSet, networkSetSha256, err := tlsCertNetworkSet(names)
	if err != nil {
		return errors.Join(passErr, err)
	}
	// read at each row, since an install may promote the pending key and drop the one it replaces
	heldKey := func(spkiSha256 []byte) *TlsDeviceKey {
		if len(spkiSha256) != sha256.Size {
			return nil
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.heldKeyWithLock([sha256.Size]byte(spkiSha256))
	}

	// the network's rows, oldest first: chains to install, and open rows a lost state file forgot
	networkRows := []*TlsCertRecord{}
	for _, row := range ownRows {
		networkRows = append(networkRows, row)
	}
	slices.SortFunc(networkRows, func(a *TlsCertRecord, b *TlsCertRecord) int {
		return a.CertId.Cmp(b.CertId)
	})
	for _, row := range networkRows {
		if !bytes.Equal(row.IdentifierSetSha256, networkSetSha256[:]) {
			continue
		}
		key := heldKey(row.SpkiSha256)
		if key == nil {
			continue
		}
		switch row.State {
		case TlsCertStateIssued:
			if len(row.Chain) == 0 {
				continue
			}
			if _, err := self.installWithPass(row.CertId, row.Chain, key, networkSet, "", TlsCertStateIssued); err != nil && !errors.Is(err, errTlsCertChainExpired) {
				note(err)
			}
		case TlsCertStateQueued, TlsCertStateOrdering, TlsCertStateWaitingDns:
			if self.openOrder(key.SpkiSha256(), networkSetSha256, "") == nil {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.state.Orders = append(self.state.Orders, &tlsCertOrderEntry{
						CertId:              row.CertId,
						SpkiSha256:          bytes.Clone(row.SpkiSha256),
						IdentifierSetSha256: bytes.Clone(row.IdentifierSetSha256),
					})
				}()
				note(self.persistWithPass())
			}
		}
	}
	note(self.promoteWithPass())
	current, pending, err = self.refreshKeysWithPass()
	if err != nil {
		return errors.Join(passErr, err)
	}

	note(self.keepNetworkWithPass(ctx, current, pending, networkSet, networkSetSha256, now))

	for _, host := range names.CustomHosts {
		note(self.keepCustomHostWithPass(ctx, names, host, current, pending, ownRows, now))
	}
	return passErr
}

// Drops every installed chain past its validity, with the pass lock held, and raises the custom signal when one was
// a custom host's: a predecessor is kept exactly until it expires.
func (self *TlsCertManager) expireWithPass() error {
	now := self.clock.Now()
	expired, customExpired := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		expired := false
		customExpired := false
		self.state.Certs = slices.DeleteFunc(self.state.Certs, func(entry *tlsCertEntry) bool {
			if now.Before(entry.leaf.NotAfter) {
				return false
			}
			expired = true
			if entry.CustomHost != "" {
				customExpired = true
			}
			return true
		})
		return expired, customExpired
	}()
	if !expired {
		return nil
	}
	if customExpired {
		self.customVersion.Update(func(version uint64) uint64 { return version + 1 })
	}
	return self.persistWithPass()
}

// Sends each revocation owed, with the pass lock held: one is done when the route took it, or when its row is no
// longer issued, since something else already retired it.
func (self *TlsCertManager) revokeOwedWithPass(ctx context.Context, api TlsCertApi, ownRows map[Id]*TlsCertRecord) error {
	owed := func() []*tlsCertRevokeEntry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.state.Revokes)
	}()
	if len(owed) == 0 {
		return nil
	}
	var firstErr error
	doneIds := []Id{}
	for _, revoke := range owed {
		if row, ok := ownRows[revoke.CertId]; !ok || row.State != TlsCertStateIssued {
			doneIds = append(doneIds, revoke.CertId)
			continue
		}
		err := api.TlsCertRevoke(ctx, &TlsCertRevokeArgs{CertId: revoke.CertId, KeyCompromise: revoke.KeyCompromise})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		doneIds = append(doneIds, revoke.CertId)
	}
	if len(doneIds) == 0 {
		return firstErr
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state.Revokes = slices.DeleteFunc(self.state.Revokes, func(revoke *tlsCertRevokeEntry) bool {
			return slices.Contains(doneIds, revoke.CertId)
		})
	}()
	return errors.Join(firstErr, self.persistWithPass())
}

// Keeps the network's certificate once a person asked for one, with the pass lock held: sets a pending successor
// when the key is due, and places an order, with `replaces`, when the key that should serve has no live certificate
// and no open order, which covers a rotation's successor and a live local chain whose row a restore lost. A
// certificate that was revoked or expired is not ordered again here: only a person's EnsureTlsCertificate does that.
func (self *TlsCertManager) keepNetworkWithPass(ctx context.Context, current *TlsDeviceKey, pending *TlsDeviceKey, networkSet []string, networkSetSha256 [sha256.Size]byte, now time.Time) error {
	wanted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.state.Wanted
	}()
	if !wanted || !self.retryDue(tlsCertNetworkTarget, now) {
		return nil
	}
	if pending == nil && TlsKeyRotationDue(current, now, self.settings) {
		rotated, err := self.keys.RotateTlsKey(TlsKeyRotationScheduled)
		if err != nil {
			self.retryNote(tlsCertNetworkTarget, now, err)
			return err
		}
		pending = rotated
		if _, _, err := self.refreshKeysWithPass(); err != nil {
			return err
		}
	}
	orderKey := current
	rowLost := false
	if pending != nil {
		orderKey = pending
	} else {
		// the key serves: order only for a live chain whose row is gone
		live := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			live := false
			for _, entry := range self.state.Certs {
				if entry.CustomHost != "" || entry.spkiSha256 != current.SpkiSha256() || !now.Before(entry.leaf.NotAfter) {
					continue
				}
				if entry.RowLost {
					rowLost = true
				} else if entry.State == TlsCertStateIssued {
					live = true
				}
			}
			return live
		}()
		if live || !rowLost {
			return nil
		}
	}
	if self.openOrder(orderKey.SpkiSha256(), networkSetSha256, "") != nil {
		return nil
	}
	replaces := self.networkReplaces(now)
	if rowLost {
		replaces = self.lostRowReplaces(current, now)
	}
	_, err := self.placeOrderWithPass(ctx, orderKey, networkSet, "", replaces)
	self.retryNote(tlsCertNetworkTarget, now, err)
	return err
}

// RFC 9773's id of the newest live network chain on key whose row is gone, which its new order names in `replaces`
// so the order stays outside §13.8's limits (plan reading 7).
func (self *TlsCertManager) lostRowReplaces(key *TlsDeviceKey, now time.Time) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var lost *tlsCertEntry
	for _, entry := range self.state.Certs {
		if entry.CustomHost != "" || !entry.RowLost || entry.spkiSha256 != key.SpkiSha256() || !now.Before(entry.leaf.NotAfter) {
			continue
		}
		if lost == nil || lost.leaf.NotBefore.Before(entry.leaf.NotBefore) {
			lost = entry
		}
	}
	if lost == nil {
		return ""
	}
	return tlsAriCertificateId(lost.leaf)
}

// Keeps one custom host's certificate, with the pass lock held (DESIGN-DETAILS 17.7's line for this task): installs
// the chains its custom_issued rows hold, and queues one CSR naming exactly the host when the device has no open row
// for it and no live certificate, or when its newest row failed for its attestation. The server names the
// predecessor, so `replaces` stays empty.
func (self *TlsCertManager) keepCustomHostWithPass(ctx context.Context, names *TlsCertNames, host string, current *TlsDeviceKey, pending *TlsDeviceKey, ownRows map[Id]*TlsCertRecord, now time.Time) error {
	customSet, customSetSha256, err := tlsCertCustomSet(names, host)
	if err != nil {
		return err
	}
	orderKey := current
	if pending != nil {
		orderKey = pending
	}
	orderSpkiSha256 := orderKey.SpkiSha256()
	hostRows := []*TlsCertRecord{}
	for _, row := range ownRows {
		if bytes.Equal(row.IdentifierSetSha256, customSetSha256[:]) {
			hostRows = append(hostRows, row)
		}
	}
	// oldest first: an Id orders by its creation
	slices.SortFunc(hostRows, func(a *TlsCertRecord, b *TlsCertRecord) int {
		return a.CertId.Cmp(b.CertId)
	})
	var firstErr error
	open := false
	for _, row := range hostRows {
		switch {
		case row.State == TlsCertStateCustomIssued && 0 < len(row.Chain):
			var key *TlsDeviceKey
			for _, held := range []*TlsDeviceKey{current, pending} {
				if held == nil {
					continue
				}
				heldSpkiSha256 := held.SpkiSha256()
				if bytes.Equal(row.SpkiSha256, heldSpkiSha256[:]) {
					key = held
				}
			}
			if key == nil {
				continue
			}
			// a chain on another key, with a second name or that does not parse is not installed
			_, err := self.installWithPass(row.CertId, row.Chain, key, customSet, host, TlsCertStateCustomIssued)
			if err != nil && !errors.Is(err, errTlsCertChainExpired) && firstErr == nil {
				firstErr = err
			}
		case row.State.CustomOpen():
			// the order key's open row waits for a desktop. One on another key that a desktop already took cannot
			// be replaced (409 in_flight), and one still queued is superseded by the new CSR.
			if bytes.Equal(row.SpkiSha256, orderSpkiSha256[:]) || row.State == TlsCertStateCustomOrdering {
				open = true
			}
		}
	}
	if open || !self.retryDue(host, now) {
		return firstErr
	}
	live := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range self.state.Certs {
			if entry.CustomHost == host && entry.spkiSha256 == orderSpkiSha256 && entry.State == TlsCertStateCustomIssued &&
				!entry.RowLost && now.Before(entry.leaf.NotAfter) {
				return true
			}
		}
		return false
	}()
	// the newest row decides a requeue: one that failed for its attestation asks for a new CSR, once, since the new
	// row is then the newest
	attestationFailed := 0 < len(hostRows) && hostRows[len(hostRows)-1].State == TlsCertStateFailed &&
		hostRows[len(hostRows)-1].CustomReason == TlsCustomReasonAttestation
	if live && !attestationFailed {
		return firstErr
	}
	_, err = self.placeOrderWithPass(ctx, orderKey, customSet, host, "")
	self.retryNote(host, now, err)
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Sets a pending successor for reason and asks for a pass, which orders its certificate with `replaces`. The key
// serving keeps serving until that chain installs. After suspicion the predecessor's certificate is revoked with
// keyCompromise once its successor serves (§13.8).
func (self *TlsCertManager) RotateTlsKey(ctx context.Context, reason TlsKeyRotationReason) error {
	if err := self.acquirePass(ctx); err != nil {
		return err
	}
	defer self.releasePass()
	if _, err := self.keys.RotateTlsKey(reason); err != nil {
		return err
	}
	if _, _, err := self.refreshKeysWithPass(); err != nil {
		return err
	}
	self.requestPass()
	return nil
}

// Marks this device's certificate certId for revocation at POST /tls/cert-revoke and stops presenting it at once,
// before the CA has heard.
func (self *TlsCertManager) RevokeTlsCertificate(ctx context.Context, certId Id, keyCompromise bool) error {
	if err := self.acquirePass(ctx); err != nil {
		return err
	}
	defer self.releasePass()
	if err := self.loadWithPass(); err != nil {
		return err
	}
	api, err := self.currentApi()
	if err != nil {
		return err
	}
	if err := api.TlsCertRevoke(ctx, &TlsCertRevokeArgs{CertId: certId, KeyCompromise: keyCompromise}); err != nil {
		return err
	}
	customChanged := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range self.state.Certs {
			if entry.CertId != certId {
				continue
			}
			if entry.CustomHost != "" {
				entry.State = TlsCertStateCustomRevoking
				customChanged = true
			} else {
				entry.State = TlsCertStateRevoking
			}
		}
	}()
	if customChanged {
		self.customVersion.Update(func(version uint64) uint64 { return version + 1 })
	}
	return self.persistWithPass()
}

// §12.8's reclaim, signed by the device's TLS key: the one signature besides a CSR and a handshake that key makes.
type TlsLabelReclaim struct {
	// The leaf, in DER, of this device's certificate naming the name: what VerifyDnsReclaimProof reads the key from.
	LeafDer []byte
	// The key's signature over the proof's bytes.
	Signature []byte
}

// Signs proof with the device key that holds a certificate naming proof's name, exactly or by the wildcard one level
// above, and answers it with that leaf. A lapsed certificate still proves who held the name, so validity is not
// asked; ErrTlsNoIssuedCertificate when no installed chain on a key this device holds names it.
func (self *TlsCertManager) SignLabelReclaim(ctx context.Context, proof *DnsReclaimProof) (*TlsLabelReclaim, error) {
	if proof == nil {
		return nil, ErrDnsReclaimProofInvalid
	}
	if err := self.acquirePass(ctx); err != nil {
		return nil, err
	}
	defer self.releasePass()
	if err := self.loadWithPass(); err != nil {
		return nil, err
	}
	if _, _, err := self.refreshKeysWithPass(); err != nil {
		return nil, err
	}
	name := canonicalDnsReclaimName(proof.Name)
	var leafDer []byte
	var key *TlsDeviceKey
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range self.state.Certs {
			if entry.CustomHost != "" || !tlsLeafCoversNames(entry.leaf, []string{name}) {
				continue
			}
			if held := self.heldKeyWithLock(entry.spkiSha256); held != nil {
				key = held
				leafDer = bytes.Clone(entry.Chain[0])
			}
		}
	}()
	if key == nil {
		return nil, ErrTlsNoIssuedCertificate
	}
	signature, err := proof.Sign(key)
	if err != nil {
		return nil, err
	}
	return &TlsLabelReclaim{LeafDer: leafDer, Signature: signature}, nil
}
