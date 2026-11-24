//go:build !sidecar_http && !ios_extension

// The tls SidecarComponent (§5.4, §13.7, §13.8; TLS-M5-18, TLS-M8-01): the device's certificate manager on a Sidecar's
// client generations, and what Sidecar.EnsureTlsCertificate, TlsCertificates, TlsSignLabelReclaim and ListenTls run
// on. The manager and what it installed live for the network across generations, since a certificate outlives a
// reconnect; each generation lends it the SidecarApi's routes and the push feed's topic tls, and takes them back when
// it ends.
//
// The component installs the manager behind Sidecar.TlsDeviceCertificate as it is made, so an issued chain answers
// from then on and the self-signed leaf only where none covers the names. Its keychain namespace is the device key's
// (tls_key.go) and its sealed directory holds certificates alone: the key never enters it.
//
// The names a certificate is ordered for come from the zone the DnsClient reads (its root, the network's label and
// alias), and the set is computed here by TlsIdentifierSet, so no certificate row's names are ever taken as the
// device's. The verified ownership rows and the device's publish grants select its scope and mapped custom hosts.
//
// The manager's service token for aud certs, as an ordering desktop's (tls_custom_domain.go), is certsServiceToken's,
// which reads why one could not be had as evs's and gkm's clients do: a refusal for good ends the call at once, and
// what may change goes again within SidecarTlsSettings' bound.
//
// Two kinds of host make one (§18.4). A host that stays up, a desktop or CLI daemon, takes TlsComponentArgs, which runs
// D-TLS-8's CT watch while it listens (tls_ct.go). An app's sidecar role runs only while the app is open (owner
// decision 197), so it takes TlsForegroundComponentArgs, which runs no watch and makes no CT client: the network's
// other listening devices that stay up keep the watch (TLS-M8-01). The CLI and SDK install the appropriate component.
//
// An app listener (ListenTls, §13.17's app listeners): a tls/ name this process serves itself rather than through a
// local port, as sdk's SidecarSockets.Listen does on a tls/ name (§18.5). Its registration goes through Sidecar.Listen,
// so §5.4's gate holds it as any tls/ listen, and §13.7's front runs on it, TLS ending on this device's key. The
// front's target is the listener's Accept: each connection the front opens to its target, which only an audience
// check's pass opens (TlsFrontConn.openTarget, FI-11), is one end of an in-memory pipe whose other end Accept answers,
// so the app reads the requests of visitors its grant admits, as the HTTP front forwards them over HTTP/1.1, and
// nothing before. The registration takes §9.5's default app mode, http, with h2 and http/1.1; raw is a desktop
// publish's (`ur bridge public-tls --tcp`). The front's target probe is off, since no probe can ask an Accept, so the
// registration serves as it began. No timer here closes or unlistens a listener: an app the OS suspends stops sending
// heartbeats, its registration lapses by the sockets service's 45 s lease (§9.5), and on resume the registrar sends
// its whole set again, which registers the name anew while the listener's Accept waits on as before.
//
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Its keychain namespace and its sealed directory (§5.9): the device key's namespace, tlsSecretsNamespace.
const tlsComponentName = "tls"

var (
	// No tls component is attached to this Sidecar, so nothing orders or holds an issued certificate.
	ErrTlsComponentAbsent = errors.New("tls: this sidecar runs no tls component")
	// A name this device cannot serve, including a scope it does not own or the mail receiver's system publish.
	ErrTlsListenInvalid = errors.New("tls listen refused")
	// The tls component has closed, so it serves no new listener.
	errTlsComponentClosed = errors.New("tls: the component has closed")
	// No client generation is attached, so the network's tier cannot be read.
	errTlsComponentOffline = errors.New("tls: offline")
)

// The local address an app listener's front names for its target, which names no service: every connection to the
// target goes through the listener's own dial, and the HTTP front only keys its target connections by it.
const tlsListenerTargetAddress = "0.0.0.0:0"

// What NewTlsComponent takes. Sidecar.TlsComponentArgs fills it for the network a Sidecar is enrolled in.
type TlsComponentArgs struct {
	// The manager's parts.
	Manager *TlsCertManagerArgs
	// Sidecar.setTlsCertificateSource: installs the manager behind TlsDeviceCertificate, nil removing it.
	SetSource func(source TlsCertificateSource) error
	// D-TLS-8's CT watch (tls_ct.go). nil runs none. Its NetworkId, Rows, Names, Store, Settings, Clock and Log are
	// the manager's where it leaves them unset.
	CtWatch *TlsCtWatchArgs
	// Sidecar.setTlsCtWatch: attaches the watch to SidecarStatus, nil detaching it.
	SetCtWatch func(watch sidecarCtWatch)
	// Called at Close, after the watch has ended: what releases the CT client the args' Sources came from.
	CloseCtSources func()
	// What §13.10's publishes need beyond the Sidecar: the grant filer, the client names and the daemon's ports
	// (tls_publish.go). nil leaves every publish refused.
	Publish *TlsPublishArgs
	// The Sidecar the publishes run on, which Sidecar.TlsComponentArgs sets. nil runs no publisher.
	sidecar *Sidecar
}

// The tls component.
type TlsComponent struct {
	// ends with the component's maker; its app listeners' fronts run under it
	ctx       context.Context
	manager   *TlsCertManager
	networkId Id
	// the names the manager orders for, which an app listener's server names come from
	names     func(ctx context.Context) (*TlsCertNames, error)
	setSource func(source TlsCertificateSource) error
	// nil when the component runs no CT watch
	ctWatch        *tlsCtWatch
	setCtWatch     func(watch sidecarCtWatch)
	closeCtSources func()
	// §13.10's publishes; nil for a component made without its Sidecar
	publisher *tlsPublisher

	stateLock sync.Mutex
	// raised for each generation attached, so an older one's end does not detach a newer one's api
	generationSeq uint64
	// closed once the newest generation's end has been followed: its hints removed and its api taken back
	generationEnded chan struct{}
	// the newest generation's api, which an app listener reads the network's tier from; nil between generations
	api *SidecarApi
	// the app listeners serving on this component (ListenTls)
	listeners map[*TlsListener]bool
	closed    bool
}

// The device key as the keychain's record holds it, through this Sidecar's key lock.
type sidecarTlsCertKeys struct {
	sidecar *Sidecar
}

// See TlsCertKeys.
func (self *sidecarTlsCertKeys) TlsKeys() (*TlsDeviceKey, *TlsDeviceKey, error) {
	state, secrets, err := self.sidecar.tlsDevice()
	if err != nil {
		return nil, nil, err
	}
	keys, err := state.keys(secrets, self.sidecar.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	return keys.current, keys.pending, nil
}

// See TlsCertKeys.
func (self *sidecarTlsCertKeys) RotateTlsKey(reason TlsKeyRotationReason) (*TlsDeviceKey, error) {
	state, secrets, err := self.sidecar.tlsDevice()
	if err != nil {
		return nil, err
	}
	keys, err := state.rotate(secrets, self.sidecar.clock.Now(), reason)
	if err != nil {
		return nil, err
	}
	return keys.pending, nil
}

// See TlsCertKeys.
func (self *sidecarTlsCertKeys) PromoteTlsKey(spkiSha256 [sha256.Size]byte) error {
	state, secrets, err := self.sidecar.tlsDevice()
	if err != nil {
		return err
	}
	_, err = state.promote(secrets, spkiSha256)
	return err
}

// The names of this Sidecar's network as its DnsClient's zone gives them: the root, the label and the alias. No
// name from another device is accepted for ordering.
func (self *Sidecar) tlsCertNames(ctx context.Context) (*TlsCertNames, error) {
	client, err := self.Dns()
	if err != nil {
		return nil, err
	}
	// Read current ownership when an order, publish or DNS hint asks. Readiness may change without a record write.
	zone, err := client.fetchZone(ctx)
	if err != nil {
		return nil, err
	}
	identity := self.currentIdentity()
	state, err := self.configState()
	if identity == nil || err != nil {
		return nil, ErrTlsPublishUnavailable
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	scope, scoped := state.TeamScopeForDevice(identity.SidecarId)
	if scoped && (scope.Label == "" || scope.MemberId != (Id{}) && !acl.ConsentedFor(identity.SidecarId, scope.MemberId)) {
		return nil, ErrTlsPublishUnavailable
	}
	return tlsDeviceZoneNames(zone, scope.Label, func(owner string) bool {
		return tlsDevicePublishGrant(acl, identity.SidecarId, owner, tlsCustomPublishPorts, self.clock.Now())
	}), nil
}

// The carrier's canonical operator owners and this device's verified publish grants select its custom SANs.
func tlsDeviceZoneNames(zone *DnsZone, scope string, granted func(string) bool) *TlsCertNames {
	names := &TlsCertNames{Root: strings.TrimSuffix(zone.Root, "."), Label: zone.Label, Scope: scope, CustomHostOwners: map[string]string{}}
	if zone.Alias != "" && scope == "" {
		names.Aliases = []string{zone.Alias}
	}
	for _, mapping := range zone.CustomHosts {
		owner, inside := strings.CutSuffix(strings.TrimSuffix(mapping.Owner, "."), "."+zone.Label+"."+names.Root)
		if !inside || mapping.State != DnsCustomHostStateActive || granted == nil || !granted(owner) {
			continue
		}
		if _, err := TlsCustomIdentifierSet(mapping.Host, []string{names.Root}); err != nil {
			continue
		}
		names.CustomHosts = append(names.CustomHosts, mapping.Host)
		names.CustomHostOwners[mapping.Host] = owner
	}
	return names
}

// A service token for aud certs at resource (§7.8), as the certificate manager's calls and an ordering desktop's custom
// routes present it: ServiceToken's, read by why one could not be had (sidecarRetryServiceToken). A refusal for good,
// the exchange's invalid_grant or no enrolled client say, ends the call at once, and one that may change, no answer
// from api, its 429 or 5xx, a keychain still locked or no api yet, is asked again within SidecarTlsSettings'
// CertsExchangeRetryCount. No request goes to api's certs routes without it.
func (self *Sidecar) certsServiceToken(ctx context.Context, resource string, scopes []string) (string, error) {
	settings := self.settings.Tls
	if settings == nil {
		settings = DefaultSidecarTlsSettings()
	}
	retry := sidecarServiceTokenRetry{
		count:   settings.CertsExchangeRetryCount,
		wait:    settings.CertsExchangeRetryWait,
		maxWait: settings.CertsExchangeRetryMaxWait,
	}
	return sidecarRetryServiceToken(ctx, self.clock, retry, func(ctx context.Context) (string, error) {
		return self.ServiceToken(ctx, resource, scopes)
	})
}

// The args a TlsComponent takes from this Sidecar for the network it is enrolled in, on a host that stays up (a
// desktop or CLI daemon): its settings, device key, Sign, certs' ServiceToken (certsServiceToken), zone, sealed
// directory, clock and log, and D-TLS-8's CT watch on a keyless client, which passes while this sidecar listens.
func (self *Sidecar) TlsComponentArgs() (*TlsComponentArgs, error) {
	return self.tlsComponentArgs(true)
}

// TlsComponentArgs for a host that does not stay up, an app's sidecar role, which runs only while the app is open
// (§18.4, owner decision 197): no CT watch and no CT client, since a pass about every 6 hours means nothing to a host
// that is suspended between foregrounds, and the network's listening devices that stay up keep the watch (TLS-M8-01).
func (self *Sidecar) TlsForegroundComponentArgs() (*TlsComponentArgs, error) {
	return self.tlsComponentArgs(false)
}

// The args for this Sidecar's network, with D-TLS-8's watch when watchCt.
func (self *Sidecar) tlsComponentArgs(watchCt bool) (*TlsComponentArgs, error) {
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil || self.instance == nil {
		return nil, fmt.Errorf("%w: tls needs an enrolled network", errInvalidSettings)
	}
	if _, _, err := self.tlsDevice(); err != nil {
		return nil, err
	}
	store, err := self.instance.Store(networkId).Directory(tlsComponentName, tlsComponentName)
	if err != nil {
		return nil, err
	}
	args := &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId:    *networkId,
			SidecarId:    identity.SidecarId,
			Settings:     self.settings.Tls,
			Keys:         &sidecarTlsCertKeys{sidecar: self},
			Sign:         self.Sign,
			ServiceToken: self.certsServiceToken,
			Names:        self.tlsCertNames,
			Store:        store,
			Clock:        self.clock,
			Log:          self.log,
		},
		SetSource: self.setTlsCertificateSource,
		sidecar:   self,
	}
	if !watchCt {
		return args, nil
	}
	// keyless: a Team's Cert Spotter key has no place to be read from yet
	ctClient, err := NewTlsCtClient(nil)
	if err != nil {
		return nil, err
	}
	args.CtWatch = &TlsCtWatchArgs{
		Sources: ctClient.Sources(),
		Identities: func() TlsCtIdentities {
			return NewTlsCtAuthorityIdentities(self.authority())
		},
		Listening: self.tlsListening,
		Event: func(event SidecarEvent) {
			self.Alarm(event)
		},
	}
	args.SetCtWatch = self.setTlsCtWatch
	args.CloseCtSources = ctClient.Close
	return args, nil
}

// Whether this sidecar listens on a published name now, a publish's or an app listener's, which is when D-TLS-8 has
// it watch CT.
func (self *Sidecar) tlsListening() bool {
	if 0 < len(self.TlsPublishedHosts()) {
		return true
	}
	component := self.tlsComponent()
	return component != nil && component.listening()
}

// A component whose manager runs until Close or ctx ends, attached to no generation yet, installed behind
// TlsDeviceCertificate.
func NewTlsComponent(ctx context.Context, args *TlsComponentArgs) (*TlsComponent, error) {
	if args == nil || args.Manager == nil {
		return nil, fmt.Errorf("%w: no tls component args", errInvalidSettings)
	}
	manager, err := NewTlsCertManager(ctx, args.Manager)
	if err != nil {
		return nil, err
	}
	if args.SetSource != nil {
		if err := args.SetSource(manager); err != nil {
			manager.Close()
			return nil, err
		}
	}
	self := &TlsComponent{
		ctx:            ctx,
		manager:        manager,
		networkId:      args.Manager.NetworkId,
		names:          args.Manager.Names,
		setSource:      args.SetSource,
		setCtWatch:     args.SetCtWatch,
		closeCtSources: args.CloseCtSources,
		listeners:      map[*TlsListener]bool{},
	}
	if args.sidecar != nil {
		self.publisher = newTlsPublisher(&sidecarTlsPublishBackend{sidecar: args.sidecar, args: args.Publish, settings: args.Manager.Settings}, args.Manager.Settings)
	}
	if args.CtWatch != nil {
		watchArgs := *args.CtWatch
		if watchArgs.NetworkId == (Id{}) {
			watchArgs.NetworkId = args.Manager.NetworkId
		}
		if watchArgs.Rows == nil {
			watchArgs.Rows = manager.Rows
		}
		if watchArgs.Names == nil {
			watchArgs.Names = args.Manager.Names
		}
		if watchArgs.Store == nil {
			watchArgs.Store = args.Manager.Store
		}
		if watchArgs.Settings == nil {
			watchArgs.Settings = args.Manager.Settings
		}
		if watchArgs.Clock == nil {
			watchArgs.Clock = args.Manager.Clock
		}
		if watchArgs.Log == nil {
			watchArgs.Log = args.Manager.Log
		}
		watch, err := newTlsCtWatch(ctx, &watchArgs)
		if err != nil {
			self.Close()
			return nil, err
		}
		self.ctWatch = watch
		if self.setCtWatch != nil {
			self.setCtWatch(watch)
		}
	}
	return self, nil
}

// "tls".
func (self *TlsComponent) Name() string {
	return tlsComponentName
}

// Follows one generation: the manager calls the certificate routes on its token until env.Ctx ends, and its push
// feed's notices on topic tls ask for the rows at once. A generation whose dispatcher has no push client yet attaches
// without hints, and the hourly resync carries it. A generation of another network is refused.
func (self *TlsComponent) Attach(env *SidecarEnv) error {
	if env == nil || env.SidecarApi == nil || env.Identity == nil {
		return fmt.Errorf("%w: tls needs the generation's api and identity", errInvalidSettings)
	}
	if env.Identity.NetworkId != self.networkId {
		return fmt.Errorf("%w: a generation of another network", errInvalidSettings)
	}
	generationEnded := make(chan struct{})
	generationSeq := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generationSeq += 1
		self.generationEnded = generationEnded
		self.api = env.SidecarApi
		return self.generationSeq
	}()
	self.manager.SetApi(env.SidecarApi)
	var subscriptions []func()
	if env.Subprotocol != nil {
		for _, topic := range []string{PushTopicTls, PushTopicDns} {
			if unsubscribe, err := env.Subprotocol.Subscribe(topic, self.manager.Hint); err == nil {
				subscriptions = append(subscriptions, unsubscribe)
			}
		}
	}
	go func() {
		defer close(generationEnded)
		<-env.Ctx.Done()
		for _, remove := range subscriptions {
			remove()
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.generationSeq == generationSeq {
			self.manager.SetApi(nil)
			self.api = nil
		}
	}()
	return nil
}

// The certificate manager.
func (self *TlsComponent) CertManager() *TlsCertManager {
	return self.manager
}

// GET /sidecar/limits on the newest generation's api: the network's tier, which an app listener's front reads for
// the Community notice. Offline between generations, which the front reads as Community.
func (self *TlsComponent) limits(ctx context.Context) (*QuotaLimits, error) {
	api := func() *SidecarApi {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.api
	}()
	if api == nil {
		return nil, errTlsComponentOffline
	}
	return api.Limits(ctx)
}

// Ends the app listeners, their registrations with them, then the manager, and takes it from behind
// TlsDeviceCertificate, after the Sidecar's last generation.
func (self *TlsComponent) Close() {
	listeners := func() []*TlsListener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		listeners := make([]*TlsListener, 0, len(self.listeners))
		for listener := range self.listeners {
			listeners = append(listeners, listener)
		}
		return listeners
	}()
	for _, listener := range listeners {
		listener.Close()
	}
	if self.publisher != nil {
		self.publisher.close()
	}
	if self.setSource != nil {
		self.setSource(nil)
	}
	if self.ctWatch != nil {
		if self.setCtWatch != nil {
			self.setCtWatch(nil)
		}
		self.ctWatch.Close()
	}
	if self.closeCtSources != nil {
		self.closeCtSources()
	}
	self.manager.Close()
}

// The CT watch's own view: whether its last pass was degraded and the alarms standing. Zero when the component runs
// no watch.
func (self *TlsComponent) CtWatchStatus() TlsCtWatchStatus {
	if self.ctWatch == nil {
		return TlsCtWatchStatus{}
	}
	return self.ctWatch.Status()
}

// The Sidecar's tls component, nil when it runs none.
func (self *Sidecar) tlsComponent() *TlsComponent {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil
	}
	for _, component := range leg.componentList() {
		if tlsComponent, ok := component.(*TlsComponent); ok {
			return tlsComponent
		}
	}
	return nil
}

// The network's certificate on this device's key (§13.8): the installed one, else an order through certs' CSR proxy
// followed until it issues or ctx ends (TlsCertManager.EnsureTlsCertificate). §13.10's step 3 and §15's receivers
// call this before they listen. ErrTlsComponentAbsent on a Sidecar that runs no tls component.
func (self *Sidecar) EnsureTlsCertificate(ctx context.Context) (*tls.Certificate, error) {
	component := self.tlsComponent()
	if component == nil {
		return nil, ErrTlsComponentAbsent
	}
	return component.manager.EnsureTlsCertificate(ctx)
}

// Every certificate this device holds for the network, the network's own first, then each custom host's. Public
// values only. Empty on a Sidecar that runs no tls component.
func (self *Sidecar) TlsCertificates() []*TlsCertificateInfo {
	component := self.tlsComponent()
	if component == nil {
		return nil
	}
	return component.manager.Certificates()
}

// Signs §12.8's reclaim tuple for name under the restore's incident with the device's TLS key, and answers the
// signature with the leaf that names it (DnsReclaimProof, VerifyDnsReclaimProof). ErrTlsComponentAbsent on a Sidecar
// that runs no tls component, ErrTlsNoIssuedCertificate when no certificate this device holds names it.
func (self *Sidecar) TlsSignLabelReclaim(ctx context.Context, name string, incidentId Id) (*TlsLabelReclaim, error) {
	component := self.tlsComponent()
	networkId := self.enrolledNetworkId()
	if component == nil || networkId == nil {
		return nil, ErrTlsComponentAbsent
	}
	return component.manager.SignLabelReclaim(ctx, &DnsReclaimProof{Name: name, NetworkId: *networkId, IncidentId: incidentId})
}

// What ListenTls takes beyond the name: §9.5's weight and §5.4's decision.
type TlsListenSettings struct {
	// The registration's share, 1 to 1000. 0 takes 100 (§9.5).
	Weight int
	// The ApprovalDecision for the listen, when the caller holds one. Nil lets the gate find a grant or a recorded
	// decision, or file the request and answer *ApprovalPendingError.
	Decision *bridge.Signed
	// §13.7's limits on the endpoint. Nil takes DefaultTlsFrontSettings. Its target probe is off whatever it says,
	// since the target is the listener's Accept.
	Front *TlsFrontSettings
}

// A registration as an app listener runs on it: what the front accepts from, and its address. *SocketListener is one.
type tlsListenRegistration interface {
	tlsFrontListener
	Addr() net.Addr
}

// What an app listener runs on beyond the component: the Sidecar's parts (ListenTls), or a test's.
type tlsListenParts struct {
	// This sidecar's network and sidecar, the subject of the endpoint's own grant.
	NetworkId Id
	SidecarId Id
	// Sidecar.Listen: the registration, through §5.4's gate, which may answer *ApprovalPendingError.
	Register func(ctx context.Context, address string, settings *SocketListenSettings) (tlsListenRegistration, error)
	// This device's own evaluation of its config (NewTlsFrontConfigPolicy).
	Policy TlsFrontPolicy
	// The tls namespace of the network's keychain.ur, which holds the key sessions are sealed under.
	Secrets SidecarSecrets
	// The edge-login issuer, SidecarSettings.AuthUrl.
	IssuerUrl string
	// Nil is real time.
	Clock Clock
	// Nil is the default logger.
	Log Logger
}

// Counts listener among the component's, false once the component has closed.
func (self *TlsComponent) track(listener *TlsListener) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.listeners[listener] = true
	return true
}

// Takes listener out of the component's.
func (self *TlsComponent) untrack(listener *TlsListener) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.listeners, listener)
}

// Whether an app listener serves on this component now.
func (self *TlsComponent) listening() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.listeners)
}

// An app listener on address: the name checked, its server names from the network's own, the network's certificate
// ensured (§13.10's step 3), then the registration through parts, then the front on it. Nothing is ordered for a name
// refused here, and nothing registers without the certificate.
func (self *TlsComponent) listen(ctx context.Context, address string, settings *TlsListenSettings, parts *tlsListenParts) (*TlsListener, error) {
	if settings == nil {
		settings = &TlsListenSettings{}
	}
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsListenInvalid, err)
	}
	name, namespace, err := ParseSocketName(parsed.Name)
	if err != nil || namespace != SocketNamespaceTls {
		return nil, fmt.Errorf("%w: a tls/<port>/<host> name, on port 443, 8443, 8883 or 5671", ErrTlsListenInvalid)
	}
	host := socketTlsHost(name)
	if name == tlsSystemPublishName {
		// §13.9: a receiver's system publish, which no listener takes
		return nil, fmt.Errorf("%w: the system publish's", ErrTlsListenInvalid)
	}
	names, err := self.names(ctx)
	if err != nil {
		return nil, err
	}
	serverNames, err := tlsPublishServerNames(host, names)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsListenInvalid, err)
	}
	if _, err := self.manager.EnsureTlsCertificate(ctx); err != nil {
		return nil, err
	}
	target := &TlsFrontTarget{
		Name:         name,
		ServerNames:  serverNames,
		AppMode:      socketListenDefaultTlsAppMode,
		LocalAddress: tlsListenerTargetAddress,
	}
	listenSettings := TlsFrontListenSettings(target, false)
	listenSettings.Weight = settings.Weight
	listenSettings.Decision = settings.Decision
	registration, err := parts.Register(ctx, address, listenSettings)
	if err != nil {
		return nil, err
	}
	var update func(*TlsFrontUpdate) error
	if socket, ok := registration.(*SocketListener); ok {
		update = socket.updateTls
	}
	listener, err := newTlsListener(self.ctx, &TlsFrontArgs{
		Custom:    &tlsFrontOwnerCertificates{manager: self.manager, owner: host},
		UpdateTls: update,
		Settings:  settings.Front,
		Target:    target,
		NetworkId: parts.NetworkId,
		SidecarId: parts.SidecarId,
		Policy:    parts.Policy,
		Certificate: func(serverName string) (*tls.Certificate, error) {
			// an issued certificate alone: a visitor is never shown the self-signed leaf
			return self.manager.PublishCertificate([]string{serverName})
		},
		Secrets:   parts.Secrets,
		IssuerUrl: parts.IssuerUrl,
		Limits:    self.limits,
		Clock:     parts.Clock,
		Log:       parts.Log,
	}, registration, self.untrack)
	if err != nil {
		registration.Close()
		return nil, err
	}
	if !self.track(listener) {
		listener.Close()
		return nil, errTlsComponentClosed
	}
	return listener, nil
}

// Serves a tls/ name in this process (TLS-M8-01; §13.17's app listeners): see the file header. address is
// tls/<port>/<host>, with a network or scoped host this device holds. The
// network's certificate on this device's key is ensured first, ordered through certs if it is missing, then the name
// registers through Listen, whose §5.4 gate may answer *ApprovalPendingError, the same call made again after the
// decision carrying on. ErrTlsComponentAbsent on a Sidecar that runs no tls component.
func (self *Sidecar) ListenTls(ctx context.Context, address string, settings *TlsListenSettings) (*TlsListener, error) {
	component := self.tlsComponent()
	if component == nil {
		return nil, ErrTlsComponentAbsent
	}
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	_, secrets, err := self.tlsDevice()
	if err != nil {
		return nil, err
	}
	sidecarId := identity.SidecarId
	return component.listen(ctx, address, settings, &tlsListenParts{
		NetworkId: *networkId,
		SidecarId: sidecarId,
		Register: func(ctx context.Context, address string, settings *SocketListenSettings) (tlsListenRegistration, error) {
			listener, err := self.Listen(ctx, address, settings)
			if err != nil {
				return nil, err
			}
			return listener, nil
		},
		Policy: NewTlsFrontConfigPolicy(sidecarId, func() *ConfigState {
			state, err := self.configState()
			if err != nil {
				return nil
			}
			return state
		}),
		Secrets:   secrets,
		IssuerUrl: self.settings.AuthUrl,
		Clock:     self.clock,
		Log:       self.log,
	})
}

// An app listener: a tls/ registration whose front hands each connection it opens to the target to Accept. Its
// net.Listener's Accept and AcceptContext answer connections that carry plaintext HTTP/1.1, the visitor's Host kept,
// and its visitor's address never (§13.7's visitor address row: only on request, which an app listener makes none
// of). Safe for concurrent use.
type TlsListener struct {
	front        *TlsFront
	registration tlsListenRegistration
	// each connection the front opens, waiting for an Accept: unbuffered, so the front's dial waits for one, at most
	// its TargetDialTimeout, as a socket with no backlog would
	accepted chan net.Conn
	// closed once the listener has ended, by its Close or its registration's
	closed    chan struct{}
	closeOnce sync.Once
	// takes the listener out of its component's, at its end
	untrack func(listener *TlsListener)
}

var _ net.Listener = (*TlsListener)(nil)

// The registration as the front owns it: closing it, whoever does, ends the listener's Accepts.
type tlsListenerFrontListener struct {
	tlsListenRegistration
	listener *TlsListener
}

// See tlsFrontListener. The listener ends first, so no Accept waits on a registration that is gone.
func (self *tlsListenerFrontListener) Close() error {
	self.listener.end()
	return self.tlsListenRegistration.Close()
}

// A listener running §13.7's front on registration, which it owns from here, with frontArgs' parts: everything but
// its listener, dial and probe, which are the listener's own. untrack, when set, runs once at the listener's end. A
// front refused leaves registration to its caller.
func newTlsListener(ctx context.Context, frontArgs *TlsFrontArgs, registration tlsListenRegistration, untrack func(listener *TlsListener)) (*TlsListener, error) {
	self := &TlsListener{
		registration: registration,
		accepted:     make(chan net.Conn),
		closed:       make(chan struct{}),
		untrack:      untrack,
	}
	settings := DefaultTlsFrontSettings()
	if frontArgs.Settings != nil {
		copied := *frontArgs.Settings
		settings = &copied
	}
	// the target is this listener's Accept, which no probe can ask: the registration serves as it began
	settings.TargetProbeInterval = 0
	args := *frontArgs
	args.Settings = settings
	args.Listener = &tlsListenerFrontListener{tlsListenRegistration: registration, listener: self}
	args.DialTarget = self.handOff
	front, err := NewTlsFront(ctx, &args)
	if err != nil {
		return nil, err
	}
	self.front = front
	return self, nil
}

// The front's dial of its target, which only an audience check's pass for one visitor's connection makes
// (TlsFrontConn.openTarget, FI-11): one end of a pipe for the front, the other for an Accept. Waits for an Accept,
// ctx, which the front's TargetDialTimeout bounds, or the listener's end.
func (self *TlsListener) handOff(ctx context.Context) (net.Conn, error) {
	frontEnd, appEnd := net.Pipe()
	select {
	case self.accepted <- appEnd:
		return frontEnd, nil
	case <-self.closed:
		frontEnd.Close()
		appEnd.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		frontEnd.Close()
		appEnd.Close()
		return nil, ctx.Err()
	}
}

// The next visitor's connection the front hands over, or ctx's error, or net.ErrClosed once the listener has ended.
func (self *TlsListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	select {
	case <-self.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case conn := <-self.accepted:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// See net.Listener: AcceptContext with no bound but the listener's end.
func (self *TlsListener) Accept() (net.Conn, error) {
	return self.AcceptContext(context.Background())
}

// See net.Listener: the registration's network and client, as ids (I-13).
func (self *TlsListener) Addr() net.Addr {
	return self.registration.Addr()
}

// Unlistens at once (§9.9) and ends every visitor's connection: the front's Close, which closes the registration. A
// second Close does nothing.
func (self *TlsListener) Close() error {
	self.end()
	return self.front.Close()
}

// Ends the Accepts and takes the listener out of its component's, once.
func (self *TlsListener) end() {
	self.closeOnce.Do(func() {
		close(self.closed)
		if self.untrack != nil {
			self.untrack(self)
		}
	})
}
