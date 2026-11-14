//go:build !sidecar_http && !ios_extension

// The tls SidecarComponent (§5.4, §13.7, §13.8; TLS-M5-18): the device's certificate manager on a Sidecar's client
// generations, and what Sidecar.EnsureTlsCertificate, TlsCertificates and TlsSignLabelReclaim run on. The manager and
// what it installed live for the network across generations, since a certificate outlives a reconnect; each
// generation lends it the SidecarApi's routes and the push feed's topic tls, and takes them back when it ends.
//
// The component installs the manager behind Sidecar.TlsDeviceCertificate as it is made, so an issued chain answers
// from then on and the self-signed leaf only where none covers the names. Its keychain namespace is the device key's
// (tls_key.go) and its sealed directory holds certificates alone: the key never enters it.
//
// The names a certificate is ordered for come from the zone the DnsClient reads (its root, the network's label and
// alias), and the set is computed here by TlsIdentifierSet, so no certificate row's names are ever taken as the
// device's. Two parts are not there to read yet, and each stays empty until its task lands: a Team scope's label
// (TLS-M6-03) and the custom hosts this device may serve, which DnsClient.Zone lists once DNS-M6-02 has landed and
// whose grant test is verified config's (DESIGN-DETAILS 17.2.5). A host that knows them passes its own Names.
//
// Nothing adds this component to a Sidecar yet: the daemon's composition does, beside the sockets component's.
// connect legs only: the sidecar_http leg runs no component (§18.10). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
)

// Its keychain namespace and its sealed directory (§5.9): the device key's namespace, tlsSecretsNamespace.
const tlsComponentName = "tls"

// No tls component is attached to this Sidecar, so nothing orders or holds an issued certificate.
var ErrTlsComponentAbsent = errors.New("tls: this sidecar runs no tls component")

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
}

// The tls component.
type TlsComponent struct {
	manager   *TlsCertManager
	networkId Id
	setSource func(source TlsCertificateSource) error
	// nil when the component runs no CT watch
	ctWatch        *tlsCtWatch
	setCtWatch     func(watch sidecarCtWatch)
	closeCtSources func()

	stateLock sync.Mutex
	// raised for each generation attached, so an older one's end does not detach a newer one's api
	generationSeq uint64
	// closed once the newest generation's end has been followed: its hints removed and its api taken back
	generationEnded chan struct{}
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
// scope and no custom host yet (see the file header).
func (self *Sidecar) tlsCertNames(ctx context.Context) (*TlsCertNames, error) {
	client, err := self.Dns()
	if err != nil {
		return nil, err
	}
	zone, err := client.Zone(ctx)
	if err != nil {
		return nil, err
	}
	names := &TlsCertNames{Root: zone.Root, Label: zone.Label}
	if zone.Alias != "" {
		names.Aliases = []string{zone.Alias}
	}
	return names, nil
}

// The args a TlsComponent takes from this Sidecar for the network it is enrolled in: its settings, device key, Sign,
// ServiceToken, zone, sealed directory, clock and log.
func (self *Sidecar) TlsComponentArgs() (*TlsComponentArgs, error) {
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
	// keyless: a Team's Cert Spotter key has no place to be read from yet
	ctClient, err := NewTlsCtClient(nil)
	if err != nil {
		return nil, err
	}
	return &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId:    *networkId,
			SidecarId:    identity.SidecarId,
			Settings:     self.settings.Tls,
			Keys:         &sidecarTlsCertKeys{sidecar: self},
			Sign:         self.Sign,
			ServiceToken: self.ServiceToken,
			Names:        self.tlsCertNames,
			Store:        store,
			Clock:        self.clock,
			Log:          self.log,
		},
		SetSource: self.setTlsCertificateSource,
		CtWatch: &TlsCtWatchArgs{
			Sources: ctClient.Sources(),
			Identities: func() TlsCtIdentities {
				return NewTlsCtAuthorityIdentities(self.authority())
			},
			Listening: self.tlsListening,
			Event: func(event SidecarEvent) {
				self.Alarm(event)
			},
		},
		SetCtWatch:     self.setTlsCtWatch,
		CloseCtSources: ctClient.Close,
	}, nil
}

// Whether this sidecar listens on a published name now, which is when D-TLS-8 has it watch CT. It watches always
// until §13.10's publishing keeps its hosts (TLS-M5-23's TlsPublishedHosts): a device that watches without listening
// costs two queries a pass and misses nothing.
func (self *Sidecar) tlsListening() bool {
	return true
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
		manager:        manager,
		networkId:      args.Manager.NetworkId,
		setSource:      args.SetSource,
		setCtWatch:     args.SetCtWatch,
		closeCtSources: args.CloseCtSources,
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
		return self.generationSeq
	}()
	self.manager.SetApi(env.SidecarApi)
	remove := func() {}
	if env.Subprotocol != nil {
		if unsubscribe, err := env.Subprotocol.Subscribe(PushTopicTls, self.manager.Hint); err == nil {
			remove = unsubscribe
		}
	}
	go func() {
		defer close(generationEnded)
		<-env.Ctx.Done()
		remove()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.generationSeq == generationSeq {
			self.manager.SetApi(nil)
		}
	}()
	return nil
}

// The certificate manager.
func (self *TlsComponent) CertManager() *TlsCertManager {
	return self.manager
}

// Ends the manager and takes it from behind TlsDeviceCertificate, after the Sidecar's last generation.
func (self *TlsComponent) Close() {
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
