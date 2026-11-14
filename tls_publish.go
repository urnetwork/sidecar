//go:build !sidecar_http && !ios_extension

// §13.10's publish (TLS-M5-23; R-TLS-5, R-TLS-7, D-TLS-5, D-TLS-13, I-7, I-8, I-9, X1): what `ur bridge public-tls`,
// the daemon's tls.publish and the tls_publish tool all run, in the section's four steps.
//
//  1. The host is checked against §9.4's grammar, §7.7's client names and §13.9's system host, and the port against
//     the four, before anything is filed.
//  2. The publish passes §5.4's gate (I-8). Its CanonicalAction is built here, never from an agent's words: host, port,
//     audience, app_mode and a raw link's pin, with the grant {dst: [dns:<host>, sock:tls/<port>/<host>], allow:
//     [publish, listen], expires} filled from the requests rule that takes it. With no active approved grant the gate
//     files the request and answers *ApprovalPendingError, which a caller shows as `ur approve <id>` and waits on; the
//     same call made again after the decision spends it.
//  3. The device's certificate is got if missing, the target is probed (tls_probe.go), and the listener and its front
//     start: Listen("tls/<port>/<host>") with the ALPN ids and the app mode, then §13.7's front on it.
//  4. The result is the URL, the expiry, the audience and "passthrough: key on this device"; for a raw link the path
//     of the client-certificate file.
//
// D-TLS-13: the registration's app mode is bound here. raw registers only under public or a certificate-pinned link,
// and nothing about ALPN picks a less restrictive path. The default audience is members.
//
// A raw link writes the one secret a publish makes: a client key and its certificate, in one file of mode 0600, whose
// SPKI pin the request carries. The file's path goes to the caller, its bytes to nobody (I-7). The file is written
// before the request is filed, so the call made again after the approval pins the same key, and it is removed when
// the publish ends.
//
// A scoped host, <label>.<scope>, is refused until Team scopes land (TLS-M6-03). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §13.10 step 4's line: the visitor's TLS ends on this device's key (X1).
const TlsPublishPassthrough = "passthrough: key on this device"

// The audiences a publish names (§13.7).
const (
	TlsPublishAudienceMembers       = "members"
	TlsPublishAudienceMembersDevice = "members-device"
	TlsPublishAudienceLink          = "link"
	TlsPublishAudiencePublic        = "public"
)

// The app modes a registration binds (§9.5, D-TLS-13).
const (
	TlsPublishAppModeHttp = "http"
	TlsPublishAppModeRaw  = "raw"
)

var (
	// The publish cannot be one: its host, port, target, audience or mode is refused before anything is filed.
	ErrTlsPublishInvalid = errors.New("tls publish refused")
	// The host is a client's name (§7.7) or the system publish's (§13.9).
	ErrTlsPublishHostTaken = errors.New("tls publish: the host is taken")
	// This device already publishes the name.
	ErrTlsPublishPublished = errors.New("tls publish: already published")
	// This device publishes no such name.
	ErrTlsPublishAbsent = errors.New("tls publish: not published")
	// Something a publish needs is not there to ask: verified config, the grant filer or the sockets.
	ErrTlsPublishUnavailable = errors.New("tls publish: unavailable")
)

// One publish as its caller asks for it: §13.10's argument and flags.
type TlsPublishSettings struct {
	// <host>: a label, or @ for the network's own name.
	Host string
	// --port: 443, 8443, 8883 or 5671. 0 takes 443.
	Port int
	// [<local ip>:]<local port>; the ip is 127.0.0.1 where none is given.
	Target string
	// --audience: members, members-device, link or public. Empty takes members.
	Audience string
	// --tcp: the registration's app mode is raw, and the local service sees the visitor's bytes after TLS.
	Tcp bool
	// --alpn: the ALPN ids served. Empty takes h2 and http/1.1 for http, and none for raw.
	Alpn []string
	// --proxy-protocol: the visitor's address reaches the service, as a PROXY v2 header on raw and a Forwarded
	// header on http.
	ProxyProtocol bool
	// --expires: how long the grant asked for lasts. 0 takes the rule's default.
	Expires time.Duration
	// The run and agent a decision binds, and the agent's own words and asked risk, for a tool's call. Nil and
	// empty from a person's terminal.
	RunId     *Id
	AgentId   *Id
	Summary   string
	AskedRisk SidecarRisk
	// The ApprovalDecision, when the caller holds one. nil lets the gate find a grant or a recorded decision.
	Decision *bridge.Signed
}

// What a publish came to: §13.10 step 4's lines.
type TlsPublishResult struct {
	// The registration's name, tls/<port>/<host>.
	Name string
	// https://<name>[:<port>] for http, <name>:<port> for raw.
	Url string
	// The names visitors reach it by.
	ServerNames []string
	// The grant the publish runs under where its approval activated one; empty under a standing grant.
	GrantId []byte
	// When the grant ends. Zero for a standing name.
	Expires  time.Time
	Audience string
	AppMode  string
	// TlsPublishPassthrough.
	Passthrough string
	// A raw link: the client key and certificate's file, mode 0600. Empty otherwise.
	ClientCertificateFile string
	// The target took the probe's connection.
	Serving bool
}

// What a publish runs on: the Sidecar's parts, or a test's. Safe for concurrent use.
type tlsPublishBackend interface {
	// The network and sidecar publishing.
	identity() (networkId Id, sidecarId Id, err error)
	// The network's root, label and aliases.
	names(ctx context.Context) (*TlsCertNames, error)
	// §7.7's client names at the newest verified state. An error when no verified state is there to read.
	clientNames() ([]string, error)
	// AclGrantFiler.Action and Effect.
	grantAction(ctx context.Context, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error)
	grantEffect(action *StoredCanonicalAction) SidecarEffect
	// Sidecar.Authorize.
	authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
	// Sidecar.EnsureTlsCertificate.
	ensureCertificate(ctx context.Context) error
	// The daemon's API and MCP ports, which the probe refuses.
	daemonPorts() []int
	// Records a probe's refusal.
	recordProbeRefusal(refusal TlsProbeRefusal)
	// Sidecar.Listen and NewTlsFront on it: the endpoint, serving.
	serve(ctx context.Context, target *TlsFrontTarget, settings *SocketListenSettings) (tlsPublishEndpoint, error)
	// AclGrantFiler.Revoke as the grant's subject, an own-resource filing from any origin (§8.8).
	revokeGrant(ctx context.Context, grantId []byte, origin SidecarActOrigin) error
	// Where a raw link's client-certificate file goes.
	clientCertificateDirectory() (string, error)
	now() time.Time
}

// A publish's listener and front.
type tlsPublishEndpoint interface {
	Close() error
}

// One live publish.
type tlsPublish struct {
	result   *TlsPublishResult
	endpoint tlsPublishEndpoint
}

// The publishes of one network on this device.
type tlsPublisher struct {
	backend  tlsPublishBackend
	settings *SidecarTlsSettings

	stateLock sync.Mutex
	// by registration name; nil while a publish of the name is on its way
	publishes map[string]*tlsPublish
}

// A publisher on backend. nil settings take the defaults.
func newTlsPublisher(backend tlsPublishBackend, settings *SidecarTlsSettings) *tlsPublisher {
	if settings == nil {
		settings = DefaultSidecarTlsSettings()
	}
	return &tlsPublisher{backend: backend, settings: settings, publishes: map[string]*tlsPublish{}}
}

// A publish's settings checked and resolved, before anything is filed.
type tlsPublishPlan struct {
	name         string
	host         string
	port         int
	localAddress netip.AddrPort
	audience     protocol.AclAudience
	audienceText string
	appMode      protocol.AclAppMode
	appModeText  string
	alpn         []string
}

// Step 1's checks that need no state: the name's grammar, the four ports, the system host, the target, the audience
// and D-TLS-13's mode rule.
func newTlsPublishPlan(settings *TlsPublishSettings) (*tlsPublishPlan, error) {
	if settings == nil {
		return nil, fmt.Errorf("%w: no settings", ErrTlsPublishInvalid)
	}
	port := settings.Port
	if port == 0 {
		port = 443
	}
	// §9.4's grammar, and the four ports, refused before any filing
	name, namespace, err := ParseSocketName("tls/" + strconv.Itoa(port) + "/" + settings.Host)
	if err != nil || namespace != SocketNamespaceTls {
		return nil, fmt.Errorf("%w: a host is a label or @, on port 443, 8443, 8883 or 5671", ErrTlsPublishInvalid)
	}
	host := socketTlsHost(name)
	if strings.Contains(host, ".") {
		return nil, fmt.Errorf("%w: a scoped host waits on Team scopes", ErrTlsPublishInvalid)
	}
	if host == socketTlsHost(tlsSystemPublishName) {
		return nil, fmt.Errorf("%w: the system publish's", ErrTlsPublishHostTaken)
	}
	plan := &tlsPublishPlan{name: name, host: host, port: port}

	target := settings.Target
	if !strings.Contains(target, ":") {
		target = "127.0.0.1:" + target
	}
	plan.localAddress, err = netip.ParseAddrPort(target)
	if err != nil || plan.localAddress.Port() == 0 {
		return nil, fmt.Errorf("%w: a target is [<local ip>:]<local port>", ErrTlsPublishInvalid)
	}

	plan.audienceText = settings.Audience
	if plan.audienceText == "" {
		plan.audienceText = TlsPublishAudienceMembers
	}
	switch plan.audienceText {
	case TlsPublishAudienceMembers:
		plan.audience = protocol.AclAudience_ACL_AUDIENCE_MEMBERS
	case TlsPublishAudienceMembersDevice:
		plan.audience = protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE
	case TlsPublishAudienceLink:
		plan.audience = protocol.AclAudience_ACL_AUDIENCE_LINK
	case TlsPublishAudiencePublic:
		plan.audience = protocol.AclAudience_ACL_AUDIENCE_PUBLIC
	default:
		return nil, fmt.Errorf("%w: an audience is members, members-device, link or public", ErrTlsPublishInvalid)
	}

	plan.appMode, plan.appModeText = protocol.AclAppMode_ACL_APP_MODE_HTTP, TlsPublishAppModeHttp
	if settings.Tcp {
		plan.appMode, plan.appModeText = protocol.AclAppMode_ACL_APP_MODE_RAW, TlsPublishAppModeRaw
		// D-TLS-13: a login the front runs needs HTTP, so raw takes only public or a pinned link
		if plan.audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC && plan.audience != protocol.AclAudience_ACL_AUDIENCE_LINK {
			return nil, fmt.Errorf("%w: --tcp takes --audience public or link", ErrTlsPublishInvalid)
		}
	}
	plan.alpn = slices.Clone(settings.Alpn)
	if len(plan.alpn) == 0 && !settings.Tcp {
		plan.alpn = []string{"h2", "http/1.1"}
	}
	if socketListenMaxAlpnCount < len(plan.alpn) {
		return nil, fmt.Errorf("%w: too many ALPN ids", ErrTlsPublishInvalid)
	}
	for _, id := range plan.alpn {
		if id == "" || 255 < len(id) {
			return nil, fmt.Errorf("%w: an ALPN id is 1 to 255 bytes", ErrTlsPublishInvalid)
		}
	}
	if settings.Expires < 0 {
		return nil, fmt.Errorf("%w: --expires is a time from now", ErrTlsPublishInvalid)
	}
	return plan, nil
}

// The names visitors reach host by: <host>.<label>.<root>, or <label>.<root> for @, and each alias's.
func tlsPublishServerNames(host string, names *TlsCertNames) ([]string, error) {
	if names == nil || names.Root == "" || names.Label == "" {
		return nil, fmt.Errorf("%w: the network has no name yet", ErrTlsPublishUnavailable)
	}
	serverNames := []string{}
	for _, label := range append([]string{names.Label}, names.Aliases...) {
		if label == "" {
			continue
		}
		if host == "@" {
			serverNames = append(serverNames, label+"."+names.Root)
		} else {
			serverNames = append(serverNames, host+"."+label+"."+names.Root)
		}
	}
	return serverNames, nil
}

// The file a raw link's client key and certificate are kept in, by the registration's name.
func tlsPublishClientCertificateFile(directory string, plan *tlsPublishPlan) string {
	host := plan.host
	if host == "@" {
		host = "apex"
	}
	return filepath.Join(directory, "link-"+strconv.Itoa(plan.port)+"-"+host+".pem")
}

// A raw link's client key and certificate at path: read back when the file is there, so the call made again after an
// approval pins the same key, else made and written, mode 0600, never replacing a file. Answers the key's SPKI pin.
func tlsPublishClientCertificate(path string, serverName string, now time.Time, lifetime time.Duration) ([]byte, error) {
	if encoded, err := os.ReadFile(path); err == nil {
		for block, rest := pem.Decode(encoded); block != nil; block, rest = pem.Decode(rest) {
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				break
			}
			spkiSha256 := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
			return spkiSha256[:], nil
		}
		return nil, fmt.Errorf("%w: the client-certificate file does not read back", ErrTlsPublishUnavailable)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: the client-certificate file does not read back", ErrTlsPublishUnavailable)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, err
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	testHookSecret("tls_link_client_key", keyDer)
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "link " + serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificateDer, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDer)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDer})
	encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("%w: the client-certificate file cannot be written", ErrTlsPublishUnavailable)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: the client-certificate file cannot be written", ErrTlsPublishUnavailable)
	}
	_, writeErr := file.Write(encoded)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("%w: the client-certificate file cannot be written", ErrTlsPublishUnavailable)
	}
	spkiSha256 := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return spkiSha256[:], nil
}

// Holds name for a publish on its way; false when the name is published or another publish of it is running.
func (self *tlsPublisher) reserve(name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.publishes[name]; ok {
		return false
	}
	self.publishes[name] = nil
	return true
}

// Ends a reservation, with the publish that came of it or with none.
func (self *tlsPublisher) settle(name string, publish *tlsPublish) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if publish == nil {
		delete(self.publishes, name)
		return
	}
	self.publishes[name] = publish
}

// §13.10's four steps. *ApprovalPendingError while the request waits for a person: the same call made again after
// the decision carries on from there.
func (self *tlsPublisher) publish(ctx context.Context, settings *TlsPublishSettings) (*TlsPublishResult, error) {
	// step 1
	plan, err := newTlsPublishPlan(settings)
	if err != nil {
		return nil, err
	}
	_, sidecarId, err := self.backend.identity()
	if err != nil {
		return nil, err
	}
	clientNames, err := self.backend.clientNames()
	if err != nil {
		// with no names to check against, the check has not passed
		return nil, fmt.Errorf("%w: no verified config to check the host against", ErrTlsPublishUnavailable)
	}
	if slices.Contains(clientNames, plan.host) {
		return nil, fmt.Errorf("%w: a client's name", ErrTlsPublishHostTaken)
	}
	names, err := self.backend.names(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: the network's names cannot be read", ErrTlsPublishUnavailable)
	}
	serverNames, err := tlsPublishServerNames(plan.host, names)
	if err != nil {
		return nil, err
	}
	if !self.reserve(plan.name) {
		return nil, ErrTlsPublishPublished
	}
	var publish *tlsPublish
	defer func() {
		self.settle(plan.name, publish)
	}()
	now := self.backend.now()

	// step 2
	base := &protocol.CanonicalAction{
		Kind:     uint32(SidecarActionPublish),
		Version:  1,
		Host:     plan.host,
		Port:     uint32(plan.port),
		Audience: uint32(plan.audience),
		AppMode:  uint32(plan.appMode),
	}
	clientCertificateFile := ""
	if plan.appMode == protocol.AclAppMode_ACL_APP_MODE_RAW && plan.audience == protocol.AclAudience_ACL_AUDIENCE_LINK {
		directory, err := self.backend.clientCertificateDirectory()
		if err != nil {
			return nil, err
		}
		clientCertificateFile = tlsPublishClientCertificateFile(directory, plan)
		lifetime := settings.Expires
		if lifetime == 0 {
			lifetime = self.settings.PublishLinkCertificateLifetime
		}
		base.LinkSpkiSha256, err = tlsPublishClientCertificate(clientCertificateFile, serverNames[0], now, lifetime)
		if err != nil {
			return nil, err
		}
	}
	request := &AclGrantRequest{
		Subject:    sidecarId,
		GrantDst:   []string{"dns:" + plan.host, "sock:" + plan.name},
		GrantAllow: []string{"publish", "listen"},
	}
	if 0 < settings.Expires {
		request.ExpiresMs = now.Add(settings.Expires).UnixMilli()
	}
	stored, err := self.backend.grantAction(ctx, base, request, now)
	if err != nil {
		return nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, settings.AskedRisk, settings.RunId, settings.AgentId)
	if err != nil {
		return nil, err
	}
	// the port and the ALPN ids ride the request, so the approval is of this target and these protocols
	action.Detail = &SidecarActionDetail{LocalPort: uint32(plan.localAddress.Port()), Alpn: slices.Clone(plan.alpn)}
	action.Summary = settings.Summary
	action.Effect = self.backend.grantEffect(stored)
	if err := self.backend.authorize(ctx, action, settings.Decision); err != nil {
		// pending, with the request's id, or refused
		return nil, err
	}
	result := &TlsPublishResult{
		Name:                  plan.name,
		ServerNames:           serverNames,
		Audience:              plan.audienceText,
		AppMode:               plan.appModeText,
		Passthrough:           TlsPublishPassthrough,
		ClientCertificateFile: clientCertificateFile,
	}
	if action.Outcome != nil {
		result.GrantId = slices.Clone(action.Outcome.EffectRef)
	}
	if expiresMs := stored.Action.GetExpiresMillis(); expiresMs != 0 {
		result.Expires = time.UnixMilli(expiresMs).UTC()
	}
	if plan.appMode == protocol.AclAppMode_ACL_APP_MODE_RAW {
		result.Url = serverNames[0] + ":" + strconv.Itoa(plan.port)
	} else if plan.port == 443 {
		result.Url = "https://" + serverNames[0]
	} else {
		result.Url = "https://" + serverNames[0] + ":" + strconv.Itoa(plan.port)
	}

	// step 3
	if err := self.backend.ensureCertificate(ctx); err != nil {
		return nil, err
	}
	probe, err := tlsProbeTarget(ctx, &tlsProbeArgs{
		LocalAddress: plan.localAddress.String(),
		DaemonPorts:  self.backend.daemonPorts(),
		Settings:     self.settings,
		Record:       self.backend.recordProbeRefusal,
	})
	if err != nil {
		return nil, err
	}
	result.Serving = probe.Reachable
	proxyV2, forwarded := TlsFrontVisitorAddressOptions(plan.appModeText, settings.ProxyProtocol)
	endpoint, err := self.backend.serve(ctx, &TlsFrontTarget{
		Name:          plan.name,
		ServerNames:   serverNames,
		AppMode:       plan.appModeText,
		Alpn:          slices.Clone(plan.alpn),
		LocalAddress:  plan.localAddress.String(),
		ProxyProtocol: proxyV2,
		Forwarded:     forwarded,
	}, &SocketListenSettings{
		Alpn:     slices.Clone(plan.alpn),
		AppMode:  plan.appModeText,
		Decision: settings.Decision,
	})
	if err != nil {
		return nil, err
	}

	// step 4
	publish = &tlsPublish{result: result, endpoint: endpoint}
	copied := *result
	return &copied, nil
}

// Ends the publish of host on port: the listener and its front at once, then the grant its approval activated, and a
// raw link's client-certificate file. ErrTlsPublishAbsent when this device publishes no such name.
func (self *tlsPublisher) unpublish(ctx context.Context, host string, port int, origin SidecarActOrigin) error {
	if port == 0 {
		port = 443
	}
	name, namespace, err := ParseSocketName("tls/" + strconv.Itoa(port) + "/" + host)
	if err != nil || namespace != SocketNamespaceTls {
		return fmt.Errorf("%w: a host is a label or @, on port 443, 8443, 8883 or 5671", ErrTlsPublishInvalid)
	}
	publish := func() *tlsPublish {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		publish := self.publishes[name]
		if publish != nil {
			delete(self.publishes, name)
		}
		return publish
	}()
	if publish == nil {
		return ErrTlsPublishAbsent
	}
	closeErr := publish.endpoint.Close()
	if publish.result.ClientCertificateFile != "" {
		os.Remove(publish.result.ClientCertificateFile)
	}
	if len(publish.result.GrantId) == 0 {
		// a standing grant is the config's, and stays
		return closeErr
	}
	return errors.Join(closeErr, self.backend.revokeGrant(ctx, publish.result.GrantId, origin))
}

// The live publishes, by name.
func (self *tlsPublisher) list() []*TlsPublishResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	results := []*TlsPublishResult{}
	for _, publish := range self.publishes {
		if publish != nil {
			copied := *publish.result
			results = append(results, &copied)
		}
	}
	slices.SortFunc(results, func(a *TlsPublishResult, b *TlsPublishResult) int {
		return strings.Compare(a.Name, b.Name)
	})
	return results
}

// Ends every publish's listener, as the component closes. Grants and files stay: the publishes were not unpublished.
func (self *tlsPublisher) close() {
	publishes := func() []*tlsPublish {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		publishes := []*tlsPublish{}
		for name, publish := range self.publishes {
			if publish != nil {
				publishes = append(publishes, publish)
				delete(self.publishes, name)
			}
		}
		return publishes
	}()
	for _, publish := range publishes {
		publish.endpoint.Close()
	}
}

// What a Sidecar's publishes need beyond the Sidecar itself, which the daemon's composition gives its tls component.
type TlsPublishArgs struct {
	// Builds and revokes the publish's grant (NewAclGrantFiler). nil refuses every publish.
	Grants *AclGrantFiler
	// §7.7's client names at the newest verified state. nil refuses every publish.
	ClientNames func() ([]string, error)
	// The daemon's API and MCP ports on this host.
	DaemonPorts func() []int
	// Where raw links' client-certificate files go: a directory only this user reads.
	ClientCertificateDirectory string
	// Records a probe's refusal. nil records none.
	RecordProbeRefusal func(refusal TlsProbeRefusal)
}

// The Sidecar's parts as a publish runs on them.
type sidecarTlsPublishBackend struct {
	sidecar *Sidecar
	args    *TlsPublishArgs
}

// A listener and the front on it.
type sidecarTlsPublishEndpoint struct {
	front *TlsFront
}

// Closes the front, which closes its listener.
func (self *sidecarTlsPublishEndpoint) Close() error {
	return self.front.Close()
}

// See tlsPublishBackend. ErrSidecarNoIdentity before enrollment.
func (self *sidecarTlsPublishBackend) identity() (Id, Id, error) {
	networkId := self.sidecar.enrolledNetworkId()
	identity := self.sidecar.currentIdentity()
	if networkId == nil || identity == nil {
		return Id{}, Id{}, ErrSidecarNoIdentity
	}
	return *networkId, identity.SidecarId, nil
}

// See tlsPublishBackend: the zone the DnsClient reads.
func (self *sidecarTlsPublishBackend) names(ctx context.Context) (*TlsCertNames, error) {
	return self.sidecar.tlsCertNames(ctx)
}

// See tlsPublishBackend. Refused until the composition gives a reader of the names.
func (self *sidecarTlsPublishBackend) clientNames() ([]string, error) {
	if self.args == nil || self.args.ClientNames == nil {
		return nil, ErrTlsPublishUnavailable
	}
	return self.args.ClientNames()
}

// See tlsPublishBackend. Refused with no grant filer.
func (self *sidecarTlsPublishBackend) grantAction(ctx context.Context, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error) {
	if self.args == nil || self.args.Grants == nil {
		return nil, fmt.Errorf("%w: no grant filer", ErrTlsPublishUnavailable)
	}
	return self.args.Grants.Action(ctx, base, request, now)
}

// See tlsPublishBackend. Called only after grantAction answered, so the filer is there.
func (self *sidecarTlsPublishBackend) grantEffect(action *StoredCanonicalAction) SidecarEffect {
	return self.args.Grants.Effect(action)
}

// See tlsPublishBackend: §5.4's gate.
func (self *sidecarTlsPublishBackend) authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	return self.sidecar.Authorize(ctx, action, decision)
}

// See tlsPublishBackend: the certificate manager's order, followed until it issues.
func (self *sidecarTlsPublishBackend) ensureCertificate(ctx context.Context) error {
	_, err := self.sidecar.EnsureTlsCertificate(ctx)
	return err
}

// See tlsPublishBackend. None where the composition names none.
func (self *sidecarTlsPublishBackend) daemonPorts() []int {
	if self.args == nil || self.args.DaemonPorts == nil {
		return nil
	}
	return self.args.DaemonPorts()
}

// See tlsPublishBackend.
func (self *sidecarTlsPublishBackend) recordProbeRefusal(refusal TlsProbeRefusal) {
	if self.args != nil && self.args.RecordProbeRefusal != nil {
		self.args.RecordProbeRefusal(refusal)
	}
}

// See tlsPublishBackend: Sidecar.Listen, then §13.7's front on the listener, which presents an issued certificate
// alone and judges visitors by this device's own evaluation of its config.
func (self *sidecarTlsPublishBackend) serve(ctx context.Context, target *TlsFrontTarget, settings *SocketListenSettings) (tlsPublishEndpoint, error) {
	networkId, sidecarId, err := self.identity()
	if err != nil {
		return nil, err
	}
	_, secrets, err := self.sidecar.tlsDevice()
	if err != nil {
		return nil, err
	}
	listener, err := self.sidecar.Listen(ctx, target.Name, settings)
	if err != nil {
		return nil, err
	}
	sidecar := self.sidecar
	front, err := NewTlsFront(sidecar.ctx, &TlsFrontArgs{
		Target:    target,
		Listener:  listener,
		NetworkId: networkId,
		SidecarId: sidecarId,
		Policy: NewTlsFrontConfigPolicy(sidecarId, func() *ConfigState {
			state, err := sidecar.configState()
			if err != nil {
				return nil
			}
			return state
		}),
		Certificate: func(serverName string) (*tls.Certificate, error) {
			// an issued certificate alone: a visitor is never shown the self-signed leaf
			component := sidecar.tlsComponent()
			if component == nil {
				return nil, ErrTlsComponentAbsent
			}
			return component.manager.PublishCertificate([]string{serverName})
		},
		Secrets:   secrets,
		IssuerUrl: sidecar.settings.AuthUrl,
		Clock:     sidecar.clock,
		Log:       sidecar.log,
	})
	if err != nil {
		listener.Close()
		return nil, err
	}
	return &sidecarTlsPublishEndpoint{front: front}, nil
}

// See tlsPublishBackend. Refused with no grant filer.
func (self *sidecarTlsPublishBackend) revokeGrant(ctx context.Context, grantId []byte, origin SidecarActOrigin) error {
	if self.args == nil || self.args.Grants == nil {
		return fmt.Errorf("%w: no grant filer", ErrTlsPublishUnavailable)
	}
	// the subject's own filing, which needs no person's confirmation (§8.8)
	return self.args.Grants.Revoke(ctx, grantId, origin, nil)
}

// See tlsPublishBackend. Refused where the composition names no directory.
func (self *sidecarTlsPublishBackend) clientCertificateDirectory() (string, error) {
	if self.args == nil || self.args.ClientCertificateDirectory == "" {
		return "", fmt.Errorf("%w: no place for a client-certificate file", ErrTlsPublishUnavailable)
	}
	return self.args.ClientCertificateDirectory, nil
}

// See tlsPublishBackend.
func (self *sidecarTlsPublishBackend) now() time.Time {
	return self.sidecar.clock.Now()
}

// The Sidecar's publisher: its tls component's.
func (self *Sidecar) tlsPublisher() (*tlsPublisher, error) {
	component := self.tlsComponent()
	if component == nil || component.publisher == nil {
		return nil, ErrTlsComponentAbsent
	}
	return component.publisher, nil
}

// Publishes a local service on a name of this network (§13.10). *ApprovalPendingError while its request waits for a
// person; the same call made again after the decision carries on. ErrTlsComponentAbsent on a Sidecar that runs no
// tls component.
func (self *Sidecar) PublishTls(ctx context.Context, settings *TlsPublishSettings) (*TlsPublishResult, error) {
	publisher, err := self.tlsPublisher()
	if err != nil {
		return nil, err
	}
	return publisher.publish(ctx, settings)
}

// Ends this device's publish of host on port, 0 for 443: the listener at once, then the grant its approval
// activated, revoked as its subject's own filing from origin.
func (self *Sidecar) UnpublishTls(ctx context.Context, host string, port int, origin SidecarActOrigin) error {
	publisher, err := self.tlsPublisher()
	if err != nil {
		return err
	}
	return publisher.unpublish(ctx, host, port, origin)
}

// This device's live publishes, by name.
func (self *Sidecar) TlsPublishes() []*TlsPublishResult {
	publisher, err := self.tlsPublisher()
	if err != nil {
		return nil
	}
	return publisher.list()
}

// The names this device publishes, each once, sorted: what D-TRUST-9's zone watch watches (DnsWatchArgs.
// PublishedHosts) and what says the CT watch's sidecar is listening.
func (self *Sidecar) TlsPublishedHosts() []string {
	hosts := []string{}
	for _, publish := range self.TlsPublishes() {
		hosts = append(hosts, publish.ServerNames...)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}
