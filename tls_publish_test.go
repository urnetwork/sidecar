//go:build !sidecar_http && !ios_extension

// §13.10's publish on a fake of what it runs on: the gate, the grant filer, the certificate, the listener and its
// front. The target is a loopback listener on a port the kernel picks.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A served endpoint, which records its close.
type tlsPublishTestEndpoint struct {
	target   *TlsFrontTarget
	settings *SocketListenSettings
	closed   bool
}

func (self *tlsPublishTestEndpoint) Close() error {
	self.closed = true
	return nil
}

// What a publish runs on, scripted: a gate that waits for the test's approval, and records of each call.
type tlsPublishTestBackend struct {
	t         *testing.T
	networkId Id
	sidecarId Id
	current   time.Time
	directory string

	stateLock sync.Mutex
	// the gate: pending until approved, then spent under grantId, or under a standing grant with none
	approved         bool
	standing         bool
	approvalId       Id
	grantId          []byte
	clients          []string
	clientsErr       error
	ports            []int
	grantCount       int
	authorized       []*SidecarAction
	certificates     int
	refusals         []TlsProbeRefusal
	endpoints        []*tlsPublishTestEndpoint
	revoked          [][]byte
	revokeOrigins    []SidecarActOrigin
	lastStoredAction *StoredCanonicalAction
}

func newTlsPublishTestBackend(t *testing.T) *tlsPublishTestBackend {
	t.Helper()
	grantId := sha256.Sum256([]byte("a publish grant"))
	return &tlsPublishTestBackend{
		t:          t,
		networkId:  testNetworkId,
		sidecarId:  tlsCertTestId("a publishing sidecar"),
		current:    time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC),
		directory:  t.TempDir(),
		approvalId: tlsCertTestId("a publish approval"),
		grantId:    grantId[:],
		clients:    []string{"laptop", "phone"},
	}
}

func (self *tlsPublishTestBackend) identity() (Id, Id, error) {
	return self.networkId, self.sidecarId, nil
}

func (self *tlsPublishTestBackend) names(ctx context.Context) (*TlsCertNames, error) {
	return &TlsCertNames{Root: tlsCertTestRoot, Label: tlsCertTestLabel}, nil
}

func (self *tlsPublishTestBackend) clientNames() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.clients), self.clientsErr
}

// As AclGrantFiler.Action fills a publish's grant from the rule that takes it: the rule's id and its default expiry.
func (self *tlsPublishTestBackend) grantAction(ctx context.Context, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.grantCount += 1
	action := base
	action.Subject = request.Subject.Bytes()
	action.GrantDst = slices.Clone(request.GrantDst)
	action.GrantAllow = slices.Clone(request.GrantAllow)
	action.ExpiresMillis = request.ExpiresMs
	if action.ExpiresMillis == 0 {
		action.ExpiresMillis = now.Add(24 * time.Hour).UnixMilli()
	}
	ruleId := tlsCertTestId("a requests rule")
	action.RuleId = ruleId[:]
	stored, err := NewCanonicalAction(action)
	if err != nil {
		return nil, err
	}
	self.lastStoredAction = stored
	return stored, nil
}

type tlsPublishTestEffect struct{}

func (self *tlsPublishTestEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	return nil, nil
}

func (self *tlsPublishTestBackend) grantEffect(action *StoredCanonicalAction) SidecarEffect {
	return &tlsPublishTestEffect{}
}

func (self *tlsPublishTestBackend) authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.authorized = append(self.authorized, action)
	if self.standing {
		action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone}
		return nil
	}
	if !self.approved {
		return &ApprovalPendingError{ApprovalId: self.approvalId}
	}
	action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: slices.Clone(self.grantId)}
	return nil
}

func (self *tlsPublishTestBackend) ensureCertificate(ctx context.Context) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.certificates += 1
	return nil
}

func (self *tlsPublishTestBackend) daemonPorts() []int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.ports)
}

func (self *tlsPublishTestBackend) recordProbeRefusal(refusal TlsProbeRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, refusal)
}

func (self *tlsPublishTestBackend) serve(ctx context.Context, target *TlsFrontTarget, settings *SocketListenSettings) (tlsPublishEndpoint, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	endpoint := &tlsPublishTestEndpoint{target: target, settings: settings}
	self.endpoints = append(self.endpoints, endpoint)
	return endpoint, nil
}

func (self *tlsPublishTestBackend) revokeGrant(ctx context.Context, grantId []byte, origin SidecarActOrigin) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revoked = append(self.revoked, grantId)
	self.revokeOrigins = append(self.revokeOrigins, origin)
	return nil
}

func (self *tlsPublishTestBackend) clientCertificateDirectory() (string, error) {
	return self.directory, nil
}

func (self *tlsPublishTestBackend) now() time.Time {
	return self.current
}

func (self *tlsPublishTestBackend) approve() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approved = true
}

// A publisher on a scripted backend, and a local service to publish.
func newTlsPublishTest(t *testing.T) (*tlsPublisher, *tlsPublishTestBackend, string) {
	t.Helper()
	backend := newTlsPublishTestBackend(t)
	target := newTlsProbeTestTarget(t, "<html><head><title>A blog</title></head></html>")
	return newTlsPublisher(backend, nil), backend, target
}

func TestTlsPublishThroughApproval(t *testing.T) {
	publisher, backend, target := newTlsPublishTest(t)
	settings := &TlsPublishSettings{Host: "blog", Target: target}

	// with no active approved grant the request is filed, and the caller is told its id to approve
	_, err := publisher.publish(t.Context(), settings)
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) || pending.ApprovalId != backend.approvalId {
		t.Fatalf("a publish with no grant: %v", err)
	}
	if len(backend.endpoints) != 0 || backend.certificates != 0 || len(publisher.list()) != 0 {
		t.Fatalf("something ran before the approval")
	}
	// the action is the daemon's own: the host, the port, the default audience, the mode and the grant asked for
	action := backend.lastStoredAction.Action
	if action.GetKind() != uint32(SidecarActionPublish) || action.GetHost() != "blog" || action.GetPort() != 443 {
		t.Errorf("the action %+v", action)
	}
	if action.GetAudience() != uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS) || action.GetAppMode() != uint32(protocol.AclAppMode_ACL_APP_MODE_HTTP) {
		t.Errorf("audience %d, app mode %d", action.GetAudience(), action.GetAppMode())
	}
	if !slices.Equal(action.GetGrantDst(), []string{"dns:blog", "sock:tls/443/blog"}) || !slices.Equal(action.GetGrantAllow(), []string{"publish", "listen"}) {
		t.Errorf("the grant asked for: %v %v", action.GetGrantDst(), action.GetGrantAllow())
	}
	if !bytes.Equal(action.GetSubject(), backend.sidecarId[:]) || len(action.GetLinkSpkiSha256()) != 0 {
		t.Errorf("subject or pin")
	}
	filed := backend.authorized[0]
	targetPort := netip.MustParseAddrPort(target).Port()
	if filed.Kind != SidecarActionPublish || filed.Detail == nil || filed.Detail.LocalPort != uint32(targetPort) || !slices.Equal(filed.Detail.Alpn, []string{"h2", "http/1.1"}) {
		t.Errorf("the request's detail %+v", filed.Detail)
	}
	if filed.Effect == nil || !bytes.Equal(filed.Canonical, backend.lastStoredAction.Bytes) {
		t.Errorf("the filed action is not the stored one with its effect")
	}

	// the same call after the decision carries on: certificate, probe, listener, front
	backend.approve()
	result, err := publisher.publish(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	serverName := "blog." + tlsCertTestLabel + "." + tlsCertTestRoot
	if result.Name != "tls/443/blog" || result.Url != "https://"+serverName || !slices.Equal(result.ServerNames, []string{serverName}) {
		t.Errorf("result %+v", result)
	}
	if result.Audience != TlsPublishAudienceMembers || result.AppMode != TlsPublishAppModeHttp || result.Passthrough != "passthrough: key on this device" {
		t.Errorf("result %+v", result)
	}
	if !bytes.Equal(result.GrantId, backend.grantId) || !result.Expires.Equal(backend.current.Add(24*time.Hour)) || !result.Serving || result.ClientCertificateFile != "" {
		t.Errorf("result %+v", result)
	}
	if backend.certificates != 1 || len(backend.endpoints) != 1 {
		t.Fatalf("%d certificates, %d endpoints", backend.certificates, len(backend.endpoints))
	}
	endpoint := backend.endpoints[0]
	if endpoint.target.Name != "tls/443/blog" || endpoint.target.LocalAddress != target || endpoint.target.AppMode != "http" || endpoint.target.ProxyProtocol || endpoint.target.Forwarded {
		t.Errorf("the front's target %+v", endpoint.target)
	}
	if endpoint.settings.AppMode != "http" || !slices.Equal(endpoint.settings.Alpn, []string{"h2", "http/1.1"}) {
		t.Errorf("the listen's settings %+v", endpoint.settings)
	}
	if list := publisher.list(); len(list) != 1 || list[0].Name != result.Name {
		t.Errorf("the publishes %+v", list)
	}
	// a second publish of the name is refused, and files nothing
	grantCount := backend.grantCount
	if _, err := publisher.publish(t.Context(), settings); !errors.Is(err, ErrTlsPublishPublished) || backend.grantCount != grantCount {
		t.Errorf("a second publish: %v", err)
	}
}

func TestTlsPublishEachFlag(t *testing.T) {
	publisher, backend, target := newTlsPublishTest(t)
	backend.approve()
	port := strconv.Itoa(int(netip.MustParseAddrPort(target).Port()))
	// a bare port takes 127.0.0.1
	result, err := publisher.publish(t.Context(), &TlsPublishSettings{
		Host:          "@",
		Port:          8443,
		Target:        port,
		Audience:      TlsPublishAudiencePublic,
		Alpn:          []string{"http/1.1"},
		ProxyProtocol: true,
		Expires:       2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	apex := tlsCertTestLabel + "." + tlsCertTestRoot
	if result.Name != "tls/8443/@" || result.Url != "https://"+apex+":8443" || result.Audience != TlsPublishAudiencePublic {
		t.Errorf("result %+v", result)
	}
	if !result.Expires.Equal(backend.current.Add(2 * time.Hour)) {
		t.Errorf("expires %s", result.Expires)
	}
	action := backend.lastStoredAction.Action
	if action.GetPort() != 8443 || action.GetHost() != "@" || action.GetAudience() != uint32(protocol.AclAudience_ACL_AUDIENCE_PUBLIC) {
		t.Errorf("the action %+v", action)
	}
	if !slices.Equal(action.GetGrantDst(), []string{"dns:@", "sock:tls/8443/@"}) || action.GetExpiresMillis() != backend.current.Add(2*time.Hour).UnixMilli() {
		t.Errorf("the grant asked for: %v until %d", action.GetGrantDst(), action.GetExpiresMillis())
	}
	endpoint := backend.endpoints[0]
	// --proxy-protocol on http is a Forwarded header, never a PROXY header the service would read as a request
	if endpoint.target.LocalAddress != "127.0.0.1:"+port || !endpoint.target.Forwarded || endpoint.target.ProxyProtocol {
		t.Errorf("the front's target %+v", endpoint.target)
	}
	if !slices.Equal(endpoint.target.Alpn, []string{"http/1.1"}) || !slices.Equal(backend.authorized[0].Detail.Alpn, []string{"http/1.1"}) {
		t.Errorf("alpn %v", endpoint.target.Alpn)
	}
	for _, audience := range []string{TlsPublishAudienceMembersDevice, TlsPublishAudienceLink} {
		other, otherBackend, otherTarget := newTlsPublishTest(t)
		otherBackend.approve()
		result, err := other.publish(t.Context(), &TlsPublishSettings{Host: "docs", Target: otherTarget, Audience: audience})
		// an http link is a signed URL token, never a client certificate
		if err != nil || result.Audience != audience || result.ClientCertificateFile != "" || len(otherBackend.lastStoredAction.Action.GetLinkSpkiSha256()) != 0 {
			t.Errorf("audience %s: %+v, %v", audience, result, err)
		}
	}
}

func TestTlsPublishRefusesBeforeAnyFiling(t *testing.T) {
	cases := []struct {
		name     string
		settings *TlsPublishSettings
		want     error
	}{
		{name: "a port outside the four", settings: &TlsPublishSettings{Host: "blog", Port: 80}, want: ErrTlsPublishInvalid},
		{name: "another port outside the four", settings: &TlsPublishSettings{Host: "blog", Port: 8080}, want: ErrTlsPublishInvalid},
		{name: "a host off the grammar", settings: &TlsPublishSettings{Host: "bad_host"}, want: ErrTlsPublishInvalid},
		{name: "no host", settings: &TlsPublishSettings{Host: ""}, want: ErrTlsPublishInvalid},
		{name: "a host with a path", settings: &TlsPublishSettings{Host: "blog/x"}, want: ErrTlsPublishInvalid},
		{name: "a scoped host", settings: &TlsPublishSettings{Host: "blog.eng"}, want: ErrTlsPublishInvalid},
		{name: "the system host", settings: &TlsPublishSettings{Host: "mta-sts"}, want: ErrTlsPublishHostTaken},
		{name: "the system host on another port", settings: &TlsPublishSettings{Host: "mta-sts", Port: 8443}, want: ErrTlsPublishHostTaken},
		{name: "a client's name", settings: &TlsPublishSettings{Host: "laptop"}, want: ErrTlsPublishHostTaken},
		{name: "an audience that is none", settings: &TlsPublishSettings{Host: "blog", Audience: "everyone"}, want: ErrTlsPublishInvalid},
		{name: "raw to members", settings: &TlsPublishSettings{Host: "blog", Tcp: true}, want: ErrTlsPublishInvalid},
		{name: "raw to members-device", settings: &TlsPublishSettings{Host: "blog", Tcp: true, Audience: TlsPublishAudienceMembersDevice}, want: ErrTlsPublishInvalid},
		{name: "an empty ALPN id", settings: &TlsPublishSettings{Host: "blog", Alpn: []string{""}}, want: ErrTlsPublishInvalid},
		{name: "an expiry in the past", settings: &TlsPublishSettings{Host: "blog", Expires: -time.Hour}, want: ErrTlsPublishInvalid},
	}
	for _, c := range cases {
		publisher, backend, target := newTlsPublishTest(t)
		backend.approve()
		c.settings.Target = target
		if _, err := publisher.publish(t.Context(), c.settings); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if backend.grantCount != 0 || len(backend.authorized) != 0 || len(backend.endpoints) != 0 {
			t.Errorf("%s: something was filed or served", c.name)
		}
	}
	for _, target := range []string{"", "notaport", "localhost:8080", "127.0.0.1:0", "70000"} {
		publisher, backend, _ := newTlsPublishTest(t)
		if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target}); !errors.Is(err, ErrTlsPublishInvalid) || backend.grantCount != 0 {
			t.Errorf("target %q: %v", target, err)
		}
	}
	if _, err := newTlsPublisher(newTlsPublishTestBackend(t), nil).publish(t.Context(), nil); !errors.Is(err, ErrTlsPublishInvalid) {
		t.Errorf("no settings: %v", err)
	}
	// with no verified config to read the client names from, the check has not passed
	publisher, backend, target := newTlsPublishTest(t)
	backend.clientsErr = errors.New("no verified state")
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target}); !errors.Is(err, ErrTlsPublishUnavailable) || backend.grantCount != 0 {
		t.Errorf("no client names: %v", err)
	}
}

func TestTlsPublishRefusesAndRecordsTheDaemonsPortAndAnAgentUi(t *testing.T) {
	publisher, backend, target := newTlsPublishTest(t)
	backend.approve()
	backend.ports = []int{int(netip.MustParseAddrPort(target).Port())}
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target}); !errors.Is(err, ErrTlsProbeRefused) {
		t.Fatalf("the daemon's port: %v", err)
	}
	agentUi := newTlsProbeTestTarget(t, tlsProbeTestAgentUis["mcp-inspector"])
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: agentUi}); !errors.Is(err, ErrTlsProbeRefused) {
		t.Fatalf("an agent UI: %v", err)
	}
	if !slices.Equal(backend.refusals, []TlsProbeRefusal{TlsProbeRefusalDaemonPort, TlsProbeRefusalAgentUi}) {
		t.Errorf("recorded %v", backend.refusals)
	}
	if len(backend.endpoints) != 0 || len(publisher.list()) != 0 {
		t.Errorf("a refused target was served")
	}
	// the name is free for a target that passes
	backend.ports = nil
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target}); err != nil {
		t.Errorf("a publish after a refused target: %v", err)
	}
}

func TestTlsPublishTcpShapes(t *testing.T) {
	// --tcp --audience public: raw, with no client certificate and no ALPN of its own
	publisher, backend, target := newTlsPublishTest(t)
	backend.approve()
	result, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "mqtt", Port: 8883, Target: target, Tcp: true, Audience: TlsPublishAudiencePublic, ProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	serverName := "mqtt." + tlsCertTestLabel + "." + tlsCertTestRoot
	if result.AppMode != TlsPublishAppModeRaw || result.Url != serverName+":8883" || result.ClientCertificateFile != "" {
		t.Errorf("result %+v", result)
	}
	action := backend.lastStoredAction.Action
	if action.GetAppMode() != uint32(protocol.AclAppMode_ACL_APP_MODE_RAW) || len(action.GetLinkSpkiSha256()) != 0 {
		t.Errorf("the action %+v", action)
	}
	endpoint := backend.endpoints[0]
	if endpoint.target.AppMode != "raw" || len(endpoint.target.Alpn) != 0 || !endpoint.target.ProxyProtocol || endpoint.target.Forwarded || endpoint.settings.AppMode != "raw" {
		t.Errorf("the front's target %+v", endpoint.target)
	}

	// --tcp --audience link: a client key and certificate in a file of mode 0600, whose pin the request carries
	link, linkBackend, linkTarget := newTlsPublishTest(t)
	settings := &TlsPublishSettings{Host: "db", Port: 5671, Target: linkTarget, Tcp: true, Audience: TlsPublishAudienceLink}
	_, err = link.publish(t.Context(), settings)
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("a raw link with no grant: %v", err)
	}
	pin := slices.Clone(linkBackend.lastStoredAction.Action.GetLinkSpkiSha256())
	if len(pin) != sha256.Size {
		t.Fatalf("a raw link's request carries no pin")
	}
	// the call after the approval pins the same key
	linkBackend.approve()
	result, err = link.publish(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(linkBackend.lastStoredAction.Action.GetLinkSpkiSha256(), pin) {
		t.Errorf("the pin changed between the request and its use")
	}
	if result.ClientCertificateFile == "" {
		t.Fatalf("a raw link's result names no client-certificate file")
	}
	info, err := os.Stat(result.ClientCertificateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the client-certificate file: %v, %v", info, err)
	}
	encoded, err := os.ReadFile(result.ClientCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, rest := pem.Decode(encoded)
	keyBlock, _ := pem.Decode(rest)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("the file is not a certificate and its key")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if spkiSha256 := sha256.Sum256(certificate.RawSubjectPublicKeyInfo); !bytes.Equal(spkiSha256[:], pin) {
		t.Errorf("the pin is not the file's key")
	}
	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Errorf("the certificate is no client's")
	}
	// the result names the file and holds none of it (I-7)
	if bytes.Contains([]byte(result.Url+result.Name+result.ClientCertificateFile), keyBlock.Bytes) {
		t.Errorf("the result carries the key")
	}
	// the file ends with the publish
	if err := link.unpublish(t.Context(), "db", 5671, SidecarActConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(result.ClientCertificateFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the client-certificate file outlived its publish: %v", err)
	}
}

func TestTlsUnpublishEndsTheListenerAndRevokesTheGrant(t *testing.T) {
	publisher, backend, target := newTlsPublishTest(t)
	backend.approve()
	if _, err := publisher.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: target}); err != nil {
		t.Fatal(err)
	}
	if err := publisher.unpublish(t.Context(), "blog", 0, SidecarActMcp); err != nil {
		t.Fatal(err)
	}
	if !backend.endpoints[0].closed || len(publisher.list()) != 0 {
		t.Errorf("the listener outlived its unpublish")
	}
	if len(backend.revoked) != 1 || !bytes.Equal(backend.revoked[0], backend.grantId) || backend.revokeOrigins[0] != SidecarActMcp {
		t.Errorf("revoked %x from %v", backend.revoked, backend.revokeOrigins)
	}
	if err := publisher.unpublish(t.Context(), "blog", 443, SidecarActMcp); !errors.Is(err, ErrTlsPublishAbsent) {
		t.Errorf("a second unpublish: %v", err)
	}
	if err := publisher.unpublish(t.Context(), "blog", 80, SidecarActMcp); !errors.Is(err, ErrTlsPublishInvalid) {
		t.Errorf("an unpublish on a port outside the four: %v", err)
	}

	// a publish under a standing grant leaves the grant, which is the config's
	standing, standingBackend, standingTarget := newTlsPublishTest(t)
	standingBackend.standing = true
	result, err := standing.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: standingTarget})
	if err != nil || len(result.GrantId) != 0 {
		t.Fatalf("a publish under a standing grant: %+v, %v", result, err)
	}
	if err := standing.unpublish(t.Context(), "blog", 443, SidecarActConfirmed); err != nil || len(standingBackend.revoked) != 0 || !standingBackend.endpoints[0].closed {
		t.Errorf("an unpublish under a standing grant: %v, revoked %d", err, len(standingBackend.revoked))
	}

	// closing the publisher ends listeners and revokes nothing
	closing, closingBackend, closingTarget := newTlsPublishTest(t)
	closingBackend.approve()
	if _, err := closing.publish(t.Context(), &TlsPublishSettings{Host: "blog", Target: closingTarget}); err != nil {
		t.Fatal(err)
	}
	closing.close()
	if !closingBackend.endpoints[0].closed || len(closingBackend.revoked) != 0 || len(closing.list()) != 0 {
		t.Errorf("a closed publisher left a listener or revoked a grant")
	}
}

func TestSidecarWithNoTlsComponentPublishesNothing(t *testing.T) {
	sidecar := newTestSidecar(t)
	if _, err := sidecar.PublishTls(t.Context(), &TlsPublishSettings{Host: "blog", Target: "8080"}); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("publish: %v", err)
	}
	if err := sidecar.UnpublishTls(t.Context(), "blog", 0, SidecarActConfirmed); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("unpublish: %v", err)
	}
	if hosts := sidecar.TlsPublishedHosts(); len(hosts) != 0 {
		t.Errorf("published hosts %v", hosts)
	}
}

func TestSidecarTlsPublishBackendRefusesWithoutItsParts(t *testing.T) {
	// what the daemon's composition has not given, a publish does not do
	backend := &sidecarTlsPublishBackend{sidecar: newTestSidecar(t)}
	if _, err := backend.clientNames(); !errors.Is(err, ErrTlsPublishUnavailable) {
		t.Errorf("client names: %v", err)
	}
	if _, err := backend.grantAction(t.Context(), &protocol.CanonicalAction{}, &AclGrantRequest{}, time.Time{}); !errors.Is(err, ErrTlsPublishUnavailable) {
		t.Errorf("grant action: %v", err)
	}
	if err := backend.revokeGrant(t.Context(), make([]byte, sha256.Size), SidecarActConfirmed); !errors.Is(err, ErrTlsPublishUnavailable) {
		t.Errorf("revoke: %v", err)
	}
	if _, err := backend.clientCertificateDirectory(); !errors.Is(err, ErrTlsPublishUnavailable) {
		t.Errorf("client-certificate directory: %v", err)
	}
	if _, _, err := backend.identity(); err == nil {
		t.Errorf("an unenrolled sidecar has an identity")
	}
}
