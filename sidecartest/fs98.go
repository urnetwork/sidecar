// FS-98's and FS-124's CLI world (CORE-M3-04; §5.6's revocation, D-CORE-20, D-CORE-13): real Sidecars, each hosted in
// a real Daemon serving the devices methods `ur devices`, `ur devices revoke` and `ur approve <proposal_id>` call, in
// one network of the admission suite's world (AdmissionNet), so on the tier's api: a FakeApi on T2, server's
// sequencer on T3. A host's Sidecar enrolls through the Net's api, is admitted in the network's log by a fixture
// device's SidecarAdmit naming its real identity key, follows the log with a ConfigClient of its own, whose
// ConfigAuthority it installs, and posts what it signs to the tier's api (FakeApi.RouteConfigDelta). Every statement a
// host lands is then applied by the AdmissionNet's reference, new devices, gates and writer follower, which the world
// compares after each (Settle).
//
// A schedule drives a host as ur does: devices.list, devices.preview, then devices.revoke as a confirmed control
// call, what ur sends once the person answered yes on /dev/tty; devices.proposal and devices.cosign for
// `ur approve <proposal_id>`. A harness hook's session and an unconfirmed control call reach the same daemon and are
// refused there, and Act reaches the Sidecar as an MCP tool or a hook handler would, with their origins. The presence
// prompt is the daemon's own (Daemon.PresencePrompt) over a FixturePresenceProvider, an authenticator of fixture keys
// whose next assertion a schedule refuses.
//
// What the world stands in: ConfigAuthority answers no SidecarProposalAuthority yet (TEAM's adapter), so a host's
// authority adds §7.9's several row for a SidecarRevoke from the same state's RevokeSignatures, and nothing else.

package sidecartest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An authenticator of fixture presence keys, as a host's platform authenticator: each Register makes the next key of
// its seed. Safe for concurrent use.
type FixturePresenceProvider struct {
	seed string
	alg  bridge.KeyAlg

	stateLock sync.Mutex
	keys      []*FixturePresenceKey
	refuse    error
	asserts   int
}

// An authenticator whose keys are of alg, webauthn-es256 or ecdsa-p256-sha256, named from seed.
func NewFixturePresenceProvider(seed string, alg bridge.KeyAlg) *FixturePresenceProvider {
	return &FixturePresenceProvider{seed: seed, alg: alg}
}

// What every assertion answers in place of a signature from now on, the person refusing or the bound passing; nil to
// assert again.
func (self *FixturePresenceProvider) Refuse(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuse = err
}

// How many assertions were asked, refused ones among them.
func (self *FixturePresenceProvider) AssertCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.asserts
}

func (self *FixturePresenceProvider) key(keyId []byte) *FixturePresenceKey {
	for _, key := range self.keys {
		if bytes.Equal(key.KeyId, keyId) {
			return key
		}
	}
	return nil
}

func (self *FixturePresenceProvider) Register(ctx context.Context) (*sidecar.PresenceKeyHandle, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := NewFixturePresenceKey(fmt.Sprintf("%s key %d", self.seed, len(self.keys)+1), self.alg)
	self.keys = append(self.keys, key)
	return &sidecar.PresenceKeyHandle{KeyId: bytes.Clone(key.KeyId), Alg: key.Alg, PublicKey: bytes.Clone(key.PublicKey)}, nil
}

func (self *FixturePresenceProvider) Holds(keyId []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.key(keyId) != nil
}

func (self *FixturePresenceProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asserts += 1
	if self.refuse != nil {
		return nil, self.refuse
	}
	key := self.key(keyId)
	if key == nil {
		return nil, errors.New("the authenticator holds no such key")
	}
	evidence, signature := key.Assert(message)
	if evidence == nil {
		evidence = &bridge.WebAuthnEvidence{}
	}
	evidence.KeyId = bytes.Clone(keyId)
	evidence.Signature = signature
	return evidence, nil
}

func (self *FixturePresenceProvider) Remove(keyId []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, key := range self.keys {
		if bytes.Equal(key.KeyId, keyId) {
			// the slot stays, so the next key's seed is a new one
			self.keys[i] = &FixturePresenceKey{Seed: key.Seed, Alg: key.Alg}
		}
	}
	return nil
}

// A host's authority: its follower's, with §7.9's several row for a SidecarRevoke, which ConfigAuthority does not
// answer yet.
type fs98Authority struct {
	*sidecar.ConfigAuthority
}

func (self fs98Authority) ProposalRequired(statement *sidecar.SidecarStatement) bool {
	if statement == nil || statement.Type != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
		return false
	}
	revoke := &bridge.SidecarRevoke{}
	if proto.Unmarshal(statement.Body, revoke) != nil {
		return false
	}
	targetId, err := sidecar.IdFromBytes(revoke.GetSidecarId())
	return err == nil && 1 < self.RevokeSignatures(targetId)
}

// A world's tunables.
type Fs98Settings struct {
	// How long a statement a host signs lives, so when a proposal it files expires: SidecarSettings.StatementTimeout
	// of every host. Zero keeps the Sidecar's default.
	StatementTimeout time.Duration
}

// The defaults, a fresh value each call.
func DefaultFs98Settings() *Fs98Settings {
	return &Fs98Settings{}
}

// The world: one AdmissionNet and the hosts in it.
type Fs98World struct {
	t         AdmissionT
	net       *Net
	settings  *Fs98Settings
	admission *AdmissionNet
	directory string
	hosts     []*Fs98Host
}

// A world on net's tier, its network bootstrapped by its owner's first device, a fixture; settings nil for
// DefaultFs98Settings. The caller closes it.
func NewFs98World(t AdmissionT, net *Net, settings *Fs98Settings) *Fs98World {
	t.Helper()
	if settings == nil {
		settings = DefaultFs98Settings()
	}
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	// a short path, since a unix socket's is bounded
	directory, err := os.MkdirTemp("/tmp", "ur-fs98-")
	if err != nil {
		t.Fatal(err)
	}
	return &Fs98World{t: t, net: net, settings: settings, admission: NewAdmissionNet(t, tier), directory: directory}
}

// The network: its fixture devices, statements and readers.
func (self *Fs98World) Admission() *AdmissionNet {
	return self.admission
}

// Stops every host's daemon and follower, then the network's writer.
func (self *Fs98World) Close() {
	for _, host := range self.hosts {
		host.restoreAuthority()
		host.Daemon.Close()
		<-host.done
		host.follower.Close()
	}
	if api, err := self.net.Api(); err == nil {
		api.RouteConfigDelta(self.admission.NetworkId(), nil)
	}
	self.admission.Close()
	os.RemoveAll(self.directory)
}

// Moves the clock on a second, as a post through the AdmissionNet does, applies what api holds at every reader of
// the network, and waits for each host's follower to stand there.
func (self *Fs98World) Settle() {
	self.t.Helper()
	self.admission.clock.Advance(time.Second)
	self.admission.Sync()
	self.catchUp()
}

func (self *Fs98World) catchUp() {
	self.t.Helper()
	for _, host := range self.hosts {
		if _, err := host.follower.WaitFor(self.admission.ctx, self.admission.applied); err != nil {
			self.t.Fatalf("%s's follower at %d: %v", host.Name, self.admission.applied, err)
		}
	}
}

// One device of the world: a real Sidecar in a real Daemon on a socket of its own.
type Fs98Host struct {
	Name string
	// The Sidecar's place in the log: its real sidecar_id and its member. It holds no key: the Sidecar's keychain does.
	Device     *AdmissionDevice
	Sidecar    *TestSidecar
	Daemon     *sidecar.Daemon
	SocketPath string
	// The host's authenticator.
	Presence *FixturePresenceProvider

	world            *Fs98World
	follower         *sidecar.ConfigClient
	restoreAuthority func()
	done             chan struct{}
}

// Adds a host named name: a Sidecar enrolled in the network through the Net's api, admitted as a device of memberId
// by admitter's SidecarAdmit with capabilities, following the log and serving the devices methods from a daemon.
func (self *Fs98World) AddHost(name string, memberId sidecar.Id, admitter *AdmissionDevice, capabilities uint32) *Fs98Host {
	self.t.Helper()
	admission := self.admission
	api, err := self.net.Api()
	if err != nil {
		self.t.Fatal(err)
	}
	// what a Sidecar of this network posts goes to the tier's api, which judges it
	api.RouteConfigDelta(admission.NetworkId(), func(ctx context.Context, signedBytes []byte) (*bridge.AuthPin, error) {
		return admission.api.AppendStatement(ctx, admission.NetworkId(), signedBytes)
	})
	sidecarSettings := sidecar.DefaultSidecarSettings()
	if 0 < self.settings.StatementTimeout {
		sidecarSettings.StatementTimeout = self.settings.StatementTimeout
	}
	testSidecar, err := self.net.AddSidecarIn(name, admission.NetworkId(), sidecarSettings)
	if err != nil {
		self.t.Fatal(err)
	}
	identity := testSidecar.Sidecar().Identity()
	if identity == nil {
		self.t.Fatalf("%s holds no identity", name)
	}
	device := &AdmissionDevice{Name: name, SidecarId: identity.SidecarId, MemberId: memberId}
	admit := admission.Admission(&AdmissionDevice{Name: name, SidecarId: identity.SidecarId, MemberId: memberId, Key: admitter.Key}, nil, false, 0, capabilities)
	admit.IdentityPublicKey = bytes.Clone(identity.IdentityPublicKey)
	admission.MustLand(admission.Sign(admitter, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit))

	clientSettings := sidecar.DefaultConfigClientSettings()
	clientSettings.Log = sidecar.NewNoopLogger()
	clientSettings.LogSettings = admissionLogSettings()
	follower, err := sidecar.NewConfigClient(admission.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    admission.networkId,
		GenesisChain: admission.genesisChain,
		Projection:   admission.projection(),
		Heads:        admission.heads,
		Clock:        admission.clock,
		Settings:     clientSettings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	directory := filepath.Join(self.directory, fmt.Sprintf("h%d", len(self.hosts)))
	if err := os.Mkdir(directory, 0o700); err != nil {
		self.t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "s")
	daemon, err := sidecar.NewDaemon(admission.ctx, &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		follower.Close()
		self.t.Fatal(err)
	}
	host := &Fs98Host{
		Name:       name,
		Device:     device,
		Sidecar:    testSidecar,
		Daemon:     daemon,
		SocketPath: socketPath,
		Presence:   NewFixturePresenceProvider(admission.NetworkId().String()+" "+name, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256),
		world:      self,
		follower:   follower,
		done:       make(chan struct{}),
	}
	host.restoreAuthority = testSidecar.Sidecar().InstallAuthority(fs98Authority{ConfigAuthority: follower.Authority()})
	daemon.SetPresenceProvider(host.Presence)
	for _, method := range sidecar.DaemonDevicesMethods(daemon) {
		if err := daemon.RegisterMethod(method); err != nil {
			self.t.Fatal(err)
		}
	}
	if err := daemon.AddSidecar(admission.NetworkId(), testSidecar.Sidecar()); err != nil {
		self.t.Fatal(err)
	}
	go func() {
		defer close(host.done)
		daemon.Run()
	}()
	self.hosts = append(self.hosts, host)
	self.catchUp()
	return host
}

// One call of method on the host's daemon from a session of mode, control, hook or mcp, with its confirmation flag.
// The call's error is the daemon's: a *sidecar.DaemonRpcError, or a *sidecar.DaemonHelloRefusal for a session it does
// not serve. Whatever the call landed is then applied at every reader.
func (self *Fs98Host) Call(mode string, confirmed bool, method string, params any, result any) error {
	self.world.t.Helper()
	self.world.catchUp()
	hello := &sidecar.DaemonHello{Mode: mode, Version: sidecar.Version, Pid: int64(os.Getpid())}
	if mode == sidecar.DaemonModeHook {
		hello.Harness = "claude-code"
	}
	client, err := sidecar.DialDaemon(self.world.admission.ctx, self.SocketPath, hello)
	if err != nil {
		return err
	}
	defer client.Close()
	err = client.Call(self.world.admission.ctx, method, params, confirmed, result)
	self.world.Settle()
	return err
}

// A control call that must answer, as ur's own.
func (self *Fs98Host) control(confirmed bool, method string, params any, result any) {
	self.world.t.Helper()
	if err := self.Call(sidecar.DaemonModeControl, confirmed, method, params, result); err != nil {
		self.world.t.Fatalf("%s: %s: %v", self.Name, method, err)
	}
}

// `ur devices`: this member's devices as the daemon lists them.
func (self *Fs98Host) Devices() []*sidecar.DaemonDevice {
	self.world.t.Helper()
	reply := &sidecar.DaemonDevicesListReply{}
	self.control(false, sidecar.DaemonMethodDevicesList, &sidecar.DaemonDevicesListParams{}, reply)
	return reply.Devices
}

// The plan `ur devices revoke <device>` prints: lost, or compromise from sinceN or the loss time. The reply holds the
// plan or §5.6's refusal.
func (self *Fs98Host) Preview(device sidecar.Id, reason string, sinceN uint64, lostAt time.Time) *sidecar.DaemonDevicesPreviewReply {
	self.world.t.Helper()
	params := &sidecar.DaemonDevicesPreviewParams{Device: device.String(), Reason: reason, SinceN: sinceN}
	if !lostAt.IsZero() {
		params.LostAtMs = lostAt.UnixMilli()
	}
	reply := &sidecar.DaemonDevicesPreviewReply{}
	self.control(false, sidecar.DaemonMethodDevicesPreview, params, reply)
	return reply
}

// What ur sends once the person answered yes on /dev/tty: the confirmed devices.revoke of the plan they read, with the
// keys they left selected.
func (self *Fs98Host) Revoke(plan *sidecar.DaemonDeviceRevokePlan, revokeKeyIds ...[]byte) *sidecar.DaemonDevicesRevokeReply {
	self.world.t.Helper()
	params := &sidecar.DaemonDevicesRevokeParams{PlanId: plan.PlanId, RevokeKeyIds: []string{}}
	for _, keyId := range revokeKeyIds {
		params.RevokeKeyIds = append(params.RevokeKeyIds, hex.EncodeToString(keyId))
	}
	reply := &sidecar.DaemonDevicesRevokeReply{}
	self.control(true, sidecar.DaemonMethodDevicesRevoke, params, reply)
	return reply
}

// The proposal `ur approve <proposal_id>` prints.
func (self *Fs98Host) Proposal(proposalId string) *sidecar.DaemonDevicesProposalReply {
	self.world.t.Helper()
	reply := &sidecar.DaemonDevicesProposalReply{}
	self.control(false, sidecar.DaemonMethodDevicesProposal, &sidecar.DaemonDevicesProposalParams{ProposalId: proposalId}, reply)
	return reply
}

// What `ur approve <proposal_id>` sends after the person's yes: the confirmed devices.cosign.
func (self *Fs98Host) Cosign(proposalId string) *sidecar.DaemonDevicesCosignReply {
	self.world.t.Helper()
	reply := &sidecar.DaemonDevicesCosignReply{}
	self.control(true, sidecar.DaemonMethodDevicesCosign, &sidecar.DaemonDevicesProposalParams{ProposalId: proposalId}, reply)
	return reply
}

// `ur keys add-presence` after the person's yes: a new key of the host's authenticator registered for the member under
// the daemon's presence prompt. Answers the key's id.
func (self *Fs98Host) AddPresenceKey() ([]byte, error) {
	self.world.t.Helper()
	self.world.catchUp()
	running := self.Sidecar.Sidecar()
	key, err := running.RegisterPresenceKey(self.world.admission.ctx, self.Presence, sidecar.SidecarActConfirmed, self.Daemon.PresencePrompt(running))
	self.world.Settle()
	if err != nil {
		return nil, err
	}
	return key.KeyId, nil
}

// `ur keys rm <key_id>` after the person's yes, under the daemon's presence prompt.
func (self *Fs98Host) RemovePresenceKey(keyId []byte) error {
	self.world.t.Helper()
	self.world.catchUp()
	running := self.Sidecar.Sidecar()
	err := running.RevokePresenceKey(self.world.admission.ctx, keyId, self.Presence, sidecar.SidecarActConfirmed, self.Daemon.PresencePrompt(running))
	self.world.Settle()
	return err
}

// What a caller of origin reaches past the daemon, an MCP tool's handler or a harness hook's: the Sidecar's own
// revocation of the plan and cosign of the proposal, each with the daemon's presence prompt at hand. Answers each
// one's error.
func (self *Fs98Host) Act(origin sidecar.SidecarActOrigin, planId sidecar.Id, proposalId []byte) (revokeErr error, cosignErr error) {
	self.world.t.Helper()
	self.world.catchUp()
	running := self.Sidecar.Sidecar()
	check := self.Daemon.PresencePrompt(running)
	_, revokeErr = running.RevokeDevicePlan(self.world.admission.ctx, planId, nil, origin, check)
	_, cosignErr = running.CosignRevokeProposal(self.world.admission.ctx, proposalId, origin, check)
	self.world.Settle()
	return revokeErr, cosignErr
}
