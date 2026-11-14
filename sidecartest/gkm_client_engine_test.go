package sidecartest

// gkm's client against gkmservice's engine on a fake host (KEYS-M2-18 with KEYS-M2-12 and KEYS-M2-13): the paths,
// scopes and bodies each side builds agree, so a device's upkeep lands its ReaderKey and KeyPackages and a writer
// claims one for an Add.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What gkm's newest verified state holds in this test: admitted sidecars and the rights each holds on one repo.
type gkmClientEngineState struct {
	stateLock     sync.Mutex
	sidecarFacts  map[sidecar.Id]*gkmservice.GkmSidecarFacts
	sidecarRights map[sidecar.Id]sidecar.AclEvsRights
}

func (self *gkmClientEngineState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *gkmClientEngineState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	facts, ok := self.sidecarFacts[sidecarId]
	if !ok {
		return nil, gkmservice.GkmAuthDenied
	}
	factsCopy := *facts
	return &factsCopy, gkmservice.GkmAuthAllowed
}

func (self *gkmClientEngineState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held := self.sidecarRights[sidecar.Id(*principal.SidecarId)]
	if right != 0 && held.Has(right) {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

func (self *gkmClientEngineState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.sidecarRights[sidecarId].Has(sidecar.AclEvsRead) {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

func (self *gkmClientEngineState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *gkmClientEngineState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *gkmClientEngineState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

// No log in this test: every pin is refused, so nothing here claims or commits.
func (self *gkmClientEngineState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	return gkmservice.GkmAuthDenied
}

func (self *gkmClientEngineState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	return gkmservice.GkmAuthDenied
}

// No holder dropped: every write here is §11.13's P1.
func (self *gkmClientEngineState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	return gkmservice.GkmAuthDenied
}

// No Delegation in this test's state.
func (self *gkmClientEngineState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*gkmservice.GkmDelegationKeyFacts, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthDenied
}

func (self *gkmClientEngineState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

// The engine's handler as a client's transport.
type gkmHandlerTransport struct {
	handler http.Handler
}

func (self *gkmHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// One device's client: its identity key and its GkmApi under tokens the fake host issues for exactly the scopes
// asked, as the exchange would.
type gkmClientEngineDevice struct {
	sidecarId  sidecar.Id
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	api        *sidecar.GkmApi
}

func (self *gkmClientEngineDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func TestGkmClientReachesTheEngineForItsUpkeepAndAClaim(t *testing.T) {
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	host := NewFakeHost(ctx, clock, nil, nil, nil)
	networkId := connect.NewId()
	host.Gates.OpenService(sidecar.ServiceGateGkm, networkId)
	state := &gkmClientEngineState{
		sidecarFacts:  map[sidecar.Id]*gkmservice.GkmSidecarFacts{},
		sidecarRights: map[sidecar.Id]sidecar.AclEvsRights{},
	}
	engine, err := gkmservice.NewGkmEngine(ctx, host.ServiceHost(), nil, &gkmservice.GkmEngineDeps{AuthState: state})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	repoId, groupId := sidecar.NewId(), sidecar.NewId()
	firstCluster, err := host.Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	place, err := (&sidecar.EvsRepoPlace{ClusterId: firstCluster.ClusterId(), CreatorSidecarId: sidecar.NewId()}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	repoObject, _ := proto.Marshal(&protocol.EvsRepoObject{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1})
	formBody, _ := proto.Marshal(&protocol.GroupForm{RepoId: repoId.Bytes(), GroupId: groupId.Bytes(), Generation: 1})
	form, _ := proto.Marshal(&bridge.Signed{Body: formBody, Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM)})
	groupOwner, _ := proto.Marshal(&protocol.GkmGroupOwner{RepoId: repoId.Bytes(), NetworkId: sidecar.NewId().Bytes()})
	for key, body := range map[string][]byte{
		sidecar.EvsPlaceKey(repoId):      place,
		gkmservice.GkmEvsRepoKey(repoId): repoObject,
		gkmservice.GkmFormKey(repoId, 1): form,
		// the group's owner marker, which every group route resolves through (DESIGN-DETAILS 6.2.2)
		gkmservice.GkmGroupOwnerKey(groupId): groupOwner,
	} {
		if _, err := firstCluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
			t.Fatal(err)
		}
	}

	newDevice := func(role string, rights sidecar.AclEvsRights) *gkmClientEngineDevice {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		device := &gkmClientEngineDevice{sidecarId: sidecar.NewId(), publicKey: publicKey, privateKey: privateKey}
		memberId := sidecar.NewId()
		state.stateLock.Lock()
		state.sidecarFacts[device.sidecarId] = &gkmservice.GkmSidecarFacts{IdentityPublicKey: publicKey, MemberDevice: true, MemberId: &memberId}
		state.sidecarRights[device.sidecarId] = rights
		state.stateLock.Unlock()
		connectSidecarId := connect.Id(device.sidecarId)
		device.api, err = sidecar.NewGkmApi(&sidecar.GkmApiArgs{
			GkmUrl:    "https://gkm.example",
			Transport: &gkmHandlerTransport{handler: engine.Handler()},
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return host.Authenticator.Issue(&sidecar.Principal{
					NetworkId: networkId,
					ClientId:  connect.NewId(),
					SidecarId: &connectSidecarId,
					Audience:  gkmservice.GkmAudience,
					Scopes:    scopes,
					IssuedAt:  clock.Now(),
					ExpiresAt: clock.Now().Add(15 * time.Minute),
				}), nil
			},
			Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		device.api.SetRepoScopes([]sidecar.GkmRepoScope{{RepoId: repoId, Role: role}})
		return device
	}
	reader := newDevice(sidecar.GkmScopeRoleRead, sidecar.AclEvsRead)
	writer := newDevice(sidecar.GkmScopeRoleWrite, sidecar.AclEvsWrite|sidecar.AclEvsRead)

	admission := sha256.Sum256(reader.sidecarId.Bytes())
	mlsEngine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         reader.sidecarId,
		IdentityPublicKey: reader.publicKey,
		AdmissionSha256:   admission[:],
		Sign:              reader.sign,
		Store:             NewFakeStore().Root(),
		Clock:             clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := sidecar.DefaultGkmSettings()
	settings.KeyPackageCount = 4
	settings.KeyPackageLowCount = 2
	upkeep, err := sidecar.NewGkmUpkeep(ctx, &sidecar.GkmUpkeepArgs{
		SidecarId:        reader.sidecarId,
		Api:              reader.api,
		Sign:             reader.sign,
		Secrets:          newGkmClientEngineSecrets(),
		CreateKeyPackage: mlsEngine.CreateKeyPackage,
		Role:             func() sidecar.GkmUpkeepRole { return sidecar.GkmUpkeepRole{MemberDevice: true} },
		Settings:         settings,
		Clock:            clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer upkeep.Close()
	for {
		count, changed := upkeep.Passes()
		if 0 < count {
			break
		}
		<-changed
	}

	// the upkeep's ReaderKey reads back through the public route, under the reader's identity key
	served, err := writer.api.ReaderKey(ctx, reader.sidecarId)
	if err != nil || served == nil {
		t.Fatalf("the reader's ReaderKey: %v", err)
	}
	if _, err := sidecar.CheckGkmReaderKey(served, reader.sidecarId, reader.publicKey, clock.Now().UnixMilli()); err != nil {
		t.Errorf("the served ReaderKey does not check: %v", err)
	}
	readerKeys, err := writer.api.ReaderKeys(ctx, []sidecar.Id{sidecar.NewId(), reader.sidecarId})
	if err != nil || len(readerKeys) != 2 || readerKeys[0] != nil || readerKeys[1] == nil {
		t.Errorf("the batch read: %v", err)
	}
	// the writer claims one of the KeyPackages upkeep uploaded, and gkm serves it whole
	claim, err := writer.api.ClaimKeyPackage(ctx, repoId, groupId, reader.sidecarId)
	if err != nil {
		t.Fatalf("a claim: %v", err)
	}
	info, err := sidecar.ParseMlsKeyPackage(claim.GetKeyPackage())
	if err != nil || !bytes.Equal(info.Ref, claim.GetKeyPackageRef()) || sidecar.Id(info.Credential.GetSidecarId()) != reader.sidecarId {
		t.Errorf("the claimed KeyPackage: %v", err)
	}
	// the reader holds an r scope alone, which reaches no claim
	if _, err := reader.api.ClaimKeyPackage(ctx, repoId, groupId, writer.sidecarId); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("a claim under r: %v", err)
	}
	welcomes, err := reader.api.Welcomes(ctx)
	if err != nil || len(welcomes) != 0 {
		t.Errorf("Welcomes before any Add: %v %v", welcomes, err)
	}
	// QD-747: the writer's ask reads welcome/<n>'s existence from the engine's HEAD, and r reaches no answer
	if stands, err := writer.api.WelcomeStands(ctx, repoId, groupId, 3); err != nil || stands {
		t.Errorf("an epoch with no Welcome: %v %v", stands, err)
	}
	if _, err := firstCluster.PutIfNoneMatch(ctx, gkmservice.GkmWelcomeKey(groupId, 3), []byte("a Welcome"), nil); err != nil {
		t.Fatal(err)
	}
	if stands, err := writer.api.WelcomeStands(ctx, repoId, groupId, 3); err != nil || !stands {
		t.Errorf("an epoch whose Welcome stands: %v %v", stands, err)
	}
	if stands, err := reader.api.WelcomeStands(ctx, repoId, groupId, 3); !sidecar.IsGkmStatus(err, http.StatusForbidden) || stands {
		t.Errorf("the ask under r: %v %v", stands, err)
	}
}

// keychain.ur's namespace in memory, for the upkeep this test runs.
type gkmClientEngineSecrets struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func newGkmClientEngineSecrets() *gkmClientEngineSecrets {
	return &gkmClientEngineSecrets{nameValues: map[string][]byte{}}
}

func (self *gkmClientEngineSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *gkmClientEngineSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *gkmClientEngineSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *gkmClientEngineSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.nameValues {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}
