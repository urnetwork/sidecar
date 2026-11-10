// The conformance suite for api's log sequencer (§7.9's statement, base, tick and uncertain rows): run on FakeApi
// here (TEAM-M2-12) and on server's model sequencer over real MinIO at T3 (TEAM-M2-13), so a schedule relies only on
// what both do (D-TEST-2). Every case runs through ConfigLogSequencer alone, on a network id of its own, so one cluster
// serves the whole run.
//
// Store results are injected by the suite itself, around the cluster each sequencer is given, the same way on both
// tiers: a lost response (the PUT applies and the answer is lost), a timeout that applied nothing, and another
// appender's entry landing first, met by a real 412 or by a timeout. A race's other entry is a real one, chaining onto
// the tip, so a sequencer that reads it back verifies and applies it as it would another api instance's.
//
// A case is a plain function returning its first failure, and RunConfigLogStoreSuite loops over them
// (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound.
const configLogSuiteCaseTimeout = 120 * time.Second

// api's log sequencer as the suite drives it: an append answers the entry's pin, or a *ConfigLogRefusal with status
// 403 (refused at the tip), 409 (a base whose tip moved) or 503 (the store's outcome unknown), its Tip the tip.
type ConfigLogSequencer interface {
	// §7.9's statement row.
	AppendStatement(ctx context.Context, networkId sidecar.Id, signed []byte) (*bridge.AuthPin, error)
	// §7.9's base row; genesis is the Signed Genesis base 1 carries, nil for every other base, and configPushes the
	// Signed EvsPush of each config version the base adds, oldest first (plan-TEAM-api-config-head-reach).
	AppendBase(ctx context.Context, networkId sidecar.Id, signedHeader []byte, rows []byte, genesis []byte, configPushes [][]byte) (*bridge.AuthPin, error)
	// §7.9's tick row.
	AppendTick(ctx context.Context, networkId sidecar.Id, tick *bridge.ApiTick) (*bridge.AuthPin, error)
}

// Makes one api instance's sequencer over cluster, on clock. A case makes two to race them over one cluster.
type ConfigLogSequencerFactory func(clock sidecar.Clock, cluster sidecar.BlobCluster) ConfigLogSequencer

// Runs every case on sequencers newSequencer makes over cluster, the first metadata cluster of the tier. t is a
// testing.TB so server's T3 test can run it inside its test environment.
func RunConfigLogStoreSuite(t testing.TB, cluster sidecar.BlobCluster, newSequencer ConfigLogSequencerFactory) {
	t.Helper()
	for _, suiteCase := range configLogSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), configLogSuiteCaseTimeout)
			defer cancel()
			env := newConfigLogSuiteEnv(ctx, cluster, newSequencer)
			if err := suiteCase.run(env); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

type configLogSuiteCase struct {
	name string
	run  func(env *configLogSuiteEnv) error
}

func configLogSuiteCases() []configLogSuiteCase {
	return []configLogSuiteCase{
		{name: "base 1 with its genesis writes its rows, entry 1 and entry 0", run: caseConfigLogGenesis},
		{name: "a statement lands at the next position, its Signed bytes verbatim", run: caseConfigLogStatementLands},
		{name: "a lost response retried leaves one entry, and a retry of the same bytes answers it", run: caseConfigLogLostResponse},
		{name: "a 412 verifies again at the new tip and lands at the next position", run: caseConfigLogRaceThenLands},
		{name: "a 412 whose new tip refuses the statement answers 403 with that tip", run: caseConfigLogRaceThenRefused},
		{name: "a 412 by the same statement answers that entry", run: caseConfigLogRaceSameStatement},
		{name: "a timeout that applied nothing repeats the PUT and lands once", run: caseConfigLogTimeoutUnapplied},
		{name: "a timeout with another entry there is a loss, and the statement lands next", run: caseConfigLogTimeoutLoss},
		{name: "a statement refused at the tip answers 403 with the tip and writes nothing", run: caseConfigLogRefused},
		{name: "a base lands, one signed at an old tip answers 409, and a stale compile 403", run: caseConfigLogBases},
		{name: "a base whose config pushes do not walk to its head answers 403 and writes nothing", run: caseConfigLogDescent},
		{name: "two genesis race base 1 and one wins", run: caseConfigLogGenesisRace},
		{name: "a base 1 whose genesis step failed finishes on its retry", run: caseConfigLogGenesisRetry},
		{name: "a tick lands as api's fact", run: caseConfigLogTick},
		{name: "two appenders racing land every statement once, one per position", run: caseConfigLogConcurrentAppenders},
	}
}

// What one PUT of an entry is made to meet.
type configLogInjection int

const (
	// The PUT applies and its answer is lost.
	configLogLostResponse configLogInjection = iota + 1
	// The PUT applies nothing and times out.
	configLogTimeoutUnapplied
	// Another appender's entry lands first, so the PUT meets a real 412.
	configLogRaceFirst
	// Another appender's entry lands first, and the PUT times out.
	configLogRaceTimeout
)

// One armed injection: the kind, and for a race the other appender's entry body.
type configLogInjectionPlan struct {
	injection configLogInjection
	// the other appender's AuthEntry body at the same position, a Signed statement
	otherBody []byte
	// how many PUTs of keys under the prefix pass before this one is met
	skip int
}

// The cluster a case's sequencers write, with injections armed on PUTs of a network's entry keys. Every other call
// passes through.
type configLogSuiteCluster struct {
	sidecar.BlobCluster
	clock sidecar.Clock

	stateLock sync.Mutex
	prefix    string
	plans     []*configLogInjectionPlan
	met       int
}

// Arms plans, in order, on the next PUTs of entry keys under prefix.
func (self *configLogSuiteCluster) arm(prefix string, plans ...*configLogInjectionPlan) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.prefix = prefix
	self.plans = append(self.plans, plans...)
}

// How many armed plans were met.
func (self *configLogSuiteCluster) metCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.met
}

// The PUT, meeting the next armed plan when its key is an entry key under the armed prefix.
func (self *configLogSuiteCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	plan := func() *configLogInjectionPlan {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if len(self.plans) == 0 || self.prefix == "" || !strings.HasPrefix(key, self.prefix) {
			return nil
		}
		if 0 < self.plans[0].skip {
			self.plans[0].skip -= 1
			return nil
		}
		plan := self.plans[0]
		self.plans = self.plans[1:]
		self.met += 1
		return plan
	}()
	if plan == nil {
		return self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
	}
	unknown := &sidecar.BlobUnknownError{Err: errors.New("the suite's injected timeout")}
	switch plan.injection {
	case configLogLostResponse:
		if _, err := self.BlobCluster.PutIfNoneMatch(ctx, key, body, options); err != nil {
			return "", err
		}
		return "", unknown
	case configLogTimeoutUnapplied:
		return "", unknown
	case configLogRaceFirst, configLogRaceTimeout:
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(body, entry); err != nil {
			return "", err
		}
		entry.Kind, entry.Body, entry.TimeMs = bridge.AuthEntryKindStatement, plan.otherBody, entry.GetTimeMs()+1
		otherBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			return "", err
		}
		if _, err := self.BlobCluster.PutIfNoneMatch(ctx, key, otherBytes, options); err != nil {
			return "", err
		}
		if plan.injection == configLogRaceTimeout {
			return "", unknown
		}
		return self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
	}
	return "", fmt.Errorf("no such injection %d", plan.injection)
}

// One case's world: a network of its own, its owner and genesis device, the cluster with injections, and the clock.
type configLogSuiteEnv struct {
	ctx          context.Context
	clock        *FakeClock
	cluster      *configLogSuiteCluster
	newSequencer ConfigLogSequencerFactory

	networkId     sidecar.Id
	ownerMemberId sidecar.Id
	owner         configLogSuiteDevice
	// the config repo the genesis names, whose main ref's pushes the bases' heads walk
	configRepo    *configLogSuiteConfigRepo
	signedGenesis []byte
	nonce         uint64
	// the tip as the case last saw it
	tip *bridge.AuthPin
}

// A device of the case's network: its sidecar and identity key.
type configLogSuiteDevice struct {
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
}

func newConfigLogSuiteEnv(ctx context.Context, cluster sidecar.BlobCluster, newSequencer ConfigLogSequencerFactory) *configLogSuiteEnv {
	clock := NewFakeClock(DefaultClockStart())
	self := &configLogSuiteEnv{
		ctx:           ctx,
		clock:         clock,
		cluster:       &configLogSuiteCluster{BlobCluster: cluster, clock: clock},
		newSequencer:  newSequencer,
		networkId:     configLogSuiteId(),
		ownerMemberId: configLogSuiteId(),
	}
	self.owner = self.device(self.ownerMemberId)
	self.configRepo = newConfigLogSuiteConfigRepo(self.owner)
	self.signedGenesis = self.genesis(self.owner, self.configRepo)
	return self
}

// A fresh id, so cases on one real cluster never meet.
func configLogSuiteId() sidecar.Id {
	var id sidecar.Id
	rand.Read(id[:])
	return id
}

// A fresh device of a member, its key random.
func (self *configLogSuiteEnv) device(memberId sidecar.Id) configLogSuiteDevice {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return configLogSuiteDevice{sidecarId: configLogSuiteId(), memberId: memberId, key: key}
}

// A config repo's main ref as its writers push it (§11.8): each version's Signed EvsPush, made on demand, and the chain
// value after it, which a base names as its config head. api's walk reads only the repo, ref, push id and the head each
// push read, so the pushes carry those and their signer, the network's first device, signing as a config writer does.
type configLogSuiteConfigRepo struct {
	repoId sidecar.Id
	refId  sidecar.Id
	signer configLogSuiteDevice
	// versionPushes[v-1] makes version v, and chains[v] is C_v
	versionPushes [][]byte
	chains        [][sha256.Size]byte
}

func newConfigLogSuiteConfigRepo(signer configLogSuiteDevice) *configLogSuiteConfigRepo {
	repoId := configLogSuiteId()
	refId := configLogSuiteId()
	return &configLogSuiteConfigRepo{
		repoId: repoId,
		refId:  refId,
		signer: signer,
		chains: [][sha256.Size]byte{sidecar.EvsChainStart(repoId, refId)},
	}
}

// Makes every version through version.
func (self *configLogSuiteConfigRepo) through(version uint64) {
	for uint64(len(self.versionPushes)) < version {
		read := uint64(len(self.versionPushes))
		pushId := configLogSuiteId()
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsPush{
			RepoId:          self.repoId.Bytes(),
			RefId:           self.refId.Bytes(),
			PushId:          pushId.Bytes(),
			BaseVersion:     read,
			BaseChain:       bytes.Clone(self.chains[read][:]),
			SignerSidecarId: self.signer.sidecarId.Bytes(),
		})
		signed, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
			Body:     body,
			SignerId: self.signer.sidecarId.Bytes(),
			// §6.11's evs-push purpose
			Signature: ed25519.Sign(self.signer.key, bridge.SignedBytes("evs-push", bridge.SignedType_SIGNED_EVS_PUSH, body)),
			Type:      uint32(bridge.SignedType_SIGNED_EVS_PUSH),
		})
		self.versionPushes = append(self.versionPushes, signed)
		self.chains = append(self.chains, sidecar.EvsChainNext(self.chains[read], pushId, sidecar.EvsStatementSha256(signed)))
	}
}

// C_version.
func (self *configLogSuiteConfigRepo) head(version uint64) [sha256.Size]byte {
	self.through(version)
	return self.chains[version]
}

// The pushes of the versions after from through to, oldest first.
func (self *configLogSuiteConfigRepo) pushes(from uint64, to uint64) [][]byte {
	self.through(to)
	return slices.Clone(self.versionPushes[from:to])
}

// body signed by the device's identity key under its type's purpose, as a Signed's bytes.
func (self *configLogSuiteEnv) sign(signer configLogSuiteDevice, signedType bridge.SignedType, body proto.Message) []byte {
	bodyBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	purpose, _ := sidecar.ConfigStatementPurpose(signedType)
	signed := &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  signer.sidecarId.Bytes(),
		Signature: ed25519.Sign(signer.key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	}
	signedBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	return signedBytes
}

// The network's Signed Genesis, its first device owner's, naming configRepo.
func (self *configLogSuiteEnv) genesis(owner configLogSuiteDevice, configRepo *configLogSuiteConfigRepo) []byte {
	return self.sign(owner, bridge.SignedType_SIGNED_GENESIS, &bridge.Genesis{
		NetworkId:              self.networkId.Bytes(),
		ConfigRepoId:           configRepo.repoId.Bytes(),
		OwnerMemberId:          owner.memberId.Bytes(),
		OwnerSidecarId:         owner.sidecarId.Bytes(),
		OwnerIdentityPublicKey: owner.key.Public().(ed25519.PublicKey),
		TimeMs:                 self.clock.Now().UnixMilli(),
	})
}

// Base 1's rows: the owner an Owner and its first device.
func (self *configLogSuiteEnv) baseOneRows(owner configLogSuiteDevice) []byte {
	rows, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: owner.memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         owner.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{owner.sidecarId.Bytes()},
			IdentityPublicKey: owner.key.Public().(ed25519.PublicKey),
			IdentityAlg:       "ed25519",
			MemberId:          owner.memberId.Bytes(),
		}},
	})
	return rows
}

// A base signed by signer at the tip given, over rows, naming the head of the env's config repo at configVersion.
func (self *configLogSuiteEnv) base(signer configLogSuiteDevice, tip *bridge.AuthPin, rows []byte, foldedThrough uint64, configVersion uint64) []byte {
	return self.baseNaming(signer, tip, rows, foldedThrough, configVersion, self.configRepo.head(configVersion))
}

// A base as base makes it, naming headSha256 as its config head.
func (self *configLogSuiteEnv) baseNaming(signer configLogSuiteDevice, tip *bridge.AuthPin, rows []byte, foldedThrough uint64, configVersion uint64, headSha256 [sha256.Size]byte) []byte {
	rowsSha256 := sha256.Sum256(rows)
	return self.sign(signer, bridge.SignedType_SIGNED_PROJECTION_HEADER, &bridge.ProjectionHeader{
		NetworkId:        self.networkId.Bytes(),
		Version:          tip.GetVersion() + 1,
		PrevChain:        tip.GetChain(),
		FoldedThrough:    foldedThrough,
		ConfigVersion:    configVersion,
		ConfigHeadSha256: headSha256[:],
		RowsSha256:       rowsSha256[:],
		RowsByteCount:    uint32(len(rows)),
		TailVerdicts:     self.tailVerdicts(foldedThrough, tip.GetVersion()),
	})
}

// The tail_verdicts a base after tip folding through foldedThrough carries (DESIGN-DETAILS 5.2.2), as the cluster
// holds the tail: every statement and tick the suite lands takes effect, and a base carries 0. Two bits an entry,
// entry foldedThrough+1+j at bits 2j and 2j+1 of byte j/4; empty when nothing is unfolded or a read fails, which the
// sequencer then refuses.
func (self *configLogSuiteEnv) tailVerdicts(foldedThrough uint64, tip uint64) []byte {
	if tip <= foldedThrough {
		return nil
	}
	count := tip - foldedThrough
	data := make([]byte, (2*count+7)/8)
	for k := foldedThrough + 1; k <= tip; k += 1 {
		entry, err := self.entry(k)
		if err != nil || entry == nil {
			return nil
		}
		if entry.GetKind() == bridge.AuthEntryKindBase {
			continue
		}
		j := k - foldedThrough - 1
		data[j/4] |= 1 << (2 * (j % 4))
	}
	return data
}

// A StatementHeader at the tip the case last saw, a fresh nonce, expiring in an hour.
func (self *configLogSuiteEnv) header() *bridge.StatementHeader {
	self.nonce += 1
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[8:], self.nonce)
	return &bridge.StatementHeader{
		NetworkId:  self.networkId.Bytes(),
		At:         proto.Clone(self.tip).(*bridge.AuthPin),
		Nonce:      nonce,
		NotAfterMs: self.clock.Now().Add(time.Hour).UnixMilli(),
	}
}

// A MemberAdmit by the owner of a fresh member.
func (self *configLogSuiteEnv) memberAdmit() []byte {
	return self.sign(self.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: self.header(), MemberId: configLogSuiteId().Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})
}

// A SidecarAdmit by the owner of a device of the owner's member.
func (self *configLogSuiteEnv) sidecarAdmit(device configLogSuiteDevice) []byte {
	return self.sign(self.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            self.header(),
		NetworkId:         self.networkId.Bytes(),
		SidecarId:         device.sidecarId.Bytes(),
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		IdentityAlg:       "ed25519",
		MemberId:          device.memberId.Bytes(),
	})
}

// The cluster key prefix of this network's entries.
func (self *configLogSuiteEnv) entryPrefix() string {
	return sidecar.ConfigEntryKeyPrefix(self.networkId)
}

// The bytes a key holds, nil for none.
func (self *configLogSuiteEnv) read(key string) ([]byte, error) {
	object, err := self.cluster.BlobCluster.Get(self.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	return io.ReadAll(object.Body)
}

// The entry at n, parsed, nil for none.
func (self *configLogSuiteEnv) entry(n uint64) (*bridge.AuthEntry, error) {
	entryBytes, err := self.read(sidecar.ConfigEntryKey(self.networkId, n))
	if err != nil || entryBytes == nil {
		return nil, err
	}
	entry := &bridge.AuthEntry{}
	return entry, proto.Unmarshal(entryBytes, entry)
}

// Every entry position the cluster holds for this network, 0 included.
func (self *configLogSuiteEnv) positions() ([]uint64, error) {
	positions := []uint64{}
	startAfter := ""
	for {
		infos, more, err := self.cluster.BlobCluster.List(self.ctx, self.entryPrefix(), startAfter, 500)
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			if n, ok := sidecar.ParseConfigEntryKey(self.networkId, info.Key); ok {
				positions = append(positions, n)
			}
			startAfter = info.Key
		}
		if !more {
			return positions, nil
		}
	}
}

// A sequencer of this case.
func (self *configLogSuiteEnv) sequencer() ConfigLogSequencer {
	return self.newSequencer(self.clock, self.cluster)
}

// Starts the network: base 1 with its genesis, the tip moved to it.
func (self *configLogSuiteEnv) start(sequencer ConfigLogSequencer) error {
	genesisChain := bridge.GenesisChain(self.signedGenesis)
	self.tip = &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}
	pin, err := sequencer.AppendBase(self.ctx, self.networkId, self.base(self.owner, self.tip, self.baseOneRows(self.owner), 0, 1),
		self.baseOneRows(self.owner), self.signedGenesis, self.configRepo.pushes(0, 1))
	if err != nil {
		return fmt.Errorf("base 1: %w", err)
	}
	if pin.GetVersion() != 1 {
		return fmt.Errorf("base 1 at %d", pin.GetVersion())
	}
	self.tip = pin
	self.clock.Advance(time.Second)
	return nil
}

// Appends a statement and moves the case's tip to it.
func (self *configLogSuiteEnv) post(sequencer ConfigLogSequencer, signed []byte) (*bridge.AuthPin, error) {
	pin, err := sequencer.AppendStatement(self.ctx, self.networkId, signed)
	if err == nil {
		self.tip = pin
		self.clock.Advance(time.Second)
	}
	return pin, err
}

// Checks that the entry at pin holds body as kind, chains on, and gives pin's A_n.
func (self *configLogSuiteEnv) checkEntry(pin *bridge.AuthPin, kind uint32, body []byte) error {
	entry, err := self.entry(pin.GetVersion())
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("no entry at %d", pin.GetVersion())
	}
	if entry.GetKind() != kind || !bytes.Equal(entry.GetBody(), body) || !bytes.Equal(entry.GetNetworkId(), self.networkId.Bytes()) {
		return fmt.Errorf("the entry at %d holds kind %d and another body", pin.GetVersion(), entry.GetKind())
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return err
	}
	if !bytes.Equal(chain[:], pin.GetChain()) {
		return fmt.Errorf("the entry at %d gives another A_n", pin.GetVersion())
	}
	return nil
}

// The refusal an append answered, failing unless it is one with status.
func configLogSuiteRefusal(err error, status int) (*ConfigLogRefusal, error) {
	refusal := &ConfigLogRefusal{}
	if !errors.As(err, &refusal) || refusal.Status != status {
		return nil, fmt.Errorf("got %v, want a %d refusal", err, status)
	}
	return refusal, nil
}

func caseConfigLogGenesis(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	genesis, err := env.read(sidecar.ConfigEntryKey(env.networkId, 0))
	if err != nil {
		return err
	}
	if !bytes.Equal(genesis, env.signedGenesis) {
		return errors.New("entry 0 does not hold the Signed Genesis verbatim")
	}
	entry, err := env.entry(1)
	if err != nil || entry == nil {
		return fmt.Errorf("entry 1: %v", err)
	}
	genesisChain := bridge.GenesisChain(env.signedGenesis)
	if entry.GetKind() != bridge.AuthEntryKindBase || !bytes.Equal(entry.GetPrevChain(), genesisChain[:]) {
		return errors.New("entry 1 is no base on A_0")
	}
	rows := env.baseOneRows(env.owner)
	rowsSha256 := sha256.Sum256(rows)
	held, err := env.read(sidecar.ConfigRowsKey(env.networkId, rowsSha256[:]))
	if err != nil {
		return err
	}
	if !bytes.Equal(held, rows) {
		return errors.New("projrows/ does not hold base 1's rows")
	}
	return nil
}

func caseConfigLogStatementLands(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	signed := env.memberAdmit()
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return err
	}
	if pin.GetVersion() != 2 {
		return fmt.Errorf("the statement at %d", pin.GetVersion())
	}
	return env.checkEntry(pin, bridge.AuthEntryKindStatement, signed)
}

func caseConfigLogLostResponse(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	signed := env.memberAdmit()
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogLostResponse})
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return fmt.Errorf("the append whose PUT answer was lost: %w", err)
	}
	if env.cluster.metCount() != 1 {
		return errors.New("the lost response was never met")
	}
	// the client lost api's answer too, and sends the same bytes again, to another instance
	again, err := env.sequencer().AppendStatement(env.ctx, env.networkId, signed)
	if err != nil {
		return fmt.Errorf("the retry: %w", err)
	}
	if !proto.Equal(pin, again) {
		return fmt.Errorf("the retry answered %d, not %d", again.GetVersion(), pin.GetVersion())
	}
	positions, err := env.positions()
	if err != nil {
		return err
	}
	if len(positions) != 3 {
		return fmt.Errorf("the log holds %d entries, 0 included, not 3", len(positions))
	}
	return env.checkEntry(pin, bridge.AuthEntryKindStatement, signed)
}

func caseConfigLogRaceThenLands(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	other := env.memberAdmit()
	signed := env.memberAdmit()
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogRaceFirst, otherBody: other})
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return err
	}
	if pin.GetVersion() != 3 {
		return fmt.Errorf("the statement at %d, not after the other appender's", pin.GetVersion())
	}
	otherEntry, err := env.entry(2)
	if err != nil || otherEntry == nil || !bytes.Equal(otherEntry.GetBody(), other) {
		return fmt.Errorf("entry 2 is not the other appender's: %v", err)
	}
	return env.checkEntry(pin, bridge.AuthEntryKindStatement, signed)
}

func caseConfigLogRaceThenRefused(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	device := env.device(env.ownerMemberId)
	other := env.sidecarAdmit(device)
	signed := env.sidecarAdmit(device)
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogRaceFirst, otherBody: other})
	_, err := env.post(sequencer, signed)
	refusal, err := configLogSuiteRefusal(err, http.StatusForbidden)
	if err != nil {
		return err
	}
	if refusal.Tip.GetVersion() != 2 {
		return fmt.Errorf("the refusal's tip is %d, not the other appender's 2", refusal.Tip.GetVersion())
	}
	positions, err := env.positions()
	if err != nil {
		return err
	}
	if len(positions) != 3 {
		return fmt.Errorf("a refused statement was written: %d entries", len(positions))
	}
	return nil
}

func caseConfigLogRaceSameStatement(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	signed := env.memberAdmit()
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogRaceFirst, otherBody: signed})
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return err
	}
	if pin.GetVersion() != 2 {
		return fmt.Errorf("the statement answered %d, not the entry another instance appended", pin.GetVersion())
	}
	positions, err := env.positions()
	if err != nil {
		return err
	}
	if len(positions) != 3 {
		return fmt.Errorf("one statement holds %d positions", len(positions)-2)
	}
	return nil
}

func caseConfigLogTimeoutUnapplied(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	signed := env.memberAdmit()
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogTimeoutUnapplied})
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return err
	}
	if pin.GetVersion() != 2 || env.cluster.metCount() != 1 {
		return fmt.Errorf("the statement at %d after %d injections", pin.GetVersion(), env.cluster.metCount())
	}
	return env.checkEntry(pin, bridge.AuthEntryKindStatement, signed)
}

func caseConfigLogTimeoutLoss(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	other := env.memberAdmit()
	signed := env.memberAdmit()
	env.cluster.arm(env.entryPrefix(), &configLogInjectionPlan{injection: configLogRaceTimeout, otherBody: other})
	pin, err := env.post(sequencer, signed)
	if err != nil {
		return err
	}
	if pin.GetVersion() != 3 {
		return fmt.Errorf("the statement at %d, not after the entry that took its position", pin.GetVersion())
	}
	return env.checkEntry(pin, bridge.AuthEntryKindStatement, signed)
}

func caseConfigLogRefused(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	stranger := env.device(env.ownerMemberId)
	signed := env.sign(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: env.header(), MemberId: configLogSuiteId().Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})
	_, err := env.post(sequencer, signed)
	refusal, err := configLogSuiteRefusal(err, http.StatusForbidden)
	if err != nil {
		return err
	}
	if !proto.Equal(refusal.Tip, env.tip) {
		return fmt.Errorf("the refusal names tip %d", refusal.Tip.GetVersion())
	}
	if entry, err := env.entry(2); err != nil || entry != nil {
		return fmt.Errorf("a refused statement was written: %v", err)
	}
	return nil
}

func caseConfigLogBases(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	if _, err := env.post(sequencer, env.memberAdmit()); err != nil {
		return err
	}
	oldTip := env.tip
	rows := env.baseOneRows(env.owner)
	if _, err := env.post(sequencer, env.memberAdmit()); err != nil {
		return err
	}
	// signed at the old tip: the tip moved
	_, err := sequencer.AppendBase(env.ctx, env.networkId, env.base(env.owner, oldTip, rows, 2, 2), rows, nil, env.configRepo.pushes(1, 2))
	refusal, err := configLogSuiteRefusal(err, http.StatusConflict)
	if err != nil {
		return fmt.Errorf("a base at an old tip: %w", err)
	}
	if !proto.Equal(refusal.Tip, env.tip) {
		return errors.New("the 409 names another tip")
	}
	// re-signed at the tip, it lands
	signedHeader := env.base(env.owner, env.tip, rows, 2, 2)
	pin, err := sequencer.AppendBase(env.ctx, env.networkId, signedHeader, rows, nil, env.configRepo.pushes(1, 2))
	if err != nil {
		return fmt.Errorf("the re-signed base: %w", err)
	}
	if err := env.checkEntry(pin, bridge.AuthEntryKindBase, signedHeader); err != nil {
		return err
	}
	env.tip = pin
	env.clock.Advance(time.Second)
	// a stale compile: a lower fold, then an older head
	for _, stale := range [][2]uint64{{1, 2}, {2, 1}} {
		_, err := sequencer.AppendBase(env.ctx, env.networkId, env.base(env.owner, env.tip, rows, stale[0], stale[1]), rows, nil, nil)
		if _, err := configLogSuiteRefusal(err, http.StatusForbidden); err != nil {
			return fmt.Errorf("a stale compile folding %d at version %d: %w", stale[0], stale[1], err)
		}
	}
	// rows that do not hash to rows_sha256
	_, err = sequencer.AppendBase(env.ctx, env.networkId, env.base(env.owner, env.tip, rows, 2, 2), append(bytes.Clone(rows), 0), nil, nil)
	if _, err := configLogSuiteRefusal(err, http.StatusForbidden); err != nil {
		return fmt.Errorf("rows off their hash: %w", err)
	}
	// a retry of the landed base answers its entry
	again, err := env.sequencer().AppendBase(env.ctx, env.networkId, signedHeader, rows, nil, env.configRepo.pushes(1, 2))
	if err != nil || !proto.Equal(again, pin) {
		return fmt.Errorf("a retry of the landed base: %v", err)
	}
	return nil
}

func caseConfigLogDescent(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	rows := env.baseOneRows(env.owner)
	before, err := env.positions()
	if err != nil {
		return err
	}
	pushes := env.configRepo.pushes(1, 3)
	other := newConfigLogSuiteConfigRepo(env.owner)
	refusals := []struct {
		name         string
		signedHeader []byte
		pushes       [][]byte
	}{
		{name: "a push short", signedHeader: env.base(env.owner, env.tip, rows, 1, 3), pushes: pushes[:1]},
		{name: "two pushes swapped", signedHeader: env.base(env.owner, env.tip, rows, 1, 3), pushes: [][]byte{pushes[1], pushes[0]}},
		{name: "another repo's pushes", signedHeader: env.baseNaming(env.owner, env.tip, rows, 1, 3, other.head(3)), pushes: other.pushes(1, 3)},
		{name: "an unchanged version naming another head", signedHeader: env.baseNaming(env.owner, env.tip, rows, 1, 1, other.head(1)), pushes: nil},
	}
	for _, refused := range refusals {
		_, err := sequencer.AppendBase(env.ctx, env.networkId, refused.signedHeader, rows, nil, refused.pushes)
		if _, err := configLogSuiteRefusal(err, http.StatusForbidden); err != nil {
			return fmt.Errorf("%s: %w", refused.name, err)
		}
	}
	after, err := env.positions()
	if err != nil {
		return err
	}
	if len(after) != len(before) {
		return fmt.Errorf("refused bases wrote %d entries", len(after)-len(before))
	}
	// the walk that reaches the head lands, and then an unchanged version naming the same head
	signedHeader := env.base(env.owner, env.tip, rows, 1, 3)
	pin, err := sequencer.AppendBase(env.ctx, env.networkId, signedHeader, rows, nil, pushes)
	if err != nil {
		return fmt.Errorf("the base the walk reaches: %w", err)
	}
	if err := env.checkEntry(pin, bridge.AuthEntryKindBase, signedHeader); err != nil {
		return err
	}
	env.tip = pin
	env.clock.Advance(time.Second)
	if _, err := sequencer.AppendBase(env.ctx, env.networkId, env.base(env.owner, env.tip, rows, 1, 3), rows, nil, nil); err != nil {
		return fmt.Errorf("an unchanged version naming its head: %w", err)
	}
	return nil
}

func caseConfigLogGenesisRace(env *configLogSuiteEnv) error {
	first, second := env.sequencer(), env.sequencer()
	if err := env.start(first); err != nil {
		return err
	}
	rival := env.device(configLogSuiteId())
	rivalRepo := newConfigLogSuiteConfigRepo(rival)
	rivalGenesis := env.genesis(rival, rivalRepo)
	rivalChain := bridge.GenesisChain(rivalGenesis)
	rows := env.baseOneRows(rival)
	rivalBase := env.baseNaming(rival, &bridge.AuthPin{Version: 0, Chain: rivalChain[:]}, rows, 0, 1, rivalRepo.head(1))
	_, err := second.AppendBase(env.ctx, env.networkId, rivalBase, rows, rivalGenesis, rivalRepo.pushes(0, 1))
	if err == nil {
		return errors.New("a second genesis took base 1")
	}
	genesis, err := env.read(sidecar.ConfigEntryKey(env.networkId, 0))
	if err != nil {
		return err
	}
	if !bytes.Equal(genesis, env.signedGenesis) {
		return errors.New("entry 0 holds the loser's genesis")
	}
	return nil
}

func caseConfigLogGenesisRetry(env *configLogSuiteEnv) error {
	genesisKey := sidecar.ConfigEntryKey(env.networkId, 0)
	env.cluster.arm(genesisKey, &configLogInjectionPlan{injection: configLogTimeoutUnapplied}, &configLogInjectionPlan{injection: configLogTimeoutUnapplied})
	sequencer := env.sequencer()
	if err := env.start(sequencer); err == nil {
		return errors.New("base 1 answered success with its genesis unwritten")
	}
	if entry, err := env.entry(1); err != nil || entry == nil {
		return fmt.Errorf("entry 1, the commit point, is not written: %v", err)
	}
	if genesis, err := env.read(genesisKey); err != nil || genesis != nil {
		return fmt.Errorf("entry 0 was written: %v", err)
	}
	if err := env.start(env.sequencer()); err != nil {
		return fmt.Errorf("the retry: %w", err)
	}
	genesis, err := env.read(genesisKey)
	if err != nil || !bytes.Equal(genesis, env.signedGenesis) {
		return fmt.Errorf("entry 0 after the retry: %v", err)
	}
	return nil
}

func caseConfigLogTick(env *configLogSuiteEnv) error {
	sequencer := env.sequencer()
	if err := env.start(sequencer); err != nil {
		return err
	}
	tick := &bridge.ApiTick{}
	pin, err := sequencer.AppendTick(env.ctx, env.networkId, tick)
	if err != nil {
		return err
	}
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(tick)
	return env.checkEntry(pin, bridge.AuthEntryKindTick, body)
}

func caseConfigLogConcurrentAppenders(env *configLogSuiteEnv) error {
	first, second := env.sequencer(), env.sequencer()
	if err := env.start(first); err != nil {
		return err
	}
	const count = 6
	statements := [2][][]byte{}
	for appender := range 2 {
		for range count {
			statements[appender] = append(statements[appender], env.memberAdmit())
		}
	}
	pins := [2][]*bridge.AuthPin{}
	errs := [2]error{}
	var group sync.WaitGroup
	for appender, sequencer := range []ConfigLogSequencer{first, second} {
		group.Add(1)
		go func() {
			defer group.Done()
			for _, signed := range statements[appender] {
				pin, err := sequencer.AppendStatement(env.ctx, env.networkId, signed)
				if err != nil {
					errs[appender] = err
					return
				}
				pins[appender] = append(pins[appender], pin)
			}
		}()
	}
	group.Wait()
	for appender, err := range errs {
		if err != nil {
			return fmt.Errorf("appender %d: %w", appender, err)
		}
	}
	positions, err := env.positions()
	if err != nil {
		return err
	}
	if len(positions) != 2+2*count {
		return fmt.Errorf("%d entries for %d statements", len(positions)-2, 2*count)
	}
	held := map[uint64]bool{}
	for appender := range 2 {
		for i, pin := range pins[appender] {
			if held[pin.GetVersion()] {
				return fmt.Errorf("two statements answered position %d", pin.GetVersion())
			}
			held[pin.GetVersion()] = true
			if err := env.checkEntry(pin, bridge.AuthEntryKindStatement, statements[appender][i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// One network's signers for a test outside the suite, server's among them: its genesis, base 1 and statements, made
// as the suite's cases make them, on a network id of its own.
type ConfigLogSuiteWorld struct {
	env *configLogSuiteEnv
}

// A fresh network over cluster, whose appends the test sends to a sequencer of its own.
func NewConfigLogSuiteWorld(ctx context.Context, cluster sidecar.BlobCluster) *ConfigLogSuiteWorld {
	return &ConfigLogSuiteWorld{env: newConfigLogSuiteEnv(ctx, cluster, nil)}
}

// A network of networkId whose owner is ownerMemberId (its user, in a personal network) and whose first device, the
// genesis owner, is ownerSidecarId: a route test's network and bound sidecar.
func NewConfigLogSuiteWorldFor(ctx context.Context, cluster sidecar.BlobCluster, networkId sidecar.Id, ownerMemberId sidecar.Id, ownerSidecarId sidecar.Id) *ConfigLogSuiteWorld {
	env := newConfigLogSuiteEnv(ctx, cluster, nil)
	env.networkId = networkId
	env.ownerMemberId = ownerMemberId
	env.owner.memberId = ownerMemberId
	env.owner.sidecarId = ownerSidecarId
	env.configRepo = newConfigLogSuiteConfigRepo(env.owner)
	env.signedGenesis = env.genesis(env.owner, env.configRepo)
	return &ConfigLogSuiteWorld{env: env}
}

// Base 1 as its first device posts it: the Signed header, the rows, the Signed Genesis and the config head's first
// push.
func (self *ConfigLogSuiteWorld) BaseOne() (signedHeader []byte, rows []byte, signedGenesis []byte, configPushes [][]byte) {
	genesisChain := bridge.GenesisChain(self.env.signedGenesis)
	rows = self.env.baseOneRows(self.env.owner)
	signedHeader = self.env.base(self.env.owner, &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}, rows, 0, 1)
	return signedHeader, rows, self.env.signedGenesis, self.env.configRepo.pushes(0, 1)
}

// The Signed EvsPush of each version of the network's config head after from through to, as a base adding them
// carries them.
func (self *ConfigLogSuiteWorld) ConfigPushes(from uint64, to uint64) [][]byte {
	return self.env.configRepo.pushes(from, to)
}

// The owner's MemberAdmit of a fresh member, signed at the tip the world last saw.
func (self *ConfigLogSuiteWorld) MemberAdmit() []byte {
	return self.env.memberAdmit()
}

// The owner's RepoCreate of a fresh repo of kind, signed at the tip the world last saw: the directory's is what api
// alone refuses outside the team tier (§8.8).
func (self *ConfigLogSuiteWorld) RepoCreate(kind protocol.RepoKind) []byte {
	return self.env.sign(self.env.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: self.env.header(), RepoId: configLogSuiteId().Bytes(), Kind: kind,
	})
}

// Moves the tip the world signs at to pin, as an append's answer gives it.
func (self *ConfigLogSuiteWorld) SetTip(pin *bridge.AuthPin) {
	self.env.tip = proto.Clone(pin).(*bridge.AuthPin)
	self.env.clock.Advance(time.Second)
}

// The network's id.
func (self *ConfigLogSuiteWorld) NetworkId() sidecar.Id {
	return self.env.networkId
}

// The clock its statements are signed by, which a sequencer it appends through must share, or they expire.
func (self *ConfigLogSuiteWorld) Clock() *FakeClock {
	return self.env.clock
}

// The network's Signed Genesis.
func (self *ConfigLogSuiteWorld) SignedGenesis() []byte {
	return self.env.signedGenesis
}

// Base 1 with the genesis, through sequencer.
func (self *ConfigLogSuiteWorld) Start(sequencer ConfigLogSequencer) error {
	return self.env.start(sequencer)
}

// The owner's MemberAdmit of a fresh member at the tip, through sequencer.
func (self *ConfigLogSuiteWorld) PostMemberAdmit(sequencer ConfigLogSequencer) (*bridge.AuthPin, error) {
	return self.env.post(sequencer, self.env.memberAdmit())
}

// The owner's member id: its user's id in a personal network.
func (self *ConfigLogSuiteWorld) OwnerMemberId() sidecar.Id {
	return self.env.owner.memberId
}

// The owner's first device, the genesis's sidecar.
func (self *ConfigLogSuiteWorld) OwnerSidecarId() sidecar.Id {
	return self.env.owner.sidecarId
}

// A StatementHeader at the tip the world last saw, with a fresh nonce, expiring in an hour: what a test's own
// statement carries.
func (self *ConfigLogSuiteWorld) Header() *bridge.StatementHeader {
	return self.env.header()
}

// body signed by the owner's first device under its type's purpose, as a Signed's bytes: a test's own statement,
// such as a SidecarAdmit of a second device or a SidecarRevoke.
func (self *ConfigLogSuiteWorld) SignAsOwner(signedType bridge.SignedType, body proto.Message) []byte {
	return self.env.sign(self.env.owner, signedType, body)
}
