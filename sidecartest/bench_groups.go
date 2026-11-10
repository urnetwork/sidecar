// §22.8's `groups` row as a runnable harness (KEYS-M2-31; D-KEYS-10, D-KEYS-14, D-TEST-11): §10.6's size table
// measured on the real MLS subset and the real ladder, at each leaf count asked for, 10, 100 and 1,000 at full
// scale, and emitted as a table that §22.8 and §19.9 consume.
//
// What one run builds and measures, per leaf count N:
//
//	group       a creator and N-1 joiners, each its own engine, identity key and store; one Add-only commit adds
//	            them all, so every parent is blank: the tree's low bound and a path commit's high bound
//	members     the creator and the joiners at leaves 1, 2, 4, 8, ..., one in each subtree beside the creator's
//	            path, join by the Welcome; the first join's time and sampled heap peak are measured
//	blank path  the creator's first path commit, which encrypts to every other leaf: the high bound
//	full path   after each member has committed a path, the creator's copath is filled: its next path commit
//	            encrypts to one node a level, the low bound; the tree then holds those parents, not all of them
//	GroupInfo   the epoch's GroupInfo with ratchet_tree and external_pub, and sealed under K_groupinfo
//	resync      the member at leaf 1, a week behind, joins from that one GroupInfo by an external commit that removes
//	            its old leaf (KF5): its size, its time and its sampled heap peak
//
// and once a run: each object of the table (KeyPackage, ReaderKey, ReaderWrap staged and late, RecoveryWrap,
// GenRotate with and without a drop key, GenWrap, the group owner marker and the Welcome pointer of DESIGN-DETAILS
// 6.2.2), and a config rotation's re-wrap to WrappedHolderCount holders, by a leaf, whose leaf_wrap serves the tree,
// and by a wrapped rotator, which wraps to every leaf as well (owner decision 144): the ReaderKeys checked, the
// deliveries sealed and signed, their bytes and their time.
//
// The heap peaks are sampled from the runtime's heap while the step runs, as the rise above what the run held when
// the step began, under a Go memory limit of that plus MemoryLimitByteCount where one is set: a peak, not an
// allocation total, and it counts garbage the collector had not yet freed. They are this machine's, on this leg;
// the ios32 surrogate cell's run (§22.9) is the same harness there. The staging run, with gkm and the file cluster
// behind it, is external.
//
// This benchmarks production code paths: NewMlsEngine's engine on a sealed-store fake, credential 0xF552 signed
// by each sidecar's identity key and admitted by a check, and gkm_keys.go's and gkm_delivery.go's seals.

package sidecartest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The rows a groups run measures. A row with a leaf count is one group's; the others are per object or per run.
const (
	GroupsBenchKeyPackage           = "KeyPackage"
	GroupsBenchAddOnlyCommit        = "Add-only commit"
	GroupsBenchWelcome              = "Welcome without the tree"
	GroupsBenchGroupInfoBlank       = "GroupInfo, parents blank"
	GroupsBenchGroupInfoPaths       = "GroupInfo, members' paths filled"
	GroupsBenchSealedGroupInfo      = "sealed GroupInfo"
	GroupsBenchPathCommitBlank      = "path commit, parents blank"
	GroupsBenchPathCommitFull       = "path commit, copath full"
	GroupsBenchWelcomeJoin          = "Welcome join"
	GroupsBenchWelcomeJoinPeak      = "Welcome join, heap peak"
	GroupsBenchPathCommitPeak       = "path commit, heap peak"
	GroupsBenchResync               = "resync by external commit"
	GroupsBenchResyncPeak           = "resync by external commit, heap peak"
	GroupsBenchReaderKey            = "ReaderKey"
	GroupsBenchReaderWrap           = "ReaderWrap, staged"
	GroupsBenchReaderWrapLate       = "ReaderWrap, late"
	GroupsBenchRecoveryWrap         = "RecoveryWrap"
	GroupsBenchGenRotate            = "GenRotate with a LeafWrap"
	GroupsBenchGenRotateNoLeafWrap  = "GenRotate without a LeafWrap"
	GroupsBenchGenRotateDropKey     = "GenRotate with a LeafWrap and a drop key"
	GroupsBenchGenWrap              = "GenWrap"
	GroupsBenchGroupOwner           = "group owner marker"
	GroupsBenchWelcomePointer       = "Welcome pointer"
	GroupsBenchRotationByLeaf       = "config rotation by a leaf, wraps"
	GroupsBenchRotationByWrapped    = "config rotation by a wrapped rotator, wraps"
	groupsBenchHeapMetric           = "/memory/classes/heap/objects:bytes"
	groupsBenchTotalMetric          = "/memory/classes/total:bytes"
	groupsBenchReleasedMetric       = "/memory/classes/heap/released:bytes"
	groupsBenchHeapSampleInterval   = 200 * time.Microsecond
	groupsBenchConfigTreeLeafCount  = 1000
	groupsBenchReducedHolderCount   = 64
	groupsBenchFullHolderCount      = 5000
	groupsBenchIos32MemoryByteCount = 32 * 1024 * 1024
)

// What a groups run measures at.
type GroupsBenchSettings struct {
	// The leaf counts §10.6's table is measured at.
	LeafCounts []int
	// The wrapped holders a config rotation re-wraps to (§20.4's Team admissions: agents and member devices past the
	// first 1,000).
	WrappedHolderCount int
	// The leaves a wrapped rotator's rotation also wraps to: a full tree's 1,000, fewer at reduced scale.
	RotationLeafCount int
	// The Go memory limit the measured joins and commits run under: the ios32 surrogate cell's 32 MiB (§18.4). Zero
	// sets none.
	MemoryLimitByteCount int64
}

// Full scale: §22.8's row.
func DefaultGroupsBenchSettings() *GroupsBenchSettings {
	return &GroupsBenchSettings{
		LeafCounts:           []int{10, 100, 1000},
		WrappedHolderCount:   groupsBenchFullHolderCount,
		RotationLeafCount:    groupsBenchConfigTreeLeafCount,
		MemoryLimitByteCount: groupsBenchIos32MemoryByteCount,
	}
}

// Reduced scale, which every test run takes: the table's first column and one tree above the 16-leaf bound.
func ReducedGroupsBenchSettings() *GroupsBenchSettings {
	return &GroupsBenchSettings{
		LeafCounts:         []int{10, 32},
		WrappedHolderCount: groupsBenchReducedHolderCount,
		RotationLeafCount:  32,
	}
}

// One measurement.
type GroupsBenchRow struct {
	Name string
	// The group's leaves, or a rotation's holders; 0 for a per-object row.
	Count int
	// The object's bytes, a step's heap peak, or a rotation's bytes in all; 0 for a row that is only a time.
	ByteCount int64
	// How long the step took on this machine; 0 for a row that is only a size.
	Duration time.Duration
}

// What a groups run measured.
type GroupsBenchReport struct {
	Rows []*GroupsBenchRow
}

// The row by name and count, nil for none.
func (self *GroupsBenchReport) Row(name string, count int) *GroupsBenchRow {
	for _, row := range self.Rows {
		if row.Name == name && row.Count == count {
			return row
		}
	}
	return nil
}

// The report as the table §22.8 and §19.9 read: one row a line, its count, bytes and milliseconds.
func (self *GroupsBenchReport) Table() string {
	lines := []string{fmt.Sprintf("%-48s %8s %12s %10s", "row", "count", "bytes", "ms")}
	for _, row := range self.Rows {
		count, byteCount, duration := "", "", ""
		if row.Count != 0 {
			count = fmt.Sprintf("%d", row.Count)
		}
		if row.ByteCount != 0 {
			byteCount = fmt.Sprintf("%d", row.ByteCount)
		}
		if row.Duration != 0 {
			duration = fmt.Sprintf("%.1f", float64(row.Duration.Microseconds())/1000)
		}
		lines = append(lines, fmt.Sprintf("%-48s %8s %12s %10s", row.Name, count, byteCount, duration))
	}
	return strings.Join(lines, "\n") + "\n"
}

func (self *GroupsBenchReport) add(name string, count int, byteCount int, duration time.Duration) {
	self.Rows = append(self.Rows, &GroupsBenchRow{Name: name, Count: count, ByteCount: int64(byteCount), Duration: duration})
}

// The sidecars one run admits to one another, standing in for the log's admissions.
type groupsBenchAdmissions struct {
	stateLock     sync.Mutex
	sidecarIdKeys map[sidecar.Id]ed25519.PublicKey
}

func (self *groupsBenchAdmissions) check(credential *protocol.UrMlsCredential) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	publicKey, ok := self.sidecarIdKeys[sidecar.Id(credential.GetSidecarId())]
	if !ok || !bytes.Equal(publicKey, credential.GetIdentityPublicKey()) {
		return errors.New("groups bench: a credential of no admitted sidecar")
	}
	return nil
}

// One sidecar of a run: its signer and its engine over its own store.
type groupsBenchSidecar struct {
	signer *FakeGkmSigner
	engine sidecar.MlsEngine
	group  sidecar.MlsGroup
}

func (self *groupsBenchAdmissions) sidecar() (*groupsBenchSidecar, error) {
	return self.sidecarWithYield(nil)
}

// A sidecar whose engine calls yield between the steps of its long loops, as a page Worker's does.
func (self *groupsBenchAdmissions) sidecarWithYield(yield func()) (*groupsBenchSidecar, error) {
	signer := NewFakeGkmSigner()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sidecarIdKeys[signer.SidecarId] = signer.PublicKey()
	}()
	admission := sha256.Sum256(append([]byte("admission of "), signer.SidecarId.Bytes()...))
	engine, err := sidecar.NewMlsEngine(&sidecar.MlsEngineArgs{
		SidecarId:         signer.SidecarId,
		IdentityPublicKey: signer.PublicKey(),
		AdmissionSha256:   admission[:],
		Sign:              signer.Sign,
		Store:             NewFakeStore().Root(),
		CheckCredential:   self.check,
		Yield:             yield,
	})
	if err != nil {
		return nil, err
	}
	return &groupsBenchSidecar{signer: signer, engine: engine}, nil
}

// Runs step and samples the heap while it does. Returns how far the highest sample rose above the heap the run
// already held when the step began, the other sidecars' engines and trees a device would not hold, and how long the
// step took. Where limit is set the step runs under a Go memory limit of what the process held at its start plus
// limit, so the collector works as it would on a device with that much to give the step.
func groupsBenchMeasure(limit int64, step func() error) (peakByteCount int, duration time.Duration, err error) {
	runtime.GC()
	read := func(name string) uint64 {
		samples := []metrics.Sample{{Name: name}}
		metrics.Read(samples)
		if samples[0].Value.Kind() != metrics.KindUint64 {
			return 0
		}
		return samples[0].Value.Uint64()
	}
	base := read(groupsBenchHeapMetric)
	if 0 < limit {
		held := int64(read(groupsBenchTotalMetric)) - int64(read(groupsBenchReleasedMetric))
		previous := debug.SetMemoryLimit(held + limit)
		defer debug.SetMemoryLimit(previous)
	}
	var peak atomic.Uint64
	peak.Store(base)
	done := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(groupsBenchHeapSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if sample := read(groupsBenchHeapMetric); peak.Load() < sample {
					peak.Store(sample)
				}
			}
		}
	}()
	start := time.Now()
	err = step()
	duration = time.Since(start)
	if sample := read(groupsBenchHeapMetric); peak.Load() < sample {
		peak.Store(sample)
	}
	close(done)
	<-sampled
	return int(peak.Load() - base), duration, err
}

// Has every listed sidecar but the committer process a commit and adopt it.
func groupsBenchFollow(members []*groupsBenchSidecar, committer *groupsBenchSidecar, message []byte) error {
	for _, member := range members {
		if member == committer {
			continue
		}
		staged, err := member.group.Process(message)
		if err != nil {
			return err
		}
		group, err := staged.Adopt()
		if err != nil {
			return err
		}
		member.group = group
	}
	return nil
}

// One path-only commit by committer, adopted by it and followed by members. Returns its MLSMessage.
func groupsBenchPathCommit(members []*groupsBenchSidecar, committer *groupsBenchSidecar) ([]byte, error) {
	staged, err := committer.group.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("path")})
	if err != nil {
		return nil, err
	}
	message := staged.Message()
	group, err := staged.Adopt()
	if err != nil {
		return nil, err
	}
	committer.group = group
	return message, groupsBenchFollow(members, committer, message)
}

// The rows of one group of leafCount leaves.
func groupsBenchGroup(report *GroupsBenchReport, settings *GroupsBenchSettings, leafCount int, key *sidecar.EvsRepoKey) error {
	if leafCount < 3 {
		return fmt.Errorf("groups bench: a group of %d leaves", leafCount)
	}
	admissions := &groupsBenchAdmissions{sidecarIdKeys: map[sidecar.Id]ed25519.PublicKey{}}
	creator, err := admissions.sidecar()
	if err != nil {
		return err
	}
	groupId := key.GroupId()
	creator.group, err = creator.engine.CreateGroup(groupId, &sidecar.MlsUrGroup{RepoId: key.RepoId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		return err
	}
	joiners := []*groupsBenchSidecar{}
	adds := [][]byte{}
	for len(joiners) < leafCount-1 {
		joiner, err := admissions.sidecar()
		if err != nil {
			return err
		}
		keyPackage, err := joiner.engine.CreateKeyPackage(false)
		if err != nil {
			return err
		}
		if len(joiners) == 0 && report.Row(GroupsBenchKeyPackage, 0) == nil {
			report.add(GroupsBenchKeyPackage, 0, len(keyPackage.Encoded), 0)
		}
		joiners = append(joiners, joiner)
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := creator.group.Commit(&sidecar.MlsCommitArgs{Adds: adds, AuthenticatedData: []byte("add")})
	if err != nil {
		return err
	}
	welcome := staged.Welcome()
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		return err
	}
	report.add(GroupsBenchAddOnlyCommit, leafCount, len(staged.Message()), 0)
	report.add(GroupsBenchWelcome, leafCount, len(welcome), 0)
	report.add(GroupsBenchGroupInfoBlank, leafCount, len(groupInfo), 0)
	if creator.group, err = staged.Adopt(); err != nil {
		return err
	}

	// the members that follow: the joiners at leaves 1, 2, 4, 8, ..., one in each subtree beside the creator's path
	members := []*groupsBenchSidecar{creator}
	for leafIndex := 1; leafIndex < leafCount; leafIndex <<= 1 {
		joiner := joiners[leafIndex-1]
		join := func() error {
			pending, err := joiner.engine.JoinWelcome(welcome)
			if err != nil {
				return err
			}
			joiner.group, err = pending.Complete(groupInfo)
			return err
		}
		if leafIndex != 1 {
			if err := join(); err != nil {
				return err
			}
		} else {
			peak, duration, err := groupsBenchMeasure(settings.MemoryLimitByteCount, join)
			if err != nil {
				return err
			}
			report.add(GroupsBenchWelcomeJoin, leafCount, 0, duration)
			report.add(GroupsBenchWelcomeJoinPeak, leafCount, peak, 0)
		}
		members = append(members, joiner)
	}
	if want := bits.Len(uint(leafCount-1)) + 1; len(members) != want {
		return fmt.Errorf("groups bench: %d members follow a group of %d leaves", len(members), leafCount)
	}

	// the high bound: every parent blank, so the path encrypts to every other leaf
	var blankMessage []byte
	peak, duration, err := groupsBenchMeasure(settings.MemoryLimitByteCount, func() error {
		blankMessage, err = groupsBenchPathCommit(members[:1], creator)
		return err
	})
	if err != nil {
		return err
	}
	report.add(GroupsBenchPathCommitBlank, leafCount, len(blankMessage), duration)
	report.add(GroupsBenchPathCommitPeak, leafCount, peak, 0)
	if err := groupsBenchFollow(members, creator, blankMessage); err != nil {
		return err
	}
	// each member's path fills the copath node above it
	for _, member := range members[1:] {
		if _, err := groupsBenchPathCommit(members, member); err != nil {
			return err
		}
	}
	fullMessage, err := groupsBenchPathCommit(members, creator)
	if err != nil {
		return err
	}
	report.add(GroupsBenchPathCommitFull, leafCount, len(fullMessage), 0)
	groupInfo, err = creator.group.GroupInfo()
	if err != nil {
		return err
	}
	report.add(GroupsBenchGroupInfoPaths, leafCount, len(groupInfo), 0)
	sealedGroupInfo, err := sidecar.SealGkmGroupInfo(key, groupId, creator.group.Epoch(), groupInfo)
	if err != nil {
		return err
	}
	report.add(GroupsBenchSealedGroupInfo, leafCount, len(sealedGroupInfo), 0)

	// KF5: the member at leaf 1 comes back from the one GroupInfo, by an external commit that removes its old leaf
	behind := members[1]
	reader, ok := behind.engine.(sidecar.MlsGroupInfoReader)
	if !ok {
		return errors.New("groups bench: the engine reads no GroupInfo")
	}
	opened, err := sidecar.OpenGkmGroupInfo(key, groupId, creator.group.Epoch(), sealedGroupInfo)
	if err != nil {
		return err
	}
	var external sidecar.MlsStagedCommit
	peak, duration, err = groupsBenchMeasure(settings.MemoryLimitByteCount, func() error {
		_, _, roster, err := reader.GroupInfoRoster(opened)
		if err != nil {
			return err
		}
		args := &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: []byte("resync")}
		for _, member := range roster {
			if member.SidecarId == behind.signer.SidecarId {
				args.Removes = []uint32{member.LeafIndex}
			}
		}
		external, err = behind.engine.JoinExternal(opened, args)
		return err
	})
	if err != nil {
		return err
	}
	report.add(GroupsBenchResync, leafCount, len(external.Message()), duration)
	report.add(GroupsBenchResyncPeak, leafCount, peak, 0)
	// the creator takes it as any member does
	received, err := creator.group.Process(external.Message())
	if err != nil {
		return err
	}
	if _, err := received.Adopt(); err != nil {
		return err
	}
	external.Discard()
	if leafCount == settings.LeafCounts[0] {
		kek, err := sidecar.MlsKek(members[2].group, key.RepoId())
		if err != nil {
			return err
		}
		genWrap, err := sidecar.SealGkmGenWrap(key, groupId, members[2].group.Epoch(), kek)
		if err != nil {
			return err
		}
		report.add(GroupsBenchGenWrap, 0, len(genWrap), 0)
	}
	return nil
}

// A statement's stored bytes.
func groupsBenchSize(message proto.Message) (int, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	return len(encoded), err
}

// The per-object rows and the config rotation's.
func groupsBenchObjects(report *GroupsBenchReport, settings *GroupsBenchSettings, key *sidecar.EvsRepoKey, rotate *protocol.GenRotate, generationArgs *sidecar.GkmGenerationArgs) error {
	rotator := NewFakeGkmSigner()
	holder := NewFakeGkmSigner()
	now := generationArgs.Time
	groupId := key.GroupId()

	// a leaf's rotation, which carries a leaf_wrap for its tree, and a wrapped rotator's, which carries none
	leafArgs := *generationArgs
	leafArgs.LeafWrapKek = bytes.Repeat([]byte{7}, 32)
	leafArgs.LeafWrapEpoch = 1 << 20
	_, leafRotate, err := key.NextGeneration(&leafArgs)
	if err != nil {
		return err
	}
	for _, each := range []struct {
		name   string
		rotate *protocol.GenRotate
	}{{GroupsBenchGenRotate, leafRotate}, {GroupsBenchGenRotateNoLeafWrap, rotate}} {
		signedRotate, err := sidecar.SignGenRotate(each.rotate, rotator.Sign)
		if err != nil {
			return err
		}
		byteCount, err := groupsBenchSize(signedRotate)
		if err != nil {
			return err
		}
		report.add(each.name, 0, byteCount, 0)
	}
	var byteCount int
	dropArgs := leafArgs
	dropArgs.DropNotAfter = now.Add(sidecar.DefaultGkmSettings().DropKeyLifetime)
	_, dropRotate, err := key.NextGeneration(&dropArgs)
	if err != nil {
		return err
	}
	signedDropRotate, err := sidecar.SignGenRotate(dropRotate, rotator.Sign)
	if err != nil {
		return err
	}
	if byteCount, err = groupsBenchSize(signedDropRotate); err != nil {
		return err
	}
	report.add(GroupsBenchGenRotateDropKey, 0, byteCount, 0)

	readerKey, _, err := sidecar.NewGkmReaderKey(holder.SidecarId, now, now.Add(sidecar.DefaultGkmSettings().ReaderKeyLifetime), holder.Sign)
	if err != nil {
		return err
	}
	if byteCount, err = groupsBenchSize(readerKey); err != nil {
		return err
	}
	report.add(GroupsBenchReaderKey, 0, byteCount, 0)
	// one delivery as a rotation makes it: the ReaderKey checked, RK sealed to it, the delivery signed
	deliver := func(kind sidecar.GkmDeliveryKind) (int, error) {
		checked, err := sidecar.CheckGkmReaderKey(readerKey, holder.SidecarId, holder.PublicKey(), now.UnixMilli())
		if err != nil {
			return 0, err
		}
		args := &sidecar.GkmDeliveryArgs{
			GroupId: groupId, Type: sidecar.GkmWrapTypeReader, Recipient: holder.SidecarId.Bytes(),
			RecipientPublicKey: checked.Body.GetXwingPublicKey(), Kind: kind,
		}
		if kind == sidecar.GkmDeliveryLate {
			args.Auth, args.Time = generationArgs.Auth, now
		}
		body, err := sidecar.SealGkmDelivery(key, args)
		if err != nil {
			return 0, err
		}
		signed, err := sidecar.SignGkmDelivery(body, sidecar.GkmWrapTypeReader, rotator.Sign)
		if err != nil {
			return 0, err
		}
		return groupsBenchSize(signed)
	}
	if byteCount, err = deliver(sidecar.GkmDeliveryStaged); err != nil {
		return err
	}
	report.add(GroupsBenchReaderWrap, 0, byteCount, 0)
	wrapByteCount := byteCount
	if byteCount, err = deliver(sidecar.GkmDeliveryLate); err != nil {
		return err
	}
	report.add(GroupsBenchReaderWrapLate, 0, byteCount, 0)

	bindingKeySha256 := sha256.Sum256([]byte("a recovery binding"))
	recoveryWrap, err := sidecar.SealGkmRecoveryWrap(key, &sidecar.GkmRecoveryArgs{
		MemberId: sidecar.NewId(), GroupId: groupId, RecoveryPublicKey: readerKeyPublicKey(readerKey), BindingKeySha256: bindingKeySha256[:],
	})
	if err != nil {
		return err
	}
	report.add(GroupsBenchRecoveryWrap, 0, len(recoveryWrap), 0)

	if byteCount, err = groupsBenchSize(&protocol.GkmGroupOwner{RepoId: key.RepoId().Bytes(), NetworkId: sidecar.NewId().Bytes()}); err != nil {
		return err
	}
	report.add(GroupsBenchGroupOwner, 0, byteCount, 0)
	keyPackageRef := sha256.Sum256([]byte("a KeyPackage"))
	if byteCount, err = groupsBenchSize(&protocol.GkmWelcomePointer{GroupId: groupId.Bytes(), Epoch: 1 << 20, KeyPackageRef: keyPackageRef[:]}); err != nil {
		return err
	}
	report.add(GroupsBenchWelcomePointer, 0, byteCount, 0)

	// a config rotation's deliveries: a leaf's leaf_wrap serves the tree, so it wraps to the wrapped holders alone;
	// a wrapped rotator wraps to every leaf as well
	rotation := func(name string, wrapCount int) error {
		start := time.Now()
		for index := 0; index < wrapCount; index += 1 {
			if _, err := deliver(sidecar.GkmDeliveryStaged); err != nil {
				return err
			}
		}
		report.add(name, wrapCount, wrapCount*wrapByteCount, time.Since(start))
		return nil
	}
	if err := rotation(GroupsBenchRotationByLeaf, settings.WrappedHolderCount); err != nil {
		return err
	}
	return rotation(GroupsBenchRotationByWrapped, settings.WrappedHolderCount+settings.RotationLeafCount)
}

// A ReaderKey's X-Wing public key, nil for one that does not parse.
func readerKeyPublicKey(signed *bridge.Signed) []byte {
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil
	}
	return body.GetXwingPublicKey()
}

// One groups run. See the file header.
func RunGroupsBench(settings *GroupsBenchSettings) (*GroupsBenchReport, error) {
	if settings == nil || len(settings.LeafCounts) == 0 {
		return nil, errors.New("groups bench: no leaf counts")
	}
	report := &GroupsBenchReport{}
	chain := sha256.Sum256([]byte("an authorization chain value"))
	holders := sha256.Sum256([]byte("a key holder set"))
	generationArgs := &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          &bridge.AuthPin{Version: 1 << 20, Chain: chain[:]},
		Time:          time.UnixMilli(1_800_000_000_000),
		HoldersSha256: holders[:],
		WrapCount:     uint32(settings.WrappedHolderCount),
	}
	var key *sidecar.EvsRepoKey
	var rotate *protocol.GenRotate
	for _, leafCount := range settings.LeafCounts {
		// each group its own repo and generation chain
		first, _, err := sidecar.NewGkmFirstGeneration(sidecar.NewId(), sidecar.NewId(), generationArgs)
		if err != nil {
			return nil, err
		}
		// a generation with a parent, as every one past the first: its GenRotate carries a GenLink
		key, rotate, err = first.NextGeneration(generationArgs)
		if err != nil {
			return nil, err
		}
		if err := groupsBenchGroup(report, settings, leafCount, key); err != nil {
			return nil, fmt.Errorf("groups bench at %d leaves: %w", leafCount, err)
		}
	}
	if err := groupsBenchObjects(report, settings, key, rotate, generationArgs); err != nil {
		return nil, err
	}
	return report, nil
}
