// Rows-only mode on the test network: a gate's walk of the log, holding no config key. Its verdicts equal a full
// reader's over a generated log; FS-62's {acl_}e case (lost, then stale with an older {acl_}v: the gate reads proj/
// and never lands on a lower n), on a fake of §7.9's read cache, since ACL-M2-13's AclGateCache is not built yet;
// forged cache entries refused whole by the chain check; a cold start held to the process's own pin; and a cold start
// from a run that misses a base's tail refused rather than built short.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A rows-only source over what the test network published.
func (self *testConfigNet) rowsOnlySource() ConfigRowsOnlySource {
	return func(networkId Id, rowsSha256 []byte) ([]byte, error) {
		return self.source.Rows(networkId, rowsSha256)
	}
}

// The refusal sentinel a verdict carries, the narrowest first, or nil for an accepted one.
func testConfigRefusalClass(err error) error {
	for _, class := range []error{ErrConfigPresence, ErrConfigReadOnly, ErrConfigRuleMissing,
		ErrConfigReplay, ErrConfigSigner, ErrConfigAuthority, ErrConfigRule, ErrConfigRefused} {
		if errors.Is(err, class) {
			return class
		}
	}
	return err
}

// A generated log on the network: members and their devices admitted and revoked, ephemeral agents reaped by ticks,
// statements refused for their signer or for a rule not built, and bases folding at random points, from a seed.
// Statements are an admin's; TestASelfAdmissionIsJudgedAlikeAtApi runs a member's own.
func (self *testConfigNet) generate(seed uint64, count int) {
	self.t.Helper()
	random := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	members := []Id{}
	devices := []testConfigDevice{}
	ephemerals := []testConfigDevice{}
	stranger := self.device("stranger", self.ownerMemberId)
	configVersion := uint64(1)
	foldedThrough := uint64(0)
	pick := func(count int) int { return random.IntN(count) }
	for i := range count {
		label := fmt.Sprintf("generated %d %d", seed, i)
		switch op := pick(9); {
		case op == 0 || len(members) == 0:
			member := testConfigId(label)
			self.post(self.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
				Header: self.header(), MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
			})
			members = append(members, member)
		case op == 1:
			device := self.device(label, members[pick(len(members))])
			self.post(self.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(device, nil, false, 0, 0))
			devices = append(devices, device)
		case op == 2:
			device := self.device(label, members[pick(len(members))])
			self.post(self.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(device, nil, true, self.timeMs+60*60*1000, 0))
			ephemerals = append(ephemerals, device)
		case op == 3 && 0 < len(devices):
			device := devices[pick(len(devices))]
			self.post(self.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
		case op == 4:
			self.post(self.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{
				Header: self.header(), MemberId: members[pick(len(members))].Bytes(),
			})
		case op == 5:
			reaped := [][]byte{}
			if 0 < len(ephemerals) && pick(3) != 0 {
				reaped = append(reaped, ephemerals[pick(len(ephemerals))].sidecarId.Bytes())
			} else if 0 < len(devices) {
				reaped = append(reaped, devices[pick(len(devices))].sidecarId.Bytes())
			}
			self.tick(&bridge.ApiTick{ReapedSidecarIds: reaped})
		case op == 6:
			self.post(self.owner, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: self.header(), KeyId: []byte(label)})
		case op == 7:
			self.post(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, self.memberAdmitStatement(label))
		default:
			// S(0)'s empty rows compile no head an honest writer saves, so a fold names a position from base 1 on; and
			// DESIGN-DETAILS 5.2.3's fold rule keeps the previous base's fold or folds at or past that base
			if pick(3) != 0 {
				previousBase := max(self.log.State().Base().GetVersion(), 1)
				foldedThrough = previousBase + uint64(pick(int(self.n-previousBase)+1))
			}
			foldedThrough = max(foldedThrough, 1)
			configVersion += uint64(pick(2))
			if verdict := self.fold(self.owner, foldedThrough, configVersion); !verdict.Accepted() {
				self.t.Fatalf("the fold at %d: %v", verdict.Pin.GetVersion(), verdict.Refusal)
			}
		}
	}
}

// A rows-only reader and a full one reach the same verdict at every position of generated logs, and stand on the same
// state there, the rows-only one never opening a config head and reporting its head-only settings unknown.
func TestARowsOnlyReaderReachesAFullReadersVerdicts(t *testing.T) {
	for seed := uint64(1); seed <= 6; seed += 1 {
		net := newTestConfigNet(t)
		net.generate(seed, 160)
		full, err := NewConfigLog(testConfigLogSettings(), net.signedGenesis)
		if err != nil {
			t.Fatal(err)
		}
		rowsOnly, err := NewConfigLogRowsOnly(testConfigLogSettings(), net.signedGenesis)
		if err != nil {
			t.Fatal(err)
		}
		accepted, refused := 0, 0
		for _, entryBytes := range net.entries {
			fullVerdict, err := full.Apply(entryBytes, net.source)
			if err != nil {
				t.Fatalf("seed %d: the full reader: %v", seed, err)
			}
			rowsOnlyVerdict, err := rowsOnly.Apply(entryBytes, net.rowsOnlySource())
			if err != nil {
				t.Fatalf("seed %d: the rows-only reader: %v", seed, err)
			}
			n := fullVerdict.Pin.GetVersion()
			if fullVerdict.Accepted() != rowsOnlyVerdict.Accepted() ||
				testConfigRefusalClass(fullVerdict.Refusal) != testConfigRefusalClass(rowsOnlyVerdict.Refusal) {
				t.Fatalf("seed %d at %d: full %v, rows-only %v", seed, n, fullVerdict.Refusal, rowsOnlyVerdict.Refusal)
			}
			if !proto.Equal(fullVerdict.Pin, rowsOnlyVerdict.Pin) || fullVerdict.StatementId != rowsOnlyVerdict.StatementId {
				t.Fatalf("seed %d at %d: pins or ids differ", seed, n)
			}
			testConfigStatesEqual(t, full.State(), rowsOnly.State())
			if fullVerdict.Accepted() {
				accepted += 1
			} else {
				refused += 1
			}
		}
		if accepted == 0 || refused == 0 {
			t.Errorf("seed %d: %d accepted and %d refused", seed, accepted, refused)
		}
		if _, known := rowsOnly.State().HeadSettings(); known || !rowsOnly.RowsOnly() || full.RowsOnly() {
			t.Errorf("seed %d: a rows-only state reports its settings", seed)
		}
	}
}

// {acl_<networkId>}e as api keeps it (§7.9's read row): the {acl_}v value it matches, and the entries of the newest
// base b through the tip m by position.
type testConfigAclCache struct {
	version uint64
	entries map[uint64][]byte
}

// What api's script leaves after its appends: every entry from the newest base on, matching version.
func (self *testConfigNet) aclCache(version uint64) *testConfigAclCache {
	cache := &testConfigAclCache{version: version, entries: map[uint64][]byte{}}
	for n := self.log.State().Base().GetVersion(); n <= self.n; n += 1 {
		cache.entries[n] = self.entries[n-1]
	}
	return cache
}

// Where a gate reads, as §7.9's read row says: the cache only when it records {acl_}v's current value and holds every
// position from the gate's next one to need, else proj/, every retained entry. Returns which it read and the error.
func testConfigGateRead(gate *ConfigLog, cache *testConfigAclCache, version uint64, proj [][]byte, need uint64, rows ConfigRowsSource) (string, error) {
	next := gate.Pin().GetVersion() + 1
	if cache != nil && cache.version == version {
		run := [][]byte{}
		for n := next; n <= need; n += 1 {
			entryBytes, found := cache.entries[n]
			if !found {
				run = nil
				break
			}
			run = append(run, entryBytes)
		}
		if run != nil {
			_, err := gate.ApplyRun(run, rows)
			return "cache", err
		}
	}
	_, err := gate.ApplyRun(proj[next-1:], rows)
	return "proj", err
}

// FS-62's {acl_}e case: api, evs and gkm read the cache while it matches {acl_}v; with it lost, then stale with an
// older {acl_}v, they read proj/ instead; a stale run handed to them moves nothing; and none lands on a lower n, a
// cold start from a stale copy included.
func TestAGateReadsProjWhenItsCacheIsLostOrStaleAndNeverLowers(t *testing.T) {
	net := newTestConfigNet(t)
	for i := range 4 {
		net.post(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("before %d", i)))
	}
	net.fold(net.owner, net.n-1, 2)
	gates := map[string]*ConfigLog{}
	for _, name := range []string{"api", "evs", "gkm"} {
		gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries}, net.rowsOnlySource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		gates[name] = gate
	}
	version := uint64(1)
	appendStatements := func(count int, label string) {
		for i := range count {
			net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("%s %d", label, i)))
			version += 1
		}
	}
	readAll := func(cache *testConfigAclCache, want string) {
		t.Helper()
		for name, gate := range gates {
			read, err := testConfigGateRead(gate, cache, version, net.entries, net.n, net.rowsOnlySource())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if read != want || !proto.Equal(gate.Pin(), net.log.Pin()) {
				t.Fatalf("%s read %s to %d, want %s to %d", name, read, gate.Pin().GetVersion(), want, net.n)
			}
		}
	}

	appendStatements(3, "fresh")
	readAll(net.aclCache(version), "cache")

	appendStatements(2, "lost")
	readAll(nil, "proj")

	staleCache := net.aclCache(version)
	staleTip := net.log.Pin()
	appendStatements(2, "stale")
	readAll(staleCache, "proj")

	for name, gate := range gates {
		run := [][]byte{}
		for n := net.log.State().Base().GetVersion(); n <= staleTip.GetVersion(); n += 1 {
			run = append(run, staleCache.entries[n])
		}
		verdicts, err := gate.ApplyRun(run, net.rowsOnlySource())
		if err != nil || len(verdicts) != 0 || !proto.Equal(gate.Pin(), net.log.Pin()) {
			t.Errorf("%s took a stale run: %d verdicts, %v, at %d", name, len(verdicts), err, gate.Pin().GetVersion())
		}
		stale := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries[:staleTip.GetVersion()]}
		if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), stale, net.rowsOnlySource(), gate.Pin()); !errors.Is(err, ErrConfigBelowPin) {
			t.Errorf("%s: a cold start below its pin: %v", name, err)
		}
		current := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries}
		if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), current, net.rowsOnlySource(), gate.Pin()); err != nil {
			t.Errorf("%s: a cold start at its pin: %v", name, err)
		}
	}
}

// A forged copy fails the chain check whole and applies nothing: an entry changed inside the run breaks the next
// one's link, one at a position the gate holds carries a second A_n, one at the next position names another
// prev_chain, and a run with a gap or another network's entry is no run. The log goes on, and proj/ moves it.
func TestAForgedCacheEntryFailsChainVerification(t *testing.T) {
	net := newTestConfigNet(t)
	gate, err := NewConfigLogRowsOnly(testConfigLogSettings(), net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.ApplyRun(net.entries, net.rowsOnlySource()); err != nil {
		t.Fatal(err)
	}
	held := gate.Pin().GetVersion()
	for i := range 3 {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("forged %d", i)))
	}
	tamper := func(entryBytes []byte, change func(entry *bridge.AuthEntry)) []byte {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		change(entry)
		return testConfigMarshal(t, entry)
	}
	runOf := func(from uint64, to uint64) [][]byte {
		return append([][]byte(nil), net.entries[from-1:to]...)
	}
	// links each entry after the first onto the one before it, as a forger who changed the first would
	rechain := func(run [][]byte) [][]byte {
		for i := 1; i < len(run); i += 1 {
			previous := testConfigEntryChain(t, run[i-1])
			run[i] = tamper(run[i], func(entry *bridge.AuthEntry) { entry.PrevChain = bytes.Clone(previous[:]) })
		}
		return run
	}

	cases := []struct {
		name string
		run  [][]byte
		want error
	}{
		{name: "a changed entry inside", want: ErrConfigRunRefused, run: func() [][]byte {
			run := runOf(held+1, held+3)
			run[1] = tamper(run[1], func(entry *bridge.AuthEntry) { entry.TimeMs += 1 })
			return run
		}()},
		{name: "a second A_n at a held position", want: ErrConfigRunRefused, run: func() [][]byte {
			run := runOf(held, held+3)
			run[0] = tamper(run[0], func(entry *bridge.AuthEntry) { entry.TimeMs += 1 })
			return rechain(run)
		}()},
		{name: "another prev_chain at the next position", want: ErrConfigRunRefused, run: func() [][]byte {
			run := runOf(held+1, held+1)
			run[0] = tamper(run[0], func(entry *bridge.AuthEntry) { entry.PrevChain[0] ^= 0xff })
			return run
		}()},
		{name: "a gap", want: ErrConfigRunRefused, run: append(runOf(held+1, held+1), net.entries[held+2])},
		{name: "another network's entry", want: ErrConfigRunRefused, run: [][]byte{tamper(net.entries[held], func(entry *bridge.AuthEntry) {
			entry.NetworkId = testConfigId("another network").Bytes()
		})}},
		{name: "a run past the next position", want: ErrConfigEntryAhead, run: runOf(held+2, held+3)},
	}
	for _, c := range cases {
		verdicts, err := gate.ApplyRun(c.run, net.rowsOnlySource())
		if !errors.Is(err, c.want) || len(verdicts) != 0 || gate.Pin().GetVersion() != held {
			t.Errorf("%s: %v, %d verdicts, at %d", c.name, err, len(verdicts), gate.Pin().GetVersion())
		}
	}
	secondAn := &ConfigRunError{}
	_, err = gate.ApplyRun(cases[1].run, net.rowsOnlySource())
	if !errors.As(err, &secondAn) || secondAn.N != held || !secondAn.HasLocalChain || secondAn.LocalChain == secondAn.RemoteChain {
		t.Errorf("the second A_n's evidence: %v", err)
	}
	if gate.Fork() != nil {
		t.Fatal("a forged copy stopped the log")
	}
	verdicts, err := gate.ApplyRun(runOf(1, net.n), net.rowsOnlySource())
	if err != nil || len(verdicts) != 3 || !proto.Equal(gate.Pin(), net.log.Pin()) {
		t.Errorf("proj/ after the forgeries: %v, %d verdicts", err, len(verdicts))
	}
	testConfigStatesEqual(t, gate.State(), net.log.State())
}

// A cold start whose entries begin after the newest base's tail would build S(b) without what the tail did, a
// revocation there included, so it is refused; from the tail's first position on it holds the tail's effects.
func TestAColdStartMissingABasesTailIsRefused(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("tail member")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := net.device("tail laptop", member)
	net.admitDevice(net.owner, laptop, 0)
	foldedThrough := net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	net.fold(net.owner, foldedThrough, 2)
	base := net.n

	short := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries[base-1:]}
	if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), short, net.rowsOnlySource(), nil); !errors.Is(err, ErrConfigEntryMalformed) {
		t.Errorf("rows-only from the base alone: %v", err)
	}
	if _, err := RestoreConfigLog(testConfigLogSettings(), short, net.source); !errors.Is(err, ErrConfigEntryMalformed) {
		t.Errorf("a full reader from the base alone: %v", err)
	}
	whole := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: net.entries[foldedThrough:]}
	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), whole, net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if gate.State().SidecarRow(laptop.sidecarId).GetRevokedAt() == 0 {
		t.Error("the tail's revocation is missing")
	}
	// rows and pin as the long-running reader's; the retention point differs, as a new device's does when it keeps
	// no base before its own (question team-m2-02-new-device-tail-verdicts)
	if !proto.Equal(gate.Pin(), net.log.Pin()) || !bytes.Equal(testConfigRowsBytes(t, gate.State()), testConfigRowsBytes(t, net.log.State())) {
		t.Error("the cold start stands on another state")
	}
}

// A rows-only reader applies a base without its config head: the head's settings stay unknown and the source's head
// check is never asked, even for a base whose head no reader could open.
func TestARowsOnlyBaseNeedsNoConfigHead(t *testing.T) {
	net := newTestConfigNet(t)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("member"))
	net.source.headError = errors.New("no reader opens this head")
	baseEntry := net.makeBase(net.owner, net.log.State().Rows(), net.n, 2, 0)
	net.source.headError = nil
	gate, err := NewConfigLogRowsOnly(testConfigLogSettings(), net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.ApplyRun(append(append([][]byte(nil), net.entries...), baseEntry), net.rowsOnlySource()); err != nil {
		t.Fatal(err)
	}
	if gate.State().Base().GetConfigVersion() != 2 {
		t.Error("the base did not apply")
	}
	if settings, known := gate.State().HeadSettings(); known || settings != nil {
		t.Error("a rows-only state reports the head's settings")
	}
	if !bytes.Equal(gate.State().Base().GetRowsSha256(), testConfigRowsSha256(t, net.log.State().Rows())) {
		t.Error("the base names other rows")
	}
}

// The SHA-256 of rows as a base names them.
func testConfigRowsSha256(t testing.TB, rows *bridge.ProjectionRows) []byte {
	digest := sha256.Sum256(testConfigMarshal(t, rows))
	return digest[:]
}

// §7.9's object keys: entry n zero-padded to 20 digits, in position order under the network's prefix, read back to
// their positions, and nothing else read as one.
func TestConfigEntryKeysParseBackToTheirPositions(t *testing.T) {
	networkId := testConfigId("keys network")
	for _, n := range []uint64{0, 1, 12345, 1<<63 - 1} {
		key := ConfigEntryKey(networkId, n)
		if !strings.HasPrefix(key, ConfigEntryKeyPrefix(networkId)) || !strings.HasSuffix(key, "/_") {
			t.Errorf("the key %q", key)
		}
		if parsed, ok := ParseConfigEntryKey(networkId, key); !ok || parsed != n {
			t.Errorf("%q parsed as %d, %t", key, parsed, ok)
		}
	}
	if ConfigEntryKey(networkId, 9) >= ConfigEntryKey(networkId, 10) {
		t.Error("keys do not sort in position order")
	}
	for _, key := range []string{
		ConfigEntryKey(testConfigId("another network"), 1),
		ConfigRowsKey(networkId, make([]byte, 32)),
		ConfigEntryKeyPrefix(networkId) + "1/_",
		ConfigEntryKeyPrefix(networkId) + "0000000000000000000x/_",
	} {
		if _, ok := ParseConfigEntryKey(networkId, key); ok {
			t.Errorf("%q parsed as an entry key", key)
		}
	}
}

// api's check of a base before it appends one: a base at the tip's next position passes; one for another position is
// ErrConfigTipMoved; a stale compile, another signer or rows off their hash are refusals; and none of them forks the
// log, which a reader's Apply of the same base would.
func TestCheckBaseRefusesWithoutForking(t *testing.T) {
	net := newTestConfigNet(t)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("member"))
	net.fold(net.owner, net.n, 2)
	rows := net.log.State().Rows()
	rowsBytes := testConfigMarshal(t, rows)
	signedHeaderOf := func(entryBytes []byte) []byte {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		return entry.GetBody()
	}
	if err := net.log.CheckBase(signedHeaderOf(net.makeBase(net.owner, rows, net.n, 2, 0)), rowsBytes, net.timeMs+1000); err != nil {
		t.Errorf("a base at the next position: %v", err)
	}
	stale := signedHeaderOf(net.makeBase(net.owner, rows, net.n, 2, 0))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("racer"))
	if err := net.log.CheckBase(stale, rowsBytes, net.timeMs+1000); !errors.Is(err, ErrConfigTipMoved) {
		t.Errorf("a base for a taken position: %v", err)
	}
	stranger := net.device("stranger", net.ownerMemberId)
	cases := []struct {
		name   string
		header []byte
		rows   []byte
		want   error
	}{
		{name: "a lower fold", header: signedHeaderOf(net.makeBase(net.owner, rows, 1, 2, 0)), rows: rowsBytes, want: ErrConfigRule},
		{name: "an older head", header: signedHeaderOf(net.makeBase(net.owner, rows, net.n, 1, 0)), rows: rowsBytes, want: ErrConfigRule},
		{name: "no config writer", header: signedHeaderOf(net.makeBase(stranger, rows, net.n, 2, 0)), rows: rowsBytes, want: ErrConfigAuthority},
		{name: "rows off their hash", header: signedHeaderOf(net.makeBase(net.owner, rows, net.n, 2, 0)), rows: append(bytes.Clone(rowsBytes), 0), want: ErrConfigRule},
	}
	for _, c := range cases {
		if err := net.log.CheckBase(c.header, c.rows, net.timeMs+1000); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if net.log.Fork() != nil {
		t.Error("a refused base forked the log")
	}
}

// A store that cannot serve a base's rows now has withheld them (§7.9's retain row): a run holding that base is
// refused whole with ErrConfigRowsUnavailable, the gate's log neither forked nor moved, and the same run applies once
// the rows are served.
func TestARunWhoseBaseRowsAreWithheldIsRefusedWhole(t *testing.T) {
	net := newTestConfigNet(t)
	gate, err := NewConfigLogRowsOnly(testConfigLogSettings(), net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.ApplyRun(net.entries, net.rowsOnlySource()); err != nil {
		t.Fatal(err)
	}
	held := gate.Pin()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("before the base"))
	net.fold(net.owner, net.n, 2)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after the base"))
	run := net.entries[held.GetVersion():]

	withholding := ConfigRowsOnlySource(func(networkId Id, rowsSha256 []byte) ([]byte, error) {
		return nil, errors.New("the store is away")
	})
	verdicts, err := gate.ApplyRun(run, withholding)
	if !errors.Is(err, ErrConfigRowsUnavailable) || len(verdicts) != 0 {
		t.Fatalf("a run with withheld rows: %v, %d verdicts", err, len(verdicts))
	}
	if gate.Fork() != nil || !proto.Equal(gate.Pin(), held) {
		t.Fatal("withheld rows forked or moved the log")
	}
	verdicts, err = gate.ApplyRun(run, net.rowsOnlySource())
	if err != nil || len(verdicts) != 3 || !proto.Equal(gate.Pin(), net.log.Pin()) {
		t.Errorf("the run once served: %v, %d verdicts", err, len(verdicts))
	}
}
