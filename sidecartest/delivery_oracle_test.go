package sidecartest

// The oracle on its own (KEYS-M2-29): what it may import, its log, its key holders and the store's part of Reach.
// Its verdicts against the members' checks, and the mutants of those checks it sees, run in gkmschedule's
// delivery_test.go, on real deliveries.

import (
	"bytes"
	"crypto/sha256"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The trap in KEYS-M2-29: the oracle shares no code with the members' delivery checks, so its file imports the
// standard library, protobuf and the protocol's types, and nothing of the sidecar package.
func TestDeliveryOracleImportsOnlyProtocolTypes(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "delivery_oracle.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"google.golang.org/protobuf/", "github.com/urnetwork/sidecar/protocol"}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		standard := !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
		named := false
		for _, prefix := range allowed {
			if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/") {
				named = true
			}
		}
		if !standard && !named {
			t.Errorf("the oracle imports %s", path)
		}
	}
}

// A pin of the test's log: its version and a chain value that names it.
func testDeliveryOraclePin(version uint64) *bridge.AuthPin {
	chain := sha256.Sum256([]byte("delivery oracle test " + strconv.FormatUint(version, 10)))
	return &bridge.AuthPin{Version: version, Chain: chain[:]}
}

// A 16-byte id of the test, by one byte.
func testDeliveryOracleId(value byte) DeliveryOracleId {
	id := DeliveryOracleId{}
	id[0] = value
	return id
}

func TestDeliveryOracleAppendTakesOnlyTheNextPosition(t *testing.T) {
	oracle := NewDeliveryOracle(nil)
	if err := oracle.Append(nil); err == nil {
		t.Errorf("appended no position")
	}
	if err := oracle.Append(&DeliveryOracleState{Pin: testDeliveryOraclePin(2)}); err == nil {
		t.Errorf("appended position 2 to an empty log")
	}
	if err := oracle.Append(&DeliveryOracleState{Pin: testDeliveryOraclePin(1)}); err != nil {
		t.Fatal(err)
	}
	if err := oracle.Append(&DeliveryOracleState{Pin: testDeliveryOraclePin(1)}); err == nil {
		t.Errorf("appended position 1 twice")
	}
	if oracle.Tip() != 1 {
		t.Errorf("the tip is %d", oracle.Tip())
	}
}

// §10.5's kinds as the oracle counts them: a member's untagged device a leaf, a tagged or ephemeral sidecar an
// agent, a reader past the time it stops reading no holder, and a revoked row, which reads nothing, none either.
func TestDeliveryOracleCountsLeavesAndAgentsAtAStateAndTime(t *testing.T) {
	memberId := testDeliveryOracleId(9)
	leaf, tagged, ephemeral, expiring := testDeliveryOracleId(1), testDeliveryOracleId(2), testDeliveryOracleId(3), testDeliveryOracleId(4)
	repoId := testDeliveryOracleId(7)
	start := time.Unix(1_800_000_000, 0)
	state := &DeliveryOracleState{
		Pin: testDeliveryOraclePin(1),
		Sidecars: []*bridge.SidecarRow{
			{SidecarId: leaf[:], MemberId: memberId[:]},
			{SidecarId: tagged[:], MemberId: memberId[:], TagIds: [][]byte{testDeliveryOracleIdBytes(5)}},
			{SidecarId: ephemeral[:], MemberId: memberId[:], Ephemeral: true},
			{SidecarId: expiring[:], MemberId: memberId[:]},
		},
		Repos: map[DeliveryOracleId]*DeliveryOracleRepo{
			repoId: {
				Kind:    protocol.RepoKind_REPO_KIND_GENERAL,
				Readers: map[DeliveryOracleId]time.Time{leaf: {}, tagged: {}, ephemeral: {}, expiring: start.Add(time.Hour)},
			},
		},
	}
	oracle := NewDeliveryOracle(nil)
	if err := oracle.Append(state); err != nil {
		t.Fatal(err)
	}
	want := func(identities ...string) []byte {
		hasher := sha256.New()
		for _, identity := range identities {
			hasher.Write([]byte(identity))
		}
		return hasher.Sum(nil)
	}
	before, ok := oracle.HoldersSha256(repoId, state.Pin, start)
	if !ok || !bytes.Equal(before, want(
		string([]byte{1})+string(leaf[:]), string([]byte{1})+string(expiring[:]), string([]byte{2})+string(tagged[:]), string([]byte{2})+string(ephemeral[:]),
	)) {
		t.Errorf("the holders before the expiry are not two leaves and two agents")
	}
	after, ok := oracle.HoldersSha256(repoId, state.Pin, start.Add(time.Hour))
	if !ok || !bytes.Equal(after, want(string([]byte{1})+string(leaf[:]), string([]byte{2})+string(tagged[:]), string([]byte{2})+string(ephemeral[:]))) {
		t.Errorf("the holders at the expiry still count the expired reader")
	}
	if _, ok := oracle.HoldersSha256(testDeliveryOracleId(8), state.Pin, start); ok {
		t.Errorf("the oracle counted holders of a repo the state does not hold")
	}
	if _, ok := oracle.HoldersSha256(repoId, testDeliveryOraclePin(2), start); ok {
		t.Errorf("the oracle counted holders above its tip")
	}
	// the roster row: a tree of the two leaves passes, one holding the agent's id is refused, at a forked pin a fork
	if verdict := oracle.JudgeRoster(repoId, state.Pin, start, [][]byte{leaf[:], expiring[:]}, 0, 0); verdict.Kind != DeliveryOracleValid {
		t.Errorf("a tree of holders: %s", verdict)
	}
	if verdict := oracle.JudgeRoster(repoId, state.Pin, start.Add(time.Hour), [][]byte{leaf[:], expiring[:]}, 0, 0); verdict.Kind != DeliveryOracleInvalid {
		t.Errorf("a tree holding an expired reader: %s", verdict)
	}
	if verdict := oracle.JudgeRoster(repoId, state.Pin, start, [][]byte{leaf[:], tagged[:]}, 0, 0); verdict.Kind != DeliveryOracleInvalid {
		t.Errorf("a tree holding an agent: %s", verdict)
	}
	forked := testDeliveryOraclePin(1)
	forked.Chain[0] ^= 1
	if verdict := oracle.JudgeRoster(repoId, forked, start, [][]byte{leaf[:]}, 0, 0); verdict.Kind != DeliveryOracleInvalid || !verdict.Fork {
		t.Errorf("a tree at a forked pin: %s", verdict)
	}
}

// A 16-byte id of the test as bytes.
func testDeliveryOracleIdBytes(value byte) []byte {
	id := testDeliveryOracleId(value)
	return id[:]
}

func TestDeliveryOracleWrapReachReadsTheNewestGenerationAtARecipientsPaths(t *testing.T) {
	paths := []string{
		"gkm/aa/wrap/00000000000000000001/c8c8/s:01/k8k8",
		"gkm/aa/wrap/00000000000000000003/c8c8/s:01/k8k8",
		"gkm/aa/wrap/00000000000000000007/c8c8/s:02/k8k8",
		"gkm/aa/wrap/not-a-number/c8c8/s:01/k8k8",
		"gkm/aa/gen/00000000000000000009",
	}
	if reach := DeliveryOracleWrapReach(paths, "s:01"); reach != 3 {
		t.Errorf("s:01 reaches %d", reach)
	}
	if reach := DeliveryOracleWrapReach(paths, "s:03"); reach != 0 {
		t.Errorf("a recipient with no delivery reaches %d", reach)
	}
}
