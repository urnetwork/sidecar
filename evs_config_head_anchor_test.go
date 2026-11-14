//go:build !ios_extension

// QD-814's anchor judgment (judgeAtAnchor) over pushes built and signed as a writer builds them: a chain whose signers
// the anchor admits passes, from C_0 or from a trusted point inside it; a signer the anchor does not admit leaves the
// push unjudged, with no alarm; a signature that does not verify under the key the anchor admits for the signer it
// names is refused and alarmed as tampering; and a push off §11.7's version rules is refused and alarmed, as the walk
// alarms each. An anchor whose genesis names another config repo, or none, reads nothing. The reads over evs are
// sidecartest's (evs_config_anchor_world_test.go).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An anchor of a test network: its genesis and the identity keys its base's rows admit.
type testEvsConfigAnchor struct {
	genesis *bridge.Genesis
	keys    map[Id][]byte
}

func (self *testEvsConfigAnchor) Genesis() *bridge.Genesis {
	return self.genesis
}

func (self *testEvsConfigAnchor) IdentityKey(sidecarId Id) []byte {
	return self.keys[sidecarId]
}

// A shared file-mode ref's pushes 1 through len(signers), each by its signer on the version before it with a rising
// authorization pin, each with its chain value; mutate, nil for none, changes a version's plan before it is signed.
func testEvsConfigAnchorChain(t *testing.T, repoId Id, refId Id, signers []*evsTestSigner, mutate func(version uint64, plan *EvsPushPlan)) []*EvsVerifiedStatement {
	t.Helper()
	pathKey := evsTestPathKey(t, repoId, 1)
	tokenPath, err := EvsPathTokens(pathKey, [][]byte{[]byte(ConfigHeadNamesPath)})
	if err != nil {
		t.Fatal(err)
	}
	chain := EvsChainStart(repoId, refId)
	statements := []*EvsVerifiedStatement{}
	for i, signer := range signers {
		version := uint64(i) + 1
		plan := &EvsPushPlan{
			RepoId: repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
			PushId: evsTestId(fmt.Sprint("anchor push ", version)), BaseVersion: version - 1, BaseChain: chain,
			Generation: 1, GroupId: evsTestId("anchor group"), GenerationCommitment: evsTestBytes("anchor commitment", 32),
			PathEpoch:       1,
			Auth:            &bridge.AuthPin{Version: 40 + version, Chain: evsTestBytes(fmt.Sprint("anchor auth ", version), 32)},
			SignerSidecarId: signer.sidecarId, ClientId: evsTestId("anchor client"), TimeMs: 1767225600000 + int64(version),
			SealedMetadata: evsTestBytes("anchor sealed metadata", 32),
			NewObjects: []*EvsNewObject{{
				Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: evsTestBytes("segment 0", 32),
				PaddedSize: 4096, UploadDay: 20454,
			}},
		}
		if mutate != nil {
			mutate(version, plan)
		}
		plan.Changes = []*EvsPlannedChange{{TokenPath: tokenPath, EntryVersion: evsTestEntryVersion(t, plan, 0, 1)}}
		built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
		if err != nil {
			t.Fatalf("the push at %d: %v", version, err)
		}
		chain = EvsChainNext(chain, plan.PushId, built.Statement.Sha256)
		statements = append(statements, &EvsVerifiedStatement{Version: version, Statement: built.Statement, Chain: chain})
	}
	return statements
}

func TestEvsConfigHeadAnchorJudgesDescentUnderTheAnchorsKeys(t *testing.T) {
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	repoId, refId := evsTestId("anchor config repo"), evsTestId("anchor main ref")
	reader, err := NewEvsConfigHeadReader(&EvsConfigHeadReaderArgs{Repo: test.client.Repo(repoId)})
	if err != nil {
		t.Fatal(err)
	}
	writer, other := newEvsTestSigner("anchor writer"), newEvsTestSigner("anchor other")
	anchor := &testEvsConfigAnchor{genesis: &bridge.Genesis{ConfigRepoId: repoId.Bytes()}, keys: map[Id][]byte{writer.sidecarId: writer.publicKey()}}
	start := EvsChainStart(repoId, refId)
	alarms := func(reason SidecarEvsAlarm) int {
		count := 0
		for _, event := range *test.events {
			if event.Kind == SidecarEventEvsAlarm && event.EvsAlarm == reason {
				count += 1
			}
		}
		return count
	}

	// pushes whose signer the anchor admits, from C_0 and from a trusted point inside the chain
	statements := testEvsConfigAnchorChain(t, repoId, refId, []*evsTestSigner{writer, writer, writer}, nil)
	if err := reader.judgeAtAnchor(anchor, refId, statements, 0, start); err != nil {
		t.Fatalf("the admitted writer's chain: %v", err)
	}
	if err := reader.judgeAtAnchor(anchor, refId, statements[1:], 1, statements[0].Chain); err != nil {
		t.Fatalf("the chain from a trusted point: %v", err)
	}

	// a signer the anchor does not admit cannot be judged: it withholds, and alarms nothing
	statements = testEvsConfigAnchorChain(t, repoId, refId, []*evsTestSigner{writer, other, writer}, nil)
	if err := reader.judgeAtAnchor(anchor, refId, statements, 0, start); !errors.Is(err, errEvsConfigHeadUnadmitted) || errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a signer the anchor does not admit: %v", err)
	}
	if count := alarms(SidecarEvsAlarmTamper) + alarms(SidecarEvsAlarmVersionRule); count != 0 {
		t.Fatalf("an unjudged push raised %d alarms", count)
	}

	// a signature by another key under the admitted signer's id is refused and alarmed as tampering
	forger := &evsTestSigner{sidecarId: writer.sidecarId, privateKey: other.privateKey}
	statements = testEvsConfigAnchorChain(t, repoId, refId, []*evsTestSigner{writer, forger, writer}, nil)
	if err := reader.judgeAtAnchor(anchor, refId, statements, 0, start); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a forged signature: %v", err)
	}
	if count := alarms(SidecarEvsAlarmTamper); count != 1 {
		t.Fatalf("a forged signature raised %d tamper alarms", count)
	}

	// a push based on a chain the ref never held breaks §11.7's rules, refused and alarmed
	statements = testEvsConfigAnchorChain(t, repoId, refId, []*evsTestSigner{writer, writer}, func(version uint64, plan *EvsPushPlan) {
		if version == 2 {
			plan.BaseChain = [32]byte(evsTestBytes("a chain the ref never held", 32))
		}
	})
	if err := reader.judgeAtAnchor(anchor, refId, statements, 0, start); !errors.Is(err, ErrEvsChainBroken) {
		t.Fatalf("a push off the ref's chain: %v", err)
	}
	if count := alarms(SidecarEvsAlarmVersionRule); count != 1 {
		t.Fatalf("a push off the ref's chain raised %d version-rule alarms", count)
	}
	// and so does an authorization pin that falls
	statements = testEvsConfigAnchorChain(t, repoId, refId, []*evsTestSigner{writer, writer}, func(version uint64, plan *EvsPushPlan) {
		if version == 2 {
			plan.Auth = &bridge.AuthPin{Version: 40, Chain: evsTestBytes("anchor auth fallen", 32)}
		}
	})
	if err := reader.judgeAtAnchor(anchor, refId, statements, 0, start); !errors.Is(err, ErrEvsChainBroken) {
		t.Fatalf("a falling authorization pin: %v", err)
	}

	// an anchor whose genesis names another config repo, or no anchor at all, reads nothing of this repo
	elsewhere := &testEvsConfigAnchor{genesis: &bridge.Genesis{ConfigRepoId: evsTestId("another config repo").Bytes()}, keys: anchor.keys}
	if _, err := reader.ReadConfigHeadAtAnchor(context.Background(), 1, start[:], elsewhere); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("an anchor of another config repo: %v", err)
	}
	if _, err := reader.ReadConfigHeadAtAnchor(context.Background(), 1, start[:], nil); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("no anchor: %v", err)
	}
	if _, err := reader.ReadConfigHeadAtAnchor(context.Background(), 1, start[:], &testEvsConfigAnchor{keys: anchor.keys}); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("an anchor with no genesis: %v", err)
	}
}
