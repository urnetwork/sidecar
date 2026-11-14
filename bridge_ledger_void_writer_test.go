//go:build !sidecar_http && !js

// BRIDGE-M4-23's void at the fold on TEAM-M2-09's real writer, T2's fake api and sidecartest's config repo
// (DESIGN-DETAILS 12.2.3 as amended for QD-761, 12.6's TestTheVoidIsMeasuredInLogTime): the wait is read in the log's
// time, the entries api sequenced, so a writer restarted and one whose clock is a day off fold as the first did, and the
// writer's config_key_waiting and config_key_void lines name the filer. The filing is a route whose sealed body names
// generation 7, which gkm never names and no key opens, so no generation key is needed; the writer's plan reads gkm
// whole at generation 1.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A logger that keeps every line, safe for concurrent use.
type testVoidWriterLines struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testVoidWriterLines) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testVoidWriterLines) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *testVoidWriterLines) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testVoidWriterLines) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testVoidWriterLines) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testVoidWriterLines) V(level int32) sidecar.Verbose {
	return testVoidWriterVerbose{lines: self}
}

// How many lines hold every one of words.
func (self *testVoidWriterLines) count(words ...string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, line := range self.lines {
		all := true
		for _, word := range words {
			all = all && strings.Contains(line, word)
		}
		if all {
			count += 1
		}
	}
	return count
}

// Every level enabled.
type testVoidWriterVerbose struct {
	lines *testVoidWriterLines
}

func (self testVoidWriterVerbose) Enabled() bool {
	return true
}

func (self testVoidWriterVerbose) Info(args ...any) {
	self.lines.Info(args...)
}

func (self testVoidWriterVerbose) Infof(format string, args ...any) {
	self.lines.Infof(format, args...)
}

// A sealed field naming generation that no key opens: the generation's 8 bytes, a zero nonce and zero bytes, which the
// id level takes and no reader opens.
func testVoidWriterSealed(generation uint64) []byte {
	sealed := binary.BigEndian.AppendUint64(nil, generation)
	return append(sealed, make([]byte, 24+256+16)...)
}

// What one run of the void at a real writer gave.
type testVoidWriterRun struct {
	// the filing's position and the base's fold
	filing        uint64
	foldedThrough uint64
	// the base's head's bridge/ledger/ files
	ledgerFiles map[string][]byte
	lines       *testVoidWriterLines
}

// The route id every run files.
func testVoidWriterRuleId() []byte {
	digest := sha256.Sum256([]byte("config writer test unformed route"))
	return digest[:]
}

// One run: the owner files a route sealed to generation 7, api sequences a BridgeEgress age later in its own time,
// and a writer of the owner's publishes a base, its plan reading gkm whole at generation 1, its clock writerOffset from
// api's. With restart set, a writer of the same device ran on a client of its own and closed before this one started,
// as a process that restarts does. The fold loop is held off, so the base is PublishBase's alone.
func testVoidWriterRunOf(t *testing.T, age time.Duration, writerOffset time.Duration, restart bool) *testVoidWriterRun {
	t.Helper()
	world := newTestWriterWorld(t)
	world.started()
	filing, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_BRIDGE_ROUTE, &bridge.BridgeRoute{
		Header: world.header(), RouteId: testVoidWriterRuleId(), Advertiser: world.owner.sidecarId.Bytes(), SealedBody: testVoidWriterSealed(7),
	}))
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(age)
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, &bridge.BridgeEgress{
		Header: world.header(), Subject: world.owner.sidecarId.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE,
	})); err != nil {
		t.Fatal(err)
	}
	newWriter := func(log sidecar.Logger) (*sidecar.ConfigClient, *sidecar.ConfigWriter) {
		client, judge := world.bridgeClient()
		judge.FormedThrough = func() uint64 { return 1 }
		world.caughtUp(client)
		settings := sidecar.DefaultConfigWriterSettings()
		settings.Clock = world.clock.WithOffset(writerOffset)
		settings.Random = func() float64 { return 0 }
		settings.FoldAge = 10 * 365 * 24 * time.Hour
		settings.PendingHeadTimeout = 10 * 365 * 24 * time.Hour
		settings.Log = log
		writer, err := sidecar.NewConfigWriter(world.ctx, &sidecar.ConfigWriterArgs{
			SidecarId:  world.owner.sidecarId,
			Sign:       world.owner.sign(),
			Client:     client,
			Heads:      world.heads.For(world.owner.sidecarId, world.owner.key),
			Publisher:  world.publisher(),
			Settings:   settings,
			BridgeFold: judge.Fold,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(writer.Close)
		return client, writer
	}
	if restart {
		_, earlier := newWriter(sidecar.NewNoopLogger())
		earlier.Close()
	}
	lines := &testVoidWriterLines{}
	client, writer := newWriter(lines)
	if _, err := writer.PublishBase(world.ctx, false); err != nil {
		t.Fatal(err)
	}
	state := world.caughtUp(client)
	head, err := world.heads.ReadConfigHead(world.ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	run := &testVoidWriterRun{filing: filing.GetVersion(), foldedThrough: state.Base().GetFoldedThrough(), ledgerFiles: map[string][]byte{}, lines: lines}
	for _, path := range head.Paths() {
		if strings.HasPrefix(path, "bridge/ledger/") {
			run.ledgerFiles[path] = head.File(path)
		}
	}
	return run
}

// 12.2.3's when the wait starts: at the filing's own entry, read against the entry the writer folds through, both in
// api's time and never a device's clock. A writer folding a tip the wait after the filing freezes it void, its base
// folding through the tip with the route's row void and config_key_void naming the filer; one a millisecond short holds
// the fold below the filing with config_key_waiting naming the filer and no ledger file. A writer restarted, and one
// whose clock is a day behind api's, fold as the first did, byte for byte; one whose clock is a day ahead, a millisecond
// short in the log's time, holds as the second did.
func TestTheVoidIsMeasuredInLogTime(t *testing.T) {
	wait := sidecar.DefaultBridgeLedgerSettings().UnformedVoidWait
	owner := testWriterDeviceOf("owner device", testWriterId("owner member")).sidecarId.String()

	first := testVoidWriterRunOf(t, wait, 0, false)
	if first.foldedThrough != first.filing+1 {
		t.Fatalf("at the wait the base folds through %d, want the tip %d", first.foldedThrough, first.filing+1)
	}
	rulesPath := sidecar.BridgeLedgerRulesPath(testVoidWriterRuleId(), 8)
	rules := &protocol.BridgeLedgerRules{}
	if err := proto.Unmarshal(first.ledgerFiles[rulesPath], rules); err != nil || len(rules.GetRows()) != 1 {
		t.Fatalf("the rule shard %s: %d rows, %v", rulesPath, len(rules.GetRows()), err)
	}
	if row := rules.GetRows()[0]; !bytes.Equal(row.GetRuleId(), testVoidWriterRuleId()) || row.GetDisposition() != protocol.BridgeLedgerDisposition_BRIDGE_LEDGER_DISPOSITION_VOID || row.GetRoute() != nil {
		t.Fatalf("the route's row: %v", row)
	}
	if first.lines.count("config_key_void", "generation 7", owner, fmt.Sprint("at ", first.filing)) != 1 || first.lines.count("config_key_waiting") != 0 {
		t.Fatalf("the writer's lines at the wait: %q", first.lines.lines)
	}

	short := testVoidWriterRunOf(t, wait-time.Millisecond, 0, false)
	if short.foldedThrough != short.filing-1 || len(short.ledgerFiles) != 0 {
		t.Fatalf("a millisecond short the base folds through %d with %d ledger files, want %d and none", short.foldedThrough, len(short.ledgerFiles), short.filing-1)
	}
	if short.lines.count("config_key_waiting", "generation 7", owner, fmt.Sprint("at ", short.filing)) != 1 || short.lines.count("config_key_void") != 0 {
		t.Fatalf("the writer's lines a millisecond short: %q", short.lines.lines)
	}

	for _, run := range []struct {
		label string
		run   *testVoidWriterRun
	}{
		{label: "a writer restarted", run: testVoidWriterRunOf(t, wait, 0, true)},
		{label: "a writer a day behind", run: testVoidWriterRunOf(t, wait, -24*time.Hour, false)},
	} {
		if run.run.foldedThrough != first.foldedThrough || !maps.EqualFunc(run.run.ledgerFiles, first.ledgerFiles, bytes.Equal) {
			t.Errorf("%s folds through %d with other files", run.label, run.run.foldedThrough)
		}
		if run.run.lines.count("config_key_void", owner) != 1 {
			t.Errorf("%s: %q", run.label, run.run.lines.lines)
		}
	}
	ahead := testVoidWriterRunOf(t, wait-time.Millisecond, 24*time.Hour, false)
	if ahead.foldedThrough != short.foldedThrough || len(ahead.ledgerFiles) != 0 || ahead.lines.count("config_key_waiting", owner) != 1 {
		t.Errorf("a writer a day ahead folds through %d: %q", ahead.foldedThrough, ahead.lines.lines)
	}
}
