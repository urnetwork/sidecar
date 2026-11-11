//go:build !sidecar_http && !js

// BRIDGE-M4-23's seams in TEAM-M2-09's writer and TEAM-M2-10's head check, on T2's fake api and sidecartest's config
// repo: a writer folds through its tip while a bridge statement is unfolded and writes the bridge ledger into the head
// its base names, which a full reader's real head check computes again and takes; and a writer with no fold installed
// folds below the first bridge statement, so no head misses its ledger. The statements are bodiless, a BridgeEgress of
// mode none and a BridgeWithdraw, so no generation key is needed.

package sidecar_test

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A full reader whose log judges bridge bodies and checks each base's bridge ledger against the heads the world holds.
func (self *testWriterWorld) bridgeClient() (*sidecar.ConfigClient, *sidecar.BridgeBodyJudge) {
	self.t.Helper()
	judge := &sidecar.BridgeBodyJudge{
		ReadHead: func(configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
			return self.heads.ReadConfigHead(self.ctx, configVersion, configHeadSha256)
		},
	}
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	logSettings.BridgeBodyJudge = judge
	settings.LogSettings = logSettings
	client, err := sidecar.NewConfigClient(self.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    self.networkId,
		GenesisChain: self.genesis.GenesisChain,
		Projection:   self.reader(),
		Heads:        self.heads,
		Clock:        self.clock,
		Settings:     settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client, judge
}

// A writer of the owner's over client with fold as its bridge fold.
func (self *testWriterWorld) bridgeWriter(client *sidecar.ConfigClient, fold sidecar.ConfigBridgeFold) *sidecar.ConfigWriter {
	self.t.Helper()
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = self.clock
	settings.Random = func() float64 { return 0 }
	settings.Log = sidecar.NewNoopLogger()
	writer, err := sidecar.NewConfigWriter(self.ctx, &sidecar.ConfigWriterArgs{
		SidecarId:  self.owner.sidecarId,
		Sign:       self.owner.sign(),
		Client:     client,
		Heads:      self.heads.For(self.owner.sidecarId, self.owner.key),
		Publisher:  self.publisher(),
		Settings:   settings,
		BridgeFold: fold,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(writer.Close)
	return writer
}

// The owner files a BridgeEgress of mode none for itself, then a BridgeWithdraw reserving an id; their pins.
func (self *testWriterWorld) bridgeStatements() (*bridge.AuthPin, *bridge.AuthPin) {
	self.t.Helper()
	egress, err := self.api.AppendStatement(self.ctx, self.networkId, self.statement(self.owner, bridge.SignedType_SIGNED_BRIDGE_EGRESS, &bridge.BridgeEgress{
		Header: self.header(), Subject: self.owner.sidecarId.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE,
	}))
	if err != nil {
		self.t.Fatal(err)
	}
	ruleId := testWriterId("reserved rule")
	withdraw, err := self.api.AppendStatement(self.ctx, self.networkId, self.statement(self.owner, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, &bridge.BridgeWithdraw{
		Header: self.header(), RuleId: append(ruleId.Bytes(), ruleId.Bytes()...), Mode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET,
	}))
	if err != nil {
		self.t.Fatal(err)
	}
	return egress, withdraw
}

// The writer rule (DESIGN-DETAILS 12.2.3): a base published without asking to fold folds through the tip while a
// bridge statement is unfolded, and its head carries the ledger: the manifest, the egress spec and the reservation. A
// full reader standing under the previous base checks the ledger in its real head check and takes the base, and the
// ledger it opens there holds both statements' effects with nothing left unfolded.
func TestAWriterFoldsTheBridgeLedgerThroughItsTip(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client, judge := world.bridgeClient()
	_, withdraw := world.bridgeStatements()
	world.caughtUp(client)
	writer := world.bridgeWriter(client, judge.Fold)
	if _, err := writer.PublishBase(world.ctx, false); err != nil {
		t.Fatal(err)
	}
	state := world.caughtUp(client)
	base := state.Base()
	if base.GetFoldedThrough() != withdraw.GetVersion() || state.Bridge().Len() != 0 {
		t.Fatalf("the base folds through %d with %d bridge statements left, want %d and none", base.GetFoldedThrough(), state.Bridge().Len(), withdraw.GetVersion())
	}
	head, err := world.heads.ReadConfigHead(context.Background(), base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{sidecar.ConfigHeadBridgeLedgerManifestPath, sidecar.ConfigHeadBridgeLedgerEgressPath} {
		if head.File(path) == nil {
			t.Errorf("the head holds no %s", path)
		}
	}
	rows, err := sidecar.NewBridgeLedgerHeadRows(head, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := sidecar.OpenBridgeLedger(rows, &sidecar.BridgeLedgerReader{State: state})
	if err != nil {
		t.Fatal(err)
	}
	if egress := ledger.Egress(); len(egress) != 1 || egress[0].Subject != world.owner.sidecarId || egress[0].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
		t.Fatalf("the ledger's egress: %+v", egress)
	}
	reservedId := testWriterId("reserved rule")
	if ledger.Reserved(append(reservedId.Bytes(), reservedId.Bytes()...)) == nil || len(ledger.Entries()) != 0 {
		t.Fatal("the ledger lost the reservation, or holds statements unfolded")
	}
	// a second full reader starting from the api takes the same base through its own head check
	other, _ := world.bridgeClient()
	if otherState := world.caughtUp(other); !otherState.OnChain(state.Pin()) {
		t.Fatal("a second reader stands elsewhere")
	}
}

// A writer that cannot write the ledger never folds a bridge statement into a head without it: with no fold installed,
// its base folds through the entry before the first bridge statement, the head holds no ledger file, a full reader's
// head check takes it, and both statements stay unfolded.
func TestAWriterWithNoBridgeFoldFoldsNoBridgeStatement(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client, _ := world.bridgeClient()
	egress, _ := world.bridgeStatements()
	world.caughtUp(client)
	writer := world.bridgeWriter(client, nil)
	if _, err := writer.PublishBase(world.ctx, true); err != nil {
		t.Fatal(err)
	}
	state := world.caughtUp(client)
	base := state.Base()
	if base.GetFoldedThrough() != egress.GetVersion()-1 || state.Bridge().Len() != 2 {
		t.Fatalf("the base folds through %d with %d bridge statements left, want %d and 2", base.GetFoldedThrough(), state.Bridge().Len(), egress.GetVersion()-1)
	}
	head, err := world.heads.ReadConfigHead(context.Background(), base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range head.Paths() {
		if len(path) > len("bridge/ledger/") && path[:len("bridge/ledger/")] == "bridge/ledger/" {
			t.Errorf("the head holds %s", path)
		}
	}
}

// The head check's other half, through a full reader's real head check: a writer whose fold leaves out a ledger file
// lands its base at api, which reads no ledger, and the reader standing under the previous base forks on it.
func TestAWriterWhoseLedgerIsWrongForksItsReaders(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client, judge := world.bridgeClient()
	_, withdraw := world.bridgeStatements()
	world.caughtUp(client)
	short := func(previous *sidecar.ConfigHead, state *sidecar.ConfigState, foldedThrough uint64, entryTimeMs func(n uint64) (int64, bool)) (*sidecar.BridgeLedgerFold, error) {
		fold, err := judge.Fold(previous, state, foldedThrough, entryTimeMs)
		if err == nil {
			delete(fold.Files, sidecar.ConfigHeadBridgeLedgerEgressPath)
		}
		return fold, err
	}
	// the writer stands on a reader that checks no ledger, as api does, so its base lands; the reader under test meets
	// the base only as it follows api
	writerClient := world.client()
	world.caughtUp(writerClient)
	writer := world.bridgeWriter(writerClient, short)
	if _, err := writer.PublishBase(world.ctx, false); err != nil {
		t.Fatal(err)
	}
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil || tip.GetVersion() != withdraw.GetVersion()+1 {
		t.Fatalf("the base did not land at api: %v, %v", tip, err)
	}
	if err := client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) || client.Fork() == nil {
		t.Fatalf("the reader took a base whose ledger is wrong: %v", err)
	}
}
