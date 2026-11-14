//go:build !js

// FuzzBridgeLedgerFold (DESIGN-DETAILS 12.6's ledger row, with QD-761's FormedThrough and entry times) as a native fuzz
// target, whose seeds in testdata/fuzz/FuzzBridgeLedgerFold run as ordinary tests under go test. Not on js: testing.F
// reads its corpus directory before it runs a seed, and js has none.

package sidecar

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fold of a random log equals the ledger of that log opened whole: the reader under test's ledger, over the rows its
// bases froze and its unfolded statements, is the ledger of every statement the log took opened over no rows, where
// no base turns a verdict. The log also files bodies of every kind sealed to generation 2, which never forms at its
// readers, with time passing by the hour: the writer, whose plan reads gkm whole at generation 1, freezes each void at
// the first fold that finds it a wait old, and a last fold a wait past the newest entry reaches the tip. The whole log
// is opened by a reader that came to hold generation 2 signed after every entry, past the grace, which judges each
// such body void by its grace alone: a void the writer froze is the verdict every reader that gains the generation
// reaches (BridgeVoid.tla's VoidsAgree).
func FuzzBridgeLedgerFold(f *testing.F) {
	for seed := range uint64(3) {
		f.Add(seed, uint8(40))
	}
	f.Fuzz(func(t *testing.T, seed uint64, stepCount uint8) {
		net, member, devices := newTestBridgePolicyNet(t)
		net.fold = net.writerJudge(1, 0)
		taken := []*BridgeLogStatement{}
		collect := func() {
			// every statement past the previous base's fold, in log order, read off the states before each base
			for _, statement := range net.log.State().Bridge().Statements() {
				if !slices.ContainsFunc(taken, func(held *BridgeLogStatement) bool { return held.StatementId == statement.StatementId }) {
					taken = append(taken, statement)
				}
			}
		}
		random := rand.New(rand.NewPCG(seed, 0xf01d))
		testBridgeLedgerRun(t, net, member, devices, random, int(stepCount%96), false, true, func() {})
		// every body sealed to generation 2 is a wait old at a last fold through the tip, which therefore reaches it
		wait, grace := testBridgeVoidTimes()
		if tip := net.tickAt(net.timeMs + wait); net.foldLedger(tip, nil) != tip {
			t.Fatalf("the last fold stopped below the tip %d", tip)
		}
		// the run's bases folded through their tips, so the statements the states held between bases are the log's:
		// replay the run's entries on a fresh reader to read each state before its base
		reader, err := NewConfigLog(net.readerSettings(), net.signedGenesis)
		if err != nil {
			t.Fatal(err)
		}
		// every entry's time, which the whole log's releases read: the reader under test keeps only its retained ones,
		// and the folds froze the rest
		entryTimes := map[uint64]int64{}
		for _, entryBytes := range net.entries {
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				t.Fatal(err)
			}
			entryTimes[entry.GetN()] = entry.GetTimeMs()
			if entry.GetKind() == bridge.AuthEntryKindBase {
				for _, statement := range reader.State().Bridge().Statements() {
					if !slices.ContainsFunc(taken, func(held *BridgeLogStatement) bool { return held.StatementId == statement.StatementId }) {
						taken = append(taken, statement)
					}
				}
			}
			if _, err := reader.Apply(entryBytes, net.ledgerSource()); err != nil {
				t.Fatal(err)
			}
		}
		collect()
		state := net.log.State()
		late := testBridgeKeySignedAt(2, net.timeMs+grace+1)
		whole := NewBridgeLog(taken).Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(append(slices.Clone(net.keys), late)...), EntryTimeMs: func(n uint64) (int64, bool) {
			timeMs, ok := entryTimes[n]
			return timeMs, ok
		}})
		if got, want := testBridgeLedgerBytes(t, net.ledgerOf(net.log)), testBridgeLedgerBytes(t, whole); !bytes.Equal(got, want) {
			t.Fatalf("the folded ledger is not the whole log's:\n%x\n%x", got, want)
		}
	})
}
