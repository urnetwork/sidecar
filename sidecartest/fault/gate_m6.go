// M6's gate (§23.6's M6 row): the case of it no convention finds, FS-126, D-PROTO-10's P2P schedule (QD-210,
// QD-1008). TEST-M6-02 writes the rest of M6's sweep here, its exit criteria and closure as items, and the cases whose
// tests sit outside the convention.
//
// FS-126's T2 run is sidecartest/p2p_test.go's (PROTO-M6-02): plain tests of package sidecartest, which the
// convention's TestFs126 in this package does not find, so the sweep names them where they run, as owner decision 548
// has the sweeps name FS-5's and FS-73's T3 tests in server's evshost. A case a sweep names runs only the tests the
// sweep lists, so its T3 test is listed too, under the convention's name in server's sidecart3, which nothing has
// written: server/connect's TestSidecarP2pT3StreamLaneOnlyWhenEnabled, PROTO-M6-02's T3 half, runs on the in-process
// exchange, which has no P2P carrier, so it moves no pair onto P2P and back and forges no ControlId frame over P2P, and
// it reads the pair's contracts bound to its stream, not a debit. Naming it would read the row passing on clauses no T3
// test shows, so the row reads missing until a T3 test of the schedule is named. Of the row's clauses, HeadCheck
// holding across each move is asserted by no test yet: p2p_test.go checks each side's view of the other's Hello.

package fault

// FS-126 on T2, as sidecartest/p2p_test.go runs it: off by default, the move to P2P and back under a live RPC and
// stream, and a ControlId frame forged over P2P dropped.
var gateFs126T2Test = &GateTest{
	Repo:    "sidecar",
	Package: "./sidecartest",
	Names:   []string{"TestP2pOffByDefault", "TestP2pPairMovesAndBackUnderALiveRpcAndStream", "TestP2pForgedControlIdStaysDroppedWithP2pOn"},
}

// FS-126 on T3, the convention's test under the convention's tags (QD-1085), which reads missing until it is written
// or a sweep names another.
var gateFs126T3Test = &GateTest{
	Repo:    "server",
	Package: "./sidecart3",
	Tags:    gateT3Tags,
	Stores:  true,
	Names:   []string{"TestFs126OnT3"},
}

var gateM6Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M6",
	Cases: map[string][]*GateTest{"FS-126": {gateFs126T2Test, gateFs126T3Test}},
})
