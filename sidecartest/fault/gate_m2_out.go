// M2's exit review (TEST-M2-19; §23.6's M2 row, §23.8's Gn-out): for now, the one case of it whose test the
// convention cannot find, FS-5 (owner decision 548; QD-995). TEST-M2-19 writes the rest of M2's sweep here: its exit
// criteria and §22.10's right column as items, and the items gate_m1.go carries for M2 until then.
//
// FS-5's T3 test drives stock git through evsgit's world. The world's hook stand-in is a helper process of the test
// binary that builds it, and the world needs a testing.TB, which a fault.Builder does not have. So no builder is
// registered for FS-5. Its test, TestFs5OnT3, runs in server's ./evshost behind sidecar_localstack, where the
// local stack's MinIO serves the block, not in the convention's ./sidecart3. The sweep names it there, the way M1's
// sweep names FS-54's tests. FS-5 runs only on T3, so this is the row's only test. A case a sweep names runs only
// the tests the sweep lists. If the test is renamed or its build tags drift, the row reads missing, never pass, and
// server's TestGateSweepsNameServerTestsDeclaredUnderTheirTags fails first.

package fault

// FS-5 on T3, as server's evshost runs it: on the private stores and the local stack, built with the convention's
// tags plus sidecar_localstack.
var gateFs5T3Test = &GateTest{
	Repo:    "server",
	Package: "./evshost",
	Tags:    "sidecar_testhooks,sidecar_pending,sidecar_localstack",
	Stores:  true,
	Names:   []string{"TestFs5OnT3"},
}

var gateM2Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M2",
	Cases: map[string][]*GateTest{"FS-5": {gateFs5T3Test}},
})
