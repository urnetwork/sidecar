// M10's exit review (TEST-M10-05; §23.6's M10 row, §23.8's Gn-out): for now, the cases of it whose T3 tests the
// convention cannot find, FS-73 and FS-72's rollback case (owner decision 548; QD-995). TEST-M10-05 writes the rest
// of M10's sweep here: its exit criteria and §22.10's right column as items.
//
// Both T3 tests run in server's ./evshost behind sidecar_localstack, where the local stack's MinIO serves the block,
// not in the convention's ./sidecart3, so the sweep names them there, the way M1's sweep names FS-54's tests:
//
//   - FS-73's T3 test, TestFs73OnT3, drives stock git and git-lfs through evsgit's world. The world's git-lfs agent
//     and git-remote-ur stand-ins are helper processes of the test binary that builds it, and the world needs a
//     testing.TB, which a fault.Builder does not have. So no builder is registered for FS-73, which runs only on
//     T3, and this is the row's only test.
//   - FS-72's rollback case, TestFs72RollbackOnT3 (EVS2-M10-30), is a registered builder that the evshost test runs
//     on T3. A case a sweep names runs only the tests the sweep lists, so its T2 test is listed too, as the
//     convention names it.
//
// If a test is renamed or its build tags drift, its row reads missing, never pass, and server's
// TestGateSweepsNameServerTestsDeclaredUnderTheirTags fails first.

package fault

// FS-73 on T3, as server's evshost runs it: on the private stores and the local stack, built with the convention's
// tags plus sidecar_localstack.
var gateFs73T3Test = &GateTest{
	Repo:    "server",
	Package: "./evshost",
	Tags:    "sidecar_testhooks,sidecar_pending,sidecar_localstack",
	Stores:  true,
	Names:   []string{"TestFs73OnT3"},
}

// FS-72's rollback case on T2: the convention's test, the thin one that calls RunRow.
var gateFs72RollbackT2Test = &GateTest{
	Repo:    "sidecar",
	Package: "./sidecartest/fault",
	Tags:    "sidecar_testhooks",
	Names:   []string{"TestFs72Rollback"},
}

// FS-72's rollback case on T3, as server's evshost runs it, with the same tags as FS-73's.
var gateFs72RollbackT3Test = &GateTest{
	Repo:    "server",
	Package: "./evshost",
	Tags:    "sidecar_testhooks,sidecar_pending,sidecar_localstack",
	Stores:  true,
	Names:   []string{"TestFs72RollbackOnT3"},
}

var gateM10Sweep = RegisterGateSweep(&GateSweep{
	Gate: "M10",
	Cases: map[string][]*GateTest{
		"FS-73":            {gateFs73T3Test},
		"FS-72's rollback": {gateFs72RollbackT2Test, gateFs72RollbackT3Test},
	},
})
