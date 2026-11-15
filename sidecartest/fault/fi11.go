// FI-11, path integrity (§22.8; §13, §14, §17; D-BRIDGE-21, I-5; TEST-M4-01): "no application byte reaches a backend
// before its audience check, whatever the SNI or ALPN, nor a target after its flow's revocation; a proof accepts only
// what the MX's own state machine accepts". Read after every step and at the end, from what the row's world made on
// its Net (sidecartest/recording_backend.go):
//
//   - every byte a RecordingBackend took off its socket since the last check, stamped with the step it arrived in, is
//     judged by the audience state when it arrived: one before the check passed, or after the flow's revocation, is a
//     violation, however few bytes and whatever they were, a TLS record included;
//   - at the end, a positive twin's backend (MustReach) must have taken a byte while admitted, or the check passed on
//     a path nothing reaches;
//   - every proof an MxProofLedger holds must be answered by a transaction its MX's own state machine took, one proof
//     to a transaction (MxProofLedger.Mismatches).
//
// A row's world says where each backend's audience check stands, so the oracle reads the path's bytes and not the
// world's account of them. FS-38 and FS-56 still check their NAT's dials through FsBridgePathIntegrity, which reads the
// bridge world's own decisions; a RecordingBackend over BridgeNet's upstream is how they come to read FI-11 here.

package fault

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(11, func(ctx context.Context, oracle *Oracle) error {
	violations := []error{}
	for _, backend := range oracle.Net.RecordingBackends() {
		for _, arrival := range backend.Stamp(oracle.Step, oracle.Final) {
			switch arrival.Audience {
			case sidecartest.RecordingBackendAdmitted:
			case sidecartest.RecordingBackendRevoked:
				violations = append(violations, fmt.Errorf("%s: a target reached after its flow's revocation: %s", backend.Name(), arrival))
			default:
				violations = append(violations, fmt.Errorf("%s: bytes before its audience check: %s", backend.Name(), arrival))
			}
		}
		if oracle.Final && backend.MustReach() && !backend.ReachedAdmitted() {
			violations = append(violations, fmt.Errorf("%s: a positive twin's backend that no byte reached admitted (%d connections), so the check passed on a dead path", backend.Name(), backend.ConnectionCount()))
		}
	}
	for _, ledger := range oracle.Net.MxProofLedgers() {
		violations = append(violations, ledger.Mismatches()...)
	}
	return errors.Join(violations...)
})
