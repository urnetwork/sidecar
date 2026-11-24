// DESIGN-COMPUTE.md §16.3's outward actions, kinds 19 to 26 appended to §5.4's list (D-CACL-2, D-CACL-5;
// CACL-M11-04), each through Sidecar.Authorize, each at CanonicalAction version 5 alone, which an approver, spender or
// gate that does not know the version refuses whole. record.proto's SidecarActionKind holds the same values, which
// record_kind_test.go checks, and sidecarGateKinds lists each, so every kind reaches the gate.
//
// A kind with no row in canonicalActionKindRows is refused by NewCanonicalAction and by every parser, and one with no
// effect lookup by the gate before its Reserve (record_effect.go), so until CACL-M12-01 lands the version-5 rows and
// each filing area registers its lookup (ENC 19, 20, 22; BAL 21; FETCH 23; HARN, SKILL and SSH 24; MAILCAL 25; CONN 26),
// Authorize refuses every one of these.
//
// On every leg: the gate's kind list names them.

package sidecar

const (
	// Creating an enclave, a start that changes its shape or provider, or any start a tool or MCP asks for (§11.7).
	SidecarActionEnclaveCreate SidecarActionKind = 19
	// Turning an enclave's default egress off, so its traffic leaves through the provider and the miner sees its
	// metadata (§11.8).
	SidecarActionEnclaveEgressDirect SidecarActionKind = 20
	// An agent or a person passing a compute budget, or a gateway grant made or raised above the server's default
	// (§7.4, §8.6, §16.4).
	SidecarActionComputeBudgetRaise SidecarActionKind = 21
	// Removing an enclave, and what that erases (§11.11).
	SidecarActionEnclaveDelete SidecarActionKind = 22
	// An agent in a tainted run fetching a URL it composed (§22.5).
	SidecarActionFetchUnlistedUrl SidecarActionKind = 23
	// A tainted run sending into an enclave whose egress is not none, or to another member's agent or enclave, at
	// every entry point §16.3 lists (§7.8).
	SidecarActionTaintedSend SidecarActionKind = 24
	// An agent's addition, change or removal of calendar events from a tainted run, or of any event with attendees
	// (§23.9).
	SidecarActionCalendarWrite SidecarActionKind = 25
	// An agent's write or send to a connected service from a tainted run (§25.10).
	SidecarActionServiceWrite SidecarActionKind = 26
)
