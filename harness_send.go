//go:build !ios_extension && !sidecar_http

// Kind 24's rule (DESIGN-COMPUTE §7.8, D-HARN-7, Q-HARN-7 answered (b), QD-1321): a tainted run may not move what it
// read past the device by another door. Its command, prompt, message or continuation is outward, kind 24
// tainted_send, when its target
//
//   - is an enclave whose egress is not none, since a receiver's taint stops nothing its bash sends;
//   - is an enclave whose egress is none but which a rule lets dial another device's services (a listener: grant, the
//     listeners rule's default for tagged sources, a dial rule to a member's device, §26.7), since a listed service
//     can act on the internet for it;
//   - is another member's agent or enclave, whatever its egress, since the text leaves the member.
//
// An untainted run's sends are never kind 24 here (other rules may make them O); a send to the member's own local
// agents is not, since the receiver's taint follows the work (§7.9). The target's facts come from its caller: ENC's
// settings for the egress, LSTN's answer for the dial rule, the config's members for whose it is. A target this rule
// cannot read, an unknown kind or egress among them, is outward, so the rule fails closed.

package sidecar

// What a send reaches.
type HarnessSendTargetKind string

const (
	// An agent of the member's in a local Harness, this one or another of the member's devices.
	HarnessSendLocalAgent HarnessSendTargetKind = "local_agent"
	// An agent, a command or a context into one of the member's enclaves.
	HarnessSendEnclave HarnessSendTargetKind = "enclave"
	// Another member's agent, wherever it runs.
	HarnessSendMemberAgent HarnessSendTargetKind = "member_agent"
	// Another member's enclave.
	HarnessSendMemberEnclave HarnessSendTargetKind = "member_enclave"
)

// An enclave's egress mode that reaches nothing outside (§11.8); every other mode reaches out.
const HarnessEnclaveEgressNone = "none"

// A send's target, as its caller read it.
type HarnessSendTarget struct {
	Kind HarnessSendTargetKind
	// An enclave's egress mode, ENC's settings' word (§11.8); empty reads as reaching out.
	EnclaveEgress string
	// LSTN's answer: whether a rule lets the enclave dial another device's services (§26.7).
	DialsServices bool
}

// Whether a send from a run whose taint is tainted to target is kind 24, as the file header says.
func HarnessSendIsOutward(tainted bool, target *HarnessSendTarget) bool {
	if !tainted {
		return false
	}
	if target == nil {
		return true
	}
	switch target.Kind {
	case HarnessSendLocalAgent:
		return false
	case HarnessSendEnclave:
		return target.EnclaveEgress != HarnessEnclaveEgressNone || target.DialsServices
	}
	// another member's agent or enclave, or a kind this rule cannot read
	return true
}

// Whether this run's send to target is kind 24 tainted_send, its taint read now.
func (self *HarnessRun) SendIsOutward(target *HarnessSendTarget) bool {
	return HarnessSendIsOutward(self.Tainted(), target)
}
