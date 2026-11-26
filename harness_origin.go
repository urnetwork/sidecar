//go:build !ios_extension && !sidecar_http

// Where a prompt, steer or follow-up comes from (DESIGN-COMPUTE §7.8, §7.9, §7.10, D-HARN-6, D-HARN-8, I-9, IC-12): its
// origin, which the receiving run reads to decide whether the text is trusted.
//
//   - person: the person, typing in the app's UI, or in `ur harness` reading /dev/tty with no harness process among
//     its ancestors, as DESIGN §5.8's confirmed commands require. Trusted.
//   - run: a run, with its agent and its taint bit as its Harness keeps them: a tool call (agent_prompt, a child's
//     launch), or a ur process whose ancestry binds a run (DESIGN §16.7). Trusted only while untainted.
//   - unknown: any other caller, an unknown run's: `ur harness` with a harness process among its ancestors, or taking
//     its input from anywhere but /dev/tty. Never trusted.
//
// Text from an origin that is not trusted taints the run it reaches before it enters that run's context, write-ahead,
// and reaches the model between untrusted-data markers naming its sender (harness_untrusted.go). An origin is set by
// whoever verified it, never by the text's writer: the daemon from its caller's confirmation and ancestry, a Harness
// for its own runs, and on an attach link the caller's sidecar, whose signed statement the receiving SSH server
// verifies (§12.5).
//
// Everything here is a value, so safe for concurrent use.

package sidecar

// An origin's kind (§7.10), as a stamped line's origin writes it.
type HarnessOriginKind string

const (
	HarnessOriginPerson  HarnessOriginKind = "person"
	HarnessOriginRun     HarnessOriginKind = "run"
	HarnessOriginUnknown HarnessOriginKind = "unknown"
)

// How the untrusted-data markers name an unknown run (§7.10's "any other caller").
const HarnessUnknownRunSender = "an unknown run"

// Who a prompt, steer or follow-up comes from.
type HarnessOrigin struct {
	Kind HarnessOriginKind
	// A run's: the run and its agent, and whether the run was tainted when its origin was set.
	RunId   *Id
	AgentId *Id
	Tainted bool
	// How the untrusted-data markers name the writer of text that is not trusted, the sender its verifier knows; empty
	// takes the kind's own words.
	Sender string
}

// The person's origin.
func HarnessPersonOrigin() *HarnessOrigin {
	return &HarnessOrigin{Kind: HarnessOriginPerson}
}

// An unknown run's origin, named sender where its verifier knows more than that, else HarnessUnknownRunSender.
func HarnessUnknownOrigin(sender string) *HarnessOrigin {
	return &HarnessOrigin{Kind: HarnessOriginUnknown, Sender: sender}
}

// A run's origin, with its taint bit as its Harness keeps it.
func HarnessRunOrigin(runId Id, agentId Id, tainted bool) *HarnessOrigin {
	return &HarnessOrigin{Kind: HarnessOriginRun, RunId: &runId, AgentId: &agentId, Tainted: tainted}
}

// Whether text from the origin is trusted: the person's, or an untainted run's that names its run and agent. A nil
// origin, an unknown kind and a run naming neither are not.
func (self *HarnessOrigin) Trusted() bool {
	if self == nil {
		return false
	}
	switch self.Kind {
	case HarnessOriginPerson:
		return true
	case HarnessOriginRun:
		return !self.Tainted && self.RunId != nil && self.AgentId != nil
	}
	return false
}

// The sender the untrusted-data markers name for text from the origin: Sender where set, else its kind's words.
func (self *HarnessOrigin) SenderLabel() string {
	if self == nil {
		return HarnessUnknownRunSender
	}
	if self.Sender != "" {
		return self.Sender
	}
	switch self.Kind {
	case HarnessOriginPerson:
		return "the person"
	case HarnessOriginRun:
		if self.AgentId != nil {
			label := "agent " + self.AgentId.String()
			if self.Tainted {
				label = "a tainted run of " + label
			}
			return label
		}
	}
	return HarnessUnknownRunSender
}
