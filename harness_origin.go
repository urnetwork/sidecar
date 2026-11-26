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
// The attach origin (§12.5's step 5, D-HARN-6; HARN-M14-01) is that statement: protocol/harness.proto's
// HarnessAttachOrigin, the body of a §6.9 Signed of purpose attach-origin and type SIGNED_ATTACH_ORIGIN by the calling
// sidecar's identity key, over the network, the calling sidecar, the enclave and its incarnation, the session's SSH
// exchange hash and the mode: carried, with its one origin, for a session whose bytes the caller's sidecar only
// carries (ur ssh), or stamped, its own Harness stamping each line (harness_rpc.go). SSH signs it
// (Sidecar.SignHarnessAttachOrigin) and verifies it outside the agents' container (VerifyHarnessAttachOrigin),
// handing the Harness the verified header; a session without one is an unknown run's (HarnessAttachUnknownHeader).
// HARN-M14-11 gives the statement its device target beside the enclave's.
//
// Everything here is a value, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

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

// The purpose an attach origin's Signed takes (§6.9, §6.11).
const HarnessAttachOriginPurpose = "attach-origin"

// How a session carries its origin (§7.10), as the statement and a session's header name it.
type HarnessAttachMode string

const (
	// One origin for the whole session, whose bytes the caller's sidecar only carries.
	HarnessAttachModeCarried HarnessAttachMode = "carried"
	// Each line stamped with its origin by the caller's own Harness.
	HarnessAttachModeStamped HarnessAttachMode = "stamped"
)

var (
	// The statement cannot be made: a carried mode with no origin, a stamped one with one, a run naming no run or agent,
	// no exchange hash.
	ErrHarnessAttachOriginInvalid = errors.New("the attach origin is malformed")
	// The statement does not verify as this session's origin: its signature, its type or purpose, or a field naming
	// another network, sidecar, enclave, incarnation or session.
	ErrHarnessAttachOriginRefused = errors.New("the attach origin is not this session's")
)

// What an attach origin states (§12.5).
type HarnessAttachOriginArgs struct {
	NetworkId Id
	// The calling sidecar, whose identity key signs.
	SidecarId   Id
	EnclaveId   Id
	Incarnation uint64
	// This SSH session's exchange hash, its session id.
	ExchangeHash []byte
	Mode         HarnessAttachMode
	// Carried's one origin; nil when stamped.
	Origin *HarnessOrigin
}

// The proto kind of an origin's kind, unspecified for a word this build does not know.
func harnessOriginKindProto(kind HarnessOriginKind) protocol.HarnessOriginKind {
	switch kind {
	case HarnessOriginPerson:
		return protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_PERSON
	case HarnessOriginRun:
		return protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_RUN
	case HarnessOriginUnknown:
		return protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_UNKNOWN
	}
	return protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_UNSPECIFIED
}

// Refuses an origin no statement or stamp may carry: nil, a kind this build does not know, a run naming no run or
// agent, a person or unknown run naming either.
func harnessOriginCheck(origin *HarnessOrigin) error {
	if origin == nil {
		return fmt.Errorf("%w: no origin", ErrHarnessAttachOriginInvalid)
	}
	switch origin.Kind {
	case HarnessOriginRun:
		if origin.RunId == nil || origin.AgentId == nil {
			return fmt.Errorf("%w: a run's origin names its run and agent", ErrHarnessAttachOriginInvalid)
		}
	case HarnessOriginPerson, HarnessOriginUnknown:
		if origin.RunId != nil || origin.AgentId != nil || origin.Tainted {
			return fmt.Errorf("%w: only a run's origin names a run", ErrHarnessAttachOriginInvalid)
		}
	default:
		return fmt.Errorf("%w: no origin kind %q", ErrHarnessAttachOriginInvalid, origin.Kind)
	}
	return nil
}

// origin as harness.proto writes it.
func harnessOriginToProto(origin *HarnessOrigin) *protocol.HarnessOrigin {
	message := &protocol.HarnessOrigin{Kind: harnessOriginKindProto(origin.Kind), Tainted: origin.Tainted}
	if origin.RunId != nil {
		message.RunId = origin.RunId.Bytes()
	}
	if origin.AgentId != nil {
		message.AgentId = origin.AgentId.Bytes()
	}
	return message
}

// The origin message holds, refusing one no statement may carry.
func harnessOriginFromProto(message *protocol.HarnessOrigin) (*HarnessOrigin, error) {
	if message == nil {
		return nil, fmt.Errorf("%w: no origin", ErrHarnessAttachOriginInvalid)
	}
	origin := &HarnessOrigin{Tainted: message.GetTainted()}
	switch message.GetKind() {
	case protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_PERSON:
		origin.Kind = HarnessOriginPerson
	case protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_RUN:
		origin.Kind = HarnessOriginRun
	case protocol.HarnessOriginKind_HARNESS_ORIGIN_KIND_UNKNOWN:
		origin.Kind = HarnessOriginUnknown
	default:
		return nil, fmt.Errorf("%w: origin kind %d", ErrHarnessAttachOriginInvalid, message.GetKind())
	}
	if 0 < len(message.GetRunId()) {
		runId, err := IdFromBytes(message.GetRunId())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginInvalid, err)
		}
		origin.RunId = &runId
	}
	if 0 < len(message.GetAgentId()) {
		agentId, err := IdFromBytes(message.GetAgentId())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginInvalid, err)
		}
		origin.AgentId = &agentId
	}
	if err := harnessOriginCheck(origin); err != nil {
		return nil, err
	}
	return origin, nil
}

// The statement's body over args, refusing one that cannot be stated: no exchange hash, a carried mode without one
// well-formed origin, a stamped mode with one, a mode this build does not know.
func NewHarnessAttachOrigin(args *HarnessAttachOriginArgs) (*protocol.HarnessAttachOrigin, error) {
	if args == nil || len(args.ExchangeHash) == 0 {
		return nil, fmt.Errorf("%w: no exchange hash", ErrHarnessAttachOriginInvalid)
	}
	statement := &protocol.HarnessAttachOrigin{
		NetworkId:    args.NetworkId.Bytes(),
		SidecarId:    args.SidecarId.Bytes(),
		EnclaveId:    args.EnclaveId.Bytes(),
		Incarnation:  args.Incarnation,
		ExchangeHash: bytes.Clone(args.ExchangeHash),
	}
	switch args.Mode {
	case HarnessAttachModeCarried:
		if err := harnessOriginCheck(args.Origin); err != nil {
			return nil, err
		}
		statement.Mode = protocol.HarnessAttachMode_HARNESS_ATTACH_MODE_CARRIED
		statement.Origin = harnessOriginToProto(args.Origin)
	case HarnessAttachModeStamped:
		if args.Origin != nil {
			return nil, fmt.Errorf("%w: a stamped session's lines carry their origins", ErrHarnessAttachOriginInvalid)
		}
		statement.Mode = protocol.HarnessAttachMode_HARNESS_ATTACH_MODE_STAMPED
	default:
		return nil, fmt.Errorf("%w: no mode %q", ErrHarnessAttachOriginInvalid, args.Mode)
	}
	return statement, nil
}

// statement signed by this sidecar's identity key, purpose attach-origin, type SIGNED_ATTACH_ORIGIN (Sidecar.Sign), in
// deterministic protobuf. A read_only device signs none, since verifiers refuse every such statement from one.
func (self *Sidecar) SignHarnessAttachOrigin(statement *protocol.HarnessAttachOrigin) (*bridge.Signed, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(statement)
	if err != nil {
		return nil, err
	}
	return self.Sign(HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN, body, nil)
}

// What the receiving end holds a session's origin to: its network, the sidecar SSH verified over the session's flow
// (§12.5's checks 1 and 2), the enclave and incarnation it serves, and this session's exchange hash.
type HarnessAttachExpect struct {
	NetworkId    Id
	SidecarId    Id
	EnclaveId    Id
	Incarnation  uint64
	ExchangeHash []byte
}

// The verified header SSH's server hands the Harness (§12.5's step 5): the calling sidecar, the mode, and carried's one
// origin, nil when stamped, each line then carrying its own.
type HarnessAttachHeader struct {
	SidecarId Id
	Mode      HarnessAttachMode
	Origin    *HarnessOrigin
}

// The header of a session without an origin statement, OpenSSH's through ur ssh agent among them (§12.9): an unknown
// run's, carried, whatever its lines say.
func HarnessAttachUnknownHeader(sidecarId Id) *HarnessAttachHeader {
	return &HarnessAttachHeader{SidecarId: sidecarId, Mode: HarnessAttachModeCarried, Origin: HarnessUnknownOrigin("")}
}

// Verifies signed as the session's origin: its signature under publicKey, the calling sidecar's identity key from the
// config, as purpose attach-origin and type SIGNED_ATTACH_ORIGIN; its body naming exactly the network, sidecar, enclave,
// incarnation and exchange hash expect does, its signer_id the sidecar; its mode carried with one well-formed origin or
// stamped with none. Anything else is ErrHarnessAttachOriginRefused, so an origin made for another session, network,
// sidecar or enclave never passes.
func VerifyHarnessAttachOrigin(signed *bridge.Signed, publicKey ed25519.PublicKey, expect *HarnessAttachExpect) (*HarnessAttachHeader, error) {
	if expect == nil || len(expect.ExchangeHash) == 0 {
		return nil, fmt.Errorf("%w: no session to hold it to", ErrHarnessAttachOriginRefused)
	}
	if err := bridge.VerifySigned(signed, HarnessAttachOriginPurpose, bridge.SignedType_SIGNED_ATTACH_ORIGIN,
		bridge.SignedKeyAlgEd25519, publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginRefused, err)
	}
	statement := &protocol.HarnessAttachOrigin{}
	if err := proto.Unmarshal(signed.GetBody(), statement); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginRefused, err)
	}
	switch {
	case !bytes.Equal(statement.GetNetworkId(), expect.NetworkId.Bytes()):
		return nil, fmt.Errorf("%w: another network's", ErrHarnessAttachOriginRefused)
	case !bytes.Equal(statement.GetSidecarId(), expect.SidecarId.Bytes()) ||
		(0 < len(signed.GetSignerId()) && !bytes.Equal(signed.GetSignerId(), expect.SidecarId.Bytes())):
		return nil, fmt.Errorf("%w: another sidecar's", ErrHarnessAttachOriginRefused)
	case !bytes.Equal(statement.GetEnclaveId(), expect.EnclaveId.Bytes()) || statement.GetIncarnation() != expect.Incarnation:
		return nil, fmt.Errorf("%w: another enclave's or incarnation's", ErrHarnessAttachOriginRefused)
	case !bytes.Equal(statement.GetExchangeHash(), expect.ExchangeHash):
		return nil, fmt.Errorf("%w: another session's", ErrHarnessAttachOriginRefused)
	}
	header := &HarnessAttachHeader{SidecarId: expect.SidecarId}
	switch statement.GetMode() {
	case protocol.HarnessAttachMode_HARNESS_ATTACH_MODE_CARRIED:
		origin, err := harnessOriginFromProto(statement.GetOrigin())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHarnessAttachOriginRefused, err)
		}
		header.Mode, header.Origin = HarnessAttachModeCarried, origin
	case protocol.HarnessAttachMode_HARNESS_ATTACH_MODE_STAMPED:
		if statement.GetOrigin() != nil {
			return nil, fmt.Errorf("%w: a stamped session states no one origin", ErrHarnessAttachOriginRefused)
		}
		header.Mode = HarnessAttachModeStamped
	default:
		return nil, fmt.Errorf("%w: mode %d", ErrHarnessAttachOriginRefused, statement.GetMode())
	}
	return header, nil
}
