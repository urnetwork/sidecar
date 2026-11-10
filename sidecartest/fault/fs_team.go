// FS-14, FS-16, FS-102 and FS-124 (§22.8; §7.9; TEAM-M2-19): the authorization log's schedules on one network of the
// admission suite's world (sidecartest.AdmissionNet), built in each schedule's first step on the Net's first metadata
// cluster, clock and context, and on the api NetSettings.ConfigLogApi names: a FakeApi on T2, server's real sequencer
// on T3 (server/sidecart3/fs_team_test.go). Every entry api lands is applied by a long-running full reader, a new
// device and a rows-only gate started at each base, and the writer's own follower, and the world fails the step at
// once if any of them stands elsewhere than the reference (DESIGN-DETAILS 5.7's note for this task); FsTeamAgreement
// checks the same after every step.
//
// The rows' FI checks are TEST-M2-04's (FI-2) and TEST-M2-05's (FI-3) oracles, which are not bound yet, so a schedule
// here names FsTeamAgreement, the verifiers' agreement its own world checks, in their place, as fi30.go does for FI-2's
// store clause; once those oracles bind, each schedule adds FI(2) or FI(3) beside it.
//
// Registered, each a refusal beside the twin that must succeed:
//
//   - FS-14 (forged, T2; its twin on T3 too): a base whose tail_verdicts lie about one tail entry forks every
//     reader present at it, the reference, new devices and gates alike; its twin, the same base with the true bits
//     through api, lands at every reader.
//   - FS-16 (forged): a malicious api's activation of a recovery proposal vetoed at 71 h is refused at every reader;
//     its twin, the veto winning, with the window carried across two folds (DESIGN-DETAILS 5.6).
//   - FS-102 (T2+T3): Delegation D admits A, C and E, A is revoked for compromise from a since_n after C's admission,
//     and the thief's copy of D's signing seed admits B: api and every reader, new devices included, refuse it, C
//     stands, E is parked until an admin's AdmissionConfirm, D's own confirmation lifts nothing, and the same
//     revocation's bytes again are one entry; its twin admits B before the revocation. FS-102's forged case appends
//     B's admission past api's check, and every reader refuses it at its position.
//   - FS-124 (T2+T3): D's covered revocation is refused with no countersignature, another key's and another device's
//     key's, and lands with D's own; its twin is the countersigned revocation alone. FS-124's forged case: the thief,
//     holding D's identity key and not its presence key, has a malicious api sequence its covered statements, each
//     refused at its position by every reader and carried as 0 in the next base's tail_verdicts.
//
// The rest of each row is a named schedule a T2 test runs: FS-14's re-signed base, stale compile, fold rule, replay
// rules and vetoed replay after a fold; FS-16's activation across a fold; FS-102's removed agent and max_admits across a fold;
// FS-124's five-statement act, a device with no key, and the sign-out that needs none. What the world cannot show is
// listed in TEAM-M2-19's report: HeadCheck between forked readers (FS-14's first clause), the recovery's forged
// genesis and RecoveryWrap through Sidecar.RecoverWithCode (FS-16), generations, wraps and the reader-seed thief
// (FS-102's key legs, KEYS-M2-28), and FS-124's CLI, Team and app-host cases.

package fault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs14       = Register("FS-14", "", []Tier{TierT2}, Twin(Fs14LyingBase, Fs14HonestBase))
	Fs16       = Register("FS-16", "", []Tier{TierT2}, Twin(Fs16ForgedActivation, Fs16VetoWins))
	Fs102      = Register("FS-102", "", []Tier{TierT2, TierT3}, Twin(Fs102CopiedBundle, Fs102AdmittedBeforeTheEnd))
	Fs102Forge = Register("FS-102", "forged", []Tier{TierT2}, Twin(Fs102ForgedAdmission, Fs102AdmittedBeforeTheEnd))
	Fs124      = Register("FS-124", "", []Tier{TierT2, TierT3}, Twin(Fs124Uncountersigned, Fs124Countersigned))
	Fs124Forge = Register("FS-124", "forged", []Tier{TierT2}, Twin(Fs124ForgedUncountersigned, Fs124Countersigned))
)

// A failure the world raised inside a step, which the step returns.
type fsTeamFailure struct {
	err error
}

// The world's AdmissionT inside a schedule: a failure panics, and fsTeamStep recovers it into the step's error.
type fsTeamFailer struct{}

func (fsTeamFailer) Helper() {}

func (fsTeamFailer) Fatal(args ...any) {
	panic(fsTeamFailure{err: errors.New(fmt.Sprint(args...))})
}

func (fsTeamFailer) Fatalf(format string, args ...any) {
	panic(fsTeamFailure{err: fmt.Errorf(format, args...)})
}

func (fsTeamFailer) Logf(format string, args ...any) {}

// Runs body, turning a failure the world raises into its error.
func fsTeamCatch(body func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(fsTeamFailure)
			if !ok {
				panic(recovered)
			}
			err = failure.err
		}
	}()
	return body()
}

// What one schedule builds in its first step and its later steps read.
type fsTeamWorld struct {
	net *sidecartest.AdmissionNet
	// devices, keys and Delegations a step makes and a later one names
	devices      map[string]*sidecartest.AdmissionDevice
	recoveryKeys map[string]*sidecartest.AdmissionRecoveryKey
	delegations  map[string]*sidecartest.AdmissionDelegation
	presenceKeys map[string]*sidecartest.FixturePresenceKey
	// positions and ids a step notes
	positions map[string]uint64
	ids       map[string][]byte
	signed    map[string][]byte
}

func newFsTeamWorld() *fsTeamWorld {
	return &fsTeamWorld{
		devices:      map[string]*sidecartest.AdmissionDevice{},
		recoveryKeys: map[string]*sidecartest.AdmissionRecoveryKey{},
		delegations:  map[string]*sidecartest.AdmissionDelegation{},
		presenceKeys: map[string]*sidecartest.FixturePresenceKey{},
		positions:    map[string]uint64{},
		ids:          map[string][]byte{},
		signed:       map[string][]byte{},
	}
}

// A step by actor running body on the world, its failures the step's.
func fsTeamDo(actor string, world *fsTeamWorld, body func(net *sidecartest.AdmissionNet) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			return body(world.net)
		})
	}}
}

// The first step: the network bootstrapped on the Net's tier, its owner's first device the writer, then body.
func fsTeamSetup(world *fsTeamWorld, body func(net *sidecartest.AdmissionNet) error) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			world.net = sidecartest.NewAdmissionNet(fsTeamFailer{}, tier)
			if body == nil {
				return nil
			}
			return body(world.net)
		})
	}}
}

// The last step: the world's writer and follower stop.
func fsTeamClose(world *fsTeamWorld) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		if world.net != nil {
			world.net.Close()
		}
		return nil
	}}
}

// The verifiers' agreement: every reader that stands, new devices and gates at each base, holds the reference's state
// at the tip. In place of FI-3's oracle until TEST-M2-05 binds it.
func FsTeamAgreement(world *fsTeamWorld) Invariant {
	return NewInvariant("FI-3/agreement", func(ctx context.Context, oracle *Oracle) error {
		if world.net == nil {
			return nil
		}
		return fsTeamCatch(func() error {
			world.net.CheckAgreement()
			return nil
		})
	})
}

// A schedule of steps on world, its id the caller's, checked by the agreement after every step.
func fsTeamSchedule(id string, world *fsTeamWorld, steps ...*Step) *Schedule {
	return &Schedule{Id: id, Steps: append(steps, fsTeamClose(world)), Check: []Invariant{FsTeamAgreement(world)}}
}

// Whether every reader that ran forked at n, the reference among them.
func fsTeamEveryReaderForkedAt(net *sidecartest.AdmissionNet, n uint64) error {
	forks := net.Forks()
	if len(forks) != net.ReaderCount() {
		return fmt.Errorf("%d of %d readers forked: %v", len(forks), net.ReaderCount(), forks)
	}
	for name, forkN := range forks {
		if forkN != n {
			return fmt.Errorf("%s forked at %d, not %d", name, forkN, n)
		}
	}
	return nil
}

// FS-14's shared start: a member and its devices, a stranger's statement a malicious api landed (refused at every
// reader, so the tail carries a 0), a fold, then two more statements in the new base's tail.
func fs14Start(world *fsTeamWorld, forged bool) *Step {
	return fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
		if forged {
			net.AllowForks()
		}
		memberId, first := net.ConsentedMember("m")
		world.devices["m first"] = first
		net.AdmitDevice(first, net.Device("m tablet", memberId), 0)
		if net.ForgedAppends() {
			stranger := net.Device("stranger", net.Id("stranger member"))
			pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, net.Sign(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT,
				net.MemberAdmit(net.Id("by a stranger"), bridge.MemberRole_MEMBER_ROLE_MEMBER)))
			world.positions["refused"] = pin.GetVersion()
		}
		net.Fold(true)
		net.AdmitMember(net.Owner(), "after the fold", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		net.AdmitDevice(first, net.Device("m phone", memberId), 0)
		return nil
	})
}

// FS-14, forged: a base keeping the fold whose tail_verdicts claim the refused entry took effect, which api would
// refuse (403) and a malicious api lands: every reader present forks at it.
func Fs14LyingBase(net *Net) *Schedule {
	world := newFsTeamWorld()
	schedule := fsTeamSchedule("FS-14 a lying base", world,
		fs14Start(world, true),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			lying := func(header *bridge.ProjectionHeader) {
				// the last tail entry, the phone's admission, claimed refused: its bits 1 made 0
				j := header.GetVersion() - 2 - header.GetFoldedThrough()
				header.TailVerdicts[j/4] ^= 1 << (2 * (j % 4))
			}
			signedHeader, rows := net.BaseKeepingTheFold(net.WriterDevice(), lying)
			if _, err := net.AppendBase(signedHeader, rows); !fsTeamRefused(err) {
				return fmt.Errorf("api's answer to a lying base: %v, want 403", err)
			}
			pin := net.SequenceAnyway(bridge.AuthEntryKindBase, signedHeader)
			return fsTeamEveryReaderForkedAt(net, pin.GetVersion())
		}),
	)
	schedule.Refuses = "a base whose tail_verdicts lie about a tail entry: every reader forks at it"
	return schedule
}

// FS-14's twin: the same base with the true bits, through api, lands and every reader applies it.
func Fs14HonestBase(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 an honest base", world,
		fs14Start(world, false),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			signedHeader, rows := net.BaseKeepingTheFold(net.WriterDevice(), nil)
			pin, err := net.AppendBase(signedHeader, rows)
			if err != nil {
				return fmt.Errorf("an honest base: %w", err)
			}
			if !net.VerdictAt(pin.GetVersion()).Accepted() || 0 < len(net.Forks()) {
				return fmt.Errorf("the honest base at %d: forks %v", pin.GetVersion(), net.Forks())
			}
			return nil
		}),
	)
}

// Whether err is api's 403.
func fsTeamRefused(err error) bool {
	refusal := &sidecartest.ConfigLogRefusal{}
	return errors.As(err, &refusal) && refusal.Status == 403
}

// FS-14: a base planned at tip n loses its position (409) to a statement that lands first, and the writer re-signs it
// at the new tip, folding through it, carrying the new statement's verdict in its tail.
func Fs14ReSignedBase(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 a re-signed base", world,
		fs14Start(world, false),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			planned := net.Tip().GetVersion()
			net.BeforeNextPublish(func() {
				if _, err := net.AppendOnly(net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT,
					net.MemberAdmit(net.Id("landed first"), bridge.MemberRole_MEMBER_ROLE_MEMBER))); err != nil {
					panic(fsTeamFailure{err: fmt.Errorf("the statement landing first: %w", err)})
				}
			})
			pin := net.Fold(true)
			if pin.GetVersion() != planned+2 {
				return fmt.Errorf("the base landed at %d, planned at %d", pin.GetVersion(), planned+1)
			}
			// re-signed at the new tip, it keeps its planned fold and carries the statement that won as a 1
			base := net.State().Base()
			j := planned + 1 - base.GetFoldedThrough() - 1
			if base.GetFoldedThrough() != planned || net.State().Member(net.Id("landed first")) == nil ||
				(base.GetTailVerdicts()[j/4]>>(2*(j%4)))&3 != 1 {
				return fmt.Errorf("the re-signed base folds through %d with verdicts %x", base.GetFoldedThrough(), base.GetTailVerdicts())
			}
			return nil
		}),
	)
}

// FS-14: a stale compile, a base whose folded_through is below the newest base's, is refused by api (403), and a FORK
// for every reader once a malicious api appends it.
func Fs14StaleCompile(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 a stale compile", world,
		fs14Start(world, true),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			net.Fold(true)
			stale := func(header *bridge.ProjectionHeader) {
				header.FoldedThrough -= 1
			}
			signedHeader, rows := net.BaseKeepingTheFold(net.WriterDevice(), stale)
			if _, err := net.AppendBase(signedHeader, rows); !fsTeamRefused(err) {
				return fmt.Errorf("api's answer to a stale compile: %v, want 403", err)
			}
			pin := net.SequenceAnyway(bridge.AuthEntryKindBase, signedHeader)
			return fsTeamEveryReaderForkedAt(net, pin.GetVersion())
		}),
	)
}

// FS-14's fold rule (DESIGN-DETAILS 5.2.3): a base whose folded_through lies between the newest base's and that base's
// position is refused by api (403), and a FORK for every reader once a malicious api appends it. The newest base, a
// head change, keeps its fold, so a position lies between.
func Fs14FoldRule(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 the fold rule", world,
		fs14Start(world, true),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			net.SetServiceSettings(&protocol.ServiceSettings{WitnessBoundHours: 48})
			previous := net.State().Base()
			if previous.GetVersion() < previous.GetFoldedThrough()+3 {
				return fmt.Errorf("the head's base at %d keeps no tail past %d", previous.GetVersion(), previous.GetFoldedThrough())
			}
			between := func(header *bridge.ProjectionHeader) {
				header.FoldedThrough = previous.GetFoldedThrough() + 1
				header.TailVerdicts = net.TailVerdicts(header.GetFoldedThrough())
			}
			signedHeader, rows := net.BaseKeepingTheFold(net.WriterDevice(), between)
			if _, err := net.AppendBase(signedHeader, rows); !fsTeamRefused(err) {
				return fmt.Errorf("api's answer to a fold between: %v, want 403", err)
			}
			pin := net.SequenceAnyway(bridge.AuthEntryKindBase, signedHeader)
			return fsTeamEveryReaderForkedAt(net, pin.GetVersion())
		}),
	)
}

// FS-14's replay rules at a long-running reader and at devices started at bases near the tip alike: a statement whose
// at precedes the retention point of the state it lands on, though within 4,096 positions, an expired one, and one
// repeated, which api answers with the entry it already holds.
func Fs14ReplayRules(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 replay rules", world,
		fs14Start(world, false),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			early := net.Header()
			net.Fold(true)
			net.AdmitMember(net.Owner(), "between", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			net.Fold(true)
			if early.GetAt().GetVersion() >= net.State().RetentionPoint() {
				return fmt.Errorf("the early header's at %d is not before the retention point %d", early.GetAt().GetVersion(), net.State().RetentionPoint())
			}
			net.MustRefuse(net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
				Header: early, MemberId: net.Id("at before the retention point").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
			}), sidecar.ErrConfigReplay)
			expired := net.Header()
			expired.NotAfterMs = net.Clock().Now().Add(-time.Second).UnixMilli()
			net.MustRefuse(net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
				Header: expired, MemberId: net.Id("expired").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
			}), sidecar.ErrConfigReplay)
			repeated := net.Sign(net.Owner(), bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id("repeated"), bridge.MemberRole_MEMBER_ROLE_MEMBER))
			first := net.MustLand(repeated)
			again, err := net.Post(repeated)
			if err != nil || again.GetVersion() != first.Pin.GetVersion() {
				return fmt.Errorf("a repeated statement: %v at %d, the first at %d", err, again.GetVersion(), first.Pin.GetVersion())
			}
			net.MustRefuseEverywhere(repeated, sidecar.ErrConfigReplay)
			return nil
		}),
	)
}

// DESIGN-DETAILS 5.6's vetoed replay after a fold: an honest api answers a recovery proposal's verbatim replay with the
// entry that holds it, appending nothing (§7.9's retry identity); a malicious api lands it after the fold, and every
// reader refuses it as a replay, the ring taken from rows at the new device and the gate the fold started. Forged, so
// T2 alone.
func Fs14VetoedReplayAfterAFold(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-14 a vetoed replay after a fold", world,
		fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
			owner := net.Owner()
			key := net.RecoveryKey(owner.MemberId, "owner")
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(key)))
			proposal := net.SignByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL,
				net.Proposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device("owner phone", owner.MemberId), nil, false, 0, 0)))
			world.positions["proposal"] = net.MustLand(proposal).Pin.GetVersion()
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_VETO, net.RecoveryVeto(sidecartest.AdmissionStatementId(proposal))))
			world.signed["proposal"] = proposal
			return nil
		}),
		fsTeamDo("writer", world, func(net *sidecartest.AdmissionNet) error {
			net.Fold(true)
			return nil
		}),
		fsTeamDo("attacker", world, func(net *sidecartest.AdmissionNet) error {
			pin, err := net.Post(world.signed["proposal"])
			if err != nil || pin.GetVersion() != world.positions["proposal"] {
				return fmt.Errorf("api's answer to the replay: %v at %d, the proposal at %d", err, pin.GetVersion(), world.positions["proposal"])
			}
			net.MustRefuseEverywhere(world.signed["proposal"], sidecar.ErrConfigReplay)
			if !net.ForgedAppends() {
				return nil
			}
			net.AllowForks()
			landed := net.SequenceAnyway(bridge.AuthEntryKindStatement, world.signed["proposal"])
			verdict := net.VerdictAt(landed.GetVersion())
			if verdict.Accepted() || !errors.Is(verdict.Refusal, sidecar.ErrConfigReplay) || 0 < len(net.Forks()) {
				return fmt.Errorf("the replay a malicious api landed: %v, forks %v", verdict.Refusal, net.Forks())
			}
			return nil
		}),
	)
}

// FS-16's start: the owner's key bound, its proposal of the owner's phone filed and carried across a fold, then a veto
// by the owner's laptop at 71 h, in the next base's tail.
func fs16Start(world *fsTeamWorld, forged bool) []*Step {
	return []*Step{
		fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
			if forged {
				net.AllowForks()
			}
			owner := net.Owner()
			key := net.RecoveryKey(owner.MemberId, "owner")
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(key)))
			phone := net.Device("owner phone", owner.MemberId)
			world.devices["phone"] = phone
			world.ids["proposal"] = net.ProposeByRecovery(key, phone)
			net.Fold(true)
			return nil
		}),
		&Step{Actor: "clock", Advance: 71 * time.Hour},
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			vetoed := net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_RECOVERY_VETO, net.RecoveryVeto(world.ids["proposal"])))
			if window := net.Window(world.ids["proposal"]); window.Closed != sidecar.ConfigProposalVetoed || window.ClosedAt != vetoed.Pin.GetVersion() {
				return fmt.Errorf("the window after the veto: %+v", window)
			}
			net.Fold(true)
			return nil
		}),
		&Step{Actor: "clock", Advance: 2 * time.Hour},
	}
}

// FS-16, forged: a malicious api lands the activation of the vetoed proposal 73 h on, and every reader refuses it.
func Fs16ForgedActivation(net *Net) *Schedule {
	world := newFsTeamWorld()
	steps := append(fs16Start(world, true), fsTeamDo("api", world, func(net *sidecartest.AdmissionNet) error {
		tick := &bridge.ApiTick{ActivatedProposalIds: [][]byte{world.ids["proposal"]}}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(tick)
		if err != nil {
			return err
		}
		pin := net.SequenceAnyway(bridge.AuthEntryKindTick, body)
		if net.VerdictAt(pin.GetVersion()).Accepted() || net.Admitted(world.devices["phone"]) || 0 < len(net.Forks()) {
			return fmt.Errorf("the forged activation at %d took effect somewhere: forks %v", pin.GetVersion(), net.Forks())
		}
		return nil
	}))
	schedule := fsTeamSchedule("FS-16 a forged activation", world, steps...)
	schedule.Refuses = "a malicious api's activation of a recovery proposal vetoed at 71 h"
	return schedule
}

// FS-16's twin: the veto at 71 h wins at every reader, a new device and a gate at each base included, and an honest
// activation after it is refused, by api or by every reader.
func Fs16VetoWins(net *Net) *Schedule {
	world := newFsTeamWorld()
	steps := append(fs16Start(world, false), fsTeamDo("api", world, func(net *sidecartest.AdmissionNet) error {
		if net.Activate(world.ids["proposal"]) || net.Admitted(world.devices["phone"]) {
			return errors.New("a vetoed proposal activated")
		}
		return nil
	}))
	return fsTeamSchedule("FS-16 the veto wins", world, steps...)
}

// FS-16 and DESIGN-DETAILS 5.6: a recovery proposal's window carried across two folds activates at a tick 72 h after
// its entry at every reader, a tick at 71 h refused. Needs an api that takes activations, so T2 alone until
// server's tick check takes them.
func Fs16ActivationAcrossFolds(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-16 an activation across folds", world,
		fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
			owner := net.Owner()
			key := net.RecoveryKey(owner.MemberId, "owner")
			net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(key)))
			tablet := net.Device("owner tablet", owner.MemberId)
			world.devices["tablet"] = tablet
			world.ids["proposal"] = net.ProposeByRecovery(key, tablet)
			net.Fold(true)
			return nil
		}),
		&Step{Actor: "clock", Advance: 71 * time.Hour},
		fsTeamDo("api", world, func(net *sidecartest.AdmissionNet) error {
			if net.Activate(world.ids["proposal"]) {
				return errors.New("an activation at 71 h")
			}
			net.Fold(true)
			return nil
		}),
		&Step{Actor: "clock", Advance: time.Hour},
		fsTeamDo("api", world, func(net *sidecartest.AdmissionNet) error {
			if !net.ApiTakesActivations() {
				return errors.New("this tier's api takes no activation tick")
			}
			if !net.Activate(world.ids["proposal"]) || !net.Admitted(world.devices["tablet"]) {
				return errors.New("the window carried across folds did not activate at 72 h")
			}
			return nil
		}),
	)
}

// FS-102's start: tags owned by the owner, Delegation D with max_admits 10, its agents A and C, the position after C's
// admission noted as since_n, and agent E admitted after it.
func fs102Start(world *fsTeamWorld, forged bool) *Step {
	return fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
		if forged {
			net.AllowForks()
		}
		owner := net.Owner()
		ci := net.Id("tag ci")
		net.SetTagOwners(map[sidecar.Id]sidecar.Id{ci: owner.MemberId})
		notAfter := net.Clock().Now().Add(30 * 24 * time.Hour).UnixMilli()
		delegation := net.Delegate(owner, "d", []sidecar.Id{ci}, 10, notAfter)
		world.delegations["d"] = delegation
		for _, label := range []string{"agent a", "agent c"} {
			agent := net.Device(label, sidecar.Id{})
			world.devices[label] = agent
			net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(agent, delegation.TagIds, false, notAfter, 0)))
		}
		world.positions["since"] = net.Tip().GetVersion() + 1
		agentE := net.Device("agent e", sidecar.Id{})
		world.devices["agent e"] = agentE
		net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(agentE, delegation.TagIds, false, notAfter, 0)))
		return nil
	})
}

// FS-102 (1) and (5): A revoked for compromise from since_n, its bytes posted twice for one entry; D ends there.
func fs102Compromise(world *fsTeamWorld) *Step {
	return fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
		revocation := net.Sign(net.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
			net.Revocation(world.devices["agent a"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, world.positions["since"]))
		landed := net.MustLand(revocation)
		again, err := net.Post(revocation)
		if err != nil || again.GetVersion() != landed.Pin.GetVersion() {
			return fmt.Errorf("the revocation posted again: %v at %d, landed at %d", err, again.GetVersion(), landed.Pin.GetVersion())
		}
		state := net.State()
		if at, ended := state.DelegationEnded(world.delegations["d"].Id); !ended || at != landed.Pin.GetVersion() {
			return fmt.Errorf("D ended at %d (%t), the revocation at %d", at, ended, landed.Pin.GetVersion())
		}
		if !state.Parked(world.devices["agent e"].SidecarId) || state.Parked(world.devices["agent c"].SidecarId) || !net.Admitted(world.devices["agent c"]) {
			return errors.New("E is not parked, or C does not stand")
		}
		world.positions["ended"] = landed.Pin.GetVersion()
		net.Fold(true)
		return nil
	})
}

// The thief's SidecarAdmit of B by the copied signing seed.
func fs102TheftOfB(world *fsTeamWorld, net *sidecartest.AdmissionNet) []byte {
	agentB := net.Device("agent b", sidecar.Id{})
	world.devices["agent b"] = agentB
	delegation := world.delegations["d"]
	return net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(agentB, delegation.TagIds, false, delegation.NotAfter, 0))
}

// FS-102 (1): after D's end, the thief's admission of B by the copied seed is refused by api and every reader, new
// devices included; D's copied key lifts no park, while an admin's AdmissionConfirm lifts E's.
func Fs102CopiedBundle(net *Net) *Schedule {
	world := newFsTeamWorld()
	schedule := fsTeamSchedule("FS-102 a copied bundle", world,
		fs102Start(world, false),
		fs102Compromise(world),
		fsTeamDo("thief", world, func(net *sidecartest.AdmissionNet) error {
			net.MustRefuse(fs102TheftOfB(world, net), sidecar.ErrConfigAuthority)
			net.MustRefuse(net.SignByDelegation(world.delegations["d"], bridge.SignedType_SIGNED_ADMISSION_CONFIRM, net.AdmissionConfirm(world.devices["agent e"])), sidecar.ErrConfigRefused)
			return nil
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_ADMISSION_CONFIRM, net.AdmissionConfirm(world.devices["agent e"])))
			if net.State().Parked(world.devices["agent e"].SidecarId) || net.Admitted(world.devices["agent b"]) {
				return errors.New("E stays parked after an admin's confirmation, or B stands")
			}
			return nil
		}),
	)
	schedule.Refuses = "the thief's admission of B by D's copied signing seed after D's end"
	return schedule
}

// FS-102's twin: B admitted by D's key before A's revocation lands, then the same revocation.
func Fs102AdmittedBeforeTheEnd(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-102 admitted before the end", world,
		fs102Start(world, false),
		fsTeamDo("holder", world, func(net *sidecartest.AdmissionNet) error {
			net.MustLand(fs102TheftOfB(world, net))
			return nil
		}),
		fs102Compromise(world),
	)
}

// FS-102, forged: the thief's admission of B appended past api's own check is refused by every reader at its
// position, a new device and a gate at each base included, and B stands nowhere.
func Fs102ForgedAdmission(net *Net) *Schedule {
	world := newFsTeamWorld()
	schedule := fsTeamSchedule("FS-102 a forged admission", world,
		fs102Start(world, true),
		fs102Compromise(world),
		fsTeamDo("api", world, func(net *sidecartest.AdmissionNet) error {
			pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, fs102TheftOfB(world, net))
			if net.VerdictAt(pin.GetVersion()).Accepted() || net.Admitted(world.devices["agent b"]) || 0 < len(net.Forks()) {
				return fmt.Errorf("the forged admission at %d took effect somewhere: forks %v", pin.GetVersion(), net.Forks())
			}
			net.Fold(true)
			return nil
		}),
	)
	schedule.Refuses = "the thief's admission of B appended past api's own check"
	return schedule
}

// FS-102 (2): A revoked as removed leaves D admitting, so B's admission lands; a DelegationRevoke with a since_n before
// B's admission parks B, ends D and refuses every admission after it, and D's copied key lifts nothing.
func Fs102RemovedAgent(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-102 a removed agent", world,
		fs102Start(world, false),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				net.Revocation(world.devices["agent a"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
			if _, ended := net.State().DelegationEnded(world.delegations["d"].Id); ended {
				return errors.New("a removal ended D")
			}
			world.positions["before b"] = net.Tip().GetVersion() + 1
			net.MustLand(fs102TheftOfB(world, net))
			return nil
		}),
		fsTeamDo("owner", world, func(net *sidecartest.AdmissionNet) error {
			net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.DelegationRevoke(world.delegations["d"].Id, world.positions["before b"])))
			if !net.State().Parked(world.devices["agent b"].SidecarId) {
				return errors.New("B is not parked")
			}
			net.Fold(true)
			delegation := world.delegations["d"]
			net.MustRefuse(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(net.Device("late", sidecar.Id{}), delegation.TagIds, false, delegation.NotAfter, 0)), sidecar.ErrConfigAuthority)
			net.MustRefuse(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, net.AdmissionConfirm(world.devices["agent b"])), sidecar.ErrConfigRefused)
			return nil
		}),
	)
}

// FS-102 (4): ten admissions, a fold and every earlier agent's not_after past, an eleventh SidecarAdmit by D's key is
// still refused at every reader, new devices included.
func Fs102MaxAdmits(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-102 max_admits across a fold", world,
		fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
			owner := net.Owner()
			ci := net.Id("tag ci")
			net.SetTagOwners(map[sidecar.Id]sidecar.Id{ci: owner.MemberId})
			delegation := net.Delegate(owner, "d", []sidecar.Id{ci}, 10, net.Clock().Now().Add(30*24*time.Hour).UnixMilli())
			world.delegations["d"] = delegation
			for i := range 10 {
				agent := net.Device(fmt.Sprintf("agent %d", i), sidecar.Id{})
				net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
					net.Admission(agent, delegation.TagIds, true, net.Clock().Now().Add(time.Hour).UnixMilli(), 0)))
			}
			net.Fold(true)
			return nil
		}),
		&Step{Actor: "clock", Advance: 48 * time.Hour},
		fsTeamDo("holder", world, func(net *sidecartest.AdmissionNet) error {
			delegation := world.delegations["d"]
			net.MustRefuse(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				net.Admission(net.Device("eleventh", sidecar.Id{}), delegation.TagIds, true, net.Clock().Now().Add(time.Hour).UnixMilli(), 0)), sidecar.ErrConfigAuthority)
			return nil
		}),
	)
}

// FS-124's start: member m's laptop D, its first device, registers a presence key, and m's tablet another; m has a
// phone too.
func fs124Start(world *fsTeamWorld, forged bool) *Step {
	return fsTeamSetup(world, func(net *sidecartest.AdmissionNet) error {
		if forged {
			net.AllowForks()
		}
		memberId, laptop := net.ConsentedMember("m")
		tablet, phone := net.Device("m tablet", memberId), net.Device("m phone", memberId)
		net.AdmitDevice(laptop, tablet, 0)
		net.AdmitDevice(laptop, phone, 0)
		world.devices["laptop"], world.devices["tablet"], world.devices["phone"] = laptop, tablet, phone
		laptopKey := sidecartest.NewFixturePresenceKey("fs-124 laptop", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		tabletKey := sidecartest.NewFixturePresenceKey("fs-124 tablet", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
		net.RegisterPresenceKey(laptop, laptopKey, nil)
		net.RegisterPresenceKey(tablet, tabletKey, nil)
		world.presenceKeys["laptop"], world.presenceKeys["tablet"] = laptopKey, tabletKey
		return nil
	})
}

// The laptop's covered revocation of the phone, identity-signed and not yet countersigned.
func fs124Revocation(world *fsTeamWorld, net *sidecartest.AdmissionNet) *bridge.Signed {
	return net.SignedBy(world.devices["laptop"], bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		net.Revocation(world.devices["phone"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0))
}

// FS-124: the laptop's covered revocation of the phone is refused by api and every member device with no
// countersignature, one by a key never registered and one by the key the tablet registered, and lands with its own.
func Fs124Uncountersigned(net *Net) *Schedule {
	world := newFsTeamWorld()
	schedule := fsTeamSchedule("FS-124 an uncountersigned revocation", world,
		fs124Start(world, false),
		fsTeamDo("laptop", world, func(net *sidecartest.AdmissionNet) error {
			net.MustRefuse(net.Marshal(fs124Revocation(world, net)), sidecar.ErrConfigPresence)
			unregistered := fs124Revocation(world, net)
			net.Countersign(sidecartest.NewFixturePresenceKey("fs-124 never registered", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256), world.devices["laptop"], unregistered)
			net.MustRefuse(net.Marshal(unregistered), sidecar.ErrConfigPresence)
			anotherDevices := fs124Revocation(world, net)
			net.Countersign(world.presenceKeys["tablet"], world.devices["laptop"], anotherDevices)
			net.MustRefuse(net.Marshal(anotherDevices), sidecar.ErrConfigPresence)
			own := fs124Revocation(world, net)
			net.Countersign(world.presenceKeys["laptop"], world.devices["laptop"], own)
			net.MustLand(net.Marshal(own))
			if net.Admitted(world.devices["phone"]) {
				return errors.New("the phone stands after the countersigned revocation")
			}
			return nil
		}),
	)
	schedule.Refuses = "a covered revocation without its signer's presence countersignature"
	return schedule
}

// FS-124's twin: the countersigned revocation alone lands.
func Fs124Countersigned(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-124 a countersigned revocation", world,
		fs124Start(world, false),
		fsTeamDo("laptop", world, func(net *sidecartest.AdmissionNet) error {
			own := fs124Revocation(world, net)
			net.Countersign(world.presenceKeys["laptop"], world.devices["laptop"], own)
			net.MustLand(net.Marshal(own))
			return nil
		}),
	)
}

// FS-124, forged: the thief on D, holding its identity key and not its presence key, has a malicious api sequence a
// compromise revocation of the phone, a KeyRevoke of D's key and a SidecarAdmit of a fresh device, none countersigned:
// each is refused at its position by every reader, and the next base carries 0 for each in its tail (DESIGN-DETAILS
// 5.6's FS-124 row).
func Fs124ForgedUncountersigned(net *Net) *Schedule {
	world := newFsTeamWorld()
	schedule := fsTeamSchedule("FS-124 the thief's statements", world,
		fs124Start(world, true),
		fsTeamDo("thief", world, func(net *sidecartest.AdmissionNet) error {
			laptop := world.devices["laptop"]
			statements := [][]byte{
				net.Sign(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(world.devices["phone"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, 1)),
				net.Sign(laptop, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{Header: net.Header(), KeyId: world.presenceKeys["laptop"].KeyId}),
				net.Sign(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device("thief's device", laptop.MemberId), nil, false, 0, 0)),
			}
			positions := []uint64{}
			for _, statement := range statements {
				net.MustRefuse(statement, sidecar.ErrConfigPresence)
				pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, statement)
				positions = append(positions, pin.GetVersion())
				if net.VerdictAt(pin.GetVersion()).Accepted() || 0 < len(net.Forks()) {
					return fmt.Errorf("the thief's statement at %d took effect somewhere: forks %v", pin.GetVersion(), net.Forks())
				}
			}
			if !net.Admitted(world.devices["phone"]) || net.State().RegisteredKey(world.presenceKeys["laptop"].KeyId).GetRevokedAt() != 0 {
				return errors.New("the thief revoked the phone or D's key")
			}
			// the next base keeps the fold, so its tail holds the thief's entries, each carried as 0
			signedHeader, rows := net.BaseKeepingTheFold(net.WriterDevice(), nil)
			if _, err := net.AppendBase(signedHeader, rows); err != nil {
				return fmt.Errorf("the next base: %w", err)
			}
			header := net.State().Base()
			for _, n := range positions {
				j := n - header.GetFoldedThrough() - 1
				if bits := (header.GetTailVerdicts()[j/4] >> (2 * (j % 4))) & 3; bits != 0 {
					return fmt.Errorf("the next base carries %d for the thief's statement at %d", bits, n)
				}
			}
			return nil
		}),
	)
	schedule.Refuses = "the thief's uncountersigned covered statements a malicious api sequenced"
	return schedule
}

// FS-124: one check covers a five-statement act whose statements land in any order or alone, each by its own path.
func Fs124FiveStatementAct(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-124 a five-statement act", world,
		fs124Start(world, false),
		fsTeamDo("laptop", world, func(net *sidecartest.AdmissionNet) error {
			laptop := world.devices["laptop"]
			devices := []*sidecartest.AdmissionDevice{}
			signed := []*bridge.Signed{}
			for i := range 5 {
				device := net.Device(fmt.Sprintf("m act device %d", i), laptop.MemberId)
				devices = append(devices, device)
				signed = append(signed, net.SignedBy(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(device, nil, false, 0, 0)))
			}
			net.Countersign(world.presenceKeys["laptop"], laptop, signed...)
			for _, i := range []int{3, 0, 4, 1, 2} {
				net.MustLand(net.Marshal(signed[i]))
			}
			for _, device := range devices {
				if !net.Admitted(device) {
					return fmt.Errorf("%s is not admitted", device.Name)
				}
			}
			return nil
		}),
	)
}

// FS-124: a device that registered no presence key signs covered statements on its confirmation alone, and D's own
// sign-out needs no countersignature.
func Fs124NoKeyAndSignOut(net *Net) *Schedule {
	world := newFsTeamWorld()
	return fsTeamSchedule("FS-124 no key and a sign-out", world,
		fs124Start(world, false),
		fsTeamDo("phone", world, func(net *sidecartest.AdmissionNet) error {
			phone := world.devices["phone"]
			net.MustLand(net.Sign(phone, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device("m by the phone", phone.MemberId), nil, false, 0, 0)))
			laptop := world.devices["laptop"]
			net.MustLand(net.Sign(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
			if net.Admitted(laptop) {
				return errors.New("the laptop's sign-out left it standing")
			}
			return nil
		}),
	)
}
