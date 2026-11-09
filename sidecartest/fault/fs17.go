// FS-17 (§22.8; §6, §11; D-PROTO-14, D-PROTO-17, D-TRUST-10; PROTO-M2-05): HeadCheck's forks, relays
// and stops on T2, between sidecars' real connect clients on the Net (sidecartest/headcheck_net.go), each
// clause one schedule on a fake clock, every one checked by FI-10's oracle (fi10.go) after each step:
//
//   - Fs17 (the row's registered case): one ref forked under an unchanged epoch, both peers replaying
//     their own chains, then meeting: a fork alarm both sides and sealing stopped in the ref's group;
//     its twin the same refs unforked, where both witness;
//   - Fs17ManyRefs: 40 shared refs, the 37th forked, shown within ceil(40/16) = 3 exchanges;
//   - Fs17GenFork: a generation fork two agents see, GenHead reporting FORK;
//   - Fs17WithheldProof: writer W learns a higher pin while api withholds the entries; past
//     HeadCheckFetchTimeout W's proof request to the holder verifies, and W stops sealing at once;
//   - Fs17ProofDropped: that proof dropped too: the pin is UNVERIFIED, W alarms, refreshes no
//     witnessed_at, its peer counts it for nothing, and W stops at witness_bound_hours;
//   - Fs17RelayedProof: holder R, CLI peer X and writer W at X's pin, the server dropping W-R: X sends
//     R's withheld tip as proven, never counts as W's witness, and W stops at its next HeadCheck with X;
//     Fs17RelayedProofDropped the same with X's proof dropped too, so W stops at witness_bound_hours;
//     Fs17ChainOfRelays the same as R-X-Y-W, Y verifying X's relayed proof and W stopping at its next
//     HeadCheck with Y; Fs17PhoneHolder the same with R a phone serving from its newest 64 KiB;
//   - Fs17PhoneNotFound: a phone R whose kept entries do not reach back to X's n answers NOT_FOUND, X
//     holds the tip UNVERIFIED with R as claimant and counts for no one, W relaying it counts no one, and
//     the relayed copy clears once a sidecar on its path is revoked;
//   - Fs17StandingPeers: a revoked, parked or suspended peer at W's pin never counts;
//   - Fs17CatchUp: a peer that cannot catch up refreshes no witnessed_at, one that catches up does, and,
//     the case the ledger marks missing, two peers that advance independently with no conflict witness
//     once the lower catches up.
//
// The row is forged, the server withholding and forking, so it runs on T2 alone and its twin carries T3.
// Each exchange is one a step starts; the rounds pick no one (HeadCheckNet's Candidates are empty), so
// nothing runs that a schedule did not ask for, but the run loops' own timers.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs17 = Register("FS-17", "", []Tier{TierT2}, Fs17RefFork)

// The world one FS-17 schedule builds in its first step and its later steps read.
type fs17World struct {
	headCheck *sidecartest.HeadCheckNet
}

// One sidecar of the world by name.
func (self *fs17World) side(name string) *sidecartest.HeadCheckSidecar {
	return self.headCheck.Sidecar(name)
}

// §6.4's timings as each sidecar runs them.
var fs17Settings = sidecar.DefaultSidecarProtocolSettings()

// A group, a repo and a ref every FS-17 world shares.
var (
	fs17GroupId = sidecar.Id{0x47, 0x17}
	fs17RepoId  = sidecar.Id{0x52, 0x17}
	fs17RefId   = sidecar.Id{0x46, 0x17}
)

// 32 bytes naming one digest of the tests, visibly synthetic.
func fs17Digest(label string) []byte {
	digest := make([]byte, 32)
	copy(digest, label)
	return digest
}

// The first step: sidecars of each name with HeadCheck, api's log at tip, each sidecar holding it
// through reach[name], or tip when reach names it not; every one a leaf of the shared group at one epoch.
func fs17Setup(world *fs17World, names []string, tip uint64, reach map[string]uint64) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		headCheck, err := net.AddHeadCheckSidecars(names...)
		if err != nil {
			return err
		}
		world.headCheck = headCheck
		headCheck.Api.Append(int(tip))
		for _, name := range names {
			side := headCheck.Sidecar(name)
			version, ok := reach[name]
			if !ok {
				version = tip
			}
			if err := side.Device.Auth.ReachFromApi(version); err != nil {
				return err
			}
		}
		return nil
	}}
}

// Pins the shared group at one epoch on each named sidecar, as leaves of it at that epoch.
func fs17SharedEpoch(world *fs17World, names ...string) {
	for _, name := range names {
		world.side(name).Device.Heads.SetGroup(&protocol.GroupHead{GroupId: fs17GroupId.Bytes(), Epoch: 3, EpochAuthenticator: fs17Digest("epoch 3")})
	}
}

// A step: from runs one exchange with to, which counts as from's witness exactly when witnessed says.
func fs17Exchange(world *fs17World, from string, to string, witnessed bool) *Step {
	return &Step{Actor: from, Action: func(ctx context.Context, net *Net) error {
		counted, err := world.side(from).HeadCheckWith(ctx, world.side(to))
		if err != nil {
			return fmt.Errorf("%s's exchange with %s: %w", from, to, err)
		}
		if counted != witnessed {
			return fmt.Errorf("%s's exchange with %s counted %t, want %t", from, to, counted, witnessed)
		}
		return nil
	}}
}

// A step: from runs one exchange with to, which counts as no witness, whether to's answer is refused, as
// one from a peer without standing in from's state is, or reconciled and found wanting; from's
// witnessed_at does not move.
func fs17NoWitness(world *fs17World, from string, to string) *Step {
	return &Step{Actor: from, Action: func(ctx context.Context, net *Net) error {
		before := world.side(from).Stop.WitnessedAt()
		counted, _ := world.side(from).HeadCheckWith(ctx, world.side(to))
		if counted || !world.side(from).Stop.WitnessedAt().Equal(before) {
			return fmt.Errorf("%s counted %s as a witness", from, to)
		}
		return nil
	}}
}

// A step: name has raised an alarm of kind, waiting for one an exchange's background acts raise.
func fs17Alarmed(world *fs17World, name string, kind sidecar.SidecarHeadAlarm) *Step {
	return &Step{Actor: name, Action: func(ctx context.Context, net *Net) error {
		return world.side(name).AwaitAlarm(ctx, kind)
	}}
}

// A step: name has raised no alarm of kind.
func fs17NotAlarmed(world *fs17World, name string, kind sidecar.SidecarHeadAlarm) *Step {
	return &Step{Actor: name, Action: func(ctx context.Context, net *Net) error {
		if alarms := world.side(name).Alarms(kind); 0 < len(alarms) {
			return fmt.Errorf("%s raised %d %s alarms", name, len(alarms), kind)
		}
		return nil
	}}
}

// A step: sealing in the shared group stops for cause at name, or, with cause empty, goes on.
func fs17Seal(world *fs17World, name string, cause sidecar.HeadStopCause) *Step {
	return &Step{Actor: name, Action: func(ctx context.Context, net *Net) error {
		err := world.side(name).Stop.SealAllowed(fs17GroupId)
		var stopErr *sidecar.HeadStopError
		switch {
		case cause == "" && err != nil:
			return fmt.Errorf("%s stopped sealing: %w", name, err)
		case cause != "" && (!errors.As(err, &stopErr) || stopErr.Cause != cause):
			return fmt.Errorf("%s's seal: %v, want a %s stop", name, err, cause)
		}
		return nil
	}}
}

// Waits until the Net's clock holds a timer for at, which a goroutine of HeadCheck's arms when it reaches
// its wait, so a step that moves the clock past at never moves it before the wait is set.
func fs17AwaitTimer(ctx context.Context, net *Net, at time.Time) error {
	for {
		pending, added := net.Clock().WatchTimers()
		if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) }) {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return fmt.Errorf("no timer for %s among %v: %w", at, pending, ctx.Err())
		}
	}
}

// A step: the clock moves past HeadCheckFetchTimeout from now, its halfway try and its deadline each
// fired once the transport has armed it: the fetch an exchange of the step before left unserved is due.
func fs17FetchTimesOut(actor string) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		start := net.Clock().Now()
		half := fs17Settings.HeadCheckFetchTimeout / 2
		if err := fs17AwaitTimer(ctx, net, start.Add(half)); err != nil {
			return err
		}
		net.Clock().Advance(half)
		if err := fs17AwaitTimer(ctx, net, start.Add(fs17Settings.HeadCheckFetchTimeout)); err != nil {
			return err
		}
		net.Clock().Advance(fs17Settings.HeadCheckFetchTimeout - half)
		return nil
	}}
}

// A step: a call's wait for its answer, armed at the clock's now, ends unanswered: the clock moves past
// HeadCheckTimeout once that wait is set.
func fs17CallTimesOut(actor string) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		at := net.Clock().Now().Add(fs17Settings.HeadCheckTimeout)
		if err := fs17AwaitTimer(ctx, net, at); err != nil {
			return err
		}
		net.Clock().Advance(fs17Settings.HeadCheckTimeout)
		return nil
	}}
}

// The row's twin: the honest network, every pin shared, where both sides witness.
func Fs17Honest(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:    "FS-17",
		Check: []Invariant{FI(10)},
		Tiers: []Tier{TierT2},
		Steps: []*Step{
			fs17Setup(world, []string{"a", "b"}, 5, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				fs17SharedEpoch(world, "a", "b")
				for _, name := range []string{"a", "b"} {
					ref := &protocol.RefHead{RepoId: fs17RepoId.Bytes(), RefId: fs17RefId.Bytes(), Version: 7, Chain: fs17Digest("ref 7")}
					world.side(name).Device.Heads.SetRef(ref, fs17GroupId)
					world.side(name).Device.Heads.StoreRef(ref)
				}
				return nil
			}},
			fs17Exchange(world, "a", "b", true),
			fs17Exchange(world, "b", "a", true),
			fs17NotAlarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17NotAlarmed(world, "b", sidecar.SidecarHeadAlarmFork),
			fs17Seal(world, "a", ""),
		},
	}
}

// One ref forked under an unchanged epoch: a and b each replay their own chain to version 7 at the
// group's same epoch, then meet. Each alarms fork, and sealing stops in the ref's group (§6.4's refs and
// FORK rows).
func Fs17RefFork(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"a", "b"}, 5, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				// the group's epoch unchanged on both
				fs17SharedEpoch(world, "a", "b")
				for _, name := range []string{"a", "b"} {
					// each replays its own history of the ref: the same version, two chains
					ref := &protocol.RefHead{RepoId: fs17RepoId.Bytes(), RefId: fs17RefId.Bytes(), Version: 7, Chain: fs17Digest("ref 7 by " + name)}
					world.side(name).Device.Heads.SetRef(ref, fs17GroupId)
					world.side(name).Device.Heads.StoreRef(ref)
				}
				return nil
			}},
			fs17Exchange(world, "a", "b", false),
			fs17Alarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17Alarmed(world, "b", sidecar.SidecarHeadAlarmFork),
			fs17Seal(world, "a", sidecar.HeadStopFork),
			fs17Seal(world, "b", sidecar.HeadStopFork),
		},
	}
}

// More refs than one message carries: 40 shared, the 37th forked at its version, so a's third exchange
// with b carries it each way and shows the fork, and the first two show nothing (ceil(40/16) = 3).
func Fs17ManyRefs(net *Net) *Schedule {
	world := &fs17World{}
	refCount := 40
	forkedIndex := 36
	return &Schedule{
		Id:     "FS-17 many refs",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"a", "b"}, 5, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				for i := range refCount {
					refId := sidecar.Id{0x46, byte(i)}
					for _, name := range []string{"a", "b"} {
						label := fmt.Sprintf("ref %d", i)
						if i == forkedIndex {
							label += " by " + name
						}
						ref := &protocol.RefHead{RepoId: fs17RepoId.Bytes(), RefId: refId.Bytes(), Version: 4, Chain: fs17Digest(label)}
						world.side(name).Device.Heads.SetRef(ref, fs17GroupId)
						world.side(name).Device.Heads.StoreRef(ref)
					}
				}
				return nil
			}},
			fs17Exchange(world, "a", "b", true),
			fs17NotAlarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17Exchange(world, "a", "b", true),
			fs17NotAlarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17Exchange(world, "a", "b", false),
			fs17Alarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17Alarmed(world, "b", sidecar.SidecarHeadAlarmFork),
		},
	}
}

// A generation fork two agents see: agents are leaves of no MLS group, so they compare generations
// (§6.4's witnesses), and two gen/ commitments at one generation are a FORK the GenHead row reports.
func Fs17GenFork(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 gen fork",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"agent1", "agent2"}, 5, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				for _, name := range []string{"agent1", "agent2"} {
					// agents are leaves of no group, so they hold no epoch pin
					side := world.side(name)
					gen := &protocol.GenHead{GroupId: fs17GroupId.Bytes(), Generation: 3, Commitment: fs17Digest("generation 3 by " + name)}
					side.Device.Heads.SetGen(gen)
					side.Device.Heads.StoreGen(gen)
				}
				return nil
			}},
			fs17Exchange(world, "agent1", "agent2", false),
			fs17Alarmed(world, "agent1", sidecar.SidecarHeadAlarmFork),
			fs17Alarmed(world, "agent2", sidecar.SidecarHeadAlarmFork),
			fs17Seal(world, "agent1", sidecar.HeadStopFork),
		},
	}
}

// Writer w at 10 learns holder r's 15 while api withholds past 10 from w: its fetch goes unserved to
// HeadCheckFetchTimeout, its proof request to r verifies, and w alarms withheld and stops sealing at
// once; r never counts as w's witness meanwhile.
func Fs17WithheldProof(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 withheld proof",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "w"}, 10, nil),
			fs17Exchange(world, "w", "r", true),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				world.headCheck.Api.Withhold(world.side("w").SidecarId, 10)
				world.headCheck.Api.Append(5)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "w", "r", false),
			fs17Seal(world, "w", ""),
			fs17FetchTimesOut("w"),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmWithheld),
			fs17Seal(world, "w", sidecar.HeadStopWithheld),
			fs17Exchange(world, "w", "r", false),
		},
	}
}

// The same with r's proof dropped too: past HeadCheckFetchTimeout the request goes unanswered, so the
// pin is UNVERIFIED with r its claimant; w alarms, refreshes no witnessed_at with y at its own pin, y
// counts w for nothing while w sends it, and w stops at witness_bound_hours from its last witness.
func Fs17ProofDropped(net *Net) *Schedule {
	world := &fs17World{}
	bound := time.Duration(sidecar.WitnessBoundDefaultHours) * time.Hour
	var witnessedAt time.Time
	return &Schedule{
		Id:     "FS-17 proof dropped",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "w", "y"}, 10, nil),
			fs17Exchange(world, "w", "y", true),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				witnessedAt = world.side("w").Stop.WitnessedAt()
				world.headCheck.Api.Withhold(world.side("w").SidecarId, 10)
				world.headCheck.Api.Withhold(world.side("y").SidecarId, 10)
				world.headCheck.Api.Append(5)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "w", "r", false),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				// the server drops w-r from here on, the proof request among it
				world.headCheck.Partition(world.side("w"), world.side("r"), true)
				return nil
			}},
			fs17FetchTimesOut("w"),
			fs17CallTimesOut("w"),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmUnverified),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				if len(world.side("w").Stop.Unverified()) != 1 {
					return fmt.Errorf("w holds %d UNVERIFIED pins", len(world.side("w").Stop.Unverified()))
				}
				return nil
			}},
			// y at w's own pin: no witness either way while w holds the pin and sends it
			fs17Exchange(world, "w", "y", false),
			fs17Exchange(world, "y", "w", false),
			fs17Seal(world, "w", ""),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				if !world.side("w").Stop.WitnessedAt().Equal(witnessedAt) {
					return fmt.Errorf("w's witnessed_at moved from %s to %s", witnessedAt, world.side("w").Stop.WitnessedAt())
				}
				net.Clock().AdvanceTo(witnessedAt.Add(bound))
				return nil
			}},
			fs17Seal(world, "w", sidecar.HeadStopUnwitnessed),
		},
	}
}

// Holder r, CLI peer x and writer w at x's pin, api withholding r's newer entries from x and w and the
// server dropping w-r: x's proof request to r verifies, so x holds the withheld tip and sends it as
// proven; w, at x's pin, counts x as no witness, fetches, and past HeadCheckFetchTimeout verifies the
// proof x serves and stops at once.
func Fs17RelayedProof(net *Net) *Schedule {
	return fs17Relayed("FS-17 relayed proof", 0)
}

// The same with r a phone that serves its proof from its newest 64 KiB of entries (§7.9's retain row,
// owner decision 147), which reach back to x's n: x sends proven and w stops at once.
func Fs17PhoneHolder(net *Net) *Schedule {
	return fs17Relayed("FS-17 phone holder", sidecar.HeadCheckMaxProofByteCount)
}

// The relayed proof's schedule, r keeping retainByteCount for its proofs, 0 for the default.
func fs17Relayed(id string, retainByteCount int) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     id,
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "x", "w"}, 10, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				if 0 < retainByteCount {
					world.side("r").Device.Auth.SetRetainByteCount(retainByteCount)
				}
				for _, name := range []string{"x", "w"} {
					world.headCheck.Api.Withhold(world.side(name).SidecarId, 10)
				}
				world.headCheck.Api.Append(5)
				world.headCheck.Partition(world.side("w"), world.side("r"), true)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "x", "r", false),
			fs17FetchTimesOut("x"),
			fs17Alarmed(world, "x", sidecar.SidecarHeadAlarmWithheld),
			fs17Seal(world, "x", sidecar.HeadStopWithheld),
			// w at x's pin: x sends proven, so it counts as no witness of w's
			fs17Exchange(world, "w", "x", false),
			fs17Seal(world, "w", ""),
			fs17FetchTimesOut("w"),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmWithheld),
			fs17Seal(world, "w", sidecar.HeadStopWithheld),
		},
	}
}

// The relayed proof over two hops, R-X-Y-W: y verifies the proof x relays and sends proven in turn, and
// w, which reaches neither r nor x, stops at its next HeadCheck with y; x and y never count as w's
// witnesses.
func Fs17ChainOfRelays(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 chain of relays",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "x", "y", "w"}, 10, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				for _, name := range []string{"x", "y", "w"} {
					world.headCheck.Api.Withhold(world.side(name).SidecarId, 10)
				}
				world.headCheck.Api.Append(5)
				// the server drops every pair but r-x, x-y and y-w
				world.headCheck.Partition(world.side("w"), world.side("r"), true)
				world.headCheck.Partition(world.side("w"), world.side("x"), true)
				world.headCheck.Partition(world.side("y"), world.side("r"), true)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "x", "r", false),
			fs17FetchTimesOut("x"),
			fs17Alarmed(world, "x", sidecar.SidecarHeadAlarmWithheld),
			fs17Exchange(world, "y", "x", false),
			fs17FetchTimesOut("y"),
			fs17Alarmed(world, "y", sidecar.SidecarHeadAlarmWithheld),
			fs17Exchange(world, "w", "y", false),
			fs17Seal(world, "w", ""),
			fs17FetchTimesOut("w"),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmWithheld),
			fs17Seal(world, "w", sidecar.HeadStopWithheld),
		},
	}
}

// The relayed proof without x's proof: the server drops w-x too once w has learned x's proven tip, so
// w's proof request goes unanswered; w holds the tip UNVERIFIED with x its claimant, alarms, refreshes no
// witnessed_at, and stops at witness_bound_hours from its last witness instead of at once.
func Fs17RelayedProofDropped(net *Net) *Schedule {
	world := &fs17World{}
	bound := time.Duration(sidecar.WitnessBoundDefaultHours) * time.Hour
	var witnessedAt time.Time
	return &Schedule{
		Id:     "FS-17 relayed proof dropped",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "x", "w"}, 10, nil),
			fs17Exchange(world, "w", "x", true),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				witnessedAt = world.side("w").Stop.WitnessedAt()
				for _, name := range []string{"x", "w"} {
					world.headCheck.Api.Withhold(world.side(name).SidecarId, 10)
				}
				world.headCheck.Api.Append(5)
				world.headCheck.Partition(world.side("w"), world.side("r"), true)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "x", "r", false),
			fs17FetchTimesOut("x"),
			fs17Alarmed(world, "x", sidecar.SidecarHeadAlarmWithheld),
			fs17Exchange(world, "w", "x", false),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				world.headCheck.Partition(world.side("w"), world.side("x"), true)
				return nil
			}},
			fs17FetchTimesOut("w"),
			fs17CallTimesOut("w"),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmUnverified),
			fs17NotAlarmed(world, "w", sidecar.SidecarHeadAlarmWithheld),
			fs17Seal(world, "w", ""),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				if !world.side("w").Stop.WitnessedAt().Equal(witnessedAt) {
					return fmt.Errorf("w's witnessed_at moved from %s to %s", witnessedAt, world.side("w").Stop.WitnessedAt())
				}
				net.Clock().AdvanceTo(witnessedAt.Add(bound))
				return nil
			}},
			fs17Seal(world, "w", sidecar.HeadStopUnwitnessed),
		},
	}
}

// A phone r whose kept entries do not reach back to x's n answers NOT_FOUND: x holds the tip UNVERIFIED
// with r as claimant and sends it as unverified, w relaying it holds the copy, both count no one, and the
// copy clears at w's next round once x, a sidecar on its path, is revoked.
func Fs17PhoneNotFound(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 phone not found",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "x", "w"}, 10, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				// a phone keeping too little to reach back five entries
				world.side("r").Device.Auth.SetRetainByteCount(64)
				for _, name := range []string{"x", "w"} {
					world.headCheck.Api.Withhold(world.side(name).SidecarId, 10)
				}
				world.headCheck.Api.Append(5)
				return world.side("r").Device.Auth.ReachFromApi(15)
			}},
			fs17Exchange(world, "x", "r", false),
			fs17FetchTimesOut("x"),
			fs17Alarmed(world, "x", sidecar.SidecarHeadAlarmUnverified),
			fs17Exchange(world, "w", "x", false),
			fs17Alarmed(world, "w", sidecar.SidecarHeadAlarmUnverified),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				held := world.side("w").Stop.Unverified()
				if len(held) != 1 {
					return fmt.Errorf("w relays %d pins", len(held))
				}
				return nil
			}},
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				// x is revoked in w's state: the copy whose path holds x clears at w's next round
				world.side("w").Device.Peers.Set(world.side("x").SidecarId, sidecar.HeadCheckPeer{Admitted: true, Revoked: true})
				net.Clock().Advance(fs17Settings.HeadCheckInterval)
				return nil
			}},
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				// the round that clears it runs on the transport's loop: an exchange runs after it
				return fs17AwaitCleared(ctx, net, world.side("w"))
			}},
		},
	}
}

// Waits until side holds no UNVERIFIED pin: a round's sweep, which the transport's loop runs once the
// clock reached it, clears a copy whose path holds a revoked sidecar.
func fs17AwaitCleared(ctx context.Context, net *Net, side *sidecartest.HeadCheckSidecar) error {
	for len(side.Stop.Unverified()) != 0 {
		// the next round's timer, set once this one ran, is when the sweep has run
		pending, added := net.Clock().WatchTimers()
		if len(side.Stop.Unverified()) == 0 {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return fmt.Errorf("%s still holds %d UNVERIFIED pins, timers %v: %w", side.Name, len(side.Stop.Unverified()), pending, ctx.Err())
		}
	}
	return nil
}

// A revoked, a parked and a suspended peer at w's pin never count as w's witness, though each answers;
// an admitted one does.
func Fs17StandingPeers(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 standing peers",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"w", "revoked", "parked", "suspended", "admitted"}, 10, nil),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				peers := world.side("w").Device.Peers
				peers.Set(world.side("revoked").SidecarId, sidecar.HeadCheckPeer{Admitted: true, Revoked: true})
				peers.Set(world.side("parked").SidecarId, sidecar.HeadCheckPeer{Admitted: true, Parked: true})
				peers.Set(world.side("suspended").SidecarId, sidecar.HeadCheckPeer{Admitted: true, Suspended: true})
				return nil
			}},
			fs17NoWitness(world, "w", "revoked"),
			fs17NoWitness(world, "w", "parked"),
			fs17Exchange(world, "w", "suspended", false),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				if !world.side("w").Stop.WitnessedAt().IsZero() {
					return errors.New("a peer without standing refreshed w's witnessed_at")
				}
				return nil
			}},
			fs17Exchange(world, "w", "admitted", true),
		},
	}
}

// A peer that cannot catch up refreshes nothing; one that catches up does; and two peers that each
// advanced on one history with no conflict witness once the lower catches up (the case the ledger marks
// missing).
func Fs17CatchUp(net *Net) *Schedule {
	world := &fs17World{}
	return &Schedule{
		Id:     "FS-17 catch up",
		Check:  []Invariant{FI(10)},
		Tiers:  []Tier{TierT2},
		Forged: true,
		Twin:   Fs17Honest,
		Steps: []*Step{
			fs17Setup(world, []string{"r", "w", "a", "b"}, 20, map[string]uint64{"w": 10, "a": 12, "b": 14}),
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				world.headCheck.Api.Withhold(world.side("w").SidecarId, 10)
				return nil
			}},
			// w cannot catch up while api withholds: no witness, witnessed_at untouched
			fs17Exchange(world, "w", "r", false),
			{Actor: "w", Action: func(ctx context.Context, net *Net) error {
				if !world.side("w").Stop.WitnessedAt().IsZero() {
					return errors.New("a peer w could not catch up to refreshed its witnessed_at")
				}
				world.headCheck.Api.Serve(world.side("w").SidecarId)
				// the fetch's second try, halfway to its deadline, is served now
				half := fs17Settings.HeadCheckFetchTimeout / 2
				if err := fs17AwaitTimer(ctx, net, net.Clock().Now().Add(half)); err != nil {
					return err
				}
				net.Clock().Advance(half)
				return world.side("w").Device.Auth.AwaitPin(ctx, 20)
			}},
			// caught up, w is at r's pin and r counts
			fs17Exchange(world, "w", "r", true),
			// a at 12 and b at 14 on one history, no conflict: a's fetch takes it to api's tip, past b, which
			// stays behind and counts for nothing; b then catches up to a and counts it, and a counts b
			fs17Exchange(world, "a", "b", false),
			fs17Exchange(world, "b", "a", true),
			fs17Exchange(world, "a", "b", true),
			fs17NotAlarmed(world, "a", sidecar.SidecarHeadAlarmFork),
			fs17NotAlarmed(world, "b", sidecar.SidecarHeadAlarmFork),
		},
	}
}
