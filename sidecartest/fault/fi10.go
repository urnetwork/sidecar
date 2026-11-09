// FI-10, witnesses (§22.8; §2, §6; D-PROTO-14, D-PROTO-17, D-TRUST-10): read after every step from every
// device with HeadCheck the Net holds (sidecartest/headcheck_net.go).
//
//   - a witness names exactly the state it compared: witnessed_at is never past the clock, and the pin a
//     device witnessed is one its own log holds, A_n as it keeps it at n;
//   - stale peers cannot manufacture freshness: witnessed_at never moves from one check to the next while
//     the device holds an UNVERIFIED pin at both, nor while it holds proof of withholding at both, since
//     a device in either state counts no one and no one counts it (§6.4's witness row);
//   - a fork under one epoch alarms or reads unwitnessed: two devices whose pins conflict at one position,
//     an auth digest, a generation's commitment, a ref's chain or an epoch's authenticator, each end the
//     run having alarmed fork or not having witnessed since the conflict was first seen.
//
// The third clause reads every pair of devices on one network, so it holds a schedule to making forked
// devices meet, directly or through peers: across a split where no HeadCheck path crosses, §2.8 says the
// bound does not hold, and a schedule modeling one checks its own narrower claim instead.

package fault

import (
	"bytes"
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(10, func(ctx context.Context, oracle *Oracle) error {
	now := oracle.Net.Clock().Now()
	for _, headCheck := range oracle.Net.HeadCheckNets() {
		sides := headCheck.Sidecars()
		for _, side := range sides {
			if side.Stop == nil {
				continue
			}
			witnessedAt := side.Stop.WitnessedAt()
			if now.Before(witnessedAt) {
				return fmt.Errorf("%s witnessed at %s, past the clock's %s", side.Name, witnessedAt, now)
			}
			if !witnessedAt.IsZero() {
				pin := side.Stop.WitnessedPin()
				if pin == nil {
					return fmt.Errorf("%s witnessed at %s and names no pin", side.Name, witnessedAt)
				}
				if chain, kept := side.Device.Auth.ChainAt(pin.GetVersion()); kept && !bytes.Equal(chain, pin.GetChain()) {
					return fmt.Errorf("%s witnessed a pin at %d its own log does not hold", side.Name, pin.GetVersion())
				}
			}
			note := headCheck.Note(side.SidecarId)
			unverified := 0 < len(side.Stop.Unverified())
			withheld := fi10Withheld(side)
			if note.HeldUnverified && unverified && witnessedAt.After(note.WitnessedAt) {
				return fmt.Errorf("%s refreshed witnessed_at while it held an UNVERIFIED pin", side.Name)
			}
			if note.HeldWithheld && withheld && witnessedAt.After(note.WitnessedAt) {
				return fmt.Errorf("%s refreshed witnessed_at while it held proof of withholding", side.Name)
			}
			note.WitnessedAt = witnessedAt
			note.HeldUnverified = unverified
			note.HeldWithheld = withheld
		}
		conflicted := map[sidecar.Id]string{}
		for i, a := range sides {
			for _, b := range sides[i+1:] {
				if conflict := fi10Conflict(a, b); conflict != "" {
					conflicted[a.SidecarId] = conflict + " with " + b.Name
					conflicted[b.SidecarId] = conflict + " with " + a.Name
				}
			}
		}
		for _, side := range sides {
			note := headCheck.Note(side.SidecarId)
			conflict, inConflict := conflicted[side.SidecarId]
			if !inConflict {
				note.ConflictWitnessedAt = nil
				continue
			}
			witnessedAt := side.Stop.WitnessedAt()
			if note.ConflictWitnessedAt == nil {
				note.ConflictWitnessedAt = &witnessedAt
			}
			if !oracle.Final {
				continue
			}
			if len(side.Alarms(sidecar.SidecarHeadAlarmFork)) == 0 && witnessedAt.After(*note.ConflictWitnessedAt) {
				return fmt.Errorf("%s holds %s, raised no fork alarm and witnessed since", side.Name, conflict)
			}
		}
	}
	return nil
})

// Whether a device holds proof of withholding, the tip it sends as proven.
func fi10Withheld(side *sidecartest.HeadCheckSidecar) bool {
	return side.Stop.Withheld() != nil
}

// The first conflict between two devices' pins at one position, or empty: §6.4's auth, gens, groups and
// refs rows, each read as the FORK row reads it.
func fi10Conflict(a *sidecartest.HeadCheckSidecar, b *sidecartest.HeadCheckSidecar) string {
	pinA := a.Device.Auth.Pin()
	pinB := b.Device.Auth.Pin()
	if version := min(pinA.GetVersion(), pinB.GetVersion()); 0 < version {
		chainA, keptA := a.Device.Auth.ChainAt(version)
		chainB, keptB := b.Device.Auth.ChainAt(version)
		if keptA && keptB && !bytes.Equal(chainA, chainB) {
			return fmt.Sprintf("an auth fork at %d", version)
		}
	}
	for _, genA := range a.Device.Heads.GenHeads(b.SidecarId) {
		genB, held := b.Device.Heads.GenHead(sidecar.Id(genA.GetGroupId()))
		if held && genB.GetGeneration() == genA.GetGeneration() && !bytes.Equal(genA.GetCommitment(), genB.GetCommitment()) {
			return fmt.Sprintf("a generation fork at %d", genA.GetGeneration())
		}
	}
	for _, groupA := range a.Device.Heads.GroupHeads(b.SidecarId) {
		groupB, held := b.Device.Heads.GroupHead(sidecar.Id(groupA.GetGroupId()))
		if held && groupB.GetEpoch() == groupA.GetEpoch() && !bytes.Equal(groupA.GetEpochAuthenticator(), groupB.GetEpochAuthenticator()) {
			return fmt.Sprintf("an epoch fork at %d", groupA.GetEpoch())
		}
	}
	for _, refA := range a.Device.Heads.RefHeads(b.SidecarId) {
		refB, held := b.Device.Heads.RefHead(sidecar.Id(refA.GetRepoId()), sidecar.Id(refA.GetRefId()))
		if held && refB.Head.GetVersion() == refA.GetVersion() && !bytes.Equal(refA.GetChain(), refB.Head.GetChain()) {
			return fmt.Sprintf("a ref fork at %d", refA.GetVersion())
		}
	}
	return ""
}
