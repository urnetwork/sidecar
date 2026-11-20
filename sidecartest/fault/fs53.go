// FS-53 (§22.8, FI-1; owner decision 136; EVSB-M2-11) on the evs world (evs_world.go): a config repo with under 256 KiB
// of aged history, written through the real client and engine. Two writers each write a statement a day for five days:
// each day's records stay in their batches until their minute is 25 h old, the run 24.5 h on taking none, and the run
// past 25 h takes them to a parcel on NVMe, one parcel a day. The write whose evacuation comes as the first record nears
// 7 d takes every parcel into one pack on the segment cluster, the parcels and their entries deleted behind it, and later
// history starts a new parcel. Reads verify at each step: FI-1's closure finds each committed record in its batch, its
// parcel or its pack as a reader would, after every step with every check the world names, and the reader reads every
// path at each stage.
//
// The repo keeps writing, so the run that evacuates it packs it. An idle repo's 7 d pack is the nightly pass's
// (EVSB-M2-12). On T3 server's evshost runs the same builder on the local stack's MinIO, the batches' and parcels'
// ages read through T3's store clock (catalog.yml's store_clock).

package fault

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs53 = Register("FS-53", "", []Tier{TierT2, TierT3}, Fs53ConfigHistoryParcelsThenPacks)

// See the file header.
func Fs53ConfigHistoryParcelsThenPacks(net *Net) *Schedule {
	settings := DefaultEvsWorldSettings()
	settings.Kind = protocol.RepoKind_REPO_KIND_CONFIG
	world := NewEvsWorld(net, settings)
	// the first records' time, against which the pack's 7 d is read
	var firstWriteTime time.Time
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			firstWriteTime = net.Clock().Now()
			return nil
		}},
	}
	paths := []string{}
	// each day's steps take 25 h 2 min of the clock: its writes, the run at 24.5 h and the run past 25 h
	for day := range 5 {
		pathA := fmt.Sprintf("statements/a-%d", day)
		pathB := fmt.Sprintf("statements/b-%d", day)
		paths = append(paths, pathA, pathB)
		written := slices.Clone(paths)
		parcelCount := day + 1
		steps = append(steps, []*Step{
			{Actor: "writerA", Action: world.Write("writerA", pathA, EvsWorldContent("fs53 "+pathA, 120))},
			{Actor: "writerB", Action: world.Write("writerB", pathB, EvsWorldContent("fs53 "+pathB, 120))},
			{Actor: "reader", Action: world.Verify("reader", written...)},
			{Advance: 24*time.Hour + 30*time.Minute},
			{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
				if result.KeptCount != 0 || result.ParcelCount != 0 {
					return fmt.Errorf("day %d: a batch under 25 h old was taken", day)
				}
				return nil
			})},
			{Actor: "check", Action: world.ExpectStoredKeyCount(fmt.Sprintf("day %d's batches, under 25 h old", day), false, evsWorldBatchPrefix, 2)},
			{Advance: 32 * time.Minute},
			{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
				if result.KeptCount != 2 || result.ParcelCount != 1 || result.PackCount != 0 || result.HasBatches {
					return fmt.Errorf("day %d: the day's two records are not one parcel", day)
				}
				return nil
			})},
			{Actor: "check", Action: world.ExpectStoredKeyCount(fmt.Sprintf("day %d's parcels", day), false, evsWorldParcelPrefix, parcelCount)},
			{Actor: "check", Action: world.ExpectStoredKeyCount(fmt.Sprintf("packs on day %d", day), true, evsWorldPackPrefix, 0)},
			{Actor: "reader", Action: world.Verify("reader", written...)},
		}...)
	}
	// 5 days of 25 h 2 min each: the clock stands at 125 h 10 min, and the next write is at 7 d less 26 h, so its
	// evacuation 25 h 2 min later comes as the first record nears 7 d
	paths = append(paths, "statements/a-late")
	written := slices.Clone(paths)
	steps = append(steps, []*Step{
		{Advance: 7*24*time.Hour - 26*time.Hour - 125*time.Hour - 10*time.Minute},
		{Actor: "writerA", Action: world.Write("writerA", "statements/a-late", EvsWorldContent("fs53 statements/a-late", 120))},
		{Advance: 25*time.Hour + 2*time.Minute},
		{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
			if result.PackCount != 1 || result.ReplacedParcelCount != 5 || result.ParcelCount != 0 || result.HasBatches {
				return fmt.Errorf("the run as the first record nears 7 d did not pack every parcel")
			}
			if age := net.Clock().Now().Sub(firstWriteTime); 7*24*time.Hour < age {
				return fmt.Errorf("the pack came %s after the first record, past 7 d", age)
			}
			return nil
		})},
		{Actor: "check", Action: world.ExpectStoredKeyCount("parcels the pack replaced", false, evsWorldParcelPrefix, 0)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("the pack", true, evsWorldPackPrefix, 1)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("the pack's entry", false, evsWorldEntryPrefix, 1)},
		{Actor: "reader", Action: world.Verify("reader", written...)},
	}...)
	// later history starts a new parcel
	paths = append(paths, "statements/b-after")
	written = slices.Clone(paths)
	steps = append(steps, []*Step{
		{Actor: "writerB", Action: world.Write("writerB", "statements/b-after", EvsWorldContent("fs53 statements/b-after", 120))},
		{Advance: 25*time.Hour + 2*time.Minute},
		{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
			if result.ParcelCount != 1 || result.PackCount != 0 {
				return fmt.Errorf("history after the pack did not start a parcel")
			}
			return nil
		})},
		{Actor: "check", Action: world.ExpectStoredKeyCount("the parcel after the pack", false, evsWorldParcelPrefix, 1)},
		{Actor: "reader", Action: world.Verify("reader", written...)},
	}...)
	return &Schedule{Id: "FS-53", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
