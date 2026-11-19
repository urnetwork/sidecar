//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package fault

// FS-83 on T2 and T3 (§22.8; §11.14's who, eligible, order, failover and sizes rows, §18.4's remote, setting and
// notice rows; owner decisions 175, 177, 178, 609; FI-24; D-TEST-16; DESIGN-DETAILS 7.2.2 to 7.2.4 and 7.6's rows;
// SEARCH-M10-39): remote search on sidecartest's remote team (search_remote_world.go), its config a real Team log with
// ACL's compile, m's phone asking with SearchRemoteClient over a transport that hands each body to the indexers'
// SearchRemoteServer, the indexers serving from their own engines' snapshots. Every leg each search sends is recorded
// for FI-24, which holds after every step: the indexer one §11.14's rule let answer every repo the request names, at
// the send; another member's only after its notice; owner-bound repos only to a device their owner consented; each
// request 4,016 B and each reply 16,384 B; neither device reading evs while it ran; one frame-size sequence a kind.
// T3 runs it on server's own config log sequencer (server/fs83_t3_test.go). The steps:
//
//	own        mode on, no notice answered: m's vault, mailbox and the team repo asked of m's desktop and NAS at
//	           once, both requests out before either reply (each reply held until both arrived), b's vault of nobody
//	           (its only eligible indexer is b's, which waits on b's notice); nothing to b's NAS or the Owner's device
//	notice     b's notice allowed: b's vault asked of b's NAS alone, never of m's own indexers, which read it too
//	only mine  "only my devices" (the notice refused, mode own): b's NAS asked nothing
//	failover   m's desktop killed before page 0: the NAS answers and the page comes with no clock moved; both killed:
//	           each leg ends as at its deadline, with no reply, and m's repos fall back to the phone's own download,
//	           never asked of b's NAS or the Owner's device
//	revoked    m's NAS revoked by m's first device: the next search never asks it
//
// A leg that got no reply (a killed indexer's) is held to the rule and its request's size in its step, since the relay
// carried nothing back for FI-24's sizes to judge, and a fallback's own download, which reads all by design (owner
// decision 155), is not the remote search's. D-TEST-16's two silent regressions each fail FI-24 on this world: an
// indexer answering early in fewer bytes than its step (TestFs83CatchesAnEarlyShortReply) and one syncing before it
// answers (TestFs83CatchesASyncBeforeAnswering).
//
// What this does not run yet (SEARCH-M10-39's report): the merge against SearchOracle over SERVED_TEXT repos, a fold
// inside a span and SkewGuard's 30-min push in parts, omission and mismatch alarms, a fabricated hit, a cursor ended
// by an ERASE and a late repeat of page 0 after it, a search reopened after 10 min idle, TOO_BROAD, INVALID past the
// filters' 768 B, CURSOR_EXPIRED and UNSUPPORTED_VERSION replies on this world (§22.7's search rows send the last two
// to an indexer directly), the fifth concurrent search and 30 requests a minute, 100 requesters, a retired, parked,
// suspended, read-only or ephemeral indexer and a forged IndexerSet, a read revoked mid-cursor, the team record, the
// directory and a group inbox, a personal network's network-scope indexer, the indexer's reads with a hint pending,
// and the T4 surrogate's app-host case. FI-18 is not held to these searches, which record no SearchRun.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs83 = Register("FS-83", "", []Tier{TierT2, TierT3}, Fs83RemoteSearch)

// The query every step asks, and what each repo holds of it.
const fs83Query = "harbor"

// Each repo's documents: one whose title holds the query, one whose body does, one that does not.
func fs83Documents(repo string) []*sidecar.SearchTestDocument {
	slug := strings.ReplaceAll(repo, " ", "-")
	return []*sidecar.SearchTestDocument{
		{Path: "notes/" + slug + "/harbor.md", Version: 1, Title: "harbor at noon", Text: "boats leave the quay early"},
		{Path: "notes/" + slug + "/tides.md", Version: 1, Title: "tides", Text: "the harbor floods at spring tide"},
		{Path: "notes/" + slug + "/garden.md", Version: 1, Title: "garden", Text: "tomatoes and beans"},
	}
}

// What FS-83's steps share.
type fs83State struct {
	team *sidecartest.SearchRemoteTeam
}

// The repos the phone asks, every step.
func (self *fs83State) repoIds() []sidecar.Id {
	return []sidecar.Id{self.team.RepoId("m vault"), self.team.RepoId("m mailbox"), self.team.RepoId("b vault"), self.team.RepoId("team")}
}

// The legs of a search: each page-0 call opens one, keyed by indexer and search_id; later calls join theirs.
type fs83Leg struct {
	indexerId sidecar.Id
	searchId  uint64
	repoIds   []sidecar.Id
	calls     []*sidecartest.SearchRemoteCall
}

// The legs calls made, in the order each opened.
func fs83Legs(calls []*sidecartest.SearchRemoteCall) []*fs83Leg {
	legs := []*fs83Leg{}
	for _, call := range calls {
		if call.Request == nil {
			continue
		}
		index := slices.IndexFunc(legs, func(leg *fs83Leg) bool {
			return leg.indexerId == call.IndexerId && leg.searchId == call.Request.GetSearchId()
		})
		if index < 0 {
			legs = append(legs, &fs83Leg{indexerId: call.IndexerId, searchId: call.Request.GetSearchId(), repoIds: call.RepoIds()})
			index = len(legs) - 1
		}
		legs[index].calls = append(legs[index].calls, call)
	}
	return legs
}

// Records each leg of a search for FI-24, with what §11.14's rule allowed at the send, read from the state then.
func (self *fs83State) record(net *Net, label string, pages *sidecartest.SearchRemotePages, noticeStood map[sidecar.Id]bool) error {
	team := self.team
	state := team.Net.State()
	acl, err := state.Acl()
	if err != nil {
		return err
	}
	phoneId := team.Id("m phone")
	reads := func(sidecarId sidecar.Id) []sidecar.Id {
		repoIds := []sidecar.Id{}
		for _, repoId := range self.repoIds() {
			if slices.Contains(state.RepoReaders(repoId), sidecarId) {
				repoIds = append(repoIds, repoId)
			}
		}
		return repoIds
	}
	owners := map[string]sidecar.Id{"m vault": team.Members["m"], "m mailbox": team.Members["m"], "b vault": team.Members["b"]}
	// the repos some leg served, whose reads would be the remote search's; the rest fell back to the phone's own
	// download, which reads all by design (owner decision 155)
	served := map[sidecar.Id]bool{}
	for _, call := range pages.Calls {
		if call.Err == nil && 0 < call.ReplyByteCount {
			for _, repoId := range call.RepoIds() {
				served[repoId] = true
			}
		}
	}
	phoneReads := []string{}
	for repoId, lines := range pages.Reads[phoneId] {
		if served[repoId] {
			phoneReads = append(phoneReads, lines...)
		}
	}
	for _, leg := range fs83Legs(pages.Calls) {
		name := team.NameOf(leg.indexerId)
		run := &RemoteSearchRun{
			Label: fmt.Sprintf("%s, %s's leg", label, name), Query: fs83Query, IndexerId: leg.indexerId,
			NamedRepoIds: slices.Clone(leg.repoIds), RequesterRepoIds: reads(phoneId), IndexerRepoIds: reads(leg.indexerId),
			OwnerBoundRepoDeviceIds: map[sidecar.Id][]sidecar.Id{}, Steps: 1,
			RequesterRequests: phoneReads, IndexerRequests: pages.Requests[leg.indexerId],
		}
		// the indexers the rule lets answer every repo the leg names
		for index, repoId := range leg.repoIds {
			eligible := slices.Clone(state.SearchIndexersFor(phoneId, repoId, func(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool) {
				return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
			}))
			if index == 0 {
				run.EligibleIndexerIds = eligible
			} else {
				run.EligibleIndexerIds = slices.DeleteFunc(run.EligibleIndexerIds, func(id sidecar.Id) bool { return !slices.Contains(eligible, id) })
			}
			if member, ok := owners[team.RepoNameOf(repoId)]; ok {
				for _, device := range team.Devices {
					if acl.ConsentedFor(device.SidecarId, member) {
						run.OwnerBoundRepoDeviceIds[repoId] = append(run.OwnerBoundRepoDeviceIds[repoId], device.SidecarId)
					}
				}
			}
		}
		indexerMember := team.Devices[name].MemberId
		run.OtherMember = indexerMember != team.Members["m"]
		run.NoticeStood = noticeStood[indexerMember]
		for _, hit := range pages.Hits {
			if hit.By == leg.indexerId.String() {
				run.Hits = append(run.Hits, hit)
			}
		}
		frames := &sidecartest.FrameSizeTrace{Label: run.Label, Kind: "1 step"}
		for _, call := range leg.calls {
			run.RequestByteCounts = append(run.RequestByteCounts, call.RequestByteCount)
			frames.Requests = append(frames.Requests, call.RequestByteCount)
			if 0 < call.ReplyByteCount {
				run.ReplyByteCounts = append(run.ReplyByteCounts, call.ReplyByteCount)
				frames.Replies = append(frames.Replies, call.ReplyByteCount)
			}
		}
		if len(frames.Replies) == 0 {
			// a leg that got no reply carried nothing back for FI-24's sizes to judge; the rule still held at its send
			if !slices.Contains(run.EligibleIndexerIds, run.IndexerId) || (run.OtherMember && !run.NoticeStood) {
				return fmt.Errorf("%s: the query left for %s, which the rule did not let answer", run.Label, name)
			}
			for _, byteCount := range run.RequestByteCounts {
				if byteCount != sidecar.DefaultSearchWireSettings().RequestByteCount {
					return fmt.Errorf("%s: a request of %d B", run.Label, byteCount)
				}
			}
			continue
		}
		run.Frames = frames
		if records, err := team.Indexers[name].Device.State().ServedRecords(); err == nil {
			run.ServedRecord = []byte(fmt.Sprint(records))
		}
		SearchRecordOf(net).RecordRemoteSearch(run)
	}
	return nil
}

// The notice answers the phone holds now, by member.
func (self *fs83State) notices() map[sidecar.Id]bool {
	stood := map[sidecar.Id]bool{}
	for _, member := range self.team.Members {
		if allow, answered, err := self.team.Phone.Device.State().Answer(member); err == nil && answered && allow {
			stood[member] = true
		}
	}
	return stood
}

// The phone's search more over every repo, recorded; the calls it made.
func (self *fs83State) search(ctx context.Context, net *Net, label string) (*sidecartest.SearchRemotePages, error) {
	noticeStood := self.notices()
	pages, err := self.team.Phone.Search(ctx, &sidecar.SearchRequest{Text: fs83Query, Repos: self.repoIds()}, 16)
	if err != nil {
		return pages, fmt.Errorf("%s: %w", label, err)
	}
	return pages, self.record(net, label, pages, noticeStood)
}

// The repos the calls to indexer named, by name.
func (self *fs83State) askedOf(calls []*sidecartest.SearchRemoteCall, indexer string) []string {
	names := []string{}
	for _, call := range calls {
		if call.IndexerId != self.team.Id(indexer) {
			continue
		}
		for _, repoId := range call.RepoIds() {
			if name := self.team.RepoNameOf(repoId); !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names
}

// See the file header.
func Fs83RemoteSearch(net *Net) *Schedule {
	state := &fs83State{}
	team := func() *sidecartest.SearchRemoteTeam { return state.team }
	steps := []*Step{
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			state.team, err = sidecartest.NewSearchRemoteTeam(ctx, &sidecartest.SearchRemoteTeamArgs{Tier: tier, Documents: fs83Documents})
			return err
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			// both own indexers' replies held until both requests have arrived: sent at once
			releaseDesktop, releaseNas := team().Indexers["m desktop"].Hold(), team().Indexers["m nas"].Hold()
			defer releaseDesktop()
			defer releaseNas()
			calls, _ := team().Remote.Calls()
			searched := make(chan error, 1)
			var pages *sidecartest.SearchRemotePages
			go func() {
				var err error
				pages, err = state.search(ctx, net, "own")
				searched <- err
			}()
			// real time bounds only the failure: two held requests arrive at once or the step fails
			bound, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			arrived, err := team().Remote.AwaitCalls(bound, len(calls), 2)
			if err != nil {
				releaseDesktop()
				releaseNas()
				<-searched
				return fmt.Errorf("the own indexers were not asked at once: %w", err)
			}
			if !(arrived[0].IndexerId != arrived[1].IndexerId && !arrived[0].Ended.After(arrived[1].Started)) {
				return fmt.Errorf("the own indexers' requests went one after the other: %s, %s", team().NameOf(arrived[0].IndexerId), team().NameOf(arrived[1].IndexerId))
			}
			releaseDesktop()
			releaseNas()
			if err := <-searched; err != nil {
				return err
			}
			for _, indexer := range []string{"m desktop", "m nas"} {
				if asked := state.askedOf(pages.Calls, indexer); !slices.Equal(asked, []string{"m mailbox", "m vault", "team"}) {
					return fmt.Errorf("%s was asked of %v", indexer, asked)
				}
			}
			for _, indexer := range []string{"b nas", "owner"} {
				if asked := state.askedOf(pages.Calls, indexer); len(asked) != 0 {
					return fmt.Errorf("%s was asked of %v before any notice and beside two own indexers", indexer, asked)
				}
			}
			if len(pages.Hits) == 0 {
				return errors.New("the search found nothing")
			}
			return nil
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			b := team().Members["b"]
			if err := team().Phone.Device.State().SetAnswer(&b, true); err != nil {
				return err
			}
			pages, err := state.search(ctx, net, "notice")
			if err != nil {
				return err
			}
			if asked := state.askedOf(pages.Calls, "b nas"); !slices.Equal(asked, []string{"b vault"}) {
				return fmt.Errorf("with b's notice allowed, b's NAS was asked of %v", asked)
			}
			for _, indexer := range []string{"m desktop", "m nas", "owner"} {
				if slices.Contains(state.askedOf(pages.Calls, indexer), "b vault") {
					return fmt.Errorf("%s, which reads b's vault but is not b's, was asked of it", indexer)
				}
			}
			return nil
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			b := team().Members["b"]
			if err := team().Phone.Device.State().SetAnswer(&b, false); err != nil {
				return err
			}
			pages, err := state.search(ctx, net, "only mine")
			if err != nil {
				return err
			}
			if asked := state.askedOf(pages.Calls, "b nas"); len(asked) != 0 {
				return fmt.Errorf("after only my devices, b's NAS was asked of %v", asked)
			}
			return nil
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			team().Indexers["m desktop"].Kill()
			started := net.Clock().Now()
			pages, err := state.search(ctx, net, "one own indexer killed")
			if err != nil {
				return err
			}
			if !net.Clock().Now().Equal(started) {
				return fmt.Errorf("the page waited %s on the killed indexer", net.Clock().Now().Sub(started))
			}
			if asked := state.askedOf(pages.Calls, "m nas"); !slices.Equal(asked, []string{"m mailbox", "m vault", "team"}) {
				return fmt.Errorf("the NAS was asked of %v with the desktop killed", asked)
			}
			if !slices.ContainsFunc(pages.Hits, func(hit sidecar.SearchHit) bool { return hit.By == team().Id("m nas").String() }) {
				return errors.New("no hit came from the NAS")
			}
			return nil
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			team().Indexers["m nas"].Kill()
			pages, err := state.search(ctx, net, "both own indexers killed")
			if err != nil {
				return err
			}
			for _, indexer := range []string{"b nas", "owner"} {
				if asked := state.askedOf(pages.Calls, indexer); slices.Contains(asked, "m vault") || slices.Contains(asked, "m mailbox") {
					return fmt.Errorf("%s was asked of m's own repos %v", indexer, asked)
				}
			}
			if pages.Progress.FallbackReason == "" {
				return fmt.Errorf("with both own indexers killed, nothing fell back: %+v", pages.Progress)
			}
			return nil
		}},
		{Actor: "mFirst", Action: func(ctx context.Context, net *Net) error {
			team().Indexers["m desktop"].Revive()
			team().Indexers["m nas"].Revive()
			// past the failed indexers' skip, so the desktop is asked again
			net.Clock().Advance(sidecar.DefaultSidecarSettings().Search.RemoteSkipTimeout + time.Second)
			return team().Do(func() error {
				admission := team().Net
				admission.MustLand(admission.Sign(team().Devices["m first"], bridge.SignedType_SIGNED_SIDECAR_REVOKE,
					admission.Revocation(team().Devices["m nas"], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
				return nil
			})
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			pages, err := state.search(ctx, net, "revoked")
			if err != nil {
				return err
			}
			if asked := state.askedOf(pages.Calls, "m nas"); len(asked) != 0 {
				return fmt.Errorf("the revoked NAS was asked of %v", asked)
			}
			if asked := state.askedOf(pages.Calls, "m desktop"); len(asked) == 0 {
				return errors.New("the desktop was not asked once the NAS was revoked")
			}
			return nil
		}},
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			team().Close()
			return nil
		}},
	}
	return &Schedule{Id: "FS-83", Steps: steps, Check: []Invariant{FI(24)}, Tiers: []Tier{TierT2, TierT3}}
}
