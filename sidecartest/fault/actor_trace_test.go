//go:build !sidecar_http && !ios_extension

// Every schedule's actors as a failing seed's trace writes them (§22.8's explorer row): one event a line, with its actor
// as one field, so an actor that holds a space leaves a failing seed no trace to replay, the seed refused for that
// space. FS-38's share rows and the acl rows' Team schedules each held such actors ("Y's ungranted reader", "m first").

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Fails t unless a trace of the schedule's steps, each its actor's one event, writes and parses back with every actor
// as the step names it.
func expectActorsFitATrace(t *testing.T, name string, schedule *Schedule) {
	t.Helper()
	trace := &Trace{Id: name, Seed: 1}
	for _, step := range schedule.Steps {
		trace.Events = append(trace.Events, &sidecartest.BarrierEvent{Kind: sidecartest.BarrierRan, Actor: step.Actor})
	}
	data, err := trace.Bytes()
	if err != nil {
		t.Errorf("a trace of %s's actors: %v", name, err)
		return
	}
	parsed, err := ParseTrace(data)
	if err != nil {
		t.Errorf("%s's trace as written: %v", name, err)
		return
	}
	for index, event := range parsed.Events {
		if event.Actor != schedule.Steps[index].Actor {
			t.Errorf("%s's step %d actor %q came back from its trace as %q", name, index, schedule.Steps[index].Actor, event.Actor)
		}
	}
}

// Every registered schedule and its twin, each built on a Net of its own, as a row's run builds it.
func TestEveryRegisteredActorFitsATrace(t *testing.T) {
	for _, registration := range theRegistry().registered() {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedule := registration.Build(net)
			expectActorsFitATrace(t, registration.String(), schedule)
			if schedule.Twin != nil {
				expectActorsFitATrace(t, registration.String()+"'s twin", schedule.Twin(net))
			}
		}()
	}
}

// The acl rows' Team schedules run outside the registry, FS-14's and FS-85's clauses (RunClause) and S3a's, S4a's and
// S13's checks: each named its actors for the devices they act as, "m first" and "b first" among them.
func TestAclTeamActorsFitATrace(t *testing.T) {
	for name, builder := range map[string]Builder{
		"FS-14's acl suspend orders":    Fs14AclSuspendOrders,
		"FS-14's acl repo revoke":       Fs14AclRepoRevoke,
		"FS-14's acl owner confirm":     Fs14AclOwnerConfirm,
		"FS-14's acl two removals":      Fs14AclTwoRemovals,
		"FS-14's acl forked readers":    Fs14AclForkedReaders,
		"FS-14's acl connected readers": Fs14AclConnectedReaders,
		"FS-85's acl worker request":    Fs85AclWorkerRequest,
		"FS-85's acl copied decision":   Fs85AclCopiedDecision,
		"FS-85's acl repo request":      Fs85AclRepoRequest,
		"FS-85's acl owner-bound":       Fs85AclOwnerBoundRequest,
		"S3a's acl checks":              AclAddsOnlyForReaders,
		"S4a's acl checks":              AclRemovalDropsEveryRight,
		"S13's grant steps":             AclS13GrantSteps,
		"S3b's acl checks":              AclMemberAddsOnlyForReaders,
		"S4b's acl checks":              AclMemberRemovalDropsEveryRight,
	} {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			expectActorsFitATrace(t, name, builder(net))
		}()
	}
}
