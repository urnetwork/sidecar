package sidecartest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

// The fake keeps what store.go promises, as server's Postgres store must.
func TestFakeCertsStorePassesTheSuite(t *testing.T) {
	store := NewFakeCertsStore(nil)
	RunCertsStoreSuite(t, store, &CertsStoreSuiteHooks{
		MarkEphemeral: func(ctx context.Context, clientId sidecar.Id) error {
			store.SetClientEphemeral(clientId)
			return nil
		},
	})
}

// A fault plan reaches a store call, and each call is counted.
func TestFakeCertsStoreTakesFaultsAndCounts(t *testing.T) {
	faults := NewFaultQueue()
	store := NewFakeCertsStore(faults)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "certs.ListQueued", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListQueued(context.Background(), sidecar.Id{}, 10); err == nil {
		t.Fatal("the planned failure did not reach the call")
	}
	if _, err := store.ListQueued(context.Background(), sidecar.Id{}, 10); err != nil {
		t.Fatal(err)
	}
	if counts := store.OpCounts(); counts["ListQueued"] != 1 {
		t.Fatalf("counts %v", counts)
	}
}

// The budget twins on one FakeRedis: a key with no marker answers unseeded, a seed writes once, a spend
// fills the window to its cap and no further, a member spends once, and an entry leaves at the window's
// end while the marker stays.
func TestCertsBudgetTwinsAnswerAsTheScripts(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	redis := NewFakeRedis(ctx, clock, nil, nil, nil)
	defer redis.Close()
	RegisterCertsBudgetTwins(redis)
	key := "{tcb_letsencrypt_root.example}"
	spend := func(now time.Time, member string) int64 {
		t.Helper()
		reply, err := redis.RunScript(ctx, certsservice.CertsBudgetSpendScript, []string{key}, []string{
			strconv.FormatInt(now.UnixMilli(), 10),
			strconv.FormatInt(time.Hour.Milliseconds(), 10),
			"2",
			member,
			strconv.FormatInt((2 * time.Hour).Milliseconds(), 10),
		})
		if err != nil {
			t.Fatal(err)
		}
		return reply.Integer
	}
	seed := func(entries ...string) int64 {
		t.Helper()
		reply, err := redis.RunScript(ctx, certsservice.CertsBudgetSeedScript, []string{key}, append([]string{strconv.FormatInt((2 * time.Hour).Milliseconds(), 10)}, entries...))
		if err != nil {
			t.Fatal(err)
		}
		return reply.Integer
	}
	now := clock.Now()
	if got := spend(now, "a"); got != -1 {
		t.Fatalf("an unseeded key answered %d", got)
	}
	if got := seed(strconv.FormatInt(now.Add(-30*time.Minute).UnixMilli(), 10), "old"); got != 1 {
		t.Fatalf("the first seed answered %d", got)
	}
	if got := seed(); got != 0 {
		t.Fatalf("a second seed answered %d", got)
	}
	if got := spend(now, "a"); got != 1 {
		t.Fatalf("the first spend answered %d", got)
	}
	if got := spend(now, "a"); got != 1 {
		t.Fatalf("a spend again answered %d", got)
	}
	if got := spend(now, "b"); got != 0 {
		t.Fatalf("past the cap answered %d", got)
	}
	// "old" leaves the window 30 minutes on, and b fits
	if got := spend(now.Add(30*time.Minute+time.Millisecond), "b"); got != 1 {
		t.Fatalf("after the window answered %d", got)
	}
	members, err := CertsBudgetMembers(ctx, redis, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := members[certsservice.CertsBudgetMarker]; !ok || len(members) != 3 {
		t.Fatalf("members %v", members)
	}
	if _, ok := members["old"]; ok {
		t.Fatal("an entry past the window stayed")
	}
}
