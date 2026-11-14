// <root>'s budget (TLS-M5-14): spends up to exactly the cap within the window and refuses the next,
// spends a row once however often it is admitted, frees a unit as the window passes, rebuilds a lost key
// equal to the rows, and never reads a lost key as an empty budget.
package certsservice_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

const testBudgetKey = "{tcb_letsencrypt_" + testRoot + "}"

// A small LE budget: 3 in an hour.
func testBudgetSettings() *certsservice.CertsSettings {
	settings := testSettings()
	settings.Cas[certsservice.CertsCaLetsEncrypt].BudgetCap = 3
	settings.Cas[certsservice.CertsCaLetsEncrypt].BudgetWindow = time.Hour
	return settings
}

// Exactly the cap fits in the window, the next does not, and one more fits once the first leaves it. A
// row spent again spends nothing more.
func TestBudgetSpendsToExactlyTheCap(t *testing.T) {
	certs := newTestCerts(t, testBudgetSettings())
	budget := certs.service.Budget()
	start := certs.clock.Now()
	ids := []sidecar.Id{}
	for index := range 3 {
		id := sidecartest.CertsIdAt(start)
		ids = append(ids, id)
		spent, err := budget.Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, id, start.Add(time.Duration(index)*time.Minute))
		if err != nil || !spent {
			t.Fatalf("unit %d: %v, %v", index+1, spent, err)
		}
	}
	spent, err := budget.Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, ids[0], start.Add(3*time.Minute))
	if err != nil || !spent {
		t.Fatalf("a row spent again: %v, %v", spent, err)
	}
	fourth := sidecartest.CertsIdAt(start)
	spent, err = budget.Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, fourth, start.Add(3*time.Minute))
	if err != nil || spent {
		t.Fatalf("one past the cap: %v, %v", spent, err)
	}
	// the first unit leaves the window an hour after it was spent
	spent, err = budget.Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, fourth, start.Add(time.Hour-time.Millisecond))
	if err != nil || spent {
		t.Fatalf("a millisecond inside the window: %v, %v", spent, err)
	}
	spent, err = budget.Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, fourth, start.Add(time.Hour+time.Millisecond))
	if err != nil || !spent {
		t.Fatalf("once the first left: %v, %v", spent, err)
	}
	// a CA with no cap never refuses
	spent, err = budget.Spend(certs.ctx, certsservice.CertsCaZeroSsl, sidecartest.CertsIdAt(start), start)
	if err != nil || !spent {
		t.Fatalf("ZeroSSL: %v, %v", spent, err)
	}
}

// The budget's members, marker aside, by score order.
func testBudgetMembers(t *testing.T, certs *testCerts) map[string]int64 {
	t.Helper()
	members, err := sidecartest.CertsBudgetMembers(certs.ctx, certs.host.Redis, testBudgetKey)
	if err != nil {
		t.Fatal(err)
	}
	delete(members, certsservice.CertsBudgetMarker)
	return members
}

// A lost key is rebuilt from the rows before anything spends from it: the new-set orders under way score
// now and the issued ones their not_before, a repeated set, a failure and an order of another CA count
// for nothing, and the rebuilt key holds exactly those orders, so a lost key never reads as an empty
// budget.
func TestBudgetRebuildsALostKeyEqualToTheRows(t *testing.T) {
	certs := newTestCerts(t, testBudgetSettings())
	issued := newTestDevice(t, "rebuild-issued")
	underWay := newTestDevice(t, "rebuild-underway")
	other := newTestDevice(t, "rebuild-other")
	issuedId := certs.accept(issued)
	underWayId := certs.accept(underWay)
	if report := certs.admit(); len(report.Admitted) != 2 {
		t.Fatalf("admitted %+v", report)
	}
	certs.clock.Advance(10 * time.Minute)
	certs.issue(issuedId, "abc1")
	issuedAt := certs.clock.Now()
	// a repeated set of the issued one, and another device's order failed at LE
	repeatId := certs.accept(newTestDeviceOf(t, issued.networkId, issued.identifierSet))
	otherId := certs.accept(other)
	if report := certs.admit(); len(report.Admitted) != 2 {
		t.Fatalf("admitted %+v", report)
	}
	if applied, err := certs.store.TransitionCert(certs.ctx, &certsservice.CertsTransition{
		CertId: otherId, From: []sidecar.TlsCertState{sidecar.TlsCertStateOrdering}, To: sidecar.TlsCertStateFailed, At: certs.clock.Now(),
	}); err != nil || !applied {
		t.Fatal(err)
	}
	before := testBudgetMembers(t, certs)
	if _, ok := before[repeatId.String()]; ok {
		t.Fatal("a repeated set spent a new-set unit")
	}

	certs.host.Redis.LoseEverything()
	certs.clock.Advance(5 * time.Minute)
	rebuildAt := certs.clock.Now()
	if err := certs.service.Budget().Rebuild(certs.ctx, certsservice.CertsCaLetsEncrypt, rebuildAt); err != nil {
		t.Fatal(err)
	}
	rebuilt := testBudgetMembers(t, certs)
	want := map[string]int64{
		issuedId.String():   issuedAt.UnixMilli(),
		underWayId.String(): rebuildAt.UnixMilli(),
	}
	if len(rebuilt) != len(want) {
		t.Fatalf("rebuilt %v, want %v", rebuilt, want)
	}
	for member, score := range want {
		if rebuilt[member] != score {
			t.Fatalf("rebuilt %v, want %v", rebuilt, want)
		}
	}
	// a second rebuild from an older read writes nothing over the first
	if err := certs.service.Budget().Rebuild(certs.ctx, certsservice.CertsCaLetsEncrypt, rebuildAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if again := testBudgetMembers(t, certs); len(again) != len(rebuilt) || again[underWayId.String()] != rebuildAt.UnixMilli() {
		t.Fatalf("a second rebuild changed the key: %v", again)
	}
}

// A spend on a lost key rebuilds it first, so the rows' orders still count against the cap.
func TestBudgetSpendAfterALostKeyCountsTheRows(t *testing.T) {
	certs := newTestCerts(t, testBudgetSettings())
	for _, label := range []string{"lost-a", "lost-b", "lost-c"} {
		certs.accept(newTestDevice(t, label))
	}
	if report := certs.admit(); len(report.Admitted) != 3 {
		t.Fatalf("admitted %+v", report)
	}
	certs.host.Redis.LoseEverything()
	spent, err := certs.service.Budget().Spend(certs.ctx, certsservice.CertsCaLetsEncrypt, sidecartest.CertsIdAt(certs.clock.Now()), certs.clock.Now())
	if err != nil || spent {
		t.Fatalf("a lost key let a fourth through: %v, %v", spent, err)
	}
	members := testBudgetMembers(t, certs)
	keys := []string{}
	for member := range members {
		keys = append(keys, member)
	}
	slices.Sort(keys)
	if len(keys) != 3 {
		t.Fatalf("members %v", keys)
	}
}
