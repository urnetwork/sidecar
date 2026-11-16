// The pure half of Team custom-domain certificates (TLS-M6-05; DESIGN-DETAILS 17.2.8, 17.2.11, 17.6; QD-990): the
// replayed bucket's level and wait, never above a reference bucket fed the same spends and equal to it after a quiet
// window, and 17.4's pacing of a host's devices; the failure backoff; the renew time spread across the ARI window over
// 10,000 ids; the custom branch's CSR test; and the settings' refusals.

package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math"
	mathrand "math/rand/v2"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

func TestCertsCustomBucketLevelAndWait(t *testing.T) {
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	set := certsservice.DefaultCertsCustomSettings().SetBucket()
	if set.Capacity != 5 || set.Refill != 34*time.Hour || set.ReplaySpan() != 2*5*34*time.Hour {
		t.Fatalf("the set bucket: %+v", set)
	}
	// a replay with no spends is full
	if level := set.Level(nil, now); level != 5 {
		t.Fatalf("no spends: %v", level)
	}
	// four spends at once leave one; two are needed, one refill away
	spends := []time.Time{now, now, now, now}
	if level := set.Level(spends, now); level != 1 {
		t.Fatalf("four spends: %v", level)
	}
	if wait := set.Wait(spends, now, 2); wait != 34*time.Hour {
		t.Fatalf("the wait for two: %v", wait)
	}
	if wait := set.Wait(spends, now, 1); wait != 0 {
		t.Fatalf("the wait for one: %v", wait)
	}
	// the replay starts empty two windows back, so the burst's window reads full at its start and a refill later the
	// burst reads two, the truth, where one window back read one (QD-990)
	if level := set.Level(spends, now.Add(34*time.Hour)); level != 2 {
		t.Fatalf("a refill on: %v", level)
	}
	if wait := set.Wait(spends, now.Add(34*time.Hour), 2); wait != 0 {
		t.Fatalf("the wait for two a refill on: %v", wait)
	}
	if level := set.Level(spends, now.Add(5*34*time.Hour)); level != 5 {
		t.Fatalf("a window on: %v", level)
	}
	if level := set.Level(spends, now.Add(30*24*time.Hour)); level != 5 {
		t.Fatalf("long after: %v", level)
	}
	// spread spends, one each refill, after a quiet window: each token is back before the next spend, so four
	// remain, as a bucket full before them holds
	spread := []time.Time{now.Add(-3 * 34 * time.Hour), now.Add(-2 * 34 * time.Hour), now.Add(-34 * time.Hour), now}
	if level := set.Level(spread, now); level != 4 {
		t.Fatalf("spread spends: %v", level)
	}
	// a spend inside the replay but before the window is refilled by now; one before the replay counts for nothing
	if level := set.Level([]time.Time{now.Add(-6 * 34 * time.Hour)}, now); level != 5 {
		t.Fatalf("an old spend: %v", level)
	}
	if level := set.Level([]time.Time{now.Add(-11 * 34 * time.Hour), now.Add(-11 * 34 * time.Hour)}, now); level != 5 {
		t.Fatalf("spends before the replay: %v", level)
	}
	// a spend exactly at the replay's start has left it, which is open there
	if level := set.Level([]time.Time{set.ReplayStart(now)}, now); level != 5 {
		t.Fatalf("a spend at the replay's start: %v", level)
	}
	// 17.2.8's literal replay, one window back, for comparison: the burst reads one a refill on
	literal := certsservice.CertsCustomBucket{Capacity: 5, Refill: 34 * time.Hour, Windows: 1}
	if level := literal.Level(spends, now.Add(34*time.Hour)); level != 1 {
		t.Fatalf("one window back, a refill on: %v", level)
	}
	// below one window reads as one
	if (certsservice.CertsCustomBucket{Capacity: 5, Refill: 34 * time.Hour}).ReplaySpan() != literal.ReplaySpan() {
		t.Fatalf("no window count")
	}
}

// A bucket fed spends the CA would take, starting full long before: the truth.
type testCertsCustomReference struct {
	random   *mathrand.Rand
	capacity float64
	refill   time.Duration
}

// The spends of up to stepCount steps of up to stepMax from start, each taken only when the truth affords it, and
// the truth at end, up to tailMax after the last.
func (self *testCertsCustomReference) run(start time.Time, stepCount int, stepMax time.Duration, tailMax time.Duration) ([]time.Time, time.Time, float64) {
	spends := []time.Time{}
	truth := self.capacity
	at := start
	for range self.random.IntN(stepCount + 1) {
		step := time.Duration(self.random.Int64N(int64(stepMax/time.Minute)+1)) * time.Minute
		truth = min(self.capacity, truth+float64(step)/float64(self.refill))
		at = at.Add(step)
		// the CA refuses a spend it cannot afford, so the truth never goes below empty
		if 1 <= truth {
			truth -= 1
			spends = append(spends, at)
		}
	}
	end := at.Add(time.Duration(self.random.Int64N(int64(tailMax/time.Minute)+1)) * time.Minute)
	truth = min(self.capacity, truth+float64(end.Sub(at))/float64(self.refill))
	return spends, end, truth
}

// A reference bucket, full long before the replay and fed the same spends, never holds less than the replay: the
// replay starts empty, so it never counts more than the truth, whatever its window count (17.2.8, C5, QD-990).
func TestCertsCustomBucketNeverAboveTheTruth(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	for _, windows := range []int{1, 2, 3} {
		bucket := certsservice.CertsCustomBucket{Capacity: 5, Refill: time.Hour, Windows: windows}
		reference := &testCertsCustomReference{random: random, capacity: 5, refill: time.Hour}
		for round := range 2000 {
			spends, end, truth := reference.run(start, 24, 3*time.Hour, 3*time.Hour)
			if level := bucket.Level(spends, end); truth+1e-9 < level {
				t.Fatalf("%d windows, round %d: the replay holds %v, the truth %v", windows, round, level, truth)
			}
		}
	}
}

// With no spend in the first of its two windows, the replay is full where its second starts, as the truth is, so
// it reads the truth exactly (QD-990).
func TestCertsCustomBucketReadsTheTruthAfterAQuietWindow(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(3, 4))
	bucket := certsservice.CertsCustomBucket{Capacity: 5, Refill: time.Hour, Windows: 2}
	window := time.Duration(bucket.Capacity) * bucket.Refill
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	reference := &testCertsCustomReference{random: random, capacity: 5, refill: time.Hour}
	for round := range 2000 {
		// every spend and the end inside one window from start, which a quiet window precedes
		spends, end, truth := reference.run(start, 12, 20*time.Minute, 20*time.Minute)
		if window < end.Sub(start) {
			continue
		}
		if level := bucket.Level(spends, end); 1e-9 < math.Abs(level-truth) {
			t.Fatalf("round %d: the replay holds %v, the truth %v", round, level, truth)
		}
	}
}

// 17.4's pacing on the set bucket with the defaults: after a burst of four certificates for a host, the fifth to the
// ninth device are each granted 34 h after the one before, and each refusal's wait is answered by a grant (QD-990).
// A replay of two windows reaches a full bucket only through the ninth: the tenth device's replay starts within the
// burst's window, reads one token under the truth, and waits until the burst leaves the replay, 340 h after it.
func TestCertsCustomSetBucketPacesDevices(t *testing.T) {
	settings := certsservice.DefaultCertsCustomSettings()
	set := settings.SetBucket()
	need := settings.SetReserve + 1
	burst := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	spends := []time.Time{burst, burst, burst, burst}
	now := burst
	for device := 5; device <= 9; device += 1 {
		wait := set.Wait(spends, now, need)
		if wait != 34*time.Hour {
			t.Fatalf("device %d: a wait of %v", device, wait)
		}
		now = now.Add(wait)
		if wait := set.Wait(spends, now, need); wait != 0 {
			t.Fatalf("device %d: refused at its retry, %v more", device, wait)
		}
		spends = append(spends, now)
	}
	// the tenth: refused at each 34 h retry until the burst leaves the replay
	for retry := range 4 {
		wait := set.Wait(spends, now, need)
		if wait != 34*time.Hour {
			t.Fatalf("the tenth device, retry %d: a wait of %v", retry, wait)
		}
		now = now.Add(wait)
		if now.Sub(burst) < set.ReplaySpan() {
			if wait := set.Wait(spends, now, need); wait == 0 {
				t.Fatalf("the tenth device granted %v after the burst", now.Sub(burst))
			}
		}
	}
	if now = now.Add(34 * time.Hour); now.Sub(burst) != set.ReplaySpan() {
		t.Fatalf("the replay's span is %v", set.ReplaySpan())
	}
	if wait := set.Wait(spends, now, need); wait != 0 {
		t.Fatalf("the tenth device once the burst left the replay: %v", wait)
	}
}

func TestCertsCustomFailureBackoffDoublesToItsCap(t *testing.T) {
	settings := certsservice.DefaultCertsCustomSettings()
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	failures := []time.Time{}
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for index, backoff := range want {
		failures = append(failures, now)
		if wait := settings.FailureWait(failures, now); wait != backoff {
			t.Errorf("after %d failures: %v, want %v", index+1, wait, backoff)
		}
	}
	if wait := settings.FailureWait(nil, now); wait != 0 {
		t.Errorf("no failure: %v", wait)
	}
}

func TestCertsCustomRenewTimeSpreadsAcrossTheWindow(t *testing.T) {
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	buckets := make([]int, 8)
	for range 10000 {
		row := &sidecar.TlsCertRecord{CertId: sidecar.NewId(), AriWindowStart: start, AriWindowEnd: end}
		at := certsservice.CertsCustomRenewTime(row, 2.0/3.0)
		if at.Before(start) || !at.Before(end) {
			t.Fatalf("%v outside the window", at)
		}
		buckets[int(at.Sub(start)*8/end.Sub(start))] += 1
	}
	for index, count := range buckets {
		// 1,250 each when uniform; a fifth either way is far outside chance for a hash
		if count < 1000 || 1500 < count {
			t.Errorf("an eighth of the window %d holds %d of 10,000", index, count)
		}
	}
	// no window: two thirds of the validity
	row := &sidecar.TlsCertRecord{CertId: sidecar.NewId(), NotBefore: start, NotAfter: start.Add(45 * 24 * time.Hour)}
	if at := certsservice.CertsCustomRenewTime(row, 2.0/3.0); !at.Equal(start.Add(30 * 24 * time.Hour)) {
		t.Errorf("with no window: %v", at)
	}
}

func TestCertsCustomCsrHostTakesOneNameUnderNoRoot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := func(names ...string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if host, custom := certsservice.CertsCustomCsrHost(csr("www.customer.example"), []string{testRoot}); !custom || host != "www.customer.example" {
		t.Fatalf("a custom host: %q, %v", host, custom)
	}
	for _, der := range [][]byte{
		csr("*.net1."+testRoot, "net1."+testRoot),
		csr("net1." + testRoot),
		csr("www.customer.example", "api.customer.example"),
		csr("*.customer.example"),
		{1, 2, 3},
	} {
		if _, custom := certsservice.CertsCustomCsrHost(der, []string{testRoot}); custom {
			t.Errorf("a CSR read as custom")
		}
	}
}

func TestCertsCustomSettingsRefuseWhatLeavesARuleUnenforced(t *testing.T) {
	if err := certsservice.DefaultCertsCustomSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(settings *certsservice.CertsCustomSettings){
		func(settings *certsservice.CertsCustomSettings) { settings.LockLease = 0 },
		func(settings *certsservice.CertsCustomSettings) { settings.SetReserve = settings.SetCap },
		func(settings *certsservice.CertsCustomSettings) { settings.HoldMax = settings.HoldDefault - 1 },
		func(settings *certsservice.CertsCustomSettings) { settings.LapseWarnFraction = 0.9 },
		func(settings *certsservice.CertsCustomSettings) { settings.ChainMaxCount = 0 },
		func(settings *certsservice.CertsCustomSettings) { settings.ReplayWindowCount = 0 },
		// spends purged inside a replay would read the set bucket above the truth: 8 d against its 2 × 170 h
		func(settings *certsservice.CertsCustomSettings) { settings.SpendRetention = 8 * 24 * time.Hour },
		func(settings *certsservice.CertsCustomSettings) { settings.ReplayWindowCount = 3 },
	} {
		settings := certsservice.DefaultCertsCustomSettings()
		change(settings)
		if err := settings.Validate(); err == nil {
			t.Errorf("a refused value passed: %+v", settings)
		}
	}
}
