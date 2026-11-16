// The pure half of Team custom-domain certificates (TLS-M6-05; DESIGN-DETAILS 17.2.8, 17.2.11, 17.6; QD-990, QD-994):
// the replayed bucket's level and wait, never above a reference bucket fed the same spends whatever the retention and
// equal to it with a quiet window within the retention, and 17.4's pacing of a host's devices; the failure backoff;
// the renew time spread across the ARI window over 10,000 ids; the custom branch's CSR test; and the settings'
// refusals.

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
	if set.Capacity != 5 || set.Refill != 34*time.Hour || set.Retention != 15*24*time.Hour {
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
	// a quiet window precedes the burst, so the replay starts full there and a refill later reads two, the truth
	if level := set.Level(spends, now.Add(34*time.Hour)); level != 2 {
		t.Fatalf("a refill on: %v", level)
	}
	if wait := set.Wait(spends, now.Add(34*time.Hour), 2); wait != 0 {
		t.Fatalf("the wait for two a refill on: %v", wait)
	}
	// a window after the last spend the bucket is full
	if level := set.Level(spends, now.Add(5*34*time.Hour)); level != 5 {
		t.Fatalf("a window on: %v", level)
	}
	// spread spends, one each refill: each token is back before the next spend, so four remain
	spread := []time.Time{now.Add(-3 * 34 * time.Hour), now.Add(-2 * 34 * time.Hour), now.Add(-34 * time.Hour), now}
	if level := set.Level(spread, now); level != 4 {
		t.Fatalf("spread spends: %v", level)
	}
	// a spend a window back is refilled; spends before the retention, or exactly at its start, count for nothing
	if level := set.Level([]time.Time{now.Add(-6 * 34 * time.Hour)}, now); level != 5 {
		t.Fatalf("an old spend: %v", level)
	}
	if level := set.Level([]time.Time{now.Add(-11 * 34 * time.Hour), now.Add(-11 * 34 * time.Hour)}, now); level != 5 {
		t.Fatalf("spends before the retention: %v", level)
	}
	if level := set.Level([]time.Time{set.ReplayStart(now)}, now); level != 5 {
		t.Fatalf("a spend at the retention's start: %v", level)
	}
	// a spend each refill reaching back past the retention: no quiet window lies within it, so the replay starts
	// empty at its start, 20 h before the oldest retained spend, and stays under the truth's four
	chain := []time.Time{}
	for at := now; !at.Before(now.Add(-374 * time.Hour)); at = at.Add(-34 * time.Hour) {
		chain = append(chain, at)
	}
	if level := set.Level(chain, now); 1 <= level || level != float64(20*time.Hour-34*time.Hour)/float64(34*time.Hour) {
		t.Fatalf("a chain past the retention: %v", level)
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

// A reference bucket, full long before and fed the same spends, never holds less than the replay, whatever the
// retention: the replay starts full only where a quiet window shows the bucket full, else empty (17.2.8, C5, QD-994).
func TestCertsCustomBucketNeverAboveTheTruth(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	for _, retention := range []time.Duration{5 * time.Hour, 10 * time.Hour, 30 * time.Hour, 200 * time.Hour} {
		bucket := certsservice.CertsCustomBucket{Capacity: 5, Refill: time.Hour, Retention: retention}
		reference := &testCertsCustomReference{random: random, capacity: 5, refill: time.Hour}
		for round := range 2000 {
			spends, end, truth := reference.run(start, 24, 6*time.Hour, 3*time.Hour)
			if level := bucket.Level(spends, end); truth+1e-9 < level {
				t.Fatalf("a retention of %v, round %d: the replay holds %v, the truth %v", retention, round, level, truth)
			}
		}
	}
}

// With a quiet window within the retention, the replay reads the truth exactly, whatever spends and gaps follow it
// (QD-994).
func TestCertsCustomBucketReadsTheTruthAfterAQuietWindow(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(3, 4))
	// every run spans at most 24 × 8 h and 8 h, so a retention of 250 h holds a quiet window before its first spend
	bucket := certsservice.CertsCustomBucket{Capacity: 5, Refill: time.Hour, Retention: 250 * time.Hour}
	start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	reference := &testCertsCustomReference{random: random, capacity: 5, refill: time.Hour}
	for round := range 4000 {
		spends, end, truth := reference.run(start, 24, 8*time.Hour, 8*time.Hour)
		if level := bucket.Level(spends, end); 1e-9 < math.Abs(level-truth) {
			t.Fatalf("round %d: the replay holds %v, the truth %v", round, level, truth)
		}
	}
}

// 17.4's pacing on the set bucket: after a burst of four certificates for a host, each further device is granted 34 h
// after the one before, and each refusal's wait is answered by a grant, while the host's busy stretch is shorter than
// the retention less one window (QD-994). With the default 15 d that holds through the ninth device, 170 h after the
// burst; the tenth's turn at 204 h finds no quiet window within the retention, reads one token under the truth, and
// is granted only 340 h after the burst, a window after the ninth. A 16 d retention paces the tenth at 204 h.
func TestCertsCustomSetBucketPacesDevices(t *testing.T) {
	pace := func(settings *certsservice.CertsCustomSettings, paced int) (time.Time, []time.Time) {
		set := settings.SetBucket()
		need := settings.SetReserve + 1
		burst := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
		spends := []time.Time{burst, burst, burst, burst}
		now := burst
		for device := 5; device < 5+paced; device += 1 {
			wait := set.Wait(spends, now, need)
			if wait != 34*time.Hour {
				t.Fatalf("a retention of %v, device %d: a wait of %v", set.Retention, device, wait)
			}
			now = now.Add(wait)
			if wait := set.Wait(spends, now, need); wait != 0 {
				t.Fatalf("a retention of %v, device %d: refused at its retry, %v more", set.Retention, device, wait)
			}
			spends = append(spends, now)
		}
		return now, spends
	}
	settings := certsservice.DefaultCertsCustomSettings()
	set := settings.SetBucket()
	need := settings.SetReserve + 1
	now, spends := pace(settings, 5)
	burst := spends[0]
	// the tenth: refused at each retry until a window after the ninth
	for now.Sub(burst) < 340*time.Hour {
		wait := set.Wait(spends, now, need)
		if wait == 0 {
			t.Fatalf("the tenth device granted %v after the burst", now.Sub(burst))
		}
		now = now.Add(wait)
		if burst.Add(340 * time.Hour).Before(now) {
			now = burst.Add(340 * time.Hour)
		}
	}
	if wait := set.Wait(spends, now, need); wait != 0 {
		t.Fatalf("the tenth device a window after the ninth: %v", wait)
	}
	// a retention past the tenth's busy stretch and a window paces it at 34 h
	longer := certsservice.DefaultCertsCustomSettings()
	longer.SpendRetention = 16 * 24 * time.Hour
	pace(longer, 6)
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
		// a retention shorter than the domain bucket's 7 d window holds no quiet window of it
		func(settings *certsservice.CertsCustomSettings) { settings.SpendRetention = 6 * 24 * time.Hour },
	} {
		settings := certsservice.DefaultCertsCustomSettings()
		change(settings)
		if err := settings.Validate(); err == nil {
			t.Errorf("a refused value passed: %+v", settings)
		}
	}
}
