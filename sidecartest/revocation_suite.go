// §22.7's revocation suite (TEST-M2-12; R-TEST-4, D-TEST-6, I-5, I-15, I-16): "a removed member reads nothing new".
// Its parts sit in five plans (KEYS, SOCK, TLS, TEAM, CORE) and no one owns it whole, so the suite is a registry and a
// runner: each area registers its checks (RegisterRevocationCheck), each naming the ways X loses access it checks,
// and the suite runs every check in every way it names, each on a fresh Net of the run's tier, X keeping its local
// state and raw store access as a malicious server allows (RevokedActor), every key it ever held recorded through
// testHookSecret.
//
//	ways   member remove, SCIM active=false, a device revoke (an admin's, or its own member's as lost or as a
//	       compromise), a read loss, a grant's expiry, a suspension, an ephemeral reap. A form is the ways one stage
//	       runs: the device form at M2, a member revoking its own device once CORE-M3-03 lands at M3, the member form
//	       at M6 (TEST-M6-01)
//	gate   a check whose point is what readers and writers hold themselves runs with evs's gate off (D-TEST-6), so a
//	       cryptographic hole cannot hide behind a server refusal; one whose point is the refusal (412 GATE_CLOSED, a
//	       token refused in its window) runs with it on. Only a sidecar_testhooks build can turn the gate off
//	       (Net.SetEvsGate, QD-338), so on another leg a gate-off check reads open, never passed
//	report each (way, check) passes, fails or reads open with why: hooks the leg lacks, a mechanism not landed.
//	       A way of the form that no registered check names fails as missing, as Missing does for a gate's rows
//
// What a check holds is its own: a check that passes because X held nothing proves nothing, so a check judging X's
// keys asserts X held the keys before the loss (RevokedActor.OpensGeneration on the old generation) and reads open
// without the hooks. Timing windows run on the Net's fake clock.
//
// Registration is from package-level vars, as fault's rows' are; safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One way X loses access (§22.7's revocation suite).
type RevocationWay string

const (
	RevocationMemberRemove              RevocationWay = "member-remove"
	RevocationScimInactive              RevocationWay = "scim-active-false"
	RevocationDeviceRevoke              RevocationWay = "device-revoke"
	RevocationOwnDeviceRevokeLost       RevocationWay = "own-device-revoke-lost"
	RevocationOwnDeviceRevokeCompromise RevocationWay = "own-device-revoke-compromise"
	RevocationReadLoss                  RevocationWay = "read-loss"
	RevocationGrantExpiry               RevocationWay = "grant-expiry"
	RevocationSuspension                RevocationWay = "suspension"
	RevocationEphemeralReap             RevocationWay = "ephemeral-reap"
)

// Every way, in §22.7's order.
func RevocationWays() []RevocationWay {
	return []RevocationWay{
		RevocationMemberRemove, RevocationScimInactive, RevocationDeviceRevoke, RevocationOwnDeviceRevokeLost,
		RevocationOwnDeviceRevokeCompromise, RevocationReadLoss, RevocationGrantExpiry, RevocationSuspension,
		RevocationEphemeralReap,
	}
}

// The ways one stage of the suite runs.
type RevocationForm string

const (
	// M2: X a device, by an admin's revoke, a read loss, a grant's expiry, a suspension or an ephemeral reap.
	RevocationFormDevice RevocationForm = "device"
	// M3: a member revoking its own device as lost or as a compromise (CORE-M3-03).
	RevocationFormOwnDevice RevocationForm = "own-device"
	// M6: X a member, removed or made inactive by SCIM (TEST-M6-01).
	RevocationFormMember RevocationForm = "member"
)

// The form's ways.
func (self RevocationForm) Ways() []RevocationWay {
	switch self {
	case RevocationFormDevice:
		return []RevocationWay{RevocationDeviceRevoke, RevocationReadLoss, RevocationGrantExpiry, RevocationSuspension, RevocationEphemeralReap}
	case RevocationFormOwnDevice:
		return []RevocationWay{RevocationOwnDeviceRevokeLost, RevocationOwnDeviceRevokeCompromise}
	case RevocationFormMember:
		return []RevocationWay{RevocationMemberRemove, RevocationScimInactive}
	}
	return nil
}

// One area's check, which the suite runs in every way it names.
type RevocationCheck struct {
	// Its name, unique: "keys/x-opens-nothing-claimed-after".
	Id string
	// The area whose mechanism it holds, to which a failure goes back: KEYS, SOCK, TLS, TEAM, CORE, EVS.
	Area string
	Ways []RevocationWay
	// Runs with evs's gate off, so readers' and writers' own checks are what refuse X (D-TEST-6).
	GateOff bool
	// Builds its world on run.Net, makes X lose access by run.Way, and checks. A non-empty open says why it could
	// judge nothing, which the report keeps apart from a pass; an error fails the way.
	Run func(run *RevocationRun) (open string, err error)
}

// What a check runs with.
type RevocationRun struct {
	Ctx   context.Context
	T     testing.TB
	Way   RevocationWay
	Check *RevocationCheck
	// A fresh Net of the suite's tier, closed after the check.
	Net *Net
	// evs's gate is off for this run.
	GateOff bool
}

// X as the run's Net knows it, under its actor's name.
func (self *RevocationRun) RevokedActor(actor string) *RevokedActor {
	return NewRevokedActor(self.Net, actor)
}

var (
	revocationCheckLock sync.Mutex
	revocationChecks    []*RevocationCheck
)

// Registers check for the suite. A check with no id, run or way, a way the suite does not know, and a second check of
// one id each panic, since a registration runs from a package-level var and a binary that cannot link it must not
// pass. Returns check, so the var has a value.
func RegisterRevocationCheck(check *RevocationCheck) *RevocationCheck {
	if err := validateRevocationCheck(check); err != nil {
		panic(err)
	}
	revocationCheckLock.Lock()
	defer revocationCheckLock.Unlock()
	for _, other := range revocationChecks {
		if other.Id == check.Id {
			panic(fmt.Sprintf("revocation check %s is registered already", check.Id))
		}
	}
	revocationChecks = append(revocationChecks, check)
	return check
}

func validateRevocationCheck(check *RevocationCheck) error {
	switch {
	case check == nil || check.Id == "" || check.Run == nil:
		return errors.New("a revocation check needs an id and a run")
	case len(check.Ways) == 0:
		return fmt.Errorf("revocation check %s names no way", check.Id)
	}
	for _, way := range check.Ways {
		if !slices.Contains(RevocationWays(), way) {
			return fmt.Errorf("revocation check %s names %q, which is no way of §22.7's", check.Id, way)
		}
	}
	return nil
}

// Every check registered in this binary, in the order registered.
func RevocationChecks() []*RevocationCheck {
	revocationCheckLock.Lock()
	defer revocationCheckLock.Unlock()
	return slices.Clone(revocationChecks)
}

// X keeping its local state and raw store access, as a malicious server allows: every key its actor held through
// testHookSecret, never a list a test wrote by hand, and every object the Net's stores hold.
type RevokedActor struct {
	Net   *Net
	Actor string
}

func NewRevokedActor(net *Net, actor string) *RevokedActor {
	return &RevokedActor{Net: net, Actor: actor}
}

// Every key of kind X held.
func (self *RevokedActor) Keys(kind string) [][]byte {
	return self.Net.HeldSecrets().Secrets(self.Actor, kind)
}

// Every key X held, of every kind.
func (self *RevokedActor) AllKeys() [][]byte {
	keys := [][]byte{}
	for _, kind := range self.Net.HeldSecrets().Kinds(self.Actor) {
		keys = append(keys, self.Keys(kind)...)
	}
	return keys
}

// Whether X held anything: false on a leg without the hooks, where nothing reaches the record.
func (self *RevokedActor) HeldAny() bool {
	return 0 < len(self.Net.HeldSecrets().Kinds(self.Actor))
}

// Whether any key X held opens generation of ladder, a group's generations as gen/ holds them: as RK_g of it or of a
// later generation linked down to it (§10.5's GenLink), whatever kind it was held as.
func (self *RevokedActor) OpensGeneration(ladder []*sidecar.GkmGeneration, generation uint64) bool {
	byGeneration := map[uint64]*sidecar.GkmGeneration{}
	newest := uint64(0)
	for _, each := range ladder {
		if each == nil || each.Rotate == nil {
			continue
		}
		byGeneration[each.Rotate.GetGeneration()] = each
		newest = max(newest, each.Rotate.GetGeneration())
	}
	keys := self.AllKeys()
	for top := generation; top <= newest; top += 1 {
		topGeneration := byGeneration[top]
		if topGeneration == nil {
			continue
		}
		for _, held := range keys {
			key, err := sidecar.OpenEvsRepoKey(topGeneration, held)
			if err != nil {
				continue
			}
			for key != nil && generation < key.Generation() {
				parent := byGeneration[key.Generation()-1]
				if parent == nil {
					key = nil
					break
				}
				if key, err = key.OpenParent(parent); err != nil {
					key = nil
				}
			}
			if key != nil {
				return true
			}
		}
	}
	return false
}

// Every object under prefix on every cluster of the Net's host, as a malicious server serves X them: read under an
// inspecting context, so X's reads take no fault and count toward nothing.
func (self *RevokedActor) Objects(ctx context.Context, prefix string) (map[string][]byte, error) {
	inspect := InspectContext(ctx)
	objects := map[string][]byte{}
	blobs := self.Net.Host().Blobs
	clusterIds := slices.Clone(blobs.MetadataClusterIds())
	if segmentCluster, err := blobs.SegmentCluster(); err == nil {
		clusterIds = append(clusterIds, segmentCluster.ClusterId())
	}
	for _, clusterId := range clusterIds {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		startAfter := ""
		for {
			infos, more, err := cluster.List(inspect, prefix, startAfter, 1000)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				object, err := cluster.Get(inspect, info.Key)
				if err != nil {
					continue
				}
				body, err := io.ReadAll(object.Body)
				object.Body.Close()
				if err == nil {
					objects[clusterId+"\x00"+info.Key] = body
				}
			}
			if !more || len(infos) == 0 {
				break
			}
			startAfter = infos[len(infos)-1].Key
		}
	}
	return objects, nil
}

// What a run judged a way by: a check passes, fails, or reads open.
type RevocationResult struct {
	Way     RevocationWay
	CheckId string
	Area    string
	GateOff bool
	// Why it judged nothing, empty when it judged.
	Open string
	Err  error
}

func (self *RevocationResult) String() string {
	gate := "gate on"
	if self.GateOff {
		gate = "gate off"
	}
	switch {
	case self.Err != nil:
		return fmt.Sprintf("%s by %s (%s, %s): failed: %v", self.Way, self.CheckId, self.Area, gate, self.Err)
	case self.Open != "":
		return fmt.Sprintf("%s by %s (%s, %s): open: %s", self.Way, self.CheckId, self.Area, gate, self.Open)
	}
	return fmt.Sprintf("%s by %s (%s, %s): passed", self.Way, self.CheckId, self.Area, gate)
}

// One run of a form.
type RevocationReport struct {
	Form    RevocationForm
	Results []*RevocationResult
	// The form's ways no check names, each a failure.
	Missing []RevocationWay
}

// Whether any check failed or any way of the form went unchecked. An open result is not a failure, and not a pass.
func (self *RevocationReport) Failed() bool {
	if 0 < len(self.Missing) {
		return true
	}
	for _, result := range self.Results {
		if result.Err != nil {
			return true
		}
	}
	return false
}

// Every result of way, in the order run.
func (self *RevocationReport) Of(way RevocationWay) []*RevocationResult {
	results := []*RevocationResult{}
	for _, result := range self.Results {
		if result.Way == way {
			results = append(results, result)
		}
	}
	return results
}

func (self *RevocationReport) String() string {
	var text strings.Builder
	fmt.Fprintf(&text, "the revocation suite's %s form:", self.Form)
	for _, way := range self.Missing {
		fmt.Fprintf(&text, "\n%s: missing, no check names it", way)
	}
	for _, result := range self.Results {
		fmt.Fprintf(&text, "\n%s", result)
	}
	return text.String()
}

// The tunables of a suite run.
type RevocationSuiteSettings struct {
	// The Net each check runs on: T2's defaults when nil, server's sidecart3 NetSettings on T3.
	Net *NetSettings
	// The checks to run; nil runs every registered check.
	Checks []*RevocationCheck
}

func DefaultRevocationSuiteSettings() *RevocationSuiteSettings {
	return &RevocationSuiteSettings{}
}

// The suite of one form.
type RevocationSuite struct {
	Form RevocationForm
}

// Runs every check of settings in every way of the form it names, each on a fresh Net closed before the next, with
// evs's gate off where the check asks. settings nil takes the defaults.
func (self *RevocationSuite) Run(t testing.TB, settings *RevocationSuiteSettings) *RevocationReport {
	if settings == nil {
		settings = DefaultRevocationSuiteSettings()
	}
	checks := settings.Checks
	if checks == nil {
		checks = RevocationChecks()
	}
	report := &RevocationReport{Form: self.Form}
	for _, way := range self.Form.Ways() {
		named := false
		for _, check := range checks {
			if !slices.Contains(check.Ways, way) {
				continue
			}
			named = true
			report.Results = append(report.Results, runRevocationCheck(t, settings, way, check))
		}
		if !named {
			report.Missing = append(report.Missing, way)
		}
	}
	return report
}

// One check in one way on a fresh Net.
func runRevocationCheck(t testing.TB, settings *RevocationSuiteSettings, way RevocationWay, check *RevocationCheck) (result *RevocationResult) {
	result = &RevocationResult{Way: way, CheckId: check.Id, Area: check.Area, GateOff: check.GateOff}
	if err := validateRevocationCheck(check); err != nil {
		result.Err = err
		return result
	}
	net := NewNet(t.Context(), settings.Net)
	defer net.Close()
	if check.GateOff {
		if err := setEvsGate(net, false); err != nil {
			result.Open = fmt.Sprintf("evs's gate cannot be switched off here: %v", err)
			return result
		}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Err = fmt.Errorf("the check panicked: %v", recovered)
		}
	}()
	result.Open, result.Err = check.Run(&RevocationRun{Ctx: net.Context(), T: t, Way: way, Check: check, Net: net, GateOff: check.GateOff})
	return result
}

// Runs the form's suite and fails t with each failure and each missing way, logging each open result.
func RunRevocationSuite(t testing.TB, form RevocationForm, settings *RevocationSuiteSettings) *RevocationReport {
	t.Helper()
	report := (&RevocationSuite{Form: form}).Run(t, settings)
	t.Log(report.String())
	for _, way := range report.Missing {
		t.Errorf("the revocation suite's %s form: %s is missing: no check names it", form, way)
	}
	for _, result := range report.Results {
		if result.Err != nil {
			t.Errorf("%s", result)
		}
	}
	return report
}

// What switches evs's gate for the process, registered by the package that links evs's engine (fault's
// evs_gate_testhooks.go), since sidecartest links no engine: off true turns 5d off.
var evsGateSwitch atomic.Pointer[func(off bool)]

// Registers switchGate as the process's gate switch. Returns true, so a package-level var has a value.
func SetEvsGateSwitch(switchGate func(off bool)) bool {
	evsGateSwitch.Store(&switchGate)
	return true
}

// The error a gate switch answers on a leg that cannot switch it, or with no engine linked to switch.
var ErrEvsGateFixed = errors.New("evs's gate is switched only in a sidecar_testhooks build that links evs's engine")
