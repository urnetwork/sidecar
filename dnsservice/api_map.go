// The custom-host map's routes and judgments (§12.6, §12.8, §13.4, D-TLS-12, D-DNS-9, FS-35, FS-122, FI-11;
// DNS-M6-03): what each lb interface's lbmap (§19.5 W1) and the dns edges' route probes tell the block, and
// what the block makes of it.
//
//   - GET /dns/internal/custom-host-map?interface=&applied=&loaded=&master_pid=&master_start_ms= (lbmap): the
//     newest version of the map, {format, version, digest, hosts}, at once when applied is absent or differs,
//     else held at most map.hold_s until it differs, then 204. Each poll is recorded: its time, and the version
//     and nginx master it says nginx runs, so a master changed since the report, or one running an older map,
//     has loaded no version. The interface must be one of the lb inventory's (plan-TLS-internal-credentials).
//   - POST /dns/internal/custom-host-map/applied (lbmap): the version the interface's nginx loaded, its digest
//     and master, the hosts it added and dropped against the map it held, and the last load that failed. The
//     report must name a version the block knows by its digest, or one it no longer holds. A failed load is
//     counted by stage and logged, and keeps the interface on the version it reported; the store keeps no
//     failure, which §12.14's report and §2.8 dns-1 do not name.
//   - POST /dns/internal/route-probes (dnsedge): a round's route probes from one edge (probe_route.go), each
//     result taken only for the version the interface reported, by that version's probe name, and each host
//     only among the hosts that version added.
//
// Judgments, each a pure function of the store's state and the block's clock (DnsMapSettings):
//
//   - An interface is current for a version v once it reported v or a later one, lbmap polled within
//     map.poll_silence_s, an edge's probe of the reported version's probe name passed within map.probe_fresh_s,
//     and the latest probe of each added host the edges probe (the first probe.route_hosts) passed.
//   - A custom host is ready once every interface is current for its map_version, which sets ready_time; one
//     that is not shows as pending, naming those interfaces (GET /network/dns). Readiness is a target, not a
//     timer: nothing turns ready by time.
//   - An interface is map-stale when it is not current for the newest version older than map.stale_after_s,
//     named in each feed answer so both edges drop it from user-name answers, and never every interface: when
//     all would be, those that reported the newest version stand.
//
// The block counts every interface of the lb inventory for readiness, since it holds no view of §12.6's
// health probes, which the edges keep to themselves: an interface failing them keeps new hosts pending, the
// closed direction, until it leaves the inventory. The map is one for the deployment's one user root.

package dnsservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The map's routes (plan-DNS-internal-route-credential's prefix over §12.8's paths).
const (
	DnsCustomHostMapPath        = DnsInternalPathPrefix + "custom-host-map"
	DnsCustomHostMapAppliedPath = DnsInternalPathPrefix + "custom-host-map/applied"
)

// The zone of every version's probe name (§13.4, RFC 6761 §6.4): nothing resolves there.
const DnsCustomHostMapProbeZone = "map.probe.invalid"

// How many hex digits of the digest a probe name takes (§13.4's digest[0:12]).
const dnsCustomHostMapProbeDigestLength = 12

// A load's stage, as a failure's report names it.
const (
	DnsMapStageRender = "render"
	DnsMapStageTest   = "test"
	DnsMapStageReload = "reload"
)

var (
	// A report or poll the block cannot take: 400. Nothing of it is recorded.
	ErrDnsMapReportRefused = errors.New("dns custom-host map report refused")
)

// One version of the map (§12.8): the body of GET custom-host-map.
type DnsCustomHostMap struct {
	// Read first, as every feed body's is.
	Format int `json:"format"`
	// Raised by each change to the active rows, never lowered.
	Version uint64 `json:"version"`
	// DnsCustomHostMapDigest of Hosts.
	Digest string `json:"digest"`
	// The active custom hosts, lowercase names with no final dot, sorted.
	Hosts []string `json:"hosts"`
}

// An nginx master as a report names it.
type DnsMapMaster struct {
	Pid             int   `json:"pid"`
	StartTimeMillis int64 `json:"start_time_ms"`
}

// The master as the store keeps it: "<pid>:<start ms>".
func (self *DnsMapMaster) key() string {
	if self == nil {
		return ""
	}
	return strconv.Itoa(self.Pid) + ":" + strconv.FormatInt(self.StartTimeMillis, 10)
}

// A load that failed: its version and digest and the stage that refused it.
type DnsMapFailure struct {
	Version uint64 `json:"version"`
	Digest  string `json:"digest,omitempty"`
	Stage   string `json:"stage"`
}

// The body of POST custom-host-map/applied (warp's LbMapReport): what one interface's nginx runs, and the last
// load that failed.
type DnsCustomHostMapReport struct {
	Format    int    `json:"format"`
	Interface string `json:"interface"`
	// The version the master runs, 0 for none.
	Version uint64        `json:"version,omitempty"`
	Digest  string        `json:"digest,omitempty"`
	Master  *DnsMapMaster `json:"master,omitempty"`
	// The hosts that version added and dropped against the map nginx held before it.
	Added   []string `json:"added,omitempty"`
	Dropped []string `json:"dropped,omitempty"`
	// The last load that failed, while its version is above Version.
	Failure *DnsMapFailure `json:"failure,omitempty"`
}

// One poll as GET custom-host-map carries it.
type DnsMapPoll struct {
	Interface string
	// The version nginx runs, 0 for none.
	Loaded uint64
	// "<pid>:<start ms>", "" when lbmap does not know it yet.
	Master string
	Time   time.Time
}

// The first map load at or above a restore's target, kept across later reports and probe rounds.
type DnsMapRestoreReport struct {
	Version  uint64   `json:"version"`
	Received bool     `json:"received,omitempty"`
	Added    []string `json:"added,omitempty"`
	Dropped  []string `json:"dropped,omitempty"`
}

// What the store keeps of one interface: dns_custom_host_map_applied's row (§12.14).
type DnsMapInterface struct {
	Name string
	// The version it reported loading, 0 for none, and that version's digest and nginx master.
	ReportedVersion uint64
	Digest          string
	Master          string
	// When lbmap last polled or reported. Zero for never.
	PollTime time.Time
	// The reported version whose probe name an edge's probe last passed, and when.
	ProbeVersion uint64
	ProbeTime    time.Time
	// The hosts the reported version added, at most probe.route_hosts, which the edges probe, and those it
	// dropped, which a restore lists.
	AddedHosts   []string
	DroppedHosts []string
	// The latest probe of each added host for the reported version.
	HostProbes map[string]bool
	Restore    *DnsMapRestoreReport
}

// A copy that shares nothing with this one.
func (self *DnsMapInterface) Clone() *DnsMapInterface {
	clone := *self
	clone.AddedHosts = slices.Clone(self.AddedHosts)
	clone.DroppedHosts = slices.Clone(self.DroppedHosts)
	if self.Restore != nil {
		report := *self.Restore
		report.Added = slices.Clone(report.Added)
		report.Dropped = slices.Clone(report.Dropped)
		clone.Restore = &report
	}
	clone.HostProbes = map[string]bool{}
	for host, passed := range self.HostProbes {
		clone.HostProbes[host] = passed
	}
	return &clone
}

// Forgets the version the interface reported, which nginx no longer runs.
func (self *DnsMapInterface) clearReport() {
	self.ReportedVersion = 0
	self.Digest = ""
	self.AddedHosts = nil
	self.DroppedHosts = nil
	self.HostProbes = map[string]bool{}
}

// One version as the store keeps it (dns_custom_host_map, 7 d).
type DnsMapVersion struct {
	Version    uint64
	Digest     string
	CreateTime time.Time
}

// The map's whole state for the judgments.
type DnsMapState struct {
	// Every version kept, in version order.
	Versions []DnsMapVersion
	// One a lb inventory interface, in name order.
	Interfaces []*DnsMapInterface
	// The distinct map versions active custom hosts hold, ascending, 0 left out.
	HostVersions []uint64
}

// The digest of a version's hosts (§13.4): SHA-256 over them in bytewise order, each followed by one 0x00
// byte, as 64 lowercase hex digits, as warp's lbmap computes it.
func DnsCustomHostMapDigest(hosts []string) string {
	sortedHosts := slices.Clone(hosts)
	slices.Sort(sortedHosts)
	hash := sha256.New()
	for _, host := range sortedHosts {
		hash.Write([]byte(host))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Whether text is a lowercase hex SHA-256.
func isDnsMapDigest(text string) bool {
	if len(text) != 2*sha256.Size || strings.ToLower(text) != text {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}

// A version's probe name, <digest[0:12]>.map.probe.invalid, with no final dot as SNI carries it; "" for a
// digest that is no SHA-256.
func DnsCustomHostMapProbeName(digest string) string {
	if !isDnsMapDigest(digest) {
		return ""
	}
	return digest[:dnsCustomHostMapProbeDigestLength] + "." + DnsCustomHostMapProbeZone
}

// Records one poll: its time, and a master changed since the report, or a version below the reported one,
// takes the report away, since nginx runs no version lbmap reported.
func ApplyDnsMapPoll(lbInterface *DnsMapInterface, poll *DnsMapPoll) {
	lbInterface.PollTime = poll.Time
	if lbInterface.ReportedVersion == 0 {
		return
	}
	if (poll.Master != "" && poll.Master != lbInterface.Master) || poll.Loaded < lbInterface.ReportedVersion {
		lbInterface.clearReport()
	}
}

// Records one report at now, the added hosts kept to the first routeHostCount in order and the dropped to
// droppedMaxCount: a repeat of the version and master keeps the host probes, and anything else starts them
// again.
func ApplyDnsMapReport(lbInterface *DnsMapInterface, report *DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) {
	lbInterface.PollTime = now
	if restore := lbInterface.Restore; restore != nil && !restore.Received && restore.Version <= report.Version {
		restore.Added = slices.Clone(report.Added)
		restore.Dropped = slices.Clone(report.Dropped)
		restore.Received = true
	}
	master := report.Master.key()
	if report.Version != 0 && report.Version == lbInterface.ReportedVersion && master == lbInterface.Master && report.Digest == lbInterface.Digest {
		return
	}
	lbInterface.clearReport()
	if report.Version == 0 {
		lbInterface.Master = master
		return
	}
	lbInterface.ReportedVersion = report.Version
	lbInterface.Digest = report.Digest
	lbInterface.Master = master
	added := slices.Clone(report.Added)
	slices.Sort(added)
	added = slices.Compact(added)
	lbInterface.AddedHosts = added[:min(len(added), max(routeHostCount, 0))]
	dropped := slices.Clone(report.Dropped)
	slices.Sort(dropped)
	dropped = slices.Compact(dropped)
	lbInterface.DroppedHosts = dropped[:min(len(dropped), max(droppedMaxCount, 0))]
}

// Takes one interface's route probes at now when they are for the version it reported, by that version's
// probe name, and each host only among the hosts that version added. Whether anything was taken.
func ApplyDnsRouteProbes(lbInterface *DnsMapInterface, result *DnsRouteProbeResult, now time.Time) bool {
	if lbInterface.ReportedVersion == 0 || result.Version != lbInterface.ReportedVersion {
		return false
	}
	if probeName := DnsCustomHostMapProbeName(lbInterface.Digest); probeName == "" || strings.TrimSuffix(result.ProbeName, ".") != probeName {
		return false
	}
	if result.ProbePassed {
		lbInterface.ProbeVersion = result.Version
		lbInterface.ProbeTime = now
	}
	if lbInterface.HostProbes == nil {
		lbInterface.HostProbes = map[string]bool{}
	}
	for _, host := range result.Hosts {
		name := strings.TrimSuffix(host.Host, ".")
		if slices.Contains(lbInterface.AddedHosts, name) {
			lbInterface.HostProbes[name] = host.Passed
		}
	}
	return true
}

// Whether lbInterface is current for version at now (see the file header).
func (self *DnsMapSettings) InterfaceCurrent(lbInterface *DnsMapInterface, version uint64, now time.Time) bool {
	if lbInterface.ReportedVersion == 0 || lbInterface.ReportedVersion < version {
		return false
	}
	if lbInterface.PollTime.IsZero() || dnsSeconds(self.PollSilenceSeconds) < now.Sub(lbInterface.PollTime) {
		return false
	}
	if lbInterface.ProbeVersion != lbInterface.ReportedVersion || lbInterface.ProbeTime.IsZero() ||
		dnsSeconds(self.ProbeFreshSeconds) < now.Sub(lbInterface.ProbeTime) {
		return false
	}
	for _, host := range lbInterface.AddedHosts {
		if !lbInterface.HostProbes[host] {
			return false
		}
	}
	return true
}

// What the block makes of the map's state at one time.
type DnsMapJudgment struct {
	// Interfaces the edges drop from user-name answers, by name.
	MapStale map[string]bool
	// Each of the state's host versions: whether every interface is current for it.
	Ready map[uint64]bool
	// Each host version that is not ready: the interfaces not current for it, in name order.
	Pending map[uint64][]string
}

// The judgments of state at now (see the file header).
func (self *DnsMapSettings) Judge(state *DnsMapState, now time.Time) *DnsMapJudgment {
	judgment := &DnsMapJudgment{MapStale: map[string]bool{}, Ready: map[uint64]bool{}, Pending: map[uint64][]string{}}
	for _, version := range state.HostVersions {
		pending := []string{}
		for _, lbInterface := range state.Interfaces {
			if !self.InterfaceCurrent(lbInterface, version, now) {
				pending = append(pending, lbInterface.Name)
			}
		}
		slices.Sort(pending)
		judgment.Ready[version] = len(state.Interfaces) != 0 && len(pending) == 0
		if !judgment.Ready[version] {
			judgment.Pending[version] = pending
		}
	}
	// the newest version older than map.stale_after_s, which every interface must be current for
	staleVersion := uint64(0)
	for _, version := range state.Versions {
		if dnsSeconds(self.StaleAfterSeconds) <= now.Sub(version.CreateTime) && staleVersion < version.Version {
			staleVersion = version.Version
		}
	}
	if staleVersion == 0 {
		return judgment
	}
	stale := []*DnsMapInterface{}
	for _, lbInterface := range state.Interfaces {
		if !self.InterfaceCurrent(lbInterface, staleVersion, now) {
			stale = append(stale, lbInterface)
		}
	}
	if len(stale) == len(state.Interfaces) {
		// never every interface: those that reported the newest version stand
		newest := uint64(0)
		for _, lbInterface := range stale {
			newest = max(newest, lbInterface.ReportedVersion)
		}
		stale = slices.DeleteFunc(stale, func(lbInterface *DnsMapInterface) bool { return lbInterface.ReportedVersion == newest })
	}
	for _, lbInterface := range stale {
		judgment.MapStale[lbInterface.Name] = true
	}
	return judgment
}

// The store's half of the map: dns_custom_host_map and dns_custom_host_map_applied, and network_dns_custom_host's
// readiness, for the deployment's one user root. Every method is safe for concurrent use, and none may be called
// with a state lock held.
type DnsCustomHostMapStore interface {
	// The newest version, nil before any.
	CustomHostMap(ctx context.Context, root string) (*DnsCustomHostMap, error)
	// The state the judgments read.
	CustomHostMapState(ctx context.Context, root string) (*DnsMapState, error)
	// Records a poll by ApplyDnsMapPoll. An interface with no row is added.
	RecordMapPoll(ctx context.Context, root string, poll *DnsMapPoll) error
	// Records a report at now by ApplyDnsMapReport. An interface with no row is added.
	RecordMapReport(ctx context.Context, root string, report *DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) error
	// Records a round's route probes at now by ApplyDnsRouteProbes, for interfaces it holds rows of.
	RecordRouteProbes(ctx context.Context, root string, report *DnsRouteProbeReport, now time.Time) error
	// Keeps one row for each of names, the lb inventory's interfaces: adds a row for each it lacks, and removes
	// every other, since a report leaves with its interface (§12.14).
	SyncMapInterfaces(ctx context.Context, root string, names []string) error
	// Sets ready_time at now on the active custom hosts of each version ready names true, where it is not set,
	// and clears it on those of each version ready names false.
	SetCustomHostReadiness(ctx context.Context, root string, ready map[uint64]bool, now time.Time) error
}

// The map's routes.
func (self *DnsApi) mapRoutes() []*dnsApiRoute {
	// none changes zone data, so writes: false leaves them be
	return []*dnsApiRoute{
		{method: http.MethodGet, path: DnsCustomHostMapPath, class: DnsCallerLbmap, serve: self.serveCustomHostMap},
		{method: http.MethodPost, path: DnsCustomHostMapAppliedPath, class: DnsCallerLbmap, serve: self.serveCustomHostMapApplied},
		{method: http.MethodPost, path: DnsRouteProbesPath, class: DnsCallerEdge, serve: self.serveRouteProbes},
	}
}

// The labels of the map counter.
const (
	dnsMapResultPolled   = "polled"
	dnsMapResultReported = "reported"
	dnsMapResultProbes   = "probes"
	dnsMapResultRefused  = "refused"
	dnsMapResultFailed   = "failed"
)

// The map's store, or a 503 answered and nil.
func (self *DnsApi) mapStore(writer http.ResponseWriter) DnsCustomHostMapStore {
	if self.deps.CustomHostMaps == nil {
		self.metrics.maps.Add(1, dnsMapResultFailed)
		retryAfter := int(math.Ceil(self.host.GatesOrClosed().RetryAfter().Seconds()))
		writer.Header().Set("Retry-After", strconv.Itoa(max(retryAfter, 1)))
		http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
		return nil
	}
	return self.deps.CustomHostMaps
}

// Whether name is an interface of the lb inventory.
func (self *DnsApi) inventoryInterface(name string) bool {
	if self.deps.Interfaces == nil || name == "" {
		return false
	}
	return slices.ContainsFunc(self.deps.Interfaces(), func(lbInterface DnsLbInterface) bool { return lbInterface.Name == name })
}

// GET custom-host-map (see the file header).
func (self *DnsApi) serveCustomHostMap(writer http.ResponseWriter, request *http.Request) {
	store := self.mapStore(writer)
	if store == nil {
		return
	}
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	query := request.URL.Query()
	name := query.Get("interface")
	if !self.inventoryInterface(name) {
		self.metrics.maps.Add(1, dnsMapResultRefused)
		http.Error(writer, "no such interface", http.StatusForbidden)
		return
	}
	poll := &DnsMapPoll{Interface: name, Time: self.clock.Now()}
	var applied *uint64
	parseVersion := func(key string) (uint64, bool) {
		value, err := strconv.ParseUint(query.Get(key), 10, 64)
		return value, err == nil
	}
	if query.Has("applied") {
		value, ok := parseVersion("applied")
		if !ok {
			http.Error(writer, "applied is not a version", http.StatusBadRequest)
			return
		}
		applied = &value
	}
	if query.Has("loaded") {
		value, ok := parseVersion("loaded")
		if !ok {
			http.Error(writer, "loaded is not a version", http.StatusBadRequest)
			return
		}
		poll.Loaded = value
	}
	if query.Has("master_pid") || query.Has("master_start_ms") {
		pid, pidErr := strconv.Atoi(query.Get("master_pid"))
		startMillis, startErr := strconv.ParseInt(query.Get("master_start_ms"), 10, 64)
		if pidErr != nil || startErr != nil || pid <= 0 {
			http.Error(writer, "a master that is not one", http.StatusBadRequest)
			return
		}
		poll.Master = (&DnsMapMaster{Pid: pid, StartTimeMillis: startMillis}).key()
	}
	if err := store.RecordMapPoll(request.Context(), root, poll); err != nil {
		self.metrics.maps.Add(1, dnsMapResultFailed)
		dnsStoreUnavailable(writer)
		return
	}
	self.metrics.maps.Add(1, dnsMapResultPolled)
	customHostMap, err := self.customHostMapAnswer(request, store, root, applied)
	if err != nil {
		dnsStoreUnavailable(writer)
		return
	}
	if customHostMap == nil {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	dnsWriteJson(writer, customHostMap)
}

// The newest version at once when applied is absent or differs, else held until it differs, the hold's end,
// the request's end or Drain, nil when it ends with nothing newer or no version exists.
func (self *DnsApi) customHostMapAnswer(request *http.Request, store DnsCustomHostMapStore, root string, applied *uint64) (*DnsCustomHostMap, error) {
	done := self.holdStarted()
	defer done()
	holdEnded := self.clock.After(dnsSeconds(self.settings.Map.HoldSeconds))
	for {
		customHostMap, err := store.CustomHostMap(request.Context(), root)
		if err != nil {
			return nil, err
		}
		if customHostMap != nil && (applied == nil || *applied != customHostMap.Version) {
			return customHostMap, nil
		}
		if applied == nil {
			// lbmap's start asks for an answer at once, and there is no version to give
			return nil, nil
		}
		next := self.clock.After(dnsSeconds(self.settings.Map.HoldPollSeconds))
		ended := self.park(func() bool {
			select {
			case <-next:
				return false
			case <-holdEnded:
			case <-self.draining:
			case <-request.Context().Done():
			}
			return true
		})
		if ended {
			if err := request.Context().Err(); err != nil {
				return nil, err
			}
			return nil, nil
		}
	}
}

// Whether report is one the block can take (see the file header), against the versions it holds.
func (self *DnsApi) validateMapReport(report *DnsCustomHostMapReport, state *DnsMapState) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsMapReportRefused, fmt.Sprintf(format, args...))
	}
	if err := checkDnsFormat(report.Format); err != nil {
		return err
	}
	if !self.inventoryInterface(report.Interface) {
		return refuse("no such interface")
	}
	if report.Version != 0 {
		if !isDnsMapDigest(report.Digest) {
			return refuse("a digest that is no SHA-256")
		}
		for _, version := range state.Versions {
			if version.Version == report.Version && version.Digest != report.Digest {
				return refuse("version %d's digest is another", report.Version)
			}
		}
	}
	if report.Master != nil && report.Master.Pid <= 0 {
		return refuse("a master that is not one")
	}
	hostLimit := self.settings.Map.ReportHostMaxCount
	if hostLimit < len(report.Added) || hostLimit < len(report.Dropped) {
		return refuse("more than %d hosts", hostLimit)
	}
	for _, host := range slices.Concat(report.Added, report.Dropped) {
		if !isDnsRouteReportName(host) {
			return refuse("a host that is empty or too long")
		}
	}
	if failure := report.Failure; failure != nil {
		if failure.Version == 0 || !slices.Contains([]string{DnsMapStageRender, DnsMapStageTest, DnsMapStageReload}, failure.Stage) {
			return refuse("a failure with no version or stage")
		}
	}
	return nil
}

// POST custom-host-map/applied (see the file header), then readiness from what it changed.
func (self *DnsApi) serveCustomHostMapApplied(writer http.ResponseWriter, request *http.Request) {
	store := self.mapStore(writer)
	if store == nil {
		return
	}
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(self.settings.Map.ReportMaxByteCount)+1))
	if err != nil || self.settings.Map.ReportMaxByteCount < len(body) {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	report := &DnsCustomHostMapReport{}
	if err := json.Unmarshal(body, report); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	state, err := store.CustomHostMapState(request.Context(), root)
	if err != nil {
		self.metrics.maps.Add(1, dnsMapResultFailed)
		dnsStoreUnavailable(writer)
		return
	}
	if err := self.validateMapReport(report, state); err != nil {
		self.metrics.maps.Add(1, dnsMapResultRefused)
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	now := self.clock.Now()
	if err := store.RecordMapReport(request.Context(), root, report, now, self.settings.Probe.RouteHostCount, self.settings.Map.ReportHostMaxCount); err != nil {
		self.metrics.maps.Add(1, dnsMapResultFailed)
		dnsStoreUnavailable(writer)
		return
	}
	self.metrics.maps.Add(1, dnsMapResultReported)
	if report.Failure != nil {
		self.metrics.mapLoadFailures.Add(1, report.Failure.Stage)
		self.log.Warningf("[dns]custom-host map: an interface's load of version %d failed at %s", report.Failure.Version, report.Failure.Stage)
	}
	self.updateCustomHostReadiness(request.Context(), store, root, now)
	writer.WriteHeader(http.StatusNoContent)
}

// POST route-probes (see the file header), then readiness from what they changed.
func (self *DnsApi) serveRouteProbes(writer http.ResponseWriter, request *http.Request) {
	store := self.mapStore(writer)
	if store == nil {
		return
	}
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(self.settings.Map.ProbesMaxByteCount)+1))
	if err != nil || self.settings.Map.ProbesMaxByteCount < len(body) {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	report, err := DecodeDnsRouteProbeReport(body)
	if err != nil {
		self.metrics.maps.Add(1, dnsMapResultRefused)
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	now := self.clock.Now()
	if err := store.RecordRouteProbes(request.Context(), root, report, now); err != nil {
		self.metrics.maps.Add(1, dnsMapResultFailed)
		dnsStoreUnavailable(writer)
		return
	}
	self.metrics.maps.Add(1, dnsMapResultProbes)
	self.updateCustomHostReadiness(request.Context(), store, root, now)
	writer.WriteHeader(http.StatusNoContent)
}

// Judges readiness from the store's state at now and has the store set and clear ready_time by it. A failure
// is logged and waits for the next report or probe round.
func (self *DnsApi) updateCustomHostReadiness(ctx context.Context, store DnsCustomHostMapStore, root string, now time.Time) {
	state, err := store.CustomHostMapState(ctx, root)
	if err == nil {
		err = store.SetCustomHostReadiness(ctx, root, self.settings.Map.Judge(state, now).Ready, now)
	}
	if err != nil {
		self.log.Warningf("[dns]custom-host readiness waits for the next report: %v", err)
	}
}

// Fills interfaces' map fields from the store's state at now (§12.6's feed): each one's reported version with
// its probe name and the hosts it added, and whether it is map-stale. A state that cannot be read leaves them
// zero, so the feed still answers, and no interface is dropped for the map meanwhile.
func (self *DnsApi) fillMapInterfaces(ctx context.Context, root string, interfaces []DnsLbInterface) {
	if self.deps.CustomHostMaps == nil || len(interfaces) == 0 {
		return
	}
	state, err := self.deps.CustomHostMaps.CustomHostMapState(ctx, root)
	if err != nil {
		self.log.Warningf("[dns]custom-host map state unread, the feed names no map: %v", err)
		return
	}
	now := self.clock.Now()
	judgment := self.settings.Map.Judge(state, now)
	for index := range interfaces {
		lbInterface := &interfaces[index]
		for _, mapInterface := range state.Interfaces {
			if mapInterface.Name != lbInterface.Name {
				continue
			}
			// a silent lbmap has loaded no version, so nothing is probed until it reports again
			silent := mapInterface.PollTime.IsZero() || dnsSeconds(self.settings.Map.PollSilenceSeconds) < now.Sub(mapInterface.PollTime)
			if mapInterface.ReportedVersion != 0 && !silent {
				lbInterface.ReportedVersion = mapInterface.ReportedVersion
				lbInterface.ProbeName = DnsCustomHostMapProbeName(mapInterface.Digest)
				lbInterface.AddedHosts = slices.Clone(mapInterface.AddedHosts)
			}
			lbInterface.MapStale = judgment.MapStale[lbInterface.Name]
		}
	}
}

// Keeps the store's interface rows to the lb inventory, for each root. A failure waits for the next probe.
func (self *DnsApi) syncMapInterfaces(ctx context.Context) {
	if self.deps.CustomHostMaps == nil || self.deps.Interfaces == nil {
		return
	}
	names := []string{}
	for _, lbInterface := range self.deps.Interfaces() {
		names = append(names, lbInterface.Name)
	}
	for _, root := range self.settings.Roots {
		if err := self.deps.CustomHostMaps.SyncMapInterfaces(ctx, root, names); err != nil {
			self.log.Warningf("[dns]custom-host map interfaces wait for the next probe: %v", err)
		}
	}
}
