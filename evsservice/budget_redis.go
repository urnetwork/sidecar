// {nvb_<set>} (§19.6's budget row, evs-10, plan-EVSB-nvb-fields): one hash a metadata cluster, whose
// fields expire one by one, as evs-10's ttl row reads: the governor's allowance and each process's
// report 15 s after their last write, and the governor's saved state 48 h after the loop's last write.
// Values are JSON: soft state that is rebuilt within an interval, read whole and never inside Lua, so
// no number passes through a double. Nothing here names a network or repo.
//
// A process writes its report as its own field, report:<process id>. The loop (EVSB-M2-07) reads the
// reports, steps its Governor, publishes the allowance and saves the state through the functions below.
// A field and its ttl are two calls, so a report whose ttl never landed could outlive its process: the
// governor drops a report older than ReportTtl by its own clock as well.

package evsservice

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The cluster's one key.
func writeBudgetKey(clusterId string) string {
	return "{nvb_" + clusterId + "}"
}

// The key's fields.
const (
	writeBudgetAllowanceField    = "allowance"
	writeBudgetStateField        = "state"
	writeBudgetReportFieldPrefix = "report:"
)

// Sets one field of the cluster's key and its ttl.
func setWriteBudgetField(ctx context.Context, redis sidecar.Redis, clusterId string, field string, value any, ttl time.Duration) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	key := writeBudgetKey(clusterId)
	if err := redis.HashSet(ctx, key, map[string][]byte{field: encoded}); err != nil {
		return err
	}
	return redis.HashExpire(ctx, key, []string{field}, ttl)
}

// Reads one field of the cluster's key into value, false when it is absent.
func getWriteBudgetField(ctx context.Context, redis sidecar.Redis, clusterId string, field string, value any) (bool, error) {
	encoded, found, err := redis.HashGet(ctx, writeBudgetKey(clusterId), field)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(encoded, value); err != nil {
		return false, err
	}
	return true, nil
}

// Writes report as the process's field, expiring with ReportTtl.
func writeWriteBudgetReport(ctx context.Context, redis sidecar.Redis, settings *WriteBudgetSettings, clusterId string, report *WriteBudgetReport) error {
	return setWriteBudgetField(ctx, redis, clusterId, writeBudgetReportFieldPrefix+report.ProcessId, report, settings.ReportTtl)
}

// The live reports on the cluster, in process id order. A field that does not parse is skipped, as the
// governor would drop it.
func ReadWriteBudgetReports(ctx context.Context, redis sidecar.Redis, clusterId string) ([]*WriteBudgetReport, error) {
	fieldValues, err := redis.HashGetAll(ctx, writeBudgetKey(clusterId))
	if err != nil {
		return nil, err
	}
	reports := []*WriteBudgetReport{}
	for _, field := range slices.Sorted(maps.Keys(fieldValues)) {
		processId, ok := strings.CutPrefix(field, writeBudgetReportFieldPrefix)
		if !ok {
			continue
		}
		report := &WriteBudgetReport{}
		if err := json.Unmarshal(fieldValues[field], report); err != nil || report.ProcessId != processId {
			continue
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// How many processes have a report on the cluster.
func readWriteBudgetReportCount(ctx context.Context, redis sidecar.Redis, clusterId string) (int, error) {
	fieldValues, err := redis.HashGetAll(ctx, writeBudgetKey(clusterId))
	if err != nil {
		return 0, err
	}
	count := 0
	for field := range fieldValues {
		if strings.HasPrefix(field, writeBudgetReportFieldPrefix) {
			count += 1
		}
	}
	return count, nil
}

// Publishes the allowance a step returned, expiring with AllowanceTtl.
func PublishWriteBudgetAllowance(ctx context.Context, redis sidecar.Redis, settings *WriteBudgetSettings, allowance *WriteBudgetAllowance) error {
	return setWriteBudgetField(ctx, redis, allowance.ClusterId, writeBudgetAllowanceField, allowance, settings.AllowanceTtl)
}

// The cluster's allowance, nil when none was published within AllowanceTtl. One that does not parse,
// or names another cluster, is an error: the process then runs as if it had none.
func readWriteBudgetAllowance(ctx context.Context, redis sidecar.Redis, clusterId string) (*WriteBudgetAllowance, error) {
	allowance := &WriteBudgetAllowance{}
	found, err := getWriteBudgetField(ctx, redis, clusterId, writeBudgetAllowanceField, allowance)
	if err != nil || !found {
		return nil, err
	}
	if allowance.ClusterId != clusterId {
		return nil, fmt.Errorf("an allowance for %q under %q", allowance.ClusterId, clusterId)
	}
	return allowance, nil
}

// Saves the governor's state, expiring with StateTtl.
func SaveGovernorState(ctx context.Context, redis sidecar.Redis, settings *WriteBudgetSettings, clusterId string, state *GovernorState) error {
	return setWriteBudgetField(ctx, redis, clusterId, writeBudgetStateField, state, settings.StateTtl)
}

// The governor's saved state, nil when it is absent, so a loop that takes the lease resumes it or starts
// B and W at zero.
func LoadGovernorState(ctx context.Context, redis sidecar.Redis, clusterId string) (*GovernorState, error) {
	state := &GovernorState{}
	found, err := getWriteBudgetField(ctx, redis, clusterId, writeBudgetStateField, state)
	if err != nil || !found {
		return nil, err
	}
	return state, nil
}
