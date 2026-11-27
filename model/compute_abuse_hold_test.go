package model

// The abuse hold's store (CARCH-M12-01; DESIGN-COMPUTE §17.2): its table as CARCH's part of MG-C1, after BAL's, read as
// server's runner and checks read a part; its reason classes; and the state the broker reads of a row. The statements
// run against PostgreSQL in server's computet3 (compute_abuse_hold_t3_test.go).

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
)

// CARCH owns MG-C1's second part, which stays unregistered until question carch-m12-01-compute-hold-row's answer
// gives compute-3 its words (I-18): the change that carries the answer registers it, and turns this test's first check
// around. Its one table holds no content, no money and no transfer balance, its times keep their zone, and server
// reads it as creating compute_abuse_hold.
func TestComputeAbuseHoldMigrationsWaitForTheirRow(t *testing.T) {
	if owners := ComputeMigrationGroupOwners(ComputeMigrationGroupC1); !slices.Equal(owners, []string{ComputeMigrationOwnerBal, ComputeMigrationOwnerCarch}) {
		t.Fatalf("MG-C1's owners are %v", owners)
	}
	if part := ComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerCarch); len(part) != 0 {
		t.Fatalf("CARCH's part registered before compute-3 names its table: %v", part)
	}
	built := ComputeAbuseHoldMigrations()
	if len(built) != 1 || built[0].Code != nil {
		t.Fatalf("the hold's part builds %v", built)
	}
	step := built[0]
	if regexp.MustCompile(`(?i)\b(DROP|RENAME|TRUNCATE)\b`).MatchString(step.Sql) {
		t.Errorf("the step %s names a word server's additivity check refuses", step.Id)
	}
	match := regexp.MustCompile(`(?is)\bCREATE TABLE (?:IF NOT EXISTS )?([a-z_][a-z0-9_]*) \((.*)\)`).FindStringSubmatch(step.Sql)
	if match == nil || match[1] != "compute_abuse_hold" || step.Id != "compute_abuse_hold" {
		t.Fatalf("the step reads as creating %v", match)
	}
	columns := []string{}
	for _, line := range strings.Split(match[2], "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] == "PRIMARY" {
			continue
		}
		columns = append(columns, fields[0])
	}
	if want := []string{"network_id", "reason", "hold_staff_id", "hold_time", "resume_staff_id", "resume_time", "version"}; !slices.Equal(columns, want) {
		t.Fatalf("compute_abuse_hold holds %v, want %v", columns, want)
	}
	sql := strings.ToLower(step.Sql)
	for _, word := range []string{"prompt", "query", "file", "body", "content", "message", "text", "transfer", "escrow", "address", "nano_usd", "numeric", "float", "timestamp without"} {
		if strings.Contains(sql, word) {
			t.Errorf("compute_abuse_hold names %s", word)
		}
	}
	if strings.Count(sql, "timestamptz") != 2 || strings.Contains(sql, " timestamp ") || strings.Contains(sql, " timestamp,") {
		t.Error("a time without its zone")
	}
}

// Every reason's word reads back as its reason, none and every other word are refused, and a row takes only a reason
// the build names.
func TestComputeAbuseHoldReasonWords(t *testing.T) {
	words := ComputeAbuseHoldReasonWords()
	if want := []string{"mining", "scanning", "spam", "fraud", "provider_complaint", "harmful_content", "terms", "takedown"}; !slices.Equal(words, want) {
		t.Fatalf("the words are %v", words)
	}
	for _, word := range words {
		reason, err := ParseComputeAbuseHoldReason(word)
		if err != nil || reason.String() != word || !reason.Valid() {
			t.Errorf("%s reads as %v %v", word, reason, err)
		}
	}
	for _, word := range []string{"none", "", "Mining", "mining ", "reason9", "abuse"} {
		if _, err := ParseComputeAbuseHoldReason(word); !errors.Is(err, ErrComputeAbuseHoldArgs) {
			t.Errorf("%q read as a reason: %v", word, err)
		}
	}
	if ComputeAbuseHoldReasonNone.Valid() || ComputeAbuseHoldReason(9).Valid() || ComputeAbuseHoldReason(9).String() != "reason9" {
		t.Error("a reason no row takes is valid")
	}
}

// The state the broker reads: a network never held reads version 0 and no hold; a standing hold its reason; a resumed
// one its version and no reason. Projection values round-trip.
func TestComputeAbuseHoldStateOfARow(t *testing.T) {
	if state := ComputeAbuseHoldStateOf(nil); state.Version != 0 || state.Held() {
		t.Fatalf("a network never held reads %+v", state)
	}
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	hold := &ComputeAbuseHold{NetworkId: sidecar.NewId(), Reason: ComputeAbuseHoldReasonFraud, HoldStaffId: sidecar.NewId(), HoldTime: now, Version: 3}
	if state := ComputeAbuseHoldStateOf(hold); state.Version != 3 || state.Reason != ComputeAbuseHoldReasonFraud || !state.Held() {
		t.Fatalf("a standing hold reads %+v", state)
	}
	staffId := sidecar.NewId()
	hold.ResumeStaffId, hold.ResumeTime = &staffId, &now
	if state := ComputeAbuseHoldStateOf(hold); state.Version != 3 || state.Held() {
		t.Fatalf("a resumed hold reads %+v", state)
	}
	for _, state := range []*ComputeAbuseHoldState{{}, {Version: 1, Reason: ComputeAbuseHoldReasonTakedown}, {Version: 1 << 40}} {
		read, err := ParseComputeAbuseHoldProjection(ComputeAbuseHoldProjectionValue(state))
		if err != nil || *read != *state {
			t.Errorf("%+v read back as %+v %v", state, read, err)
		}
	}
	networkId := sidecar.NewId()
	if key := ComputeAbuseHoldRedisKey(networkId); !strings.HasPrefix(key, ComputeProjectionKey(networkId)) || !strings.HasSuffix(key, "}:a") {
		t.Fatalf("the projection's key %s is not in its network's slot", key)
	}
}

// A change with no network, no staff member or a reason no row takes is refused before the store is asked.
func TestComputeAbuseHoldChangesRefuseTheirArgs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	networkId, staffId := sidecar.NewId(), sidecar.NewId()
	for label, change := range map[string]func() error{
		"no network": func() error {
			_, _, err := ComputeAbuseHoldSuspendInTx(nil, ctx, nil, operator.Id{}, ComputeAbuseHoldReasonSpam, staffId, now)
			return err
		},
		"no staff": func() error {
			_, _, err := ComputeAbuseHoldSuspendInTx(nil, ctx, nil, networkId, ComputeAbuseHoldReasonSpam, operator.Id{}, now)
			return err
		},
		"no reason": func() error {
			_, _, err := ComputeAbuseHoldSuspendInTx(nil, ctx, nil, networkId, ComputeAbuseHoldReasonNone, staffId, now)
			return err
		},
		"a reason the build does not name": func() error {
			_, _, err := ComputeAbuseHoldSuspendInTx(nil, ctx, nil, networkId, ComputeAbuseHoldReason(42), staffId, now)
			return err
		},
		"a resume with no staff": func() error {
			_, _, err := ComputeAbuseHoldResumeInTx(nil, ctx, nil, networkId, operator.Id{}, now)
			return err
		},
	} {
		if err := change(); !errors.Is(err, ErrComputeAbuseHoldArgs) {
			t.Errorf("%s: %v", label, err)
		}
	}
}
