package model

// MG-C1's statements (BAL-M12-01): every column an id, an amount, a unit, a code or a time, never content (R-BAL-6);
// nothing shared with the transfer balance (IC-4); BAL's part registered as built; and compute_charge's partitions
// bounded at UTC midnights.

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// What a ledger column may hold. Each column of MG-C1 is named here with its class, so a column added without being
// placed in one fails until someone says what it holds.
var testComputeLedgerColumnClasses = map[string][]string{
	// opaque ids (I-13)
	"id": {
		"network_id", "lot_id", "charge_id", "subject_ref", "sidecar_id", "agent_id", "member_id", "enclave_id",
		"op_key", "payer_member_id", "request_id", "approval_id", "effect_key", "subject_id", "code_id",
		"redemption_id", "user_id",
	},
	// nano-USD
	"amount": {
		"settled_nano_usd", "negative_floor_nano_usd", "indexer_reserve_nano_usd", "amount_nano_usd",
		"remaining_nano_usd", "lapsed_nano_usd", "refunded_nano_usd", "cost_nano_usd", "absorbed_nano_usd",
		"hold_nano_usd", "reserve_nano_usd", "below_nano_usd", "month_limit_nano_usd", "top_up_month_nano_usd",
	},
	// counts and typed units, a jsonb of them included
	"unit": {
		"units", "input_tokens", "output_tokens", "cached_tokens", "seconds", "egress_bytes", "searches", "count",
		"device_units", "provider_units", "pack_credits", "monthly_credits", "top_up_day_count", "failure_day_count",
		"failure_run_count", "redeem_max_count", "redeem_count", "search_cap_override", "attempt", "approval_use",
	},
	// times and UTC days
	"time": {
		"update_time", "create_time", "expire_time", "reversed_time", "start_time", "end_time", "settle_time",
		"first_charge_day", "day", "top_up_day", "top_up_month", "next_retry_time", "last_day", "redeem_time",
		"first_purchase_day", "accept_time", "state_time",
	},
	// identifiers, enums, flags and versions
	"code": {
		"state", "kind", "market", "provider", "shard", "mode", "enabled", "off_reason", "period",
		"paid_lot_required", "version", "catalog_version", "price_read", "terms_version", "clause", "draw_index",
	},
	// another party's id for the same money, model or call: a PaymentIntent, a transaction, an order, a catalog id,
	// an instance and its nonce, a Stripe customer, method or subscription
	"reference": {
		"market_ref", "catalog_id", "provider_ref", "stripe_customer_id", "stripe_payment_method_id",
		"stripe_subscription_id",
	},
	// keyed hashes (§9.11)
	"hash": {"code_hash", "payer_hash"},
	// an operator's own words about a campaign, §14.4's "the operator and the reason", never a person's content
	"operator": {"campaign", "created_by", "reason"},
	// a settled operation's units, amounts and times (ComputeOpOutcome)
	"outcome": {"outcome"},
}

// The transfer balance's tables (server/db_migrations.go), which no ledger table may be or name.
var testTransferBalanceTables = []string{
	"transfer_balance", "transfer_balance_code", "transfer_balance_grant_run", "transfer_contract", "transfer_escrow",
	"transfer_escrow_sweep", "account_balance",
}

// One CREATE TABLE of a step: its name and its columns' names, in order.
type testComputeTable struct {
	name    string
	columns []string
}

var (
	testCreateTablePattern = regexp.MustCompile(`(?is)^\s*CREATE TABLE (\w+) \((.*?)\)\s*(PARTITION BY RANGE \(\w+\))?\s*$`)
	testConstraintPattern  = regexp.MustCompile(`(?i)^(PRIMARY KEY|UNIQUE|CONSTRAINT|FOREIGN KEY|CHECK)\b`)
	// a column a later step adds to a table MG-C1 created, nullable, as BAL-M12-12's state_time
	testAddColumnPattern = regexp.MustCompile(`(?is)^\s*ALTER TABLE (\w+) ADD COLUMN (\w+) \w+\s*$`)
)

// The tables MG-C1's steps create, each with its columns.
func testComputeLedgerTables(t *testing.T) []*testComputeTable {
	tables := []*testComputeTable{}
	for _, migration := range ComputeLedgerMigrations() {
		match := testCreateTablePattern.FindStringSubmatch(migration.Sql)
		if match == nil {
			continue
		}
		table := &testComputeTable{name: match[1]}
		for _, line := range strings.Split(match[2], "\n") {
			line = strings.TrimSuffix(strings.TrimSpace(line), ",")
			if line == "" || testConstraintPattern.MatchString(line) {
				continue
			}
			table.columns = append(table.columns, strings.Fields(line)[0])
		}
		if migration.Id != table.name {
			t.Errorf("the step %s creates %s", migration.Id, table.name)
		}
		tables = append(tables, table)
	}
	// a column a later step adds joins its table, which an earlier step created
	for _, migration := range ComputeLedgerMigrations() {
		match := testAddColumnPattern.FindStringSubmatch(migration.Sql)
		if match == nil {
			continue
		}
		added := false
		for _, table := range tables {
			if table.name == match[1] {
				table.columns = append(table.columns, match[2])
				added = true
			}
		}
		if !added {
			t.Errorf("the step %s adds a column to %s, which no earlier step created", migration.Id, match[1])
		}
	}
	return tables
}

// Every column of every ledger table is checked against the classes above, so none holds a prompt, an output, a file
// or a query; every table is §14.4's MG-C1's and none is, names or links to the transfer balance's.
func TestComputeSchemaHoldsNoContentColumn(t *testing.T) {
	classOf := map[string]string{}
	for class, columns := range testComputeLedgerColumnClasses {
		for _, column := range columns {
			if other, ok := classOf[column]; ok {
				t.Fatalf("%s is in two classes, %s and %s", column, other, class)
			}
			classOf[column] = class
		}
	}
	tables := testComputeLedgerTables(t)
	names := []string{}
	for _, table := range tables {
		names = append(names, table.name)
		if !strings.HasPrefix(table.name, "compute_") {
			t.Errorf("%s is no compute table", table.name)
		}
		if len(table.columns) == 0 {
			t.Errorf("%s has no column", table.name)
		}
		for _, column := range table.columns {
			if _, ok := classOf[column]; !ok {
				t.Errorf("%s.%s holds nothing the ledger's classes name", table.name, column)
			}
			for _, word := range []string{"prompt", "query", "file", "body", "content", "message", "text", "transfer", "escrow"} {
				if strings.Contains(column, word) {
					t.Errorf("%s.%s names %s", table.name, column, word)
				}
			}
		}
	}
	// §14.4's MG-C1 row, table by table
	want := []string{
		"compute_account", "compute_lot", "compute_charge", "compute_charge_lot", "compute_charge_day",
		"compute_charge_total", "compute_charge_pruned", "compute_op", "compute_auto_renew", "compute_dispute",
		"compute_budget_raise", "compute_promo_code", "compute_promo_redemption", "compute_payer",
		"compute_payer_day", "compute_terms",
	}
	if !slices.Equal(names, want) {
		t.Errorf("MG-C1 creates %v, want %v", names, want)
	}
	for _, migration := range ComputeLedgerMigrations() {
		sql := strings.ToLower(migration.Sql)
		for _, table := range testTransferBalanceTables {
			if regexp.MustCompile(`\b` + table + `\b`).MatchString(sql) {
				t.Errorf("the step %s names the transfer balance's %s", migration.Id, table)
			}
		}
		// money is bigint nano-USD, never a float or numeric (D-BAL-2), and times are timestamptz
		for _, word := range []string{"real", "double precision", "numeric", "float", "money", "timestamp without"} {
			if strings.Contains(sql, word) {
				t.Errorf("the step %s holds a %s", migration.Id, word)
			}
		}
		if strings.Contains(sql, " timestamp ") || strings.Contains(sql, " timestamp,") || strings.Contains(sql, " timestamp\n") {
			t.Errorf("the step %s holds a timestamp without its zone", migration.Id)
		}
	}
	// the payer's tables keep no network (§9.11, compute-2)
	for _, table := range tables {
		if (table.name == "compute_payer" || table.name == "compute_payer_day") && slices.Contains(table.columns, "network_id") {
			t.Errorf("%s names a network", table.name)
		}
	}
	// the lifetime rollup keeps no day, sidecar or agent (Q-BAL-10)
	for _, table := range tables {
		if table.name != "compute_charge_total" {
			continue
		}
		for _, column := range []string{"day", "sidecar_id", "agent_id"} {
			if slices.Contains(table.columns, column) {
				t.Errorf("compute_charge_total keeps %s", column)
			}
		}
	}
}

// BAL's part of MG-C1 is what ComputeLedgerMigrations builds, step for step, registered at init; each step has its
// own id and a statement alone, as server's runner takes a part (C-30).
func TestComputeLedgerMigrationsRegisterAsBalsPart(t *testing.T) {
	part := ComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerBal)
	built := ComputeLedgerMigrations()
	if len(part) != len(built) || len(part) == 0 {
		t.Fatalf("BAL's part holds %d steps, ComputeLedgerMigrations %d", len(part), len(built))
	}
	ids := map[string]bool{}
	for i, step := range part {
		if step.Id != built[i].Id || step.Sql != built[i].Sql || step.Code != nil {
			t.Errorf("step %d of BAL's part is not %s's statement", i, built[i].Id)
		}
		if ids[step.Id] {
			t.Errorf("the id %s twice", step.Id)
		}
		ids[step.Id] = true
		// server's additivity check refuses these words in a sidecar group's statement
		if regexp.MustCompile(`(?i)\b(DROP|RENAME|TRUNCATE)\b`).MatchString(step.Sql) {
			t.Errorf("the step %s names a word server's additivity check refuses", step.Id)
		}
		// server's schema guard and additivity check read the tables a group creates with these patterns: each name
		// they read is the step's own table, never a keyword such as IF
		for _, pattern := range []*regexp.Regexp{
			regexp.MustCompile(`(?is)\bCREATE TABLE (?:IF NOT EXISTS )?([a-z_][a-z0-9_]*)`),
			regexp.MustCompile(`(?i)\bCREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?`),
		} {
			for _, match := range pattern.FindAllStringSubmatch(step.Sql, -1) {
				if strings.ToLower(match[1]) != step.Id {
					t.Errorf("server reads the step %s as creating %s", step.Id, match[1])
				}
			}
		}
	}
	// §9.4's indexes for the later tasks' reads, and the rollups' UNIQUE NULLS NOT DISTINCT
	joined := ""
	for _, step := range built {
		joined += step.Sql
	}
	for _, index := range []string{
		"ON compute_charge (network_id, start_time)",
		"ON compute_op (shard, state)",
		"ON compute_op (state, start_time)",
		"ON compute_lot (network_id, kind, expire_time)",
		"UNIQUE NULLS NOT DISTINCT (network_id, day, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id)",
		"UNIQUE NULLS NOT DISTINCT (network_id, kind, member_id, catalog_id, provider, enclave_id)",
		"UNIQUE (market, market_ref)",
		"PRIMARY KEY (start_time, charge_id)",
		"PARTITION BY RANGE (start_time)",
		"UNIQUE (code_id, network_id)",
		"UNIQUE (effect_key)",
		"PRIMARY KEY (approval_id, approval_use)",
	} {
		if !strings.Contains(joined, index) {
			t.Errorf("MG-C1 lacks %s", index)
		}
	}
}

// A day's partition is bounded at its UTC midnight and the next, whatever zone or hour names the day, and its name is
// the UTC day's; the migration's own step bounds today the same way.
func TestComputeChargePartitionBoundsUtcDays(t *testing.T) {
	zone := time.FixedZone("UTC-8", -8*60*60)
	// 2026-11-25 20:30 at UTC-8 is 2026-11-26 04:30 UTC
	day := time.Date(2026, 11, 25, 20, 30, 0, 0, zone)
	if name := ComputeChargePartitionName(day); name != "compute_charge_20261126" {
		t.Errorf("the partition of %v is %s", day, name)
	}
	want := "CREATE TABLE IF NOT EXISTS compute_charge_20261126 PARTITION OF compute_charge FOR VALUES FROM ('2026-11-26 00:00:00+00') TO ('2026-11-27 00:00:00+00')"
	if statement := ComputeChargePartitionStatement(day); statement != want {
		t.Errorf("the partition's statement is %s", statement)
	}
	// a year's last day bounds the next year's first
	if statement := ComputeChargePartitionStatement(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)); !strings.Contains(statement, "TO ('2027-01-01 00:00:00+00')") {
		t.Errorf("the year's last day: %s", statement)
	}
	for _, step := range ComputeLedgerMigrations() {
		if step.Id != "compute_charge_today" {
			continue
		}
		for _, part := range []string{"(now() AT TIME ZONE 'UTC')::date", "' 00:00:00+00'", "'compute_charge_' || to_char(today, 'YYYYMMDD')"} {
			if !strings.Contains(step.Sql, part) {
				t.Errorf("today's partition step lacks %s", part)
			}
		}
		return
	}
	t.Error("MG-C1 makes no partition for today")
}
