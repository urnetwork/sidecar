// MG-C1, the compute ledger's schema (DESIGN-COMPUTE §9.4, §14.4; BAL-M12-01): §9.4's SQL as printed and §14.4's
// MG-C1 rows as listed, one statement a step, in order, registered as BAL's part of MG-C1 at init (CONTRACTS C-30),
// which server's migration runner applies under sidecar_pending until M12's exit registers the group (DESIGN §19.7).
//
// What each table holds, and the row of §2.8's list each sits under (I-18; sidecartest's schema guard reads them):
//
//	compute_account           a network's settled balance, state, floor, first charge day and version (compute-3);
//	                          with compute-plan-money-schema-gaps' indexer reserve and search-cap override (QD-1252)
//	compute_lot               each credit and what is left of it, unique by (market, market_ref) so a replayed
//	                          webhook credits once; a Play subscription's reference is its order id, never its
//	                          purchase token; with a self-serve refund's amount (QD-1252) (compute-2)
//	compute_charge            each charge, partitioned by range on start_time, one partition a UTC day: the
//	                          migration makes the parent and today's, compute_rollup_day the rest (BAL-M12-05)
//	                          through ComputeChargePartitionStatement (compute-1)
//	compute_charge_lot        each lot a charge drew, in draw order; a refund's draws negative (compute-3)
//	compute_charge_day        the day rollup, typed units, UNIQUE NULLS NOT DISTINCT (compute-1, compute-3)
//	compute_charge_total      the lifetime rollup, no day, sidecar or agent (Q-BAL-10, QD-1258) (compute-3)
//	compute_charge_pruned     the day rows dropped past 400 days, summed per kind (compute-3)
//	compute_op                each billable operation from before its liability until booked (compute-1)
//	compute_auto_renew        each network's two modes (compute-6)
//	compute_dispute           each charge_mismatch (compute-8)
//	compute_budget_raise      each raise kind 21 approved, unique by approval and use and by effect key (compute-6)
//	compute_promo_code        each promotion code, by a keyed hash of it (compute-2)
//	compute_promo_redemption  each redemption, unique per code and network (compute-2)
//	compute_payer             a payer's keyed hash and first purchase day, no network column (compute-2)
//	compute_payer_day         a payer's day's purchases, no network column (compute-2)
//	compute_terms             the compute terms' clauses a network accepted, by whom and when (compute-2; QD-1252)
//
// Traps the statements keep: money is bigint nano-USD, never a float or numeric; times are timestamptz, and a day is
// a date counted in UTC, so a partition's bounds are written at +00 and today is (now() AT TIME ZONE 'UTC')::date,
// never the session's zone; no column holds a prompt, an output, a file or a query (R-BAL-6); and no table or column
// is shared with the transfer balance's, nor converts between the two (IC-4). The rollups' UNIQUE NULLS NOT DISTINCT
// needs PostgreSQL 15 or later, which MG-C1's floor (server's computeRequirePostgres15) checks before this part runs.
//
// Every step is additive and works with the release running when it applies; once M12's exit registers the group,
// none changes again (§19.7). No statement here may name the words server's additivity check refuses.

package model

import (
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// BAL's part of MG-C1, registered once at init, before server builds its migrations slice.
func init() {
	RegisterComputeMigrationPart(ComputeMigrationGroupC1, ComputeMigrationOwnerBal, ComputeLedgerMigrations())
}

// The prefix of compute_charge's daily partitions: compute_charge_YYYYMMDD, the UTC day.
const computeChargePartitionPrefix = "compute_charge_"

// The name of compute_charge's partition for the UTC day day falls in.
func ComputeChargePartitionName(day time.Time) string {
	return computeChargePartitionPrefix + day.UTC().Format("20060102")
}

// The statement that makes compute_charge's partition for the UTC day day falls in, bounded at UTC midnights,
// doing nothing where it exists: what compute_rollup_day runs for the days ahead (BAL-M12-05).
func ComputeChargePartitionStatement(day time.Time) string {
	start := day.UTC().Truncate(24 * time.Hour)
	end := start.AddDate(0, 0, 1)
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF compute_charge FOR VALUES FROM ('%s 00:00:00+00') TO ('%s 00:00:00+00')",
		ComputeChargePartitionName(start),
		start.Format(time.DateOnly),
		end.Format(time.DateOnly),
	)
}

// MG-C1's ledger part, in order: what CSRV's group registration takes (CONTRACTS C-30).
func ComputeLedgerMigrations() []*operator.Migration {
	return []*operator.Migration{
		{
			Id: "compute_account",
			Sql: `
				CREATE TABLE compute_account (
					network_id uuid NOT NULL,
					settled_nano_usd bigint NOT NULL DEFAULT 0,
					state smallint NOT NULL,
					negative_floor_nano_usd bigint NOT NULL,
					first_charge_day date,
					indexer_reserve_nano_usd bigint NOT NULL DEFAULT 0,
					search_cap_override bigint,
					version bigint NOT NULL,
					update_time timestamptz NOT NULL,
					PRIMARY KEY (network_id)
				)
			`,
		},
		{
			Id: "compute_lot",
			Sql: `
				CREATE TABLE compute_lot (
					lot_id uuid NOT NULL,
					network_id uuid NOT NULL,
					kind smallint NOT NULL,
					market smallint NOT NULL,
					market_ref text NOT NULL,
					amount_nano_usd bigint NOT NULL,
					remaining_nano_usd bigint NOT NULL,
					create_time timestamptz NOT NULL,
					expire_time timestamptz,
					reversed_time timestamptz,
					lapsed_nano_usd bigint,
					refunded_nano_usd bigint,
					PRIMARY KEY (lot_id),
					UNIQUE (market, market_ref)
				)
			`,
		},
		{
			// the draw order: unexpired promotions by nearest expiry, then subscription grants, then purchases
			Id: "compute_lot_draw",
			Sql: `
				CREATE INDEX compute_lot_draw ON compute_lot (network_id, kind, expire_time)
			`,
		},
		{
			Id: "compute_charge",
			Sql: `
				CREATE TABLE compute_charge (
					charge_id uuid NOT NULL,
					network_id uuid NOT NULL,
					kind smallint NOT NULL,
					subject_ref uuid NOT NULL,
					sidecar_id uuid NOT NULL,
					agent_id uuid,
					member_id uuid,
					enclave_id uuid,
					catalog_id text,
					provider smallint NOT NULL,
					units jsonb NOT NULL,
					amount_nano_usd bigint NOT NULL,
					cost_nano_usd bigint NOT NULL,
					absorbed_nano_usd bigint NOT NULL,
					start_time timestamptz NOT NULL,
					end_time timestamptz NOT NULL,
					settle_time timestamptz NOT NULL,
					PRIMARY KEY (start_time, charge_id)
				) PARTITION BY RANGE (start_time)
			`,
		},
		{
			// a network's charges by time: the charges route and the per-request reads
			Id: "compute_charge_network",
			Sql: `
				CREATE INDEX compute_charge_network ON compute_charge (network_id, start_time)
			`,
		},
		{
			// today's partition, in UTC, made when the step runs; compute_rollup_day makes the rest. The parent is
			// this group's, so no partition stands before it, and the statement names no IF NOT EXISTS: server's
			// table patterns would read IF as the name of a table the group creates.
			Id: "compute_charge_today",
			Sql: `
				DO $$
				DECLARE
					today date := (now() AT TIME ZONE 'UTC')::date;
				BEGIN
					EXECUTE format(
						'CREATE TABLE %I PARTITION OF compute_charge FOR VALUES FROM (%L) TO (%L)',
						'compute_charge_' || to_char(today, 'YYYYMMDD'),
						to_char(today, 'YYYY-MM-DD') || ' 00:00:00+00',
						to_char(today + 1, 'YYYY-MM-DD') || ' 00:00:00+00'
					);
				END
				$$
			`,
		},
		{
			Id: "compute_charge_lot",
			Sql: `
				CREATE TABLE compute_charge_lot (
					charge_id uuid NOT NULL,
					draw_index smallint NOT NULL,
					lot_id uuid NOT NULL,
					amount_nano_usd bigint NOT NULL,
					PRIMARY KEY (charge_id, draw_index)
				)
			`,
		},
		{
			Id: "compute_charge_day",
			Sql: `
				CREATE TABLE compute_charge_day (
					network_id uuid NOT NULL,
					day date NOT NULL,
					kind smallint NOT NULL,
					sidecar_id uuid NOT NULL,
					agent_id uuid,
					catalog_id text,
					member_id uuid,
					provider smallint NOT NULL,
					enclave_id uuid,
					input_tokens bigint NOT NULL,
					output_tokens bigint NOT NULL,
					cached_tokens bigint NOT NULL,
					seconds bigint NOT NULL,
					egress_bytes bigint NOT NULL,
					searches bigint NOT NULL,
					amount_nano_usd bigint NOT NULL,
					refunded_nano_usd bigint NOT NULL,
					count bigint NOT NULL,
					UNIQUE NULLS NOT DISTINCT (network_id, day, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id)
				)
			`,
		},
		{
			Id: "compute_charge_total",
			Sql: `
				CREATE TABLE compute_charge_total (
					network_id uuid NOT NULL,
					kind smallint NOT NULL,
					member_id uuid,
					catalog_id text,
					provider smallint NOT NULL,
					enclave_id uuid,
					input_tokens bigint NOT NULL,
					output_tokens bigint NOT NULL,
					cached_tokens bigint NOT NULL,
					seconds bigint NOT NULL,
					egress_bytes bigint NOT NULL,
					searches bigint NOT NULL,
					amount_nano_usd bigint NOT NULL,
					refunded_nano_usd bigint NOT NULL,
					count bigint NOT NULL,
					UNIQUE NULLS NOT DISTINCT (network_id, kind, member_id, catalog_id, provider, enclave_id)
				)
			`,
		},
		{
			Id: "compute_charge_pruned",
			Sql: `
				CREATE TABLE compute_charge_pruned (
					network_id uuid NOT NULL,
					kind smallint NOT NULL,
					amount_nano_usd bigint NOT NULL,
					count bigint NOT NULL,
					PRIMARY KEY (network_id, kind)
				)
			`,
		},
		{
			Id: "compute_op",
			Sql: `
				CREATE TABLE compute_op (
					op_key uuid NOT NULL,
					network_id uuid NOT NULL,
					shard smallint NOT NULL,
					state smallint NOT NULL,
					kind smallint NOT NULL,
					subject_ref uuid NOT NULL,
					attempt smallint,
					sidecar_id uuid NOT NULL,
					agent_id uuid,
					member_id uuid,
					enclave_id uuid,
					catalog_id text,
					catalog_version bigint,
					provider smallint NOT NULL,
					price_read bigint,
					provider_ref text,
					hold_nano_usd bigint NOT NULL,
					reserve_nano_usd bigint NOT NULL,
					start_time timestamptz NOT NULL,
					outcome jsonb,
					PRIMARY KEY (op_key)
				)
			`,
		},
		{
			// compute_settle's batches: a shard's settled rows
			Id: "compute_op_shard_state",
			Sql: `
				CREATE INDEX compute_op_shard_state ON compute_op (shard, state)
			`,
		},
		{
			// compute_op_recover's sweep: rows open or settled past their age
			Id: "compute_op_state_start",
			Sql: `
				CREATE INDEX compute_op_state_start ON compute_op (state, start_time)
			`,
		},
		{
			Id: "compute_auto_renew",
			Sql: `
				CREATE TABLE compute_auto_renew (
					network_id uuid NOT NULL,
					mode smallint NOT NULL,
					enabled boolean NOT NULL,
					market smallint NOT NULL,
					below_nano_usd bigint,
					pack_credits bigint,
					month_limit_nano_usd bigint,
					monthly_credits bigint,
					payer_member_id uuid,
					stripe_customer_id text,
					stripe_payment_method_id text,
					stripe_subscription_id text,
					off_reason smallint,
					top_up_day date,
					top_up_day_count integer NOT NULL DEFAULT 0,
					failure_day_count integer NOT NULL DEFAULT 0,
					failure_run_count integer NOT NULL DEFAULT 0,
					top_up_month date,
					top_up_month_nano_usd bigint NOT NULL DEFAULT 0,
					next_retry_time timestamptz,
					update_time timestamptz NOT NULL,
					PRIMARY KEY (network_id, mode)
				)
			`,
		},
		{
			// compute_auto_renew's job: the threshold rows due a retry
			Id: "compute_auto_renew_retry",
			Sql: `
				CREATE INDEX compute_auto_renew_retry ON compute_auto_renew (next_retry_time) WHERE next_retry_time IS NOT NULL
			`,
		},
		{
			Id: "compute_dispute",
			Sql: `
				CREATE TABLE compute_dispute (
					request_id uuid NOT NULL,
					network_id uuid NOT NULL,
					provider smallint NOT NULL,
					device_units jsonb NOT NULL,
					provider_units jsonb NOT NULL,
					charge_id uuid,
					state smallint NOT NULL,
					create_time timestamptz NOT NULL,
					update_time timestamptz NOT NULL,
					PRIMARY KEY (request_id)
				)
			`,
		},
		{
			// D-BAL-11's count: a network's disputes a UTC day
			Id: "compute_dispute_network",
			Sql: `
				CREATE INDEX compute_dispute_network ON compute_dispute (network_id, create_time)
			`,
		},
		{
			Id: "compute_budget_raise",
			Sql: `
				CREATE TABLE compute_budget_raise (
					approval_id uuid NOT NULL,
					approval_use integer NOT NULL,
					effect_key uuid NOT NULL,
					network_id uuid NOT NULL,
					subject_id uuid NOT NULL,
					period smallint NOT NULL,
					amount_nano_usd bigint NOT NULL,
					expire_time timestamptz NOT NULL,
					create_time timestamptz NOT NULL,
					PRIMARY KEY (approval_id, approval_use),
					UNIQUE (effect_key)
				)
			`,
		},
		{
			// the raises in force for a network's subjects, which the projection carries
			Id: "compute_budget_raise_subject",
			Sql: `
				CREATE INDEX compute_budget_raise_subject ON compute_budget_raise (network_id, subject_id, expire_time)
			`,
		},
		{
			Id: "compute_promo_code",
			Sql: `
				CREATE TABLE compute_promo_code (
					code_id uuid NOT NULL,
					code_hash bytea NOT NULL,
					campaign text NOT NULL,
					amount_nano_usd bigint NOT NULL,
					redeem_max_count bigint NOT NULL,
					redeem_count bigint NOT NULL DEFAULT 0,
					last_day date NOT NULL,
					paid_lot_required boolean NOT NULL,
					created_by text NOT NULL,
					reason text NOT NULL,
					create_time timestamptz NOT NULL,
					PRIMARY KEY (code_id),
					UNIQUE (code_hash)
				)
			`,
		},
		{
			Id: "compute_promo_redemption",
			Sql: `
				CREATE TABLE compute_promo_redemption (
					redemption_id uuid NOT NULL,
					code_id uuid NOT NULL,
					network_id uuid NOT NULL,
					lot_id uuid NOT NULL,
					sidecar_id uuid NOT NULL,
					redeem_time timestamptz NOT NULL,
					PRIMARY KEY (redemption_id),
					UNIQUE (code_id, network_id)
				)
			`,
		},
		{
			// §9.11's one code a network in 30 days
			Id: "compute_promo_redemption_network",
			Sql: `
				CREATE INDEX compute_promo_redemption_network ON compute_promo_redemption (network_id, redeem_time)
			`,
		},
		{
			Id: "compute_payer",
			Sql: `
				CREATE TABLE compute_payer (
					payer_hash bytea NOT NULL,
					first_purchase_day date NOT NULL,
					PRIMARY KEY (payer_hash)
				)
			`,
		},
		{
			Id: "compute_payer_day",
			Sql: `
				CREATE TABLE compute_payer_day (
					payer_hash bytea NOT NULL,
					day date NOT NULL,
					amount_nano_usd bigint NOT NULL,
					PRIMARY KEY (payer_hash, day)
				)
			`,
		},
		{
			Id: "compute_terms",
			Sql: `
				CREATE TABLE compute_terms (
					network_id uuid NOT NULL,
					clause text NOT NULL,
					terms_version bigint NOT NULL,
					user_id uuid NOT NULL,
					accept_time timestamptz NOT NULL,
					PRIMARY KEY (network_id, clause)
				)
			`,
		},
	}
}
