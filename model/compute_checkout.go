// The compute terms a purchase accepts (DESIGN-COMPUTE §21.9, §14.4, compute-2; BAL-M12-08): a network accepts the
// compute terms with its first purchase, which its checkout shows, and compute_terms keeps the version it accepted,
// by whom and when, one row a clause. The terms themselves are the clause compute; §21.9's web search clause is
// BAL-M13-03's, accepted on its own route.
//
// A later purchase under a newer version records that version, since its checkout showed the newer text; an older or
// equal one changes nothing, so a replayed webhook writes once.

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// The clause compute_terms keeps the compute terms themselves under: an identifier.
const ComputeTermsClauseCompute = "compute"

// The version of the compute terms a checkout shows now: a version number, an identifier, raised with each revision
// of the terms' text.
const ComputeTermsVersion int64 = 1

// Records in tx that networkId accepted clause at version, by userId at acceptTime, unless the network accepted that
// version or a newer one before. Whether this call wrote a row.
func ComputeTermsAcceptInTx(env operator.Env, ctx context.Context, tx operator.DbTx, terms *ComputeTerms) (bool, error) {
	var zero operator.Id
	if terms.NetworkId == zero || terms.UserId == zero || terms.Clause == "" || terms.TermsVersion <= 0 {
		return false, fmt.Errorf("%w: an acceptance names its network, user, clause and version", ErrComputeLotArgs)
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO compute_terms (network_id, clause, terms_version, user_id, accept_time) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (network_id, clause) DO UPDATE
			SET terms_version = EXCLUDED.terms_version, user_id = EXCLUDED.user_id, accept_time = EXCLUDED.accept_time
			WHERE compute_terms.terms_version < EXCLUDED.terms_version
	`, terms.NetworkId, terms.Clause, terms.TermsVersion, terms.UserId, terms.AcceptTime.UTC())
	if err != nil {
		return false, err
	}
	return result.RowsAffected == 1, nil
}

// networkId's acceptance of clause, nil where it accepted none, in tx.
func ComputeTermsOfInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, clause string) (*ComputeTerms, error) {
	rows, err := tx.Query(ctx, `
		SELECT terms_version, user_id, accept_time FROM compute_terms WHERE network_id = $1 AND clause = $2
	`, networkId, clause)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	terms := &ComputeTerms{NetworkId: networkId, Clause: clause}
	var acceptTime time.Time
	if err := rows.Scan(&terms.TermsVersion, &terms.UserId, &acceptTime); err != nil {
		return nil, err
	}
	terms.AcceptTime = acceptTime.UTC()
	return terms, rows.Err()
}
