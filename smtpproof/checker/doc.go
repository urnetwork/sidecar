// An oracle for the public relation of smtpproof/SPEC.md, written apart from the prover tree
// (§22.10, SMTP-M9-28). Given what the edge saw of one connection, every record in its order, the
// disclosed SHTS and each part the sidecar submitted, with the edge's own values and a witness per
// part, Check derives Z1's public inputs itself and says which of E1-E3 and Z1-Z9 fail.
//
// It imports nothing from smtpproof, only the standard library and x/crypto, and it was written from
// SPEC.md sections 4 to 7, DESIGN.md §14.4 and §14.5, and DESIGN-DETAILS.md 3.2.2 to 3.2.5 alone,
// without reading relation.go or the circuits. From DESIGN-DETAILS 3.2 it takes parts bound to one key
// part: Z1 in two steps, the key part's derivation of both directions and its commitment C, then every
// later part's opening of the C the edge kept; roles by position alone; Z5 and Z6 over the header block's
// and DATA's body records with the scan's state between them, which it reads from the state's definition
// over the octets so far and holds each carry to; Z8 by each part's reply_count; and the gate's order
// rules, part by part. The twisted Edwards curve under C and the carries is its own arithmetic in
// math/big.
//
// Its worth is disagreement: a case where it and the circuits or relation.go differ is a bug in one of
// them. It is a test oracle, slow and allocation-heavy, and is never linked into a prover or an edge.
//
// Where SPEC.md or DESIGN-DETAILS leaves a point to the reader, this package takes the reading named at
// that point in its source, so a reviewer can set each against relation.go's. One reading covers the
// whole package: it checks the relation and the gate's rules, not the shape catalog's capacities, so a
// part that no catalog shape holds, which the gate refuses at DESIGN-DETAILS 3.2.5's step 12, is one this
// oracle still reads.
package checker
