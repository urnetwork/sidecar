// An oracle for the public relation of smtpproof/SPEC.md, written apart from the prover tree
// (§22.10, SMTP-M9-28). Given what the edge saw of one connection, every record in its order, the
// disclosed SHTS and each part the sidecar submitted, with the edge's own values and a witness per
// part, Check derives Z1's public inputs itself and says which of E1-E3 and Z1-Z9 fail.
//
// It imports nothing from smtpproof, only the standard library and x/crypto, and it was written from
// SPEC.md sections 4 to 7 and DESIGN.md §14.4 and §14.5 alone, without reading relation.go or the
// circuits. Its worth is disagreement: a case where it and the circuits or relation.go differ is a bug
// in one of them. It is a test oracle, slow and allocation-heavy, and is never linked into a prover or
// an edge.
//
// Where SPEC.md leaves a point to the reader, this package takes the reading named at that point in
// its source, so a reviewer can set each against relation.go's.
package checker
