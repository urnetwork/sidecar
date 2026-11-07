// The X7 BDAT and DATA preamble provers and their verifier (§14; owner decision 125). SPEC.md states
// what is proved, by whom, against which relation and why it is sound; read it first.
//
// Files group by prefix: tls_ is the sidecar's own TLS client, relation is the reference relation
// over plain Go values, edge is E1-E3, prover drives a connection, circuit_ holds the R1CS gadgets,
// and backend and setup are Groth16 and its keys.
//
// A nested module so its requirements stay out of consumers' module graphs: cli/ and server inject
// it through root interfaces, and the root never requires it (§4.7). No keys ship yet, so a Prover
// or Verifier built here refuses every part (SPEC.md section 12).
package smtpproof
