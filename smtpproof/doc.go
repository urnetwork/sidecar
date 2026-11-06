// The X7 BDAT and DATA preamble provers and their verifier (§14; owner decision 125). No prover
// exists yet.
//
// A nested module so its requirements stay out of consumers' module graphs: cli/ and server inject
// it through root interfaces, and the root never requires it (§4.7).
package smtpproof
