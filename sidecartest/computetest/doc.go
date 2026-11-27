// Compute's shared fakes (DESIGN-COMPUTE §18; the CTEST plan): the stand-ins two or more compute areas test against,
// under the names the other plans cite as computetest.X. A feature area tests its own code; what lives here is what the
// areas share, and each fake's real part is its owner's.
//
// What lives where:
//
//   - scripted_model.go, ScriptedModel: a model behind the router, INFER's local engine seam (sidecar.InferLocalEngine),
//     answering each call from a script of turns matched on the call's last message or tool result, and recording every
//     request it received in full. Its manifest (Manifest) lists its models as the release manifest would, and
//     scripted_model_router.go, under sidecar_testhooks, puts it behind INFER's own router
//     (sidecar.NewInferRouterForTest), so the Harness, the gateway, the skill and the classifier's callers run unchanged
//     against it; the untagged build's Router answers ErrScriptedRouterUnlinked.
//   - policy.go, FakeComputePolicy: §5.4's signed objects made with test keys from a seed: FakePolicyKeys, a test
//     release key certifying a test compute-policy key and a test staging key; policies built through ATTEST's own
//     ComputePolicy type and signed through its SSHSIG signer; freshness tickets as a sitting's batch; and
//     FakeTicketHost, the ticket host and its serving path on the test's clock, a sidecar.ComputePolicySource.
//     policy_testhooks.go, under sidecar_testhooks, gives the verifier that pins the test release key
//     (sidecar.NewComputePolicyVerifierForTest) and a device's policy store, gate and fetcher over it; the untagged
//     build's answer ErrFakeComputePolicyUnlinked.
//   - calendar*.go, FakeCalendarServer: the calendars a calendar link reaches (§23.7), one loopback HTTPS listener
//     serving CalDAV (go-webdav's server over the fake's store, with discovery, privileges, sharing, expanded
//     recurrences, ETag preconditions and RFC 6638's scheduling beside it), ICS feeds by secret address, and Google
//     Calendar's and Microsoft Graph's calendar endpoints; every write logged with its precondition and what the
//     provider mailed (FakeCalendarWrite), and a stop after a write applied and before its answer leaves
//     (FakeCalendarStop) for §23.9's recovery.
//   - parallel.go, FakeParallel: Parallel's keyless gateway (§21.3, §21.5), POST /api/search answering an unpaid
//     request with an x402 v2 exact offer and a fresh payee, verifying a paid retry's EIP-3009 authorization for real
//     and settling it through its facilitator onto FakeBase, then answering synthetic results in Parallel's schema;
//     scriptable rate limits, upstream failures after settlement (CO-30), lost and stalled answers and aged payees.
//   - base.go and base_evm.go, FakeBase: one Base chain served as two JSON-RPC sources (CDP-like and Alchemy-like),
//     USDC's transferWithAuthorization with FiatToken's checks, a finalized head the test moves, reorgs of the unsafe
//     head, disagreements and lags between the sources; and the EVM primitives both fakes share, EIP-712's digest and
//     secp256k1 signatures made and recovered with decred's library and Keccak-256.
//   - fake_https.go: the loopback HTTPS server the network fakes share, named .example hosts under a test authority
//     drawn from the seed, reached through each fake's dialer and trusted by its pool alone.
//
// Its rules, as sidecartest's:
//
//   - It imports the root, computeservice and searchsigner, and sidecartest, its parent, and no server package; server
//     imports it for T3, as it imports sidecartest.
//   - A test that uses it is an external test package: an internal test of the root or of computeservice cannot import
//     it without a cycle, so a root test that drives these fakes declares package sidecar_test.
//   - What reaches past a format's public surface into a test's seam needs sidecar_testhooks, which no shipped build
//     carries: a test that drives a fake behind INFER's router or ATTEST's verifier builds with the tag, and on the
//     untagged build the same call answers a named error, never a quiet default.
//   - Every value is synthetic: .example hosts, RFC 5737 and RFC 3849 addresses where one is needed, and keys, hashes and
//     nonces drawn from a seed, so two fakes of one seed and one clock make the same bytes and vectors hold. A production
//     build trusts none of these keys: its verifier pins the release key alone (attest_policy_root.go).
//   - Each fake has a settings struct whose defaults only its Default...Settings sets (QD-702), a format's limits read
//     from the format owner's settings, which each fake's settings carry, and each takes the injected clock
//     (sidecartest.Clock). Nothing here sleeps: a stall is a barrier the test releases.
//   - Each fake fails a call it was not scripted for with a named error, never a default answer.
package computetest
