// Package conformance is the harness conformance runner (CTEST-M12-03; DESIGN-COMPUTE §18's gateway row, §8.3,
// R-CCTX-10): it replays a harness's recorded sessions against the gateway and holds each answer to what that harness
// needs, as MCP-M3-28's hook conformance holds ur hook to each harness's hook payloads (mcp/conformance_test.go).
//
//	transcript.go   Transcript: one harness's sessions at one pinned release, testdata/<harness>/<version>/, each
//	                request the harness's bytes and headers, written from the published API schema and the harness's
//	                own request shapes, synthetic in every value and never captured traffic, with the model's answer
//	                an in-process replay scripts and what the answer must be
//	runner.go       Run: each session's requests sent in order under a token of its own, each answer parsed and
//	                checked by the harness's profile and the request's expectations; a later request may carry what
//	                an earlier answer gave (the gateway's reasoning blob), as the harness sends it back
//	codex.go        Codex's profile (§8.3): stateless full-history Responses requests (store false, include
//	                reasoning.encrypted_content, item ids it never issued) answered by a stream of well-formed SSE
//	                events whose complete items arrive in response.output_item.done and whose terminal is
//	                response.completed with the response's id and integer usage; insufficient_quota ending the turn in
//	                a form Codex does not retry; store true and previous_response_id refused 400 unsupported_parameter
//	target.go       GatewayTarget: the root's gateway in process over a T2 Sidecar, the router a test gives behind it
//	                (computetest.ScriptedModel's under sidecar_testhooks), each session bound to a run of its own and
//	                each call recorded, so a test asserts what the model saw and where each call was recorded
//	live.go         LiveHarness: a real harness binary where UR_CONFORMANCE_HARNESS names one, run under a temporary
//	                HOME holding the gateway's harness settings, for the compute rota's per-release run (§14.10); a
//	                host with no binary reads open, never passed
//
// The runner checks the wire contract a harness acts on, never a model's words: event order and shape, ids, usage's
// integers, error codes. A transcript's version is part of its path, since its bytes are that release's. Open
// Responses' own suite and OpenCode's and Aider's smoke are live runs (External), and Claude Code's profile and
// transcripts are CTEST-M13-05's, on the Messages front.
package conformance
