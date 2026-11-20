// §15's receive path on T2 in one process, MailWorld (world.go), for S7, the mail privacy rows, FS-13 and FS-121
// (MAIL-M7-27), and M8's composed runs (MAIL-M8-10): M8World (m8_world.go), one network with mail on over the admission
// suite's log, which the indexer paths and FS-36's forced miss stand on, and S10's receive-only half as a scenario
// (s10.go), one builder that sidecartest's test runs on T2 and server's sidecart3 on T3's stores. And M9's (MAIL-M9-06):
// M9World (m9_world.go), M8's network whose owner's laptop sends through MailClient and, as the member's prover host,
// through SMTP's sender, which S6's forwarding rows and FS-123's mail side stand on, and S10's replying half as a
// scenario (s10_replying.go), again one builder for T2 and T3. It sits apart from sidecartest because it builds evs's
// engine, whose own tests import sidecartest. Only the sidecar_testhooks build has the world, since the TLS front's test
// listener it hands streams to is a testhooks type; on every other leg this package is empty.
package mailworld
