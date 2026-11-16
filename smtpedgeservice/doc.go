// The smtpedge engine (§14.9, D-SMTP-11): outbound mail's edge and the report host's intake. server
// hosts it, the edge in server/cli/smtpedge and the intake in mxedge's platform block
// (plan-SMTP-report-intake-home), and only server imports this package. TLS runs end to end from the
// sidecar to the MX, so the edge sees ciphertext plus the proven preamble (X7); reports are parsed
// header-only, then sealed to the network mail key or dropped (D-SMTP-12). What lives where:
//
//   - settings.go, config/<env>/smtpedge.yml.
//   - records.go and store.go, SmtpEdgeStore and SmtpReportLookups: the only way this engine reaches
//     Postgres, and the rows §2.8's smtp-3 to smtp-6 allow.
//   - service.go, the engine's lifecycle and readiness.
//   - metrics.go, the metric families and their closed label values.
//   - report_mime.go, the bounded MIME walk every report goes through.
//   - report_arf.go, ARF's header-only parse and the header-block parse the abuse form shares.
//   - report_inflate.go, report_dmarc_xml.go and report_tlsrpt_json.go, the aggregate parsers.
//   - report_dkim.go and report_dkim_canon.go, the reporter's DKIM check and the header-only check of
//     reported headers.
//   - report_seal.go, the sealed copy's format.
//   - report_intake.go, SmtpReportIntake: what the platform listener calls for each report.
//   - preamble.go, one preamble's path at the edge: bounds, gate, quota, key set, MX, issued values.
//   - gate.go, the send gate over SmtpGate's memory and §21.5's breaker state.
//   - issue.go, send_id, X-UR-Ref and Feedback-ID.
//   - quota.go, quota_scripts.go, breaker.go and destination.go, §14.7's enforcement on Redis.
//   - mx_resolve.go, mx_chain.go, mx_pretls.go and mx_reply.go, MX resolution, dnssec_chain and the
//     pre-TLS dialog; sending_set.go, the sending addresses and their FCrDNS; mx_dial_linux.go, the
//     fwmark dial.
//
// Nothing here logs report text, an envelope, a recipient or an address (I-13; §2.8 mx-4).
package smtpedgeservice
