# Assembled header blocks

Header blocks as `AssembleSmtpMessage` and `SmtpDkimSign` make them (SMTP-M9-04), in DESIGN-DETAILS
3.2.3's order. The head comes first: X-UR-Ref, Feedback-ID, From, Message-ID and, on a BULK message,
List-Unsubscribe-Post, then the fixed signature's first line, which carries its d= and s=. The rest of
the fixed signature, the full signature and the message's other fields, in their order, follow. The
prover cuts a header block into records by length alone (3.2.4), and Z5 holds every single field and
the fixed signature's d= and s= to the first record, so the head leads and
`SmtpSenderSettings.HeaderHeadMaxByteCount` (720 octets) bounds it below the shortest first record.
Lines end in LF here; the test turns every CRLF it renders into LF before comparing.

Each block is rendered as `ByteCount` renders it, with b= as the base64 of 256 zero octets, since a
signature is a function of a key and no key is kept here (the tests' keys exist only for the run).
Every other octet is the signed message's: the issued values, the selector and the signing time,
2026-11-08 12:00 UTC, are synthetic, and the names are `.example` ones. bh= is the relaxed body hash
of the message's body, `Hi.`, `We lost the game.  Are you hungry yet?` and `Joe.` for `plain.txt`
(RFC 8463's example body, whose hash that RFC publishes), and `Offers.` for `bulk.txt`.
smtp_assemble_test.go's `TestAssembledHeaderBlocksAreTheVectors` holds the sender to these files, and
`-update-smtp-assemble-vectors` rewrites them.

- `plain.txt`: RFC 8463's example message at `n1.root.example`, its Bcc dropped.
- `bulk.txt`: a BULK message whose From and Message-ID came after its other fields, which keep their
  order behind both signatures, and which gains List-Unsubscribe-Post in the head.
