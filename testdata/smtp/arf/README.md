# ARF fixtures

Feedback reports in the three shapes §14.8 reads, for smtpedgeservice's header-only parse
(SMTP-M5-02). Lines end in LF here; the tests turn every LF into CRLF before parsing. Names are
`.example`, addresses are RFC 5737's: 192.0.2.10 is the tests' one sending address, and
198.51.100.0/24 stands for third parties, which no parse output may name. Every enclosed body holds
`BODY-CANARY`, and every enclosed Subject `SUBJECT-CANARY`, which no output may hold either. The DKIM
signatures' b= and bh= values are placeholders: these fixtures test the parse, not a verify.

- `rfc5965.eml`: plain RFC 5965, with the original message as message/rfc822.
- `jmrp.eml`: Microsoft JMRP's shape, with the receiver's internal hops above the one from the sending
  address.
- `jmrp-redacted.eml`: the same with the recipient masked, as JMRP sends it.
- `cfl.eml`: Yahoo CFL's shape, headers only, as text/rfc822-headers.
