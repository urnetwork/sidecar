# Aggregate fixtures

DMARC (RFC 9990) and TLS-RPT (RFC 8460) aggregate reports for smtpedgeservice's bounded parsers
(SMTP-M5-03). The tests gzip or zip them at run time and build the bombs themselves, so nothing binary
is kept here. 192.0.2.10 is the tests' one sending address; 198.51.100.0/24 stands for third parties,
whose rows the parser drops and whose addresses no output may name.

- `dmarc.xml`: three records, two from the sending address (a network's own domain and one of its
  burner labels) and one from a third party.
- `tlsrpt.json`: two policies, one a network's sts and one a burner label's no-policy-found, with
  failure details naming a third-party sending MTA.
