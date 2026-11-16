# X-UR-Ref vectors

The bytes of the reference smtpedge issues for each accepted preamble (§14.6, D-SMTP-6), as
plan-SMTP-small-readings#3 fixes them: `1.` then lowercase unpadded base32 of `key_id` (1 octet) ‖
`send_id` (12 octets) ‖ HMAC-SHA256(key, `send_id` ‖ `network_id` (16 octets) ‖ `day`)[0:8], `day` a u32be
count of UTC days since the Unix epoch: 21 octets, 34 characters, 36 in all. smtpedgeservice's
issue_test.go holds `IssueSmtpXUrRef` and `VerifySmtpXUrRef` to this file (SMTP-M9-10).

The values were computed with Python's standard library (hmac, hashlib, base64, struct), apart from the
Go code they check, so the two agree on the bytes rather than on a shared mistake. Keys, send ids and
network ids are synthetic.

- `vectors`: each issued reference. Every one verifies under its own key, network and day.
- `refusals`: each verified under the first vector's key (as key id 1, beside the other vectors' keys),
  network and day, and each refused: issued to another network (§22.5's replay under another network's
  id), issued on another day, under a key id the edge does not hold, a changed character of the send id
  or of the MAC, a change to the last character's unused bits (one reference has one form), another
  version, upper case, and one character too many or too few.
