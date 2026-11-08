# Mutated witnesses (SMTP-M9-29)

Written by `TestMutatedWitnessTable` from `mutate_test.go`'s registry, which fails when this file differs; set `SMTPPROOF_WRITE_MUTATIONS` to rewrite it. Each row is a break of one honest connection that the named check alone refuses. The gate, whose verifier is `relationCheckPart` over the edge's own statement, and `smtpproof/checker`, which reads SPEC.md apart from this module, each name exactly that check; then the circuit refuses the part named, through gnark's solver over the edge's own statement, or `edgeSession` refuses on its own ("gate"), with the solver as its verifier as well. Every record keeps its length, so a break's part fits the shape its honest twin's does. The test named runs the row on every run of the package; its circuit half runs in the leg without `sidecar_testhooks`.

| Check | TLS | Mode | Refused at | Mutation | Test |
|---|---|---|---|---|---|
| E1 | 1.3 AES-128-GCM | BDAT | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.3 AES-128-GCM | DATA | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.3 ChaCha20-Poly1305 | DATA | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a client record of another type after the handshake | TestMutatedWitnessE1 |
| E1 | 1.3 AES-128-GCM | BDAT | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E1 | 1.3 AES-128-GCM | DATA | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E1 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E1 | 1.3 ChaCha20-Poly1305 | DATA | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E1 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E1 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a server record of type handshake after the handshake, renegotiation in 1.2 | TestMutatedWitnessE1 |
| E2 | 1.3 AES-128-GCM | BDAT | gate | a disclosed SHTS one bit off | TestMutatedWitnessE2 |
| E2 | 1.3 AES-128-GCM | DATA | gate | a disclosed SHTS one bit off | TestMutatedWitnessE2 |
| E2 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a disclosed SHTS one bit off | TestMutatedWitnessE2 |
| E2 | 1.3 ChaCha20-Poly1305 | DATA | gate | a disclosed SHTS one bit off | TestMutatedWitnessE2 |
| E2 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a ServerKeyExchange whose signature is one bit off | TestMutatedWitnessE2 |
| E2 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a ServerKeyExchange whose signature is one bit off | TestMutatedWitnessE2 |
| E3 | 1.3 AES-128-GCM | BDAT | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | DATA | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | DATA | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a record one bit off the ciphertext its part proved | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | BDAT | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | DATA | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | DATA | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a part's record of another outer type, which the circuit cannot see | TestMutatedWitnessE3 |
| Z1 | 1.3 AES-128-GCM | BDAT | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 AES-128-GCM | DATA | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | BDAT | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | DATA | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi1, Z1 in its circuit | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z2 | 1.3 AES-128-GCM | BDAT | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 AES-128-GCM | DATA | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 ChaCha20-Poly1305 | BDAT | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 ChaCha20-Poly1305 | DATA | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi2 | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z3 | 1.3 AES-128-GCM | BDAT | pi3 | pi3's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 AES-128-GCM | DATA | pi3 | pi3's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | pi3's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 ChaCha20-Poly1305 | DATA | pi3 | pi3's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z4 | 1.3 AES-128-GCM | BDAT | pi3 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 AES-128-GCM | DATA | pi2 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 ChaCha20-Poly1305 | DATA | pi2 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi3 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi2 | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z5 | 1.3 AES-128-GCM | BDAT | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 AES-128-GCM | DATA | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | DATA | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi3 | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z6 | 1.3 AES-128-GCM | BDAT | pi3 | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi3 | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.3 AES-128-GCM | DATA | pi4 | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z6 | 1.3 ChaCha20-Poly1305 | DATA | pi4 | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z6 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi4 | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z7 | 1.3 AES-128-GCM | BDAT | pi3 | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 AES-128-GCM | DATA | pi3 | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 ChaCha20-Poly1305 | DATA | pi3 | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z8 | 1.3 AES-128-GCM | BDAT | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | DATA | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | BDAT | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | DATA | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | pi3 | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z9 | 1.3 AES-128-GCM | BDAT | pi2 | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |
| Z9 | 1.3 ChaCha20-Poly1305 | BDAT | pi2 | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |
| Z9 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | pi2 | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |

Cells no witness can break alone:

| Check | TLS | Mode | Why |
|---|---|---|---|
| Z3 | 1.2 | BDAT | 1.2's Z3 holds nothing private: the outer type is public, which E1 checks on the stream and E3 on a part's records before any verification (see E3's rows), and the plaintext's length is the record's, which Z2 fixes |
| Z3 | 1.2 | DATA | 1.2's Z3 holds nothing private: the outer type is public, which E1 checks on the stream and E3 on a part's records before any verification (see E3's rows), and the plaintext's length is the record's, which Z2 fixes |
| Z7 | 1.2 | BDAT | 1.2's server record types are public: E1 refuses any but application_data after the handshake and an alert closes the connection (see E1's rows), and a record opens at its own sequence number by Z2 |
| Z7 | 1.2 | DATA | 1.2's server record types are public: E1 refuses any but application_data after the handshake and an alert closes the connection (see E1's rows), and a record opens at its own sequence number by Z2 |
| Z9 | 1.3 | DATA | DATA has no Z9 condition: DATA to an MX offering CHUNKING is allowed (SPEC.md Z9) |
| Z9 | 1.2 | DATA | DATA has no Z9 condition: DATA to an MX offering CHUNKING is allowed (SPEC.md Z9) |
