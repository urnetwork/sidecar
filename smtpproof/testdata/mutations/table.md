# Mutated witnesses (SMTP-M9-29)

Written by `TestMutatedWitnessTable` from `mutate_test.go`'s registry, which fails when this file differs; set `SMTPPROOF_WRITE_MUTATIONS` to rewrite it. Each row is a break of one honest connection that the named check alone refuses. Parts are bound to one key part (DESIGN-DETAILS 3.2): part 1 (key) derives the session's keys from the handshake and commits to them, and every later part opens that commitment, part 2 (env) with MAIL and the RCPTs, part 3 (msg) with the header block's first record, a hdr part with a later header record and in DATA mode a body part with a body record. The gate, whose verifier is `relationCheckPart` over the edge's own statement, and `smtpproof/checker`, which reads SPEC.md and DESIGN-DETAILS 3.2 apart from this module, each name exactly that check; then the circuit refuses the part named, through gnark's solver over the edge's own statement, or `edgeSession` refuses on its own ("gate"), with the solver as its verifier as well. The solver takes each part on a test shape sized to it, which holds every check of its kind and the opening of the key commitment but not the key part's derivation; Z1's rows take part 1 on its production shape, which holds that too. Every record keeps its length, so a break's part fits the shape its honest twin's does, and the part named has the kind named in the honest connection. The header-record rows of DESIGN-DETAILS 3.6's cells start from a send whose header block takes two records, the first ending inside a field's name; the forged-scan rows also hold that the record scans from the forged state on its own, so that the carry alone refuses. The row of an env part's own reply_count starts from a send whose envelope goes one command a group (DESIGN-DETAILS 3.2.4), each env part after part 2 covering the reply to the command before, where the gate's order bounds a part's reply_count and only the relation fixes it. The test named runs the row on every run of the package; its circuit half runs in the leg without `sidecar_testhooks`.

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
| E3 | 1.3 AES-128-GCM | BDAT | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | DATA | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | BDAT | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | DATA | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | a part opening one record more, which its position gives a role the part cannot open | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | BDAT | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| E3 | 1.3 AES-128-GCM | DATA | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | BDAT | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| E3 | 1.3 ChaCha20-Poly1305 | DATA | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| E3 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | gate | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | TestMutatedWitnessE3 |
| Z1 | 1.3 AES-128-GCM | BDAT | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 AES-128-GCM | DATA | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | BDAT | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | DATA | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 1 (key), on its production shape | another HS or master secret, the keys it gave kept | TestMutatedWitnessZ1 |
| Z1 | 1.3 AES-128-GCM | BDAT | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z1 | 1.3 AES-128-GCM | DATA | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | BDAT | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z1 | 1.3 ChaCha20-Poly1305 | DATA | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z1 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 2 (env) | the env part's client key one bit off, its records sealed again under that key | TestMutatedWitnessZ1 |
| Z2 | 1.3 AES-128-GCM | BDAT | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 AES-128-GCM | DATA | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 ChaCha20-Poly1305 | BDAT | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.3 ChaCha20-Poly1305 | DATA | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z2 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 2 (env) | a MAIL record whose first ciphertext octet no longer opens to the claimed M | TestMutatedWitnessZ2 |
| Z3 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | the msg part's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 AES-128-GCM | DATA | part 3 (msg) | the msg part's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | the msg part's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z3 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | the msg part's first record sealed with inner type 22 under the true key | TestMutatedWitnessZ3 |
| Z4 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 AES-128-GCM | DATA | part 2 (env) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.3 ChaCha20-Poly1305 | DATA | part 2 (env) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z4 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 2 (env) | a command of its template's length that says another: BDAT's count, or DATB | TestMutatedWitnessZ4 |
| Z5 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 AES-128-GCM | DATA | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 3 (msg) | a header block whose Feedback-ID field is renamed, so it has none | TestMutatedWitnessZ5 |
| Z5 | 1.3 AES-128-GCM | BDAT | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z5 | 1.3 AES-128-GCM | DATA | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | BDAT | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z5 | 1.3 ChaCha20-Poly1305 | DATA | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z5 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 4 (hdr) | header record 2 scanned from the start state, where record 1 ended inside a field's name | TestMutatedWitnessZ5 |
| Z6 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | QUIX in QUIT's place at last_record | TestMutatedWitnessZ6 |
| Z6 | 1.3 AES-128-GCM | DATA | part 4 (body) | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z6 | 1.3 ChaCha20-Poly1305 | DATA | part 4 (body) | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z6 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 4 (body) | a body record ending the message early, as long as its honest twin | TestMutatedWitnessZ6 |
| Z6 | 1.3 AES-128-GCM | DATA | part 5 (body) | body record 2 scanned from the start state, where record 1 ended inside a line | TestMutatedWitnessZ6 |
| Z6 | 1.3 ChaCha20-Poly1305 | DATA | part 5 (body) | body record 2 scanned from the start state, where record 1 ended inside a line | TestMutatedWitnessZ6 |
| Z6 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 5 (body) | body record 2 scanned from the start state, where record 1 ended inside a line | TestMutatedWitnessZ6 |
| Z7 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 AES-128-GCM | DATA | part 3 (msg) | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z7 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | an RCPT reply's record replaced by a server KeyUpdate | TestMutatedWitnessZ7 |
| Z8 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | DATA | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 3 (msg) | an RCPT reply refused, 550 in 250's place | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | DATA | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 3 (msg) | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | BDAT | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | DATA | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 3 (msg) | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | BDAT | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z8 | 1.3 AES-128-GCM | DATA | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | BDAT | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z8 | 1.3 ChaCha20-Poly1305 | DATA | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z8 | 1.2 ECDHE-ECDSA AES-128-GCM | DATA | part 3 (env) | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | TestMutatedWitnessZ8 |
| Z9 | 1.3 AES-128-GCM | BDAT | part 2 (env) | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |
| Z9 | 1.3 ChaCha20-Poly1305 | BDAT | part 2 (env) | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |
| Z9 | 1.2 ECDHE-ECDSA AES-128-GCM | BDAT | part 2 (env) | an EHLO reply whose CHUNKING line is misspelled CHUNKINX | TestMutatedWitnessZ9 |

DESIGN-DETAILS 3.6's cells, each filled in every TLS version and mode its check applies to there:

| Check | Cell | Mutation | Modes |
|---|---|---|---|
| Z1 | a later part opens other keys than the key part committed | the env part's client key one bit off, its records sealed again under that key | BDAT and DATA, every leg |
| Z5 | a scan started from another state than the record before left | header record 2 scanned from the start state, where record 1 ended inside a field's name | BDAT and DATA, every leg |
| Z6 | a scan started from another state than the record before left | body record 2 scanned from the start state, where record 1 ended inside a line | DATA, every leg |
| Z8 | reply_count is not what the records hold | reply_count one more than the records hold: MAIL's reply continued into the first RCPT's, in its length | BDAT and DATA, every leg |
| Z8 | reply_count is not what the records hold | reply_count one fewer than the records hold: the first RCPT's reply rewritten as two replies, in its length | BDAT and DATA, every leg |
| Z8 | reply_count is not what the records hold | an env part's own reply_count one fewer on the wire than its records hold, the envelope one command a group | BDAT and DATA, every leg |
| E3 | a first message record before 2 + R replies are proven | the msg part covers none of the envelope's replies, its own count of them 0, so only the EHLO reply is proven | BDAT and DATA, every leg |

Cells no witness can break alone:

| Check | TLS | Mode | Why |
|---|---|---|---|
| Z3 | 1.2 | BDAT | 1.2's Z3 holds nothing private: the outer type is public, which E1 checks on the stream and E3 on a part's records before any verification (see E3's rows), and the plaintext's length is the record's, which Z2 fixes |
| Z3 | 1.2 | DATA | 1.2's Z3 holds nothing private: the outer type is public, which E1 checks on the stream and E3 on a part's records before any verification (see E3's rows), and the plaintext's length is the record's, which Z2 fixes |
| Z7 | 1.2 | BDAT | 1.2's server record types are public: E1 refuses any but application_data after the handshake and an alert closes the connection (see E1's rows), and a record opens at its own sequence number by Z2 |
| Z7 | 1.2 | DATA | 1.2's server record types are public: E1 refuses any but application_data after the handshake and an alert closes the connection (see E1's rows), and a record opens at its own sequence number by Z2 |
| Z9 | 1.3 | DATA | DATA has no Z9 condition: DATA to an MX offering CHUNKING is allowed (SPEC.md Z9) |
| Z9 | 1.2 | DATA | DATA has no Z9 condition: DATA to an MX offering CHUNKING is allowed (SPEC.md Z9) |
