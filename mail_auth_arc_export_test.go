//go:build !sidecar_http && !js

// Bridges for MAIL-M7-09's external tests: RFC 6376's canonicalization and signature check, which the RFC's own
// examples test, and how many check slots are taken and waited for, so a test knows its arrivals have queued.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
)

// RFC 6376 §3.4.2's relaxed form of a field given with its CRLF, with one.
func MailCanonHeaderRelaxedForTest(field []byte) []byte {
	return append(mailCanonHeaderRelaxed(bytes.TrimSuffix(field, []byte("\r\n"))), '\r', '\n')
}

// The canonical form of body, relaxed or simple, as its hash covers it.
func MailCanonBodyForTest(body []byte, relaxed bool) []byte {
	var canonical bytes.Buffer
	canonicalizer := &mailBodyCanonicalizer{out: bufio.NewWriter(&canonical), relaxed: relaxed}
	// fed a byte at a time, so a CRLF split across reads is tested as well as one whole
	for index := range body {
		canonicalizer.write(body[index : index+1])
	}
	if err := canonicalizer.close(); err != nil {
		panic(err)
	}
	return canonical.Bytes()
}

// The SHA-256 of body's canonical form, read in chunks.
func MailCanonBodyHashForTest(body []byte, relaxed bool) ([]byte, error) {
	return mailCanonBodyHash(context.Background(), bytes.NewReader(body), relaxed)
}

// Whether signature holds over data's SHA-256 under publicKey.
func MailVerifySignatureDataForTest(publicKey crypto.PublicKey, data []byte, signature []byte) bool {
	return mailVerifySignatureData(publicKey, data, signature)
}

// A field as its own signature covers it, its b= value gone.
func MailFieldWithoutSignatureForTest(field []byte) ([]byte, bool) {
	return mailFieldWithoutSignature(field)
}

// How many of slots' slots are taken, and how many messages wait for one.
func MailAuthSlotsStateForTest(slots *MailAuthSlots) (takenCount int, waitingCount int) {
	slots.stateLock.Lock()
	defer slots.stateLock.Unlock()
	return slots.takenCount, len(slots.waiters)
}
