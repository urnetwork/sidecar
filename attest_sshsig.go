//go:build !ios_extension && !sidecar_http

// OpenSSH's SSHSIG (PROTOCOL.sshsig), the signature `ssh-keygen -Y sign` writes, which signs the compute policy and its
// freshness tickets (DESIGN-COMPUTE §5.4, compute-plan-policy-signature-format, QD-1256): one signature over the exact
// bytes, detached and armored, under a namespace, by a key whose OpenSSH certificate the release key signs. This file
// is the framing alone, the armor, the blob and the signed data, in both directions; what may sign and under which
// namespace is the verifier's (attest_policy_verify.go).
//
//	armor     "-----BEGIN SSH SIGNATURE-----\n", the blob in base64 in lines, "\n-----END SSH SIGNATURE-----\n";
//	          the final newline optional, nothing before or after, every line ended by \n alone
//	blob      byte[6] "SSHSIG" | uint32 version 1 | string publickey | string namespace | string reserved, empty |
//	          string hash_algorithm, sha256 or sha512 | string signature, the SSH wire signature
//	signed    byte[6] "SSHSIG" | string namespace | string reserved | string hash_algorithm | string H(message)
//
// The parser is total and bounded by its caller's size limit: anything else is errComputeSshsigFormat, which never
// repeats the input. Everything here is a function of its arguments, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// PROTOCOL.sshsig's identifiers.
const (
	computeSshsigMagic      = "SSHSIG"
	computeSshsigVersion    = 1
	computeSshsigBegin      = "-----BEGIN SSH SIGNATURE-----"
	computeSshsigEnd        = "-----END SSH SIGNATURE-----"
	computeSshsigHashSha256 = "sha256"
	computeSshsigHashSha512 = "sha512"
	// The width ssh-keygen wraps the armor's base64 at (sshbuf_dtob64's), which ComputeSshsigSign writes so its
	// output is ssh-keygen's byte for byte. Part of the armor's form, not a limit: a reader takes any width.
	computeSshsigArmorWidth = 70
)

// Armor or a blob that is not one SSHSIG of PROTOCOL.sshsig's form.
var errComputeSshsigFormat = errors.New("not an SSHSIG signature")

// One parsed SSHSIG, its fields as the blob carries them.
type computeSshsig struct {
	// The key that signed, a certificate where one is carried, as parsed.
	publicKey ssh.PublicKey
	// The namespace the signature was made under.
	namespace string
	// sha256 or sha512.
	hashAlgorithm string
	// The SSH wire signature over computeSshsigSignedData's bytes.
	signature *ssh.Signature
}

// The blob, as ssh.Unmarshal reads it after the magic.
type computeSshsigBlob struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	Signature     []byte
}

// The base64 between the armor's lines, decoded. Strict: the begin line and \n first, the end line last with at most
// one \n after it, no \r, no space, and base64 with its padding and zero padding bits.
func computeSshsigDearmor(armored []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(armored, []byte(computeSshsigBegin+"\n"))
	if !ok {
		return nil, errComputeSshsigFormat
	}
	rest = bytes.TrimSuffix(rest, []byte("\n"))
	body, ok := bytes.CutSuffix(rest, []byte("\n"+computeSshsigEnd))
	if !ok || len(body) == 0 {
		return nil, errComputeSshsigFormat
	}
	encoded := make([]byte, 0, len(body))
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(line) == 0 {
			return nil, errComputeSshsigFormat
		}
		encoded = append(encoded, line...)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		return nil, errComputeSshsigFormat
	}
	return blob, nil
}

// The SSHSIG armored holds. Its key is parsed but not trusted: the verifier decides that.
func computeSshsigParse(armored []byte) (*computeSshsig, error) {
	blob, err := computeSshsigDearmor(armored)
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(blob, []byte(computeSshsigMagic))
	if !ok {
		return nil, errComputeSshsigFormat
	}
	fields := &computeSshsigBlob{}
	if err := ssh.Unmarshal(rest, fields); err != nil {
		return nil, errComputeSshsigFormat
	}
	if fields.Version != computeSshsigVersion || len(fields.Reserved) != 0 {
		return nil, errComputeSshsigFormat
	}
	if fields.HashAlgorithm != computeSshsigHashSha256 && fields.HashAlgorithm != computeSshsigHashSha512 {
		return nil, errComputeSshsigFormat
	}
	publicKey, err := ssh.ParsePublicKey(fields.PublicKey)
	if err != nil {
		return nil, errComputeSshsigFormat
	}
	signature := &ssh.Signature{}
	if err := ssh.Unmarshal(fields.Signature, signature); err != nil {
		return nil, errComputeSshsigFormat
	}
	return &computeSshsig{
		publicKey:     publicKey,
		namespace:     fields.Namespace,
		hashAlgorithm: fields.HashAlgorithm,
		signature:     signature,
	}, nil
}

// The bytes an SSHSIG's signature covers: the magic, the namespace, an empty reserved string, the hash algorithm's
// name and the message's hash under it.
func computeSshsigSignedData(namespace string, hashAlgorithm string, message []byte) ([]byte, error) {
	var digest []byte
	switch hashAlgorithm {
	case computeSshsigHashSha256:
		sum := sha256.Sum256(message)
		digest = sum[:]
	case computeSshsigHashSha512:
		sum := sha512.Sum512(message)
		digest = sum[:]
	default:
		return nil, errComputeSshsigFormat
	}
	signed := ssh.Marshal(&struct {
		Namespace     string
		Reserved      []byte
		HashAlgorithm string
		Digest        []byte
	}{
		Namespace:     namespace,
		Reserved:      []byte{},
		HashAlgorithm: hashAlgorithm,
		Digest:        digest,
	})
	return append([]byte(computeSshsigMagic), signed...), nil
}

// An armored SSHSIG over message under namespace, as `ssh-keygen -Y sign -n <namespace>` writes it: SHA-512, an RSA
// key signing with rsa-sha2-512, and the signer's public key, which a signer from ssh.NewCertSigner makes its
// certificate. For tests, CTEST's fakes and the policy pipeline's software keys; the holders sign with ssh-keygen on
// their tokens, so no private key of theirs touches a tool (§14.10). random feeds the signer where its algorithm
// draws.
func ComputeSshsigSign(random io.Reader, signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	if signer == nil || namespace == "" {
		return nil, errors.New("sshsig sign: a signer and a namespace")
	}
	signed, err := computeSshsigSignedData(namespace, computeSshsigHashSha512, message)
	if err != nil {
		return nil, err
	}
	var signature *ssh.Signature
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if ok && computeSshsigUnderlyingType(signer.PublicKey()) == ssh.KeyAlgoRSA {
		signature, err = algorithmSigner.SignWithAlgorithm(random, signed, ssh.KeyAlgoRSASHA512)
	} else {
		signature, err = signer.Sign(random, signed)
	}
	if err != nil {
		return nil, fmt.Errorf("sshsig sign: %w", err)
	}
	blob := append([]byte(computeSshsigMagic), ssh.Marshal(&computeSshsigBlob{
		Version:       computeSshsigVersion,
		PublicKey:     signer.PublicKey().Marshal(),
		Namespace:     namespace,
		Reserved:      []byte{},
		HashAlgorithm: computeSshsigHashSha512,
		Signature:     ssh.Marshal(signature),
	})...)
	encoded := base64.StdEncoding.EncodeToString(blob)
	armored := &bytes.Buffer{}
	armored.WriteString(computeSshsigBegin + "\n")
	for 0 < len(encoded) {
		width := min(computeSshsigArmorWidth, len(encoded))
		armored.WriteString(encoded[:width] + "\n")
		encoded = encoded[width:]
	}
	armored.WriteString(computeSshsigEnd + "\n")
	return armored.Bytes(), nil
}

// The type of the key under a certificate, or the key's own.
func computeSshsigUnderlyingType(publicKey ssh.PublicKey) string {
	if certificate, ok := publicKey.(*ssh.Certificate); ok {
		return certificate.Key.Type()
	}
	return publicKey.Type()
}
