//go:build !ios_extension

// §12.8's label reclaim (DNS-M5-16; D-DNS-10, R-DNS-5, I-14, FS-41, FS-42): after a Postgres restore, a name the CT
// replay found logged and dns_label lacked sits retiring with no network, and only the holder of a logged
// certificate's key that names it can bind it back to its network. The proof is a signature by that key over
//
//	("urnetwork-sidecar-v1/label-reclaim", name, network_id, nonce)
//
// each part a 2-byte big-endian length then its bytes: the domain's ASCII; the name as CT logs it, the label or
// alias with its root, lowercase with no final dot; the network's id and the nonce, the restore's incident id, each
// its 16 bytes. The domain keeps the signature from passing as any TLS one, whose contexts differ, and the lengths
// keep two tuples from encoding alike. A signature over one name, network or incident fits no other.
//
// The key is a device's TLS key, ECDSA P-256 (§13.8), signing SHA-256 of the bytes in ASN.1 form, as crypto.Signer
// does: Sidecar.TlsSignLabelReclaim (TLS-M5-18) signs with it, and api and the dns block verify through
// VerifyDnsReclaimProof, so both ends read one encoding. On every leg but the ios_extension legs, with no connect
// import.

package sidecar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The domain a reclaim's signed bytes begin with (§12.8).
const DnsReclaimDomain = "urnetwork-sidecar-v1/label-reclaim"

// §12.8's two reclaim routes: api's for the console and network credentials, the dns block's for sidecars
// (plan-DNS-sidecar-zone-read).
const (
	NetworkDnsLabelReclaimPath = "/network/dns/label-reclaim"
	DnsLabelReclaimPath        = "/dns/label-reclaim"
)

var (
	// A proof whose parts cannot be encoded: an empty or overlong name, or a zero id.
	ErrDnsReclaimProofInvalid = errors.New("dns reclaim proof invalid")
	// A leaf, key or signature that does not prove the tuple: not P-256, not naming the name, or not verifying.
	ErrDnsReclaimRefused = errors.New("dns reclaim refused")
)

// The tuple a reclaim signs.
type DnsReclaimProof struct {
	// The name as CT logs it: <label>.<root>, lowercase with no final dot.
	Name      string
	NetworkId Id
	// The nonce: the restore's incident id (§19.10).
	IncidentId Id
}

// The proof's name as the tuple holds it: lowercase with no final dot.
func canonicalDnsReclaimName(name string) string {
	return strings.TrimSuffix(dnsAsciiLower(strings.TrimSpace(name)), ".")
}

// The bytes the certificate's key signs. See the file header.
func (self *DnsReclaimProof) SignedBytes() ([]byte, error) {
	name := canonicalDnsReclaimName(self.Name)
	if name == "" || 255 < len(name) || self.NetworkId == (Id{}) || self.IncidentId == (Id{}) {
		return nil, ErrDnsReclaimProofInvalid
	}
	parts := [][]byte{[]byte(DnsReclaimDomain), []byte(name), self.NetworkId[:], self.IncidentId[:]}
	signedBytes := []byte{}
	for _, part := range parts {
		signedBytes = binary.BigEndian.AppendUint16(signedBytes, uint16(len(part)))
		signedBytes = append(signedBytes, part...)
	}
	return signedBytes, nil
}

// The proof signed by signer, an ECDSA P-256 key: an ASN.1 signature over SHA-256 of SignedBytes. What
// Sidecar.TlsSignLabelReclaim runs with the device's TLS key.
func (self *DnsReclaimProof) Sign(signer crypto.Signer) ([]byte, error) {
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: the key is not ECDSA P-256", ErrDnsReclaimRefused)
	}
	signedBytes, err := self.SignedBytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signedBytes)
	return signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// SHA-256 of a leaf certificate's DER, as the CT replay records it.
func DnsReclaimLeafSha256(leafDer []byte) [sha256.Size]byte {
	return sha256.Sum256(leafDer)
}

// Whether leafDer is a certificate naming proof's name, exactly or as the wildcard one level above, on an ECDSA
// P-256 key whose signature over the proof's bytes is signature. It checks no chain or time: the CT replay's record
// of the leaf's hash is what vouches for the certificate, and a lapsed certificate's key still proves who held the
// name. Refusals wrap ErrDnsReclaimRefused or ErrDnsReclaimProofInvalid.
func VerifyDnsReclaimProof(proof *DnsReclaimProof, leafDer []byte, signature []byte) error {
	signedBytes, err := proof.SignedBytes()
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(leafDer)
	if err != nil {
		return fmt.Errorf("%w: the leaf does not parse", ErrDnsReclaimRefused)
	}
	name := canonicalDnsReclaimName(proof.Name)
	names := []string{}
	for _, dnsName := range leaf.DNSNames {
		names = append(names, canonicalDnsReclaimName(dnsName))
	}
	if !slices.Contains(names, name) && !slices.Contains(names, "*."+name) {
		return fmt.Errorf("%w: the leaf does not name %s", ErrDnsReclaimRefused, name)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: the leaf's key is not ECDSA P-256", ErrDnsReclaimRefused)
	}
	digest := sha256.Sum256(signedBytes)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return fmt.Errorf("%w: the signature does not verify", ErrDnsReclaimRefused)
	}
	return nil
}

// The body of POST /network/dns/label-reclaim and POST /dns/label-reclaim: the tuple's parts, the leaf and the
// signature over the tuple by its key.
type DnsLabelReclaimRequest struct {
	// <label>.<root>, as the tuple names it.
	Name      string `json:"name"`
	NetworkId Id     `json:"network_id"`
	// The restore's incident id, the tuple's nonce.
	IncidentId Id `json:"incident_id"`
	// The CT-logged leaf certificate's DER.
	Leaf      []byte `json:"leaf"`
	Signature []byte `json:"signature"`
}

// What a reclaim answers: the name, now its network's again, and the kind it took back.
type DnsLabelReclaimAnswer struct {
	Name string `json:"name"`
	// label or alias.
	Kind string `json:"kind"`
}
