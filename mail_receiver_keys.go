//go:build !sidecar_http && !ios_extension

// §15.5's mail host key and its TLSA (D-MAIL-4, I-8, I-14, I-15, X6, R-MAIL-1; MAIL-M7-13): which key a receiver
// serves, and from when. The key is §13's device TLS key (TlsDeviceKey), sealed in the keychain under the tls
// namespace and nowhere else: no URnetwork component and no evs repo holds it, and only its SubjectPublicKeyInfo
// leaves this device, in POST /dns/key-record's body beside the identity key's TlsKeyAttestation for it (§13.8).
//
//	publish  each key the keychain holds for the network, the current one and a rotation's pending successor, has its
//	         TLSA 3 1 1 published once, through POST /dns/key-record (§12.8): the successor as soon as the rotation
//	         sets it, so its TLSA is live by the time its certificate installs and the keychain promotes it. The time
//	         each publication was taken is kept in the mail component's store, public values only: the host, the
//	         SPKI's SHA-256 and the time
//	live     a key goes live 2 TTLs after its publication (RFC 7671 §8.1): 600 s at §15.5's TTL of 300 s, counted on
//	         the receiver's clock from when the route answered. A key serves only once live, so a DANE sender never
//	         meets a key that the TLSA it may hold cached does not name
//	serve    the current key once it is live; while a rotation's successor is current and not live yet, the key the
//	         receiver served before, which it holds in memory past the keychain's promotion with the certificate it
//	         last presented on it; a restart inside that window serves nothing until the new key is live (§9.9's
//	         serving=false), the closed direction, so senders retry
//	retire   a key neither held nor served has its record dropped. Its TLSA stays until the receiver's removal
//	         retires every key of it (DNS-M7-02, I-15): no route retires one key alone, which question
//	         mail-m7-13-rotated-key-tlsa raises
//
// Nothing here logs a host, a name or a key (I-13). The store's records are public values, and the private key is
// reached only as a crypto.Signer, by crypto/tls and by a self-signed leaf's signature.

package sidecar

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The mail component's store file that holds the receiver's TLSA publications.
const mailReceiverTlsaFileName = "receiver-tlsa.json"

// That file's format.
const mailReceiverTlsaFormat = 1

var (
	// The keys or the names a receiver needs are not there to read: no tls state, a locked keychain, or no zone.
	ErrMailReceiverKeys = errors.New("mail receiver: no key or names to serve")
	// The TLSA publication store does not read as this format writes it.
	errMailReceiverTlsaFormat = fmt.Errorf("%w: the receiver's tlsa records do not decode", ErrSidecarStoreFailed)
)

// The device key as a receiver reaches it (§13.8): the keychain's record through the Sidecar's key lock, and the
// certificate the device presents on its current key. Nothing here answers a private key. Safe for concurrent use.
type MailReceiverKeys interface {
	// The key serving now, made on first use, and the successor a rotation set, nil when none is pending.
	TlsKeys() (current *TlsDeviceKey, pending *TlsDeviceKey, err error)
	// What the device presents for names on its current key: §13's issued chain once one covers them, else a
	// self-signed leaf on the same key (Sidecar.TlsDeviceCertificate).
	TlsDeviceCertificate(names []string) (*tls.Certificate, error)
}

// POST /dns/key-record (§12.8) as a receiver calls it. Safe for concurrent use.
type MailReceiverKeyPublisher interface {
	// Publishes key's TLSA 3 1 1 at _25._tcp.<host> under the network's zone, with the identity key's attestation for
	// key and identifierSet; nil once the zone's TLSA holds it, which a key published before answers too.
	PublishKeyRecord(ctx context.Context, host string, key *TlsDeviceKey, identifierSet []string) error
}

// MailReceiverKeys over a Sidecar's device key.
type mailReceiverSidecarKeys struct {
	sidecar *Sidecar
}

// See MailReceiverKeys.
func (self *mailReceiverSidecarKeys) TlsKeys() (*TlsDeviceKey, *TlsDeviceKey, error) {
	return (&sidecarTlsCertKeys{sidecar: self.sidecar}).TlsKeys()
}

// See MailReceiverKeys.
func (self *mailReceiverSidecarKeys) TlsDeviceCertificate(names []string) (*tls.Certificate, error) {
	return self.sidecar.TlsDeviceCertificate(names)
}

// This Sidecar's device key as a receiver reaches it.
func (self *Sidecar) MailReceiverKeys() MailReceiverKeys {
	return &mailReceiverSidecarKeys{sidecar: self}
}

// MailReceiverKeyPublisher over a network's DnsClient: the body names the key's SPKI and carries the attestation the
// identity key signs for it and the network's identifier set, so the TLSA the route writes names only a key this
// sidecar holds (DNS-M7-02). The route's service token is the DnsClient's.
type mailReceiverDnsPublisher struct {
	dns       *DnsClient
	sign      TlsKeyAttestationSignFunction
	networkId Id
	sidecarId Id
	clock     Clock
}

// A publisher over dns, signing with sign as sidecarId of networkId.
func newMailReceiverDnsPublisher(dns *DnsClient, sign TlsKeyAttestationSignFunction, networkId Id, sidecarId Id, clock Clock) *mailReceiverDnsPublisher {
	return &mailReceiverDnsPublisher{dns: dns, sign: sign, networkId: networkId, sidecarId: sidecarId, clock: clockOrReal(clock)}
}

// See MailReceiverKeyPublisher.
func (self *mailReceiverDnsPublisher) PublishKeyRecord(ctx context.Context, host string, key *TlsDeviceKey, identifierSet []string) error {
	if self.dns == nil || self.sign == nil || key == nil {
		return ErrMailReceiverKeys
	}
	identifierSetSha256, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		return err
	}
	spkiSha256 := key.SpkiSha256()
	attestation, err := SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           self.networkId[:],
		SidecarId:           self.sidecarId[:],
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
		IssueTimeMillis:     uint64(self.clock.Now().UnixMilli()),
	}, self.sign)
	if err != nil {
		return err
	}
	body, err := json.Marshal(&DnsKeyRecordRequest{Host: host, Spki: key.Spki(), Attestation: attestation})
	if err != nil {
		return fmt.Errorf("dns POST %s: a body that does not marshal", DnsKeyRecordPath)
	}
	answer, err := self.dns.do(ctx, "POST "+DnsKeyRecordPath, http.MethodPost, DnsKeyRecordPath, body, nil)
	if err != nil {
		return err
	}
	parsed := &DnsKeyRecordAnswer{}
	if err := json.Unmarshal(answer, parsed); err != nil {
		return fmt.Errorf("%w: POST %s", ErrDnsClientReply, DnsKeyRecordPath)
	}
	// the zone's own hint carries the new version to the client's cache (dns_hint.go)
	return nil
}

// §13.8's identifier set for the network as its DnsClient's zone gives it: {*.<net>.<root>, <net>.<root>}, and the
// alias's pair beside it, which covers mx.<net>.<root> and every burner under the wildcard MX (§15.9).
func mailReceiverZoneNames(ctx context.Context, dns *DnsClient) ([]string, error) {
	if dns == nil {
		return nil, ErrMailReceiverKeys
	}
	zone, err := dns.Zone(ctx)
	if err != nil {
		return nil, err
	}
	aliases := []string{}
	if zone.Alias != "" {
		aliases = append(aliases, zone.Alias)
	}
	// the root as the server computes the set the attestation is checked against: canonical, with no final dot
	return TlsIdentifierSet(strings.TrimSuffix(zone.Root, "."), zone.Label, "", aliases)
}

// The zone watch this Sidecar's host attached, nil for none (SetDnsWatch).
func (self *Sidecar) mailDnsWatch() *DnsWatch {
	self.dns.stateLock.Lock()
	defer self.dns.stateLock.Unlock()
	watch, _ := self.dns.watch.(*DnsWatch)
	return watch
}

// One key's TLSA publication as the store keeps it: public values only.
type mailReceiverTlsaRecord struct {
	Host              string `json:"host"`
	SpkiSha256        string `json:"spki_sha256"`
	PublishTimeMillis int64  `json:"publish_time_ms"`
}

// The store file's form.
type mailReceiverTlsaFile struct {
	Format  int                       `json:"format"`
	Records []*mailReceiverTlsaRecord `json:"records"`
}

// The receiver's TLSA publications: in memory, and in the store when one is given, so a restart knows when each key
// went out and serves none early. Not safe for concurrent use: the receiver's key pass alone reads and writes it.
type mailReceiverTlsaRecords struct {
	store  SidecarStore
	host   string
	loaded bool
	// by the SPKI's SHA-256 in hex
	publishTimes map[string]time.Time
}

// Records of host's keys in store, which may be nil.
func newMailReceiverTlsaRecords(store SidecarStore, host string) *mailReceiverTlsaRecords {
	return &mailReceiverTlsaRecords{store: store, host: host, publishTimes: map[string]time.Time{}}
}

// Reads the store once. A file that does not decode is a failure, never absence (D-CORE-15), so nothing is taken as
// unpublished that was published, nor the other way.
func (self *mailReceiverTlsaRecords) load() error {
	if self.loaded {
		return nil
	}
	if self.store != nil {
		reader, err := self.store.Open(mailReceiverTlsaFileName)
		switch {
		case errors.Is(err, ErrSidecarStoreAbsent):
		case err != nil:
			return err
		default:
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				return err
			}
			file := &mailReceiverTlsaFile{}
			if err := json.Unmarshal(data, file); err != nil || file.Format != mailReceiverTlsaFormat {
				return errMailReceiverTlsaFormat
			}
			for _, record := range file.Records {
				if record == nil || record.Host != self.host {
					continue
				}
				if decoded, err := hex.DecodeString(record.SpkiSha256); err != nil || len(decoded) != sha256.Size {
					return errMailReceiverTlsaFormat
				}
				self.publishTimes[record.SpkiSha256] = time.UnixMilli(record.PublishTimeMillis)
			}
		}
	}
	self.loaded = true
	return nil
}

// When key's TLSA went out, false for a key not published.
func (self *mailReceiverTlsaRecords) publishTime(key *TlsDeviceKey) (time.Time, bool) {
	spkiSha256 := key.SpkiSha256()
	publishTime, ok := self.publishTimes[hex.EncodeToString(spkiSha256[:])]
	return publishTime, ok
}

// Keeps key's publication at publishTime, durably before it counts.
func (self *mailReceiverTlsaRecords) put(key *TlsDeviceKey, publishTime time.Time) error {
	spkiSha256 := key.SpkiSha256()
	publishTimes := map[string]time.Time{}
	for spki, at := range self.publishTimes {
		publishTimes[spki] = at
	}
	publishTimes[hex.EncodeToString(spkiSha256[:])] = publishTime
	if err := self.write(publishTimes); err != nil {
		return err
	}
	self.publishTimes = publishTimes
	return nil
}

// Drops the records of every key but those in keys, which may hold nils.
func (self *mailReceiverTlsaRecords) keepOnly(keys ...*TlsDeviceKey) error {
	kept := map[string]time.Time{}
	for _, key := range keys {
		if key == nil {
			continue
		}
		spkiSha256 := key.SpkiSha256()
		spki := hex.EncodeToString(spkiSha256[:])
		if at, ok := self.publishTimes[spki]; ok {
			kept[spki] = at
		}
	}
	if len(kept) == len(self.publishTimes) {
		return nil
	}
	if err := self.write(kept); err != nil {
		return err
	}
	self.publishTimes = kept
	return nil
}

// The records as the store's file, replacing what it held.
func (self *mailReceiverTlsaRecords) write(publishTimes map[string]time.Time) error {
	if self.store == nil {
		return nil
	}
	file := &mailReceiverTlsaFile{Format: mailReceiverTlsaFormat, Records: []*mailReceiverTlsaRecord{}}
	for spki, at := range publishTimes {
		file.Records = append(file.Records, &mailReceiverTlsaRecord{Host: self.host, SpkiSha256: spki, PublishTimeMillis: at.UnixMilli()})
	}
	slices.SortFunc(file.Records, func(a *mailReceiverTlsaRecord, b *mailReceiverTlsaRecord) int {
		return strings.Compare(a.SpkiSha256, b.SpkiSha256)
	})
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(mailReceiverTlsaFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// The SHA-256 of the SubjectPublicKeyInfo of certificate's leaf, false when it has none that parses.
func mailCertificateSpkiSha256(certificate *tls.Certificate) ([sha256.Size]byte, bool) {
	if certificate == nil {
		return [sha256.Size]byte{}, false
	}
	leaf := certificate.Leaf
	if leaf == nil {
		if len(certificate.Certificate) == 0 {
			return [sha256.Size]byte{}, false
		}
		parsed, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return [sha256.Size]byte{}, false
		}
		leaf = parsed
	}
	return sha256.Sum256(leaf.RawSubjectPublicKeyInfo), true
}

// Whether certificate's leaf is within its validity at now.
func mailCertificateValidAt(certificate *tls.Certificate, now time.Time) bool {
	if certificate == nil {
		return false
	}
	leaf := certificate.Leaf
	if leaf == nil {
		if len(certificate.Certificate) == 0 {
			return false
		}
		parsed, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return false
		}
		leaf = parsed
	}
	return !now.Before(leaf.NotBefore) && !now.After(leaf.NotAfter)
}
