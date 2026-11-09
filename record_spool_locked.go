// The spool's locked half (§16.7's spool row; D-MCP-5): while the keychain is locked, capture seals each record to the
// epoch's spool public key with crypto/hpke, so it goes on with no key in memory, and the private half waits in
// keychain.ur for the next unlock's drain. Neither file here is sealed under R_n, since a locked daemon has none, so
// both sit in the network's ingest/ directory as plain backend files, which a rotation leaves where they are:
//
//	epoch file    spool-epoch/<epoch_id>: magic "URSE" | version 1 | epoch id, 16 B | X-Wing public key
//	segment       spool/<segment_id>.locked: magic "URSP" | version 1 | epoch id, 16 B | enc length, uint16 | enc
//	              record 0 | record 1 | ...   each as the log's: length, uint32 | its complement, uint32 | sealed
//
// HPKE-XWing (KEM 0x647a, HKDF-SHA256, ChaCha20Poly1305, as wasm's AES is table-based, D-CORE-10), base mode, info
// "urnetwork-sidecar-v1/spool", one context a segment: record i is the context's i-th Seal, its additional data the
// segment's header, its path, i and the SHA-256 of record i-1 as stored, so a record moved, reordered or dropped from
// the middle fails as a log's does. A segment whose append fails is closed, and the next record opens a new one, so
// the context's count never parts from the file's. A torn tail ends a segment as it ends a log.
//
// The epoch file holds a public key alone. Anyone who can write it can make the next locked records seal to another
// key, which any process of this user can do in any case (TB1); a drain holds the epoch's private key to it, and a
// segment whose epoch's key is gone is a coverage gap, never read.

package sidecar

import (
	"bufio"
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The locked half's format values.
const (
	spoolSegmentMagic = "URSP"
	spoolEpochMagic   = "URSE"
	spoolFileVersion  = 1
	spoolHpkeInfo     = "urnetwork-sidecar-v1/spool"
	// an epoch file's fixed part: magic, version and the epoch's id
	spoolEpochFixedByteCount = 4 + 1 + 16
	// a segment header's fixed part: magic, version, the epoch's id and enc's length
	spoolSegmentFixedByteCount = 4 + 1 + 16 + 2
	// the most a segment's enc or an epoch's public key holds: X-Wing's are 1,120 and 1,216 bytes
	spoolKeyMaxByteCount = 4 * 1024
)

var (
	// A spool file that does not hold its format.
	errSpoolFormat = fmt.Errorf("%w: not a spool file", ErrSidecarStoreFailed)
	// A locked record that fails to open: a wrong key, a record moved or dropped, or a bit flip.
	errSpoolOpen = fmt.Errorf("%w: a spooled record failed", ErrSidecarStoreFailed)
)

// Whether a file starting with prefix is one of the spool's plain files, which no root seals, so a rotation passes it
// by.
func isSpoolPlainFile(prefix []byte) bool {
	return bytes.Equal(prefix, []byte(spoolSegmentMagic)) || bytes.Equal(prefix, []byte(spoolEpochMagic))
}

// The spool's HPKE suite.
func spoolHpkeSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()
}

// One epoch's public half, as its file holds it.
type spoolEpoch struct {
	epochId   Id
	publicKey hpke.PublicKey
}

// An epoch file's bytes.
func encodeSpoolEpoch(epochId Id, publicKey []byte) []byte {
	encoded := make([]byte, 0, spoolEpochFixedByteCount+len(publicKey))
	encoded = append(encoded, spoolEpochMagic...)
	encoded = append(encoded, spoolFileVersion)
	encoded = append(encoded, epochId[:]...)
	return append(encoded, publicKey...)
}

// An epoch file, which must name epochId and hold a key the suite takes.
func decodeSpoolEpoch(encoded []byte, epochId Id) (*spoolEpoch, error) {
	if len(encoded) < spoolEpochFixedByteCount || string(encoded[0:4]) != spoolEpochMagic ||
		encoded[4] != spoolFileVersion || !bytes.Equal(encoded[5:21], epochId[:]) {
		return nil, errSpoolFormat
	}
	kem, _, _ := spoolHpkeSuite()
	publicKey, err := kem.NewPublicKey(encoded[spoolEpochFixedByteCount:])
	if err != nil {
		return nil, errSpoolFormat
	}
	return &spoolEpoch{epochId: epochId, publicKey: publicKey}, nil
}

// A locked segment's header.
func encodeSpoolSegmentHeader(epochId Id, enc []byte) []byte {
	encoded := make([]byte, 0, spoolSegmentFixedByteCount+len(enc))
	encoded = append(encoded, spoolSegmentMagic...)
	encoded = append(encoded, spoolFileVersion)
	encoded = append(encoded, epochId[:]...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(enc)))
	return append(encoded, enc...)
}

// Reads a locked segment's header from the front of in: its epoch, its enc and the header's bytes. torn reports a file
// a kill cut before its header was whole, which holds no record.
func readSpoolSegmentHeader(in *bufio.Reader) (epochId Id, enc []byte, encodedHeader []byte, torn bool, err error) {
	fixed := make([]byte, spoolSegmentFixedByteCount)
	n, err := io.ReadFull(in, fixed)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return Id{}, nil, nil, true, nil
	}
	if err != nil {
		return Id{}, nil, nil, false, storeFault(err)
	}
	if string(fixed[0:4]) != spoolSegmentMagic || fixed[4] != spoolFileVersion {
		zero, err := zeroTail(fixed[:n], in)
		if err != nil {
			return Id{}, nil, nil, false, err
		}
		if zero {
			return Id{}, nil, nil, true, nil
		}
		return Id{}, nil, nil, false, errSpoolFormat
	}
	copy(epochId[:], fixed[5:21])
	encByteCount := int(binary.BigEndian.Uint16(fixed[21:23]))
	if encByteCount == 0 || spoolKeyMaxByteCount < encByteCount {
		return Id{}, nil, nil, false, errSpoolFormat
	}
	enc = make([]byte, encByteCount)
	if _, err := io.ReadFull(in, enc); err == io.EOF || err == io.ErrUnexpectedEOF {
		return Id{}, nil, nil, true, nil
	} else if err != nil {
		return Id{}, nil, nil, false, storeFault(err)
	}
	return epochId, enc, append(fixed, enc...), false, nil
}

// Record index's additional data in a locked segment: the log's form.
func spoolLockedAdditionalData(encodedHeader []byte, path string, index uint64, previous *[sha256.Size]byte) []byte {
	return storeLogAdditionalData(encodedHeader, path, index, previous)
}

// A locked segment open for appends in this process: its HPKE context, which counts its Seals, and where the file
// ends.
type spoolLockedSegment struct {
	segmentId     Id
	epochId       Id
	path          string
	sender        *hpke.Sender
	encodedHeader []byte
	recordCount   uint64
	previous      [sha256.Size]byte
	// bytes written, the header included
	byteCount int64
}

// A new locked segment of epoch, its context drawn now. Nothing is written until its first record.
func newSpoolLockedSegment(epoch *spoolEpoch, path string) (*spoolLockedSegment, error) {
	_, kdf, aead := spoolHpkeSuite()
	enc, sender, err := hpke.NewSender(epoch.publicKey, kdf, aead, []byte(spoolHpkeInfo))
	if err != nil {
		return nil, fmt.Errorf("a spool segment's context: %w", err)
	}
	return &spoolLockedSegment{
		epochId:       epoch.epochId,
		path:          path,
		sender:        sender,
		encodedHeader: encodeSpoolSegmentHeader(epoch.epochId, enc),
	}, nil
}

// Seals record as the segment's next and appends it, with the header before the first, fsynced before this returns,
// and the directory after the file's first sync. After an error the segment must not take another record: its
// context has counted a Seal the file may not hold.
func (self *spoolLockedSegment) append(backend SidecarStoreBackend, backendPath string, record []byte) (int64, error) {
	additionalData := spoolLockedAdditionalData(self.encodedHeader, self.path, self.recordCount, &self.previous)
	sealed, err := self.sender.Seal(additionalData, record)
	if err != nil {
		return 0, fmt.Errorf("a spooled record's seal: %w", err)
	}
	frame := storeLogFrame(len(sealed))
	out := make([]byte, 0, len(self.encodedHeader)+len(frame)+len(sealed))
	if self.recordCount == 0 {
		out = append(out, self.encodedHeader...)
	}
	out = append(out, frame...)
	out = append(out, sealed...)
	file, created, err := backend.OpenAppend(backendPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	size, err := file.Size()
	if err != nil {
		return 0, err
	}
	if size != self.byteCount {
		// another writer, or a kill this process cannot have seen: the segment is not what this context wrote
		return 0, errSpoolFormat
	}
	if _, err := file.Write(out); err != nil {
		return 0, err
	}
	if err := file.Sync(); err != nil {
		return 0, err
	}
	if created || self.recordCount == 0 {
		if err := backend.SyncDirectory(backendPath); err != nil {
			return 0, err
		}
	}
	self.previous = storeLogRecordHash(frame, sealed)
	self.recordCount += 1
	self.byteCount += int64(len(out))
	return int64(len(out)), nil
}

// Reads a locked segment from in, at path, opening its records with the private key privateKeyOf answers for its
// epoch and handing each to visit. A torn tail ends it. privateKeyOf answers ErrSidecarStoreAbsent when the epoch's
// key is gone, which makes the segment unreadable for good.
func readSpoolLockedSegment(in io.Reader, path string, privateKeyOf func(epochId Id) (hpke.PrivateKey, error),
	visit func(index uint64, record []byte) error) error {
	reader := bufio.NewReader(in)
	epochId, enc, encodedHeader, torn, err := readSpoolSegmentHeader(reader)
	if err != nil || torn {
		return err
	}
	var recipient *hpke.Recipient
	var previous [sha256.Size]byte
	frame := make([]byte, storeLogFrameByteCount)
	for index := uint64(0); ; index += 1 {
		n, err := io.ReadFull(reader, frame)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return storeFault(err)
		}
		sealedByteCount := binary.BigEndian.Uint32(frame[0:4])
		if ^sealedByteCount != binary.BigEndian.Uint32(frame[4:8]) ||
			StoreLogRecordMaxByteCount+storeLogSealedMinByteCount < sealedByteCount {
			zero, err := zeroTail(frame[:n], reader)
			if err != nil {
				return err
			}
			if zero {
				return nil
			}
			return errSpoolFormat
		}
		sealed, err := io.ReadAll(io.LimitReader(reader, int64(sealedByteCount)))
		if err != nil {
			return storeFault(err)
		}
		if len(sealed) < int(sealedByteCount) {
			return nil
		}
		if recipient == nil {
			privateKey, err := privateKeyOf(epochId)
			if err != nil {
				return err
			}
			_, kdf, aead := spoolHpkeSuite()
			recipient, err = hpke.NewRecipient(enc, privateKey, kdf, aead, []byte(spoolHpkeInfo))
			if err != nil {
				return errSpoolOpen
			}
		}
		record, err := recipient.Open(spoolLockedAdditionalData(encodedHeader, path, index, &previous), sealed)
		if err != nil {
			return errSpoolOpen
		}
		if err := visit(index, record); err != nil {
			return err
		}
		previous = storeLogRecordHash(frame, sealed)
	}
}

// The epoch a locked daemon seals to when it has seen no unlock: the newest epoch file on disk, nil for none, which
// makes every record a gap until an unlock.
func (self *Spool) newestEpochOnDisk() (*spoolEpoch, error) {
	entries, err := self.instance.backend.List(self.backendPath(spoolEpochDirectoryName + "/"))
	if err != nil {
		return nil, err
	}
	for i := len(entries) - 1; 0 <= i; i -= 1 {
		name := entries[i].Name[len(self.backendPath(spoolEpochDirectoryName+"/")):]
		epochId, err := ParseId(name)
		if err != nil || epochId.String() != name {
			continue
		}
		encoded, err := readBackendFile(self.instance.backend, entries[i].Name, spoolEpochFixedByteCount+spoolKeyMaxByteCount)
		if err != nil {
			continue
		}
		epoch, err := decodeSpoolEpoch(encoded, epochId)
		if err != nil {
			continue
		}
		return epoch, nil
	}
	return nil, nil
}

// The private half of epochId's key pair, from keychain.ur: ErrSidecarStoreAbsent once it is gone.
func (self *Spool) epochPrivateKey(epochId Id) (hpke.PrivateKey, error) {
	seed, err := self.secrets.Get(spoolEpochSecretName(epochId))
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	testHookSecret("spool_private_key", seed)
	kem, _, _ := spoolHpkeSuite()
	privateKey, err := kem.NewPrivateKey(seed)
	if err != nil {
		return nil, errSpoolFormat
	}
	return privateKey, nil
}

// Reads and checks a locked segment's header alone: its epoch.
func (self *Spool) lockedSegmentEpoch(backendPath string) (Id, bool, error) {
	in, err := self.instance.backend.Open(backendPath)
	if err != nil {
		return Id{}, false, err
	}
	defer in.Close()
	epochId, _, _, torn, err := readSpoolSegmentHeader(bufio.NewReader(in))
	if err != nil {
		return Id{}, false, err
	}
	return epochId, !torn, nil
}

// errors.Is for the answers that mean a locked segment can never be read: its epoch's key is gone.
func spoolKeyGone(err error) bool {
	return errors.Is(err, ErrSidecarStoreAbsent)
}
