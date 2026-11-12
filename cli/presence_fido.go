// A FIDO2 authenticator on HID as ur daemon's presence provider (MCP-M3-09; §16.6's webauthn-es256 profile), with no
// cgo: CTAPHID's framing (CTAP 2.1 §11.2) over a urFidoDevice, presence_linux.go's hidraw on Linux, and CTAP2's
// authenticatorMakeCredential and authenticatorGetAssertion in canonical CBOR, rp ur.io, ES256, user presence and
// user verification required of the authenticator itself.
//
//	register  makeCredential: a non-resident ES256 credential under a random user id, client data a webauthn.create;
//	          the authenticator data must carry UP, UV and the attested credential, its rp id hash ur.io's; the key's
//	          COSE point becomes a SEC 1 one (QD-445). No attestation is kept (QD-137).
//	assert    getAssertion over the credential, client data a webauthn.get of the message (presence.go), UP and UV
//	          asked and checked; each device tried in turn, one that holds no such credential passed over
//	key_id    the first 16 bytes of SHA-256 of the credential id, which may pass KeyRegister's 64 bytes, so the provider
//	          keeps each key_id's credential id in <state>/presence/fido.json; neither is secret
//
// User verification by a PIN, CTAP2's clientPIN and its pinUvAuthToken, is not built: an authenticator that verifies
// its user only by a PIN answers refused, and nothing registers or signs, failing closed. Every CTAPHID wait ends with
// its caller's context. Safe for concurrent use.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// CTAPHID's and CTAP2's identifiers: command and status bytes, COSE's ES256 and EC2 values, and authenticator data's
// flags (CTAP 2.1 §§6, 8, 11.2; WebAuthn §6.1).
const (
	urFidoBroadcastChannel   uint32 = 0xffffffff
	urFidoCommandInit        byte   = 0x86
	urFidoCommandCbor        byte   = 0x90
	urFidoCommandKeepalive   byte   = 0xbb
	urFidoCommandError       byte   = 0xbf
	urFidoMakeCredential     byte   = 0x01
	urFidoGetAssertion       byte   = 0x02
	urFidoStatusOk           byte   = 0x00
	urFidoStatusNoCredential byte   = 0x2e
	urFidoCoseEs256          int64  = -7
	urFidoCoseKeyTypeEc2     int64  = 2
	urFidoCoseCurveP256      int64  = 1
	urFidoFlagUserPresent    byte   = 0x01
	urFidoFlagUserVerified   byte   = 0x04
	urFidoFlagAttested       byte   = 0x40
	// the file of key_ids' credential ids under <state>/presence
	urFidoCredentialsName = "fido.json"
)

var (
	// The authenticator answered other than CTAP2's ok, or answered in a form CTAP2 does not have.
	errUrFido = errors.New("the security key refused")
	// The security key did not verify its user, or gave no user presence.
	errUrFidoUnverified = errors.New("the security key verified no user")
)

// CTAPHID's and the CBOR reader's bounds, the protocol's values.
type urFidoSettings struct {
	// One HID report: 64 bytes, FIDO's usage page fixes it.
	ReportByteCount int
	// The longest CTAPHID message: an init packet's 57 bytes and 128 continuation packets' 59 each, 7,609.
	MessageByteCount int
	// The most CBOR nesting a response is read to: 16, past CTAP2's deepest, an attestation's.
	CborDepthCount int
	// A credential id's bytes, at most: 1,023 (CTAP 2.1 §6.1's credential id limit).
	CredentialIdByteCount int
	// Bytes of each value a nonce, a challenge and a user id draw: 8, 32 and 16.
	InitNonceByteCount int
	ChallengeByteCount int
	UserIdByteCount    int
	// key_id's bytes: 16, the fixtures' and the Secure Enclave's.
	KeyIdByteCount int
}

// The protocol's values.
func defaultUrFidoSettings() *urFidoSettings {
	return &urFidoSettings{
		ReportByteCount:       64,
		MessageByteCount:      57 + 128*59,
		CborDepthCount:        16,
		CredentialIdByteCount: 1023,
		InitNonceByteCount:    8,
		ChallengeByteCount:    32,
		UserIdByteCount:       16,
		KeyIdByteCount:        16,
	}
}

// One HID authenticator: a report written, a report read. Not safe for concurrent use: one transaction at a time.
type urFidoDevice interface {
	// One report of ReportByteCount bytes out.
	Write(report []byte) error
	// One report in, waiting no longer than ctx.
	Read(ctx context.Context) ([]byte, error)
	Close() error
}

// A CTAPHID channel on one device.
type urFidoChannel struct {
	device    urFidoDevice
	settings  *urFidoSettings
	channelId uint32
}

// Opens a channel by CTAPHID_INIT on the broadcast channel, its nonce echoed.
func urFidoOpenChannel(ctx context.Context, device urFidoDevice, settings *urFidoSettings, random io.Reader) (*urFidoChannel, error) {
	nonce := make([]byte, settings.InitNonceByteCount)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	broadcast := &urFidoChannel{device: device, settings: settings, channelId: urFidoBroadcastChannel}
	response, err := broadcast.transact(ctx, urFidoCommandInit, nonce)
	if err != nil {
		return nil, err
	}
	if len(response) < len(nonce)+4 || !bytes.Equal(response[:len(nonce)], nonce) {
		return nil, fmt.Errorf("%w: an init answer that does not echo its nonce", errUrFido)
	}
	channelId := binary.BigEndian.Uint32(response[len(nonce):])
	if channelId == 0 || channelId == urFidoBroadcastChannel {
		return nil, fmt.Errorf("%w: channel %#x", errUrFido, channelId)
	}
	return &urFidoChannel{device: device, settings: settings, channelId: channelId}, nil
}

// One CTAPHID transaction: payload out as an init packet and continuations, the answer back, keepalives passed over.
func (self *urFidoChannel) transact(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	reportByteCount := self.settings.ReportByteCount
	if self.settings.MessageByteCount < len(payload) {
		return nil, fmt.Errorf("%w: a message of %d bytes", errUrFido, len(payload))
	}
	report := make([]byte, reportByteCount)
	binary.BigEndian.PutUint32(report, self.channelId)
	report[4] = command
	binary.BigEndian.PutUint16(report[5:], uint16(len(payload)))
	sent := copy(report[7:], payload)
	if err := self.device.Write(report); err != nil {
		return nil, err
	}
	for sequence := byte(0); sent < len(payload); sequence += 1 {
		report = make([]byte, reportByteCount)
		binary.BigEndian.PutUint32(report, self.channelId)
		report[4] = sequence
		sent += copy(report[5:], payload[sent:])
		if err := self.device.Write(report); err != nil {
			return nil, err
		}
	}

	var response []byte
	length := 0
	for {
		in, err := self.device.Read(ctx)
		if err != nil {
			return nil, err
		}
		if len(in) < 7 || binary.BigEndian.Uint32(in) != self.channelId {
			// another channel's, or a short report
			continue
		}
		switch in[4] {
		case urFidoCommandKeepalive:
			continue
		case urFidoCommandError:
			return nil, fmt.Errorf("%w: CTAPHID error %#x", errUrFido, in[7])
		case command:
		default:
			return nil, fmt.Errorf("%w: an answer to command %#x", errUrFido, in[4])
		}
		length = int(binary.BigEndian.Uint16(in[5:]))
		if self.settings.MessageByteCount < length {
			return nil, fmt.Errorf("%w: an answer of %d bytes", errUrFido, length)
		}
		response = append(response, in[7:min(len(in), 7+length)]...)
		break
	}
	for sequence := byte(0); len(response) < length; sequence += 1 {
		in, err := self.device.Read(ctx)
		if err != nil {
			return nil, err
		}
		if len(in) < 5 || binary.BigEndian.Uint32(in) != self.channelId {
			continue
		}
		if in[4] != sequence {
			return nil, fmt.Errorf("%w: continuation %d out of order", errUrFido, in[4])
		}
		response = append(response, in[5:min(len(in), 5+length-len(response))]...)
	}
	return response, nil
}

// One CTAP2 command: its request map out as canonical CBOR, its answer's status checked and its map read.
func (self *urFidoChannel) cbor(ctx context.Context, ctapCommand byte, request urCborMap) (map[any]any, byte, error) {
	encoded, err := urCborAppend(nil, request)
	if err != nil {
		return nil, 0, err
	}
	response, err := self.transact(ctx, urFidoCommandCbor, append([]byte{ctapCommand}, encoded...))
	if err != nil {
		return nil, 0, err
	}
	if len(response) == 0 {
		return nil, 0, fmt.Errorf("%w: an empty answer", errUrFido)
	}
	if response[0] != urFidoStatusOk {
		return nil, response[0], fmt.Errorf("%w: CTAP2 status %#x", errUrFido, response[0])
	}
	value, rest, err := urCborRead(response[1:], self.settings.CborDepthCount)
	if err != nil {
		return nil, 0, err
	}
	answer, ok := value.(map[any]any)
	if !ok || len(rest) != 0 {
		return nil, 0, fmt.Errorf("%w: an answer that is no CBOR map", errUrFido)
	}
	return answer, urFidoStatusOk, nil
}

// The provider over the devices a platform finds.
type urFidoProvider struct {
	settings *urFidoSettings
	devices  func() ([]urFidoDevice, error)
	// <state>/presence, holding urFidoCredentialsName
	directory string
	random    io.Reader
	log       sidecar.Logger
	// one read or rewrite of the credentials file at a time: never stateLock, since it is held across the file
	credentialsLock sync.Mutex
}

var _ sidecar.PresenceProvider = (*urFidoProvider)(nil)

// A provider over devices, its credentials file in directory.
func newUrFidoProvider(directory string, devices func() ([]urFidoDevice, error), settings *urFidoSettings, log sidecar.Logger) *urFidoProvider {
	return &urFidoProvider{settings: settings, devices: devices, directory: directory, random: rand.Reader, log: log}
}

// The credentials file: each key_id's credential id, both hex.
func (self *urFidoProvider) readCredentialsWithLock() (map[string]string, error) {
	encoded, err := os.ReadFile(filepath.Join(self.directory, urFidoCredentialsName))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	keyIdCredentials := map[string]string{}
	if err := json.Unmarshal(encoded, &keyIdCredentials); err != nil {
		return nil, fmt.Errorf("the security keys' file does not decode: %w", err)
	}
	return keyIdCredentials, nil
}

// Replaces the credentials file whole, by a temporary file and a rename.
func (self *urFidoProvider) writeCredentialsWithLock(keyIdCredentials map[string]string) error {
	if err := os.MkdirAll(self.directory, 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(keyIdCredentials)
	if err != nil {
		return err
	}
	path := filepath.Join(self.directory, urFidoCredentialsName)
	temporary := path + ".new"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// The credential id of keyId, false for one this provider did not make.
func (self *urFidoProvider) credentialId(keyId []byte) ([]byte, bool) {
	self.credentialsLock.Lock()
	defer self.credentialsLock.Unlock()
	keyIdCredentials, err := self.readCredentialsWithLock()
	if err != nil {
		self.log.Warningf("[presence]%s", err)
		return nil, false
	}
	credentialHex, ok := keyIdCredentials[hex.EncodeToString(keyId)]
	if !ok {
		return nil, false
	}
	credentialId, err := hex.DecodeString(credentialHex)
	return credentialId, err == nil
}

// The devices the platform finds, each opened; the caller closes each.
func (self *urFidoProvider) openDevices() ([]urFidoDevice, error) {
	devices, err := self.devices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, sidecar.ErrPresenceUnavailable
	}
	return devices, nil
}

// See PresenceProvider: makeCredential on the first device found.
func (self *urFidoProvider) Register(ctx context.Context) (*sidecar.PresenceKeyHandle, error) {
	devices, err := self.openDevices()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, device := range devices {
			device.Close()
		}
	}()
	channel, err := urFidoOpenChannel(ctx, devices[0], self.settings, self.random)
	if err != nil {
		return nil, err
	}
	challenge := make([]byte, self.settings.ChallengeByteCount)
	userId := make([]byte, self.settings.UserIdByteCount)
	if _, err := io.ReadFull(self.random, challenge); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(self.random, userId); err != nil {
		return nil, err
	}
	clientDataHash := sha256.Sum256(urPresenceClientData(urPresenceCreateType, challenge))
	answer, _, err := channel.cbor(ctx, urFidoMakeCredential, urCborMap{
		{Key: int64(1), Value: clientDataHash[:]},
		{Key: int64(2), Value: urCborMap{{Key: "id", Value: urPresenceRpId}, {Key: "name", Value: "URnetwork"}}},
		{Key: int64(3), Value: urCborMap{{Key: "id", Value: userId}, {Key: "name", Value: "ur"}, {Key: "displayName", Value: "ur"}}},
		{Key: int64(4), Value: []any{urCborMap{{Key: "alg", Value: urFidoCoseEs256}, {Key: "type", Value: "public-key"}}}},
		{Key: int64(7), Value: urCborMap{{Key: "rk", Value: false}, {Key: "uv", Value: true}}},
	})
	if err != nil {
		return nil, err
	}
	authenticatorData, ok := answer[int64(2)].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: no authenticator data", errUrFido)
	}
	credentialId, publicKey, err := urFidoAttestedCredential(authenticatorData, self.settings)
	if err != nil {
		return nil, err
	}
	keyIdHash := sha256.Sum256(credentialId)
	keyId := keyIdHash[:self.settings.KeyIdByteCount]
	err = func() error {
		self.credentialsLock.Lock()
		defer self.credentialsLock.Unlock()
		keyIdCredentials, err := self.readCredentialsWithLock()
		if err != nil {
			return err
		}
		keyIdCredentials[hex.EncodeToString(keyId)] = hex.EncodeToString(credentialId)
		return self.writeCredentialsWithLock(keyIdCredentials)
	}()
	if err != nil {
		return nil, err
	}
	return &sidecar.PresenceKeyHandle{KeyId: bytes.Clone(keyId), Alg: bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, PublicKey: publicKey}, nil
}

// Whether the credentials file names keyId.
func (self *urFidoProvider) Holds(keyId []byte) bool {
	_, ok := self.credentialId(keyId)
	return ok
}

// See PresenceProvider: getAssertion on each device until one holds the credential.
func (self *urFidoProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	credentialId, ok := self.credentialId(keyId)
	if !ok {
		return nil, sidecar.ErrPresenceNoKey
	}
	devices, err := self.openDevices()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, device := range devices {
			device.Close()
		}
	}()
	clientData := urPresenceClientData(urPresenceGetType, message)
	clientDataHash := sha256.Sum256(clientData)
	request := urCborMap{
		{Key: int64(1), Value: urPresenceRpId},
		{Key: int64(2), Value: clientDataHash[:]},
		{Key: int64(3), Value: []any{urCborMap{{Key: "id", Value: credentialId}, {Key: "type", Value: "public-key"}}}},
		{Key: int64(5), Value: urCborMap{{Key: "up", Value: true}, {Key: "uv", Value: true}}},
	}
	var lastErr error = sidecar.ErrPresenceNoKey
	for _, device := range devices {
		channel, err := urFidoOpenChannel(ctx, device, self.settings, self.random)
		if err != nil {
			lastErr = err
			continue
		}
		answer, status, err := channel.cbor(ctx, urFidoGetAssertion, request)
		if status == urFidoStatusNoCredential {
			continue
		}
		if err != nil {
			return nil, err
		}
		authenticatorData, dataOk := answer[int64(2)].([]byte)
		signature, signatureOk := answer[int64(3)].([]byte)
		if !dataOk || !signatureOk {
			return nil, fmt.Errorf("%w: an assertion without its data or signature", errUrFido)
		}
		if err := urFidoCheckFlags(authenticatorData); err != nil {
			return nil, err
		}
		return &bridge.WebAuthnEvidence{
			AuthenticatorData: bytes.Clone(authenticatorData),
			ClientDataJson:    clientData,
			KeyId:             bytes.Clone(keyId),
			Signature:         bytes.Clone(signature),
		}, nil
	}
	return nil, lastErr
}

// Forgets keyId's credential id. A non-resident credential is the id itself, so nothing on the key changes.
func (self *urFidoProvider) Remove(keyId []byte) error {
	self.credentialsLock.Lock()
	defer self.credentialsLock.Unlock()
	keyIdCredentials, err := self.readCredentialsWithLock()
	if err != nil {
		return err
	}
	name := hex.EncodeToString(keyId)
	if _, ok := keyIdCredentials[name]; !ok {
		return nil
	}
	delete(keyIdCredentials, name)
	return self.writeCredentialsWithLock(keyIdCredentials)
}

// That authenticator data is ur.io's, with UP and UV.
func urFidoCheckFlags(authenticatorData []byte) error {
	if len(authenticatorData) < 32+1+4 {
		return fmt.Errorf("%w: authenticator data of %d bytes", errUrFido, len(authenticatorData))
	}
	rpIdHash := sha256.Sum256([]byte(urPresenceRpId))
	if !bytes.Equal(authenticatorData[:32], rpIdHash[:]) {
		return fmt.Errorf("%w: another rp id's authenticator data", errUrFido)
	}
	flags := authenticatorData[32]
	if flags&urFidoFlagUserPresent == 0 || flags&urFidoFlagUserVerified == 0 {
		return errUrFidoUnverified
	}
	return nil
}

// A makeCredential's authenticator data read: the credential id and the key as a SEC 1 point, after UP, UV and the
// attested credential flag, the rp id ur.io's.
func urFidoAttestedCredential(authenticatorData []byte, settings *urFidoSettings) ([]byte, []byte, error) {
	if err := urFidoCheckFlags(authenticatorData); err != nil {
		return nil, nil, err
	}
	if authenticatorData[32]&urFidoFlagAttested == 0 {
		return nil, nil, fmt.Errorf("%w: no attested credential", errUrFido)
	}
	rest := authenticatorData[32+1+4:]
	// the AAGUID, then the credential id's length and the id
	if len(rest) < 16+2 {
		return nil, nil, fmt.Errorf("%w: a short attested credential", errUrFido)
	}
	credentialIdByteCount := int(binary.BigEndian.Uint16(rest[16:]))
	rest = rest[16+2:]
	if credentialIdByteCount == 0 || settings.CredentialIdByteCount < credentialIdByteCount || len(rest) < credentialIdByteCount {
		return nil, nil, fmt.Errorf("%w: a credential id of %d bytes", errUrFido, credentialIdByteCount)
	}
	credentialId := bytes.Clone(rest[:credentialIdByteCount])
	value, _, err := urCborRead(rest[credentialIdByteCount:], settings.CborDepthCount)
	if err != nil {
		return nil, nil, err
	}
	coseKey, ok := value.(map[any]any)
	if !ok || coseKey[int64(1)] != urFidoCoseKeyTypeEc2 || coseKey[int64(3)] != urFidoCoseEs256 || coseKey[int64(-1)] != urFidoCoseCurveP256 {
		return nil, nil, fmt.Errorf("%w: a credential key that is no ES256 P-256 key", errUrFido)
	}
	x, xOk := coseKey[int64(-2)].([]byte)
	y, yOk := coseKey[int64(-3)].([]byte)
	if !xOk || !yOk || len(x) != 32 || len(y) != 32 {
		return nil, nil, fmt.Errorf("%w: a credential key's coordinates", errUrFido)
	}
	publicKey := append(append([]byte{0x04}, x...), y...)
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKey); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errUrFido, err)
	}
	return credentialId, publicKey, nil
}

// Whether a HID report descriptor declares FIDO's usage page, 0xF1D0, as Usage Page (long) does.
func urFidoReportDescriptor(descriptor []byte) bool {
	return bytes.Contains(descriptor, []byte{0x06, 0xd0, 0xf1})
}

// A CBOR map whose pairs urCborAppend writes in CTAP2's canonical order.
type urCborMap []urCborPair

// One pair: an int64 or a string key, and a value urCborAppend writes.
type urCborPair struct {
	Key   any
	Value any
}

// The head of a major type and argument, shortest form (RFC 8949 §4.2.1).
func urCborHead(out []byte, major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return append(out, major<<5|byte(argument))
	case argument <= 0xff:
		return append(out, major<<5|24, byte(argument))
	case argument <= 0xffff:
		return binary.BigEndian.AppendUint16(append(out, major<<5|25), uint16(argument))
	case argument <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(out, major<<5|26), uint32(argument))
	}
	return binary.BigEndian.AppendUint64(append(out, major<<5|27), argument)
}

// value appended as canonical CBOR: int64, bool, []byte, string, []any and urCborMap, each map's keys in CTAP2's
// order, by major type, then encoded length, then bytes.
func urCborAppend(out []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case int64:
		if typed < 0 {
			return urCborHead(out, 1, uint64(-1-typed)), nil
		}
		return urCborHead(out, 0, uint64(typed)), nil
	case bool:
		if typed {
			return append(out, 0xf5), nil
		}
		return append(out, 0xf4), nil
	case []byte:
		return append(urCborHead(out, 2, uint64(len(typed))), typed...), nil
	case string:
		return append(urCborHead(out, 3, uint64(len(typed))), typed...), nil
	case []any:
		out = urCborHead(out, 4, uint64(len(typed)))
		for _, element := range typed {
			var err error
			if out, err = urCborAppend(out, element); err != nil {
				return nil, err
			}
		}
		return out, nil
	case urCborMap:
		type encodedPair struct{ key, value []byte }
		pairs := make([]encodedPair, 0, len(typed))
		for _, pair := range typed {
			switch pair.Key.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("a CBOR map key of type %T", pair.Key)
			}
			key, err := urCborAppend(nil, pair.Key)
			if err != nil {
				return nil, err
			}
			encodedValue, err := urCborAppend(nil, pair.Value)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, encodedPair{key: key, value: encodedValue})
		}
		slices.SortFunc(pairs, func(a encodedPair, b encodedPair) int {
			if a.key[0]>>5 != b.key[0]>>5 {
				return int(a.key[0]>>5) - int(b.key[0]>>5)
			}
			if len(a.key) != len(b.key) {
				return len(a.key) - len(b.key)
			}
			return bytes.Compare(a.key, b.key)
		})
		out = urCborHead(out, 5, uint64(len(pairs)))
		for i, pair := range pairs {
			if 0 < i && bytes.Equal(pairs[i-1].key, pair.key) {
				return nil, errors.New("a CBOR map with a key twice")
			}
			out = append(append(out, pair.key...), pair.value...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("no CBOR form for %T", value)
}

// One CBOR item read from data and what follows it: an unsigned or negative integer as int64, a byte string as []byte,
// a text string as string, an array as []any, a map as map[any]any keyed by int64 or string, true, false and null.
// Indefinite lengths, floats, tags and nesting past depthCount are refused, as is an integer past int64.
func urCborRead(data []byte, depthCount int) (any, []byte, error) {
	if depthCount <= 0 {
		return nil, nil, errors.New("CBOR nested too deep")
	}
	if len(data) == 0 {
		return nil, nil, errors.New("CBOR ends early")
	}
	major := data[0] >> 5
	additional := data[0] & 0x1f
	data = data[1:]
	argument := uint64(additional)
	switch {
	case additional < 24:
	case additional <= 27:
		size := 1 << (additional - 24)
		if len(data) < size {
			return nil, nil, errors.New("CBOR ends early")
		}
		argument = 0
		for _, b := range data[:size] {
			argument = argument<<8 | uint64(b)
		}
		data = data[size:]
	default:
		return nil, nil, fmt.Errorf("CBOR additional value %d", additional)
	}
	switch major {
	case 0:
		if argument > 1<<63-1 {
			return nil, nil, errors.New("a CBOR integer past int64")
		}
		return int64(argument), data, nil
	case 1:
		if argument > 1<<63-1 {
			return nil, nil, errors.New("a CBOR integer past int64")
		}
		return -1 - int64(argument), data, nil
	case 2, 3:
		if uint64(len(data)) < argument {
			return nil, nil, errors.New("CBOR ends early")
		}
		value := data[:argument]
		if major == 2 {
			return bytes.Clone(value), data[argument:], nil
		}
		return string(value), data[argument:], nil
	case 4:
		// each element takes a byte at least, so a count past what is left cannot be real
		if uint64(len(data)) < argument {
			return nil, nil, errors.New("CBOR ends early")
		}
		elements := make([]any, 0, argument)
		for range argument {
			element, rest, err := urCborRead(data, depthCount-1)
			if err != nil {
				return nil, nil, err
			}
			elements = append(elements, element)
			data = rest
		}
		return elements, data, nil
	case 5:
		if uint64(len(data)) < 2*argument {
			return nil, nil, errors.New("CBOR ends early")
		}
		pairs := make(map[any]any, argument)
		for range argument {
			key, rest, err := urCborRead(data, depthCount-1)
			if err != nil {
				return nil, nil, err
			}
			switch key.(type) {
			case int64, string:
			default:
				return nil, nil, fmt.Errorf("a CBOR map key of type %T", key)
			}
			if _, seen := pairs[key]; seen {
				return nil, nil, errors.New("a CBOR map with a key twice")
			}
			value, rest, err := urCborRead(rest, depthCount-1)
			if err != nil {
				return nil, nil, err
			}
			pairs[key] = value
			data = rest
		}
		return pairs, data, nil
	case 7:
		switch additional {
		case 20:
			return false, data, nil
		case 21:
			return true, data, nil
		case 22:
			return nil, data, nil
		}
		return nil, nil, fmt.Errorf("CBOR simple value %d", additional)
	}
	return nil, nil, fmt.Errorf("CBOR major type %d", major)
}
