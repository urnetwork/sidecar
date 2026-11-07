// sidecar.json (§5.9): what an instance records outside any seal. Nothing here is secret: urls, each
// network's ids, the instance id, a machine-id hash and the times of recent wrong passes. Being
// unsealed, it is read as hostile input: anything that does not decode exactly is ErrSidecarStoreFailed,
// and is never taken for a fresh instance (D-CORE-15).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// The format's values. Far above any real file, so the bound only stops a decoder from reading a
// garbage file whole.
const (
	stateJsonVersion      = 1
	stateJsonMaxByteCount = 1024 * 1024
)

// The machine-id hash's domain. The instance id salts it, so two instances on one machine do not
// correlate.
const stateMachineIdDomain = "urnetwork-sidecar-v1/local/machine-id"

var errStateJsonFormat = fmt.Errorf("%w: sidecar.json does not decode", ErrSidecarStoreFailed)

// One network this instance is enrolled in. Recording it is the last step of an enrollment
// (CORE-M1-09), and it is what makes a lost key an alarm and not a first run (D-CORE-15).
type SidecarNetworkRecord struct {
	NetworkId Id `json:"network_id"`
	ClientId  Id `json:"client_id"`
	SidecarId Id `json:"sidecar_id"`
	// connect's InstanceId, kept so a restart keeps the resident (§5.9). Never the instance id
	// above it, which stays on this device.
	ConnectInstanceId Id `json:"connect_instance_id"`
}

// The service urls an instance was set up against.
type sidecarStateUrls struct {
	ApiUrl      string `json:"api_url,omitempty"`
	PlatformUrl string `json:"platform_url,omitempty"`
	AuthUrl     string `json:"auth_url,omitempty"`
	EvsUrl      string `json:"evs_url,omitempty"`
	GkmUrl      string `json:"gkm_url,omitempty"`
	SocketsUrl  string `json:"sockets_url,omitempty"`
	DnsUrl      string `json:"dns_url,omitempty"`
}

// The urls settings names.
func stateUrlsFromSettings(settings *SidecarSettings) sidecarStateUrls {
	return sidecarStateUrls{
		ApiUrl:      settings.ApiUrl,
		PlatformUrl: settings.PlatformUrl,
		AuthUrl:     settings.AuthUrl,
		EvsUrl:      settings.EvsUrl,
		GkmUrl:      settings.GkmUrl,
		SocketsUrl:  settings.SocketsUrl,
		DnsUrl:      settings.DnsUrl,
	}
}

// sidecar.json's content.
type sidecarStateDocument struct {
	Version int `json:"version"`
	// Drawn once, and never sent anywhere. Names this instance's key store items and salts the
	// machine-id hash.
	InstanceId Id `json:"instance_id"`
	// Empty on a host with no machine id, where a copy cannot be told.
	MachineIdHash string                 `json:"machine_id_hash,omitempty"`
	Urls          sidecarStateUrls       `json:"urls"`
	Networks      []SidecarNetworkRecord `json:"networks"`
	// When each recent wrong pass came, in unix milliseconds, oldest first (§5.4's limit).
	PassAttemptMillis []int64 `json:"pass_attempt_millis,omitempty"`
}

// A copy sharing nothing a later edit changes.
func (self *sidecarStateDocument) clone() *sidecarStateDocument {
	clone := *self
	clone.Networks = slices.Clone(self.Networks)
	clone.PassAttemptMillis = slices.Clone(self.PassAttemptMillis)
	return &clone
}

// Whether a sidecar_id is recorded for networkId.
func (self *sidecarStateDocument) recordsNetwork(networkId Id) bool {
	return slices.ContainsFunc(self.Networks, func(record SidecarNetworkRecord) bool {
		return record.NetworkId == networkId
	})
}

// The file's bytes.
func (self *sidecarStateDocument) encode() ([]byte, error) {
	encoded, err := json.MarshalIndent(self, "", "\t")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// Exactly one document of this version, with every id set and no network listed twice, or
// ErrSidecarStoreFailed. The error never repeats the file.
func decodeStateDocument(encoded []byte) (*sidecarStateDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	document := &sidecarStateDocument{}
	if err := decoder.Decode(document); err != nil {
		return nil, errStateJsonFormat
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errStateJsonFormat
	}
	if document.Version != stateJsonVersion || document.InstanceId == (Id{}) {
		return nil, errStateJsonFormat
	}
	networkIds := map[Id]bool{}
	for _, record := range document.Networks {
		if record.NetworkId == (Id{}) || record.ClientId == (Id{}) || record.SidecarId == (Id{}) ||
			record.ConnectInstanceId == (Id{}) || networkIds[record.NetworkId] {
			return nil, errStateJsonFormat
		}
		networkIds[record.NetworkId] = true
	}
	return document, nil
}

// The hash sidecar.json keeps of machineId, which is empty with no machine id to hash.
func stateMachineIdHash(instanceId Id, machineId []byte) string {
	if len(machineId) == 0 {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte(stateMachineIdDomain))
	hash.Write(instanceId[:])
	hash.Write(machineId)
	return hex.EncodeToString(hash.Sum(nil))
}
