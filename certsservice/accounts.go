// URnetwork's ACME accounts (§13.8): one per CA, its key and any EAB key in certs' secret_files, never
// in Postgres, Redis or a log. CertsAccountSet holds them in memory as the host loaded them, and
// certsAcme resolves each against its CA on first use: an existing account by its key, else a new one,
// bound by EAB where the CA asks for it (GTS, ZeroSSL).
//
// Rollover, yearly, is RFC 8555 §7.3.5's key change. certs cannot write to vault, so a rollover is the
// operator's step and certs': the operator puts the next key in the account's file as next_private_key,
// and certs, once the current key is a year old, signs the key change with both and orders with the
// next key from then on. A process that restarts with both keys still in the file finds the account
// under whichever key the CA holds, so the file may keep both until the operator promotes the next.
//
// Deactivation, on a key's compromise, is RFC 8555 §7.3.6: the CA refuses the account from then on,
// and so does this set.
//
// Safe for concurrent use. No lock is held across ACME I/O: two first uses of one CA may both resolve
// it, and each finds the same account, since an account is its key's.

package certsservice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mholt/acmez/v3/acme"
)

var (
	// A CA certs holds no account for.
	ErrCertsAccountMissing = errors.New("certs holds no ACME account for this CA")
	// An account certs deactivated, which no order may use.
	ErrCertsAccountDeactivated = errors.New("the ACME account is deactivated")
	// An account file certs cannot use. The wrapping error names the field, never a value.
	ErrCertsAccountFileRefused = errors.New("certs account file refused")
)

// One account's file in certs' secret_files, YAML. The keys are PEM, PKCS #8 or SEC 1 for EC, PKCS #1
// for RSA; the EAB MAC key is base64url as the CA issued it.
type CertsAccountFile struct {
	Ca CertsCa `yaml:"ca"`
	// The account's key now.
	PrivateKey string `yaml:"private_key"`
	// The key the next rollover moves the account to, when the operator has placed one.
	NextPrivateKey string `yaml:"next_private_key"`
	// When the current key was made, from which the yearly rollover counts.
	KeyCreateTime time.Time `yaml:"key_create_time"`
	// RFC 8555 §7.3.4's binding, for a CA that asks for one.
	EabKeyId  string `yaml:"eab_key_id"`
	EabMacKey string `yaml:"eab_mac_key"`
	// The account's contact URLs, such as mailto:. Optional.
	Contact []string `yaml:"contact"`
}

// One CA's account as this process holds it.
type certsAccountState struct {
	ca            CertsCa
	key           crypto.Signer
	nextKey       crypto.Signer
	keyCreateTime time.Time
	eab           *acme.EAB
	contact       []string
	// the account at its CA once resolved: its location is the account URI CAA names (§13.8)
	account     *acme.Account
	deactivated bool
}

// The accounts, one per CA. See the file header.
type CertsAccountSet struct {
	stateLock sync.Mutex
	cas       map[CertsCa]*certsAccountState
}

// A private key from PEM, the kinds ACME takes for an account: EC, RSA or Ed25519.
func certsParsePrivateKey(text string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	testHookSecret("acme_account_key", block.Bytes)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch signer := key.(type) {
		case *ecdsa.PrivateKey:
			return signer, nil
		case *rsa.PrivateKey:
			return signer, nil
		case ed25519.PrivateKey:
			return signer, nil
		}
		return nil, errors.New("a key ACME does not take")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("not a private key")
}

// The set from account files' contents, as the host read them from secret_files. Two files for one
// CA are refused, so no CA has two accounts by mistake.
func NewCertsAccountSet(files [][]byte) (*CertsAccountSet, error) {
	self := &CertsAccountSet{cas: map[CertsCa]*certsAccountState{}}
	for index, data := range files {
		file := &CertsAccountFile{}
		if err := yaml.Unmarshal(data, file); err != nil {
			return nil, fmt.Errorf("%w: file %d does not parse", ErrCertsAccountFileRefused, index)
		}
		if !file.Ca.valid() {
			return nil, fmt.Errorf("%w: file %d: ca", ErrCertsAccountFileRefused, index)
		}
		if _, ok := self.cas[file.Ca]; ok {
			return nil, fmt.Errorf("%w: CA %s has two accounts", ErrCertsAccountFileRefused, file.Ca)
		}
		state := &certsAccountState{ca: file.Ca, keyCreateTime: file.KeyCreateTime, contact: slices.Clone(file.Contact)}
		key, err := certsParsePrivateKey(file.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("%w: CA %s: private_key: %w", ErrCertsAccountFileRefused, file.Ca, err)
		}
		state.key = key
		if file.NextPrivateKey != "" {
			nextKey, err := certsParsePrivateKey(file.NextPrivateKey)
			if err != nil {
				return nil, fmt.Errorf("%w: CA %s: next_private_key: %w", ErrCertsAccountFileRefused, file.Ca, err)
			}
			state.nextKey = nextKey
		}
		if file.EabKeyId != "" || file.EabMacKey != "" {
			macKey, err := base64.RawURLEncoding.DecodeString(file.EabMacKey)
			if file.EabKeyId == "" || err != nil || len(macKey) == 0 {
				return nil, fmt.Errorf("%w: CA %s: eab_key_id and eab_mac_key", ErrCertsAccountFileRefused, file.Ca)
			}
			testHookSecret("acme_eab_mac_key", macKey)
			state.eab = &acme.EAB{KeyID: file.EabKeyId, MACKey: file.EabMacKey}
		}
		self.cas[file.Ca] = state
	}
	return self, nil
}

// The CAs the set holds an account for.
func (self *CertsAccountSet) Cas() []CertsCa {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cas := []CertsCa{}
	for ca := range self.cas {
		cas = append(cas, ca)
	}
	slices.Sort(cas)
	return cas
}

// A copy of a CA's state, under the lock.
func (self *CertsAccountSet) state(ca CertsCa) (certsAccountState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.cas[ca]
	if !ok {
		return certsAccountState{}, ErrCertsAccountMissing
	}
	if state.deactivated {
		return certsAccountState{}, ErrCertsAccountDeactivated
	}
	return *state, nil
}

// Records a CA's account as resolved at the CA, under key, which becomes the current key.
func (self *CertsAccountSet) resolved(ca CertsCa, account acme.Account, key crypto.Signer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.cas[ca]
	if !ok {
		return
	}
	if key != state.key && key == state.nextKey {
		// the CA holds the next key already: a rollover done before this process started
		state.key, state.nextKey = state.nextKey, nil
	}
	state.account = &account
}

// Moves a CA's account to its next key after the CA took the key change.
func (self *CertsAccountSet) rolledOver(ca CertsCa, account acme.Account, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.cas[ca]
	if !ok {
		return
	}
	state.key = account.PrivateKey
	state.nextKey = nil
	state.keyCreateTime = now
	state.account = &account
}

// Marks a CA's account deactivated: no order uses it again.
func (self *CertsAccountSet) markDeactivated(ca CertsCa) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if state, ok := self.cas[ca]; ok {
		state.deactivated = true
		state.account = nil
	}
}

// The account URI at ca, as CAA's accounturi names it (§13.8), and false before the account resolves.
func (self *CertsAccountSet) AccountUri(ca CertsCa) (string, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.cas[ca]
	if !ok || state.account == nil {
		return "", false
	}
	return state.account.Location, true
}

// Whether ca's key is old enough to roll over at now, and whether a next key is there to roll to.
func (self *CertsAccountSet) RolloverDue(ca CertsCa, now time.Time, age time.Duration) (due bool, ready bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.cas[ca]
	if !ok || state.deactivated || state.keyCreateTime.IsZero() {
		return false, false
	}
	return age <= now.Sub(state.keyCreateTime), state.nextKey != nil
}
