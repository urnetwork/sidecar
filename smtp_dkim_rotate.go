//go:build !sidecar_http

// The writes behind SmtpDkimKeys (§14.6): a domain's first key, its rotation every DkimRotateTimeout,
// and its retirement when a burner label burns (§15.9). Each is one POST /smtp/dkim-keys, and each is
// written down before it is sent, so a kill at any point leaves a record that says what to send again:
// a pending selector names the selectors its call retires, and a retiring one waits for its answer.
// The server takes a repeat of either as done (api_smtp.go's header), so a lost answer costs one more
// call and never a second key.
//
// A refusal for good (a 4xx other than 401, 408 and 429) applied nothing on the server, so the new key
// is deleted and the refusal returned with its code. Anything else leaves the record to be sent again.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Publishes a new selector for domain now, retiring every selector published for it in the same call,
// under publishLock. The key is made here and reaches the keychain before the call, so the call can
// be sent again with the same key after a kill.
func (self *SmtpDkimKeys) publishNewWithPublishLock(ctx context.Context, records map[string]*smtpDkimRecord, domain string, now time.Time) (*smtpDkimRecord, error) {
	selector, err := newSmtpDkimSelector()
	if err != nil {
		return nil, err
	}
	if _, taken := records[selector]; taken {
		return nil, errors.New("smtp dkim: a fresh selector is taken")
	}
	key, err := rsa.GenerateKey(cryptorand.Reader, SmtpDkimRsaKeyBitCount)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	testHookSecret("dkim_private_key", der)
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	record := &smtpDkimRecord{
		Version:      smtpDkimRecordVersion,
		Selector:     selector,
		Domain:       domain,
		State:        smtpDkimStatePending,
		CreateTimeMs: now.UnixMilli(),
		PublicKey:    publicKey,
	}
	for _, existing := range records {
		if existing.Domain == domain && existing.State == smtpDkimStatePublished {
			record.Replaces = append(record.Replaces, existing.Selector)
		}
	}
	// the key first: a selector record never names a key that is not there
	if err := self.secrets.Put(smtpDkimKeyRecordName(selector), der); err != nil {
		return nil, err
	}
	if err := self.putWithPublishLock(record); err != nil {
		return nil, err
	}
	records[selector] = record
	return self.sendPendingWithPublishLock(ctx, records, record, now)
}

// Whether a refusal applied nothing and never will for the same body: a 4xx, but not 401, which the
// token manager answers, nor 408 or 429, which ask the caller to wait.
func smtpDkimRefusedForGood(err error) bool {
	apiErr := &SidecarApiError{}
	if !errors.As(err, &apiErr) {
		return false
	}
	return 400 <= apiErr.Status && apiErr.Status < 500 && apiErr.Status != 401 && apiErr.Status != 408 && apiErr.Status != 429
}

// Sends a pending selector's call, under publishLock: its publish and the retire of what it replaces.
// On the answer, the replaced selectors are written retired first and the new one published after, so
// a kill between leaves the pending record naming them and the same call is sent again.
func (self *SmtpDkimKeys) sendPendingWithPublishLock(ctx context.Context, records map[string]*smtpDkimRecord, record *smtpDkimRecord, now time.Time) (*smtpDkimRecord, error) {
	args := &SmtpDkimKeysArgs{
		Publish: []*SmtpDkimKeyPublish{{Selector: record.Selector, Domain: record.Domain, PublicKey: record.PublicKey}},
	}
	for _, replaced := range record.Replaces {
		args.Retire = append(args.Retire, &SmtpDkimKeyRetire{Selector: replaced, Domain: record.Domain})
	}
	testHookBarrier("smtp.dkim_publish.before", record.Selector)
	_, err := self.publisher.SmtpDkimKeys(ctx, args)
	testHookBarrier("smtp.dkim_publish.after", record.Selector)
	if err != nil {
		if smtpDkimRefusedForGood(err) {
			if deleteErr := self.deleteWithPublishLock(records, record.Selector); deleteErr != nil {
				return nil, deleteErr
			}
			return nil, fmt.Errorf("%w: %w", ErrSmtpDkimPublishRefused, err)
		}
		return nil, err
	}
	for _, replaced := range record.Replaces {
		existing, ok := records[replaced]
		if !ok || existing.State == smtpDkimStateRetired {
			continue
		}
		existing.State = smtpDkimStateRetired
		existing.RetireTimeMs = now.UnixMilli()
		if err := self.putWithPublishLock(existing); err != nil {
			return nil, err
		}
	}
	record.State = smtpDkimStatePublished
	record.PublishTimeMs = now.UnixMilli()
	record.Replaces = nil
	if err := self.putWithPublishLock(record); err != nil {
		return nil, err
	}
	return record, nil
}

// Sends the retire of each record, which are all written retiring already, under publishLock, and
// writes them retired on the answer.
func (self *SmtpDkimKeys) sendRetireWithPublishLock(ctx context.Context, retiring []*smtpDkimRecord, now time.Time) error {
	args := &SmtpDkimKeysArgs{}
	for _, record := range retiring {
		args.Retire = append(args.Retire, &SmtpDkimKeyRetire{Selector: record.Selector, Domain: record.Domain})
	}
	testHookBarrier("smtp.dkim_retire.before", "")
	_, err := self.publisher.SmtpDkimKeys(ctx, args)
	testHookBarrier("smtp.dkim_retire.after", "")
	if err != nil {
		return err
	}
	for _, record := range retiring {
		record.State = smtpDkimStateRetired
		record.RetireTimeMs = now.UnixMilli()
		if err := self.putWithPublishLock(record); err != nil {
			return err
		}
	}
	return nil
}

// Publishes a new selector for domain now, whatever its current one's age, and retires every selector
// published for it in the same call. A domain with none gets its first. A send already holding the
// old selector keeps signing under it.
func (self *SmtpDkimKeys) Rotate(ctx context.Context, domain string) error {
	domain = strings.ToLower(domain)
	if !smtpDkimDomainForm(domain) {
		return ErrSmtpDkimDomain
	}
	self.publishLock.Lock()
	defer self.publishLock.Unlock()
	records, err := self.prepareWithPublishLock(ctx)
	if err != nil {
		return err
	}
	now := self.clock.Now()
	// one call at a time per domain: an unanswered one goes again before a newer is made
	if pending := smtpDkimNewest(records, domain, smtpDkimStatePending); pending != nil {
		if _, err := self.sendPendingWithPublishLock(ctx, records, pending, now); err != nil {
			return err
		}
	}
	_, err = self.publishNewWithPublishLock(ctx, records, domain, now)
	return err
}

// Retires every selector domain has, as a burn does to its burner label (§15.9): one call, after
// which no send pins one, and the server keeps them in DNS 7 days more. A pending selector is retired
// too, since its answer may only have been lost. Returns once the server answered; a failed call
// leaves them retiring, never signing again, and the next call of any kind sends the retire again. A
// domain with no selector is no error.
func (self *SmtpDkimKeys) Retire(ctx context.Context, domain string) error {
	domain = strings.ToLower(domain)
	if !smtpDkimDomainForm(domain) {
		return ErrSmtpDkimDomain
	}
	self.publishLock.Lock()
	defer self.publishLock.Unlock()
	records, err := self.prepareWithPublishLock(ctx)
	if err != nil {
		return err
	}
	var retiring []*smtpDkimRecord
	for _, record := range records {
		if record.Domain != domain || record.State == smtpDkimStateRetired {
			continue
		}
		if record.State != smtpDkimStateRetiring {
			record.State = smtpDkimStateRetiring
			record.Replaces = nil
			if err := self.putWithPublishLock(record); err != nil {
				return err
			}
		}
		retiring = append(retiring, record)
	}
	if len(retiring) == 0 {
		return nil
	}
	return self.sendRetireWithPublishLock(ctx, retiring, self.clock.Now())
}
