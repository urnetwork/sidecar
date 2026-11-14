package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Fetches a key set's published files (DESIGN-DETAILS 3.2.7): a plain HTTPS GET of
// <KeySettings.BaseUrl>/<id in hex>/<name>, with Range to resume, one file at a time. It sends no cookie,
// token, account or identifying header and follows no redirect, so the origin sees what §2.8's smtp-7
// row says and no other host sees anything. Every octet is hashed as it arrives, against a hash that
// chains to the release's pin, and a file is renamed into place only once all of it passes, so nothing
// unchecked is ever parsed and the path needs no trust. A failed file is deleted unread, but for one cut
// off midway, whose octets so far are kept and hashed again when the next attempt resumes it. How soon
// that is, is the caller's: KeySettings' retry intervals. Safe for concurrent use.

// The client name a fetch sends: Go's own default, which every Go program sends, so it says nothing of
// the build or the host.
const keyFetchUserAgent = "Go-http-client/1.1"

// What a download's partial file appends to the name of the file it becomes.
const keyFetchPartialSuffix = ".fetch"

type keyFetch struct {
	settings *KeySettings
	client   *http.Client

	// One file at a time.
	fetchLock sync.Mutex
}

func newKeyFetch(settings *KeySettings) *keyFetch {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// a ranged read counts the file's own octets, never a compressed form's
	transport.DisableCompression = true
	return newKeyFetchWithTransport(settings, transport)
}

func newKeyFetchWithTransport(settings *KeySettings, transport http.RoundTripper) *keyFetch {
	client := &http.Client{
		Transport: transport,
		// another host would see a fetch smtp-7 does not name
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &keyFetch{settings: settings, client: client}
}

// A file's URL under the base: only a plain https URL with a host serves.
func (self *keyFetch) fileUrl(keySetId []byte, name string) (string, error) {
	base, err := url.Parse(self.settings.BaseUrl)
	if err != nil {
		return "", err
	}
	if base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", errors.New("smtpproof: the key set url is not a plain https url")
	}
	return base.JoinPath(hex.EncodeToString(keySetId), name).String(), nil
}

func (self *keyFetch) newRequest(ctx context.Context, fileUrl string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", keyFetchUserAgent)
	return request, nil
}

// Fetches keyset.json, whose length nothing names: at most ManifestMaxByteCount octets, kept only if they
// hash to the set's id, the release's pin (step 1).
func (self *keyFetch) fetchManifest(ctx context.Context, keySetId []byte, path string) error {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	fileUrl, err := self.fileUrl(keySetId, keySetManifestName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, self.settings.FetchTimeout)
	defer cancel()
	request, err := self.newRequest(ctx, fileUrl)
	if err != nil {
		return err
	}
	response, err := self.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("smtpproof: %s: %s", keySetManifestName, response.Status)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ManifestMaxByteCount+1))
	if err != nil {
		return err
	}
	if self.settings.ManifestMaxByteCount < int64(len(encoded)) {
		return fmt.Errorf("smtpproof: %s is longer than %d octets", keySetManifestName, self.settings.ManifestMaxByteCount)
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(sum[:], keySetId) {
		return fmt.Errorf("smtpproof: the fetched %s is not the pinned one", keySetManifestName)
	}
	return keyFetchWriteWhole(path, encoded)
}

// Writes a small file under a partial name and renames it into place.
func keyFetchWriteWhole(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	partialPath := path + keyFetchPartialSuffix
	err := func() error {
		file, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.Write(content); err != nil {
			return err
		}
		return file.Sync()
	}()
	if err == nil {
		err = os.Rename(partialPath, path)
	}
	if err != nil {
		os.Remove(partialPath)
	}
	return err
}

// The first octet a 206's Content-Range names, as "bytes <first>-<last>/<length>".
func keyFetchRangeStart(contentRange string) (int64, bool) {
	rest, ok := strings.CutPrefix(contentRange, "bytes ")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	return start, err == nil && 0 <= start
}

// Fetches one file keyset.json names into path: no more than its byte_count, no fewer, and only if all
// of it hashes to its sha256. A cut connection leaves what arrived, which the next call hashes again and
// resumes from; any other failure deletes it.
func (self *keyFetch) fetchFile(ctx context.Context, keySetId []byte, file *keySetFile, path string) error {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	if file.ByteCount <= 0 || self.settings.FetchFileMaxByteCount < file.ByteCount {
		return keyRefused("%s is %d octets, past the %d a host fetches", file.Name, file.ByteCount, self.settings.FetchFileMaxByteCount)
	}
	fileUrl, err := self.fileUrl(keySetId, file.Name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, self.settings.FetchTimeout)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	partialPath := path + keyFetchPartialSuffix
	partial, err := os.OpenFile(partialPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	kept := false
	defer func() {
		partial.Close()
		if !kept {
			os.Remove(partialPath)
		}
	}()

	// what an earlier attempt left is hashed again before it is resumed
	digest := sha256.New()
	offset, err := io.Copy(digest, io.LimitReader(partial, file.ByteCount+1))
	if err != nil {
		return err
	}
	restart := func() error {
		digest.Reset()
		offset = 0
		if err := partial.Truncate(0); err != nil {
			return err
		}
		_, err := partial.Seek(0, io.SeekStart)
		return err
	}
	// a whole file a crash left unrenamed is checked below like any other; more than whole is not one
	if file.ByteCount < offset {
		if err := restart(); err != nil {
			return err
		}
	}

	if offset < file.ByteCount {
		request, err := self.newRequest(ctx, fileUrl)
		if err != nil {
			return err
		}
		if 0 < offset {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, file.ByteCount-1))
		}
		response, err := self.client.Do(request)
		if err != nil {
			kept = true
			return err
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusOK:
			// a server that takes no range sends the whole file again
			if 0 < offset {
				if err := restart(); err != nil {
					return err
				}
			}
		case http.StatusPartialContent:
			start, ok := keyFetchRangeStart(response.Header.Get("Content-Range"))
			if offset == 0 || !ok || start != offset {
				return fmt.Errorf("smtpproof: %s: a range from octet %d, not %d", file.Name, start, offset)
			}
		default:
			// an answer that is no file says nothing of what arrived before, but for a range the server
			// cannot serve, which what arrived is not the start of
			kept = response.StatusCode != http.StatusRequestedRangeNotSatisfiable
			return fmt.Errorf("smtpproof: %s: %s", file.Name, response.Status)
		}
		remaining := file.ByteCount - offset
		written, err := io.Copy(io.MultiWriter(partial, digest), io.LimitReader(response.Body, remaining+1))
		switch {
		case remaining < written:
			return fmt.Errorf("smtpproof: %s is longer than its %d octets", file.Name, file.ByteCount)
		case err != nil:
			// cut off: what arrived stays for the next attempt to resume
			kept = true
			return err
		case written < remaining:
			return fmt.Errorf("smtpproof: %s is shorter than its %d octets", file.Name, file.ByteCount)
		}
	}
	if hex.EncodeToString(digest.Sum(nil)) != file.Sha256 {
		return fmt.Errorf("smtpproof: %s is not the file keyset.json names", file.Name)
	}
	if err := partial.Sync(); err != nil {
		return err
	}
	if err := os.Rename(partialPath, path); err != nil {
		return err
	}
	kept = true
	return nil
}
