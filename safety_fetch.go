//go:build !ios_extension && !sidecar_http

// The classifier's files on a device (DESIGN-COMPUTE §27.5's Shipping and Falling back; SAFE-M13-05): SafetyModelStore,
// which fetches the files the release pins for this device (safety_manifest.go) and loads none until its SHA-256
// matches.
//
//   - Which files: the model the device's class runs, its vocabulary, the confusables table, and on a desktop the
//     runtime library its platform pins; an app's runtime is in its bundle. The model, vocabulary and table go to
//     <models>/safety, beside the local models, and the runtime to <engine>/safety, the two directories the ur-engine
//     helper may read (§6.5); an app keeps <state>/models/safety.
//   - When: Fetch, which the component calls at the device's first tainted run in auto mode, or beside the bot tab's
//     first local model, never at install. It goes from the device itself with no credential, so URnetwork's release
//     host sees a download as it sees an update's.
//   - How: each file whole from the manifest's https url, through the host's egress-bound transport, redirects held to
//     https and the url's host or the settings' release hosts. A file in place on its pin is kept; one off it is
//     deleted first. The bytes go to a part beside it, resumed by a Range request where a part is there, so a cut
//     costs only what was not yet written; the part is held to the manifest's size, then hashed whole, and moved into
//     place only on its SHA-256: a part off its pin is deleted and refused, never loaded, and the next fetch starts it
//     over.
//   - Check verifies what is in place without the network, as at a daemon's start: each file hashed whole, the
//     vocabulary and the table parsed from the very bytes hashed. Ready is false until every file of the device's
//     model is verified.
//
// Classifier answers the verified set, or ErrSafetyUnavailable, so every verdict asks, reason unavailable: before the
// files are verified, where this build pins no classifier or none for this device's class or platform, after a file
// failed its hash, where the release ships the model's switch off, and on a device that runs no classifier at all,
// the extension, a tagged or cloud sidecar or a read_only device, whose store fetches nothing (Excluded). The threshold
// and the switch are the verified manifest's alone (Q-SAFE-6).
//
// A store implements SafetyEngineFiles for the desktop's engine scorer. Safe for concurrent use: one fetch or check runs
// at a time.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// The directory under the models' and the engine's that keeps the classifier's files.
const safetyFileDirectoryName = "safety"

// The suffix of a file being fetched.
const safetyPartSuffix = ".part"

// The kinds of file a fetch reports.
type SafetyFileKind string

const (
	SafetyFileModel       SafetyFileKind = "model"
	SafetyFileVocabulary  SafetyFileKind = "vocabulary"
	SafetyFileConfusables SafetyFileKind = "confusables"
	SafetyFileRuntime     SafetyFileKind = "runtime"
)

// How far a fetch is: the file in hand by its bytes, and its place among the fetch's.
type SafetyFetchProgress struct {
	Kind          SafetyFileKind `json:"kind"`
	File          string         `json:"file"`
	ByteCount     int64          `json:"byte_count"`
	DoneByteCount int64          `json:"done_byte_count"`
	FileIndex     int            `json:"file_index"`
	FileCount     int            `json:"file_count"`
}

// What a device's classifier runs on, every file verified.
type SafetyModelSet struct {
	// The release whose manifest pinned it, which each auto_verdict entry names.
	Release string
	// The model's entry: its name, threshold and switch.
	Model *SafetyManifestModel
	// The model's verified file.
	ModelPath   string
	ModelSha256 string
	// The runtime library, verified; nil on an app, whose runtime is in its bundle.
	Runtime *SafetyRuntimeFile
	// The vocabulary's tokenizer and the confusables table, parsed from the bytes verified.
	Tokenizer   *SafetyTokenizer
	Confusables *SafetyConfusables
}

// What a store needs from its host.
type SafetyModelStoreArgs struct {
	// The release's pins; nil for this build's.
	Manifest *SafetyManifest
	// This device, as its local engine reports it: its platform and class. Required.
	Device func(ctx context.Context) (*InferDeviceCapabilities, error)
	// Where the local models are kept, absolute (InferModelDirectory); the store keeps <it>/safety.
	ModelDirectory string
	// Where a desktop's engine files are kept, absolute (InferEngineDirectory), the store keeping <it>/safety; empty on
	// an app, which fetches no runtime.
	EngineDirectory string
	// Why this device runs no classifier: the extension, a tagged or cloud sidecar, a read_only device (§27.5's last
	// row); empty where it runs one. A store with a reason fetches nothing and answers unavailable.
	Excluded string
	// What every request goes through: the host's egress-bound transport, never net/http's default. Required where
	// the store fetches.
	Transport http.RoundTripper
	// Nil for the defaults.
	Settings *SafetySettings
	// Nil for real time.
	Clock Clock
	// Nil logs to connect's default logger.
	Log Logger
	// The bytes free to this process on a directory's volume; nil reads the OS's.
	FreeByteCount func(directory string) (int64, error)
}

// The classifier's files on this device (see the file comment).
type SafetyModelStore struct {
	manifest        *SafetyManifest
	device          func(ctx context.Context) (*InferDeviceCapabilities, error)
	modelDirectory  string
	engineDirectory string
	excluded        string
	settings        *SafetySettings
	clock           Clock
	log             Logger
	freeByteCount   func(directory string) (int64, error)
	// the release host's client: no jar, no credential, its redirects held
	client *http.Client

	// one fetch or check at a time
	workLock sync.Mutex

	stateLock sync.Mutex
	// the device's verified files, nil until Check or Fetch verifies them
	verified *SafetyModelSet
	// why the files are not verified, once a check found one off its pin
	failed error
}

// A store on args, refused unless its directories and transport are fit. It reads nothing until Check or Fetch.
func NewSafetyModelStore(args *SafetyModelStoreArgs) (*SafetyModelStore, error) {
	if args == nil || args.Device == nil {
		return nil, errors.New("safety model store: no device")
	}
	if args.ModelDirectory == "" || !filepath.IsAbs(args.ModelDirectory) || (args.EngineDirectory != "" && !filepath.IsAbs(args.EngineDirectory)) {
		return nil, errors.New("safety model store: a directory that is not absolute")
	}
	if args.Excluded == "" && args.Transport == nil {
		return nil, errors.New("safety model store: no transport")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSafetySettings()
	}
	manifest := args.Manifest
	if manifest == nil {
		var err error
		manifest, err = SafetyReleaseManifest(settings)
		if err != nil {
			return nil, err
		}
	}
	freeByteCount := args.FreeByteCount
	if freeByteCount == nil {
		freeByteCount = inferDownloadFreeByteCount
	}
	self := &SafetyModelStore{
		manifest:       manifest,
		device:         args.Device,
		modelDirectory: filepath.Join(args.ModelDirectory, safetyFileDirectoryName),
		excluded:       args.Excluded,
		settings:       settings,
		clock:          clockOrReal(args.Clock),
		log:            loggerOrDefault(args.Log),
		freeByteCount:  freeByteCount,
	}
	if args.EngineDirectory != "" {
		self.engineDirectory = filepath.Join(args.EngineDirectory, safetyFileDirectoryName)
	}
	self.client = &http.Client{Transport: args.Transport, CheckRedirect: self.checkRedirect}
	return self, nil
}

// A redirect: https alone, to the url's own host or one under FetchRedirectHostSuffixes, at most
// FetchRedirectMaxCount, with no Referer.
func (self *SafetyModelStore) checkRedirect(request *http.Request, via []*http.Request) error {
	if self.settings.FetchRedirectMaxCount < len(via) {
		return errors.New("the release host redirected too often")
	}
	if request.URL.Scheme != "https" {
		return errors.New("the release host redirected off https")
	}
	host := strings.ToLower(request.URL.Hostname())
	allowed := host == strings.ToLower(via[0].URL.Hostname()) || slices.ContainsFunc(self.settings.FetchRedirectHostSuffixes, func(suffix string) bool {
		suffix = strings.ToLower(suffix)
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	})
	if !allowed {
		return errors.New("the release host redirected to a host it does not name")
	}
	request.Header.Del("Referer")
	return nil
}

// One file of the device's set and where it is kept.
type safetyStoreFile struct {
	kind      SafetyFileKind
	file      *SafetyManifestFile
	directory string
}

// The path the file is kept at.
func (self *safetyStoreFile) path() string {
	return filepath.Join(self.directory, self.file.Name)
}

// The device's model and runtime and the files they take, or unavailable: an excluded device, a build that pins no
// classifier, or none for this device's class or, on a desktop, its platform.
func (self *SafetyModelStore) selection(ctx context.Context) (*SafetyManifestModel, *SafetyManifestRuntime, []*safetyStoreFile, error) {
	if self.excluded != "" {
		return nil, nil, nil, safetyUnavailable("this device runs no classifier: %s", self.excluded)
	}
	device, err := self.device(ctx)
	if err != nil {
		return nil, nil, nil, safetyUnavailable("this device's capabilities do not read: %s", err)
	}
	model := self.manifest.ModelFor(device.Class)
	if model == nil {
		return nil, nil, nil, safetyUnavailable("this build pins no classifier for a %s", device.Class)
	}
	files := []*safetyStoreFile{}
	var runtime *SafetyManifestRuntime
	if self.engineDirectory != "" {
		runtime = self.manifest.RuntimeFor(device.Platform)
		if runtime == nil {
			return nil, nil, nil, safetyUnavailable("this build pins no classifier runtime for %s", device.Platform)
		}
		files = append(files, &safetyStoreFile{kind: SafetyFileRuntime, file: runtime.Library, directory: self.engineDirectory})
	}
	files = append(files,
		&safetyStoreFile{kind: SafetyFileModel, file: model.Model, directory: self.modelDirectory},
		&safetyStoreFile{kind: SafetyFileVocabulary, file: model.Vocabulary, directory: self.modelDirectory},
		&safetyStoreFile{kind: SafetyFileConfusables, file: self.manifest.Confusables, directory: self.modelDirectory},
	)
	return model, runtime, files, nil
}

// Fetches each file of the device's set that is not in place on its pin, then verifies them all (see the file
// comment), reporting progress to listener where it is not nil, one call at a time. An error matches
// ErrSafetyUnavailable; what was written is kept for the next fetch.
func (self *SafetyModelStore) Fetch(ctx context.Context, listener func(*SafetyFetchProgress)) error {
	self.workLock.Lock()
	defer self.workLock.Unlock()
	_, _, files, err := self.selection(ctx)
	if err != nil {
		return err
	}
	for i, file := range files {
		report := func(done int64) {
			if listener != nil {
				listener(&SafetyFetchProgress{Kind: file.kind, File: file.file.Name, ByteCount: file.file.ByteCount,
					DoneByteCount: done, FileIndex: i + 1, FileCount: len(files)})
			}
		}
		if err := self.fetchFile(ctx, file, report); err != nil {
			return err
		}
	}
	return self.checkWithLock(ctx)
}

// Verifies the device's set in place, without the network: Ready once every file matches its pin. An error matches
// ErrSafetyUnavailable.
func (self *SafetyModelStore) Check(ctx context.Context) error {
	self.workLock.Lock()
	defer self.workLock.Unlock()
	return self.checkWithLock(ctx)
}

// Check's work, with workLock held.
func (self *SafetyModelStore) checkWithLock(ctx context.Context) error {
	set, err := self.verify(ctx)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.verified, self.failed = set, err
	return err
}

// The device's set, each file read whole and matched to its pin, the vocabulary and the table parsed from the bytes
// matched.
func (self *SafetyModelStore) verify(ctx context.Context) (*SafetyModelSet, error) {
	model, runtime, files, err := self.selection(ctx)
	if err != nil {
		return nil, err
	}
	set := &SafetyModelSet{Release: self.manifest.Release, Model: model}
	for _, file := range files {
		switch file.kind {
		case SafetyFileVocabulary, SafetyFileConfusables:
			data, err := safetyReadPinned(file.path(), file.file)
			if err != nil {
				return nil, err
			}
			if file.kind == SafetyFileVocabulary {
				vocabulary, err := LoadSafetyVocabulary(data, self.settings)
				if err != nil {
					return nil, err
				}
				if set.Tokenizer, err = NewSafetyTokenizer(vocabulary, self.settings); err != nil {
					return nil, err
				}
			} else if set.Confusables, err = LoadSafetyConfusables(data, self.settings); err != nil {
				return nil, err
			}
		default:
			matches, err := safetyFileMatches(file.path(), file.file)
			if err != nil || !matches {
				return nil, safetyUnavailable("%s is not on its pin", file.file.Name)
			}
			if file.kind == SafetyFileModel {
				set.ModelPath, set.ModelSha256 = file.path(), file.file.Sha256
			} else {
				set.Runtime = &SafetyRuntimeFile{Path: file.path(), Sha256: file.file.Sha256, ApiVersion: runtime.ApiVersion}
			}
		}
	}
	return set, nil
}

// Whether every file of the device's set is verified.
func (self *SafetyModelStore) Ready() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.verified != nil
}

// The verified set, where its model's switch is on; else ErrSafetyUnavailable, saying why, so every verdict asks.
func (self *SafetyModelStore) Classifier() (*SafetyModelSet, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.excluded != "":
		return nil, safetyUnavailable("this device runs no classifier: %s", self.excluded)
	case self.verified == nil && self.failed != nil:
		return nil, self.failed
	case self.verified == nil:
		return nil, safetyUnavailable("the classifier's files are not verified yet")
	case !self.verified.Model.Auto:
		return nil, safetyUnavailable("the release ships %s with automatic approvals off", self.verified.Model.Name)
	}
	return self.verified, nil
}

// See SafetyEngineFiles: the verified runtime library.
func (self *SafetyModelStore) Runtime(ctx context.Context) (*SafetyRuntimeFile, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.verified == nil || self.verified.Runtime == nil {
		return nil, safetyUnavailable("no verified runtime")
	}
	runtime := *self.verified.Runtime
	return &runtime, nil
}

// See SafetyEngineFiles: the pin of the verified model at path.
func (self *SafetyModelStore) ModelSha256(ctx context.Context, path string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.verified == nil || self.verified.ModelPath != path {
		return "", safetyUnavailable("no verified model at that path")
	}
	return self.verified.ModelSha256, nil
}

// The bytes of the file at path, read whole and matched to file's size and SHA-256.
func safetyReadPinned(path string, file *SafetyManifestFile) ([]byte, error) {
	opened, err := os.Open(path)
	if err != nil {
		return nil, safetyUnavailable("%s is not in place", file.Name)
	}
	defer opened.Close()
	data, err := io.ReadAll(io.LimitReader(opened, file.ByteCount+1))
	if err != nil {
		return nil, safetyUnavailable("%s does not read", file.Name)
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != file.ByteCount || hex.EncodeToString(digest[:]) != file.Sha256 {
		return nil, safetyUnavailable("%s is not on its pin", file.Name)
	}
	return data, nil
}

// Whether the file at path is file, by its size and SHA-256; an error only where it is there and does not read.
func safetyFileMatches(path string, file *SafetyManifestFile) (bool, error) {
	opened, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != file.ByteCount {
		return false, err
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, opened); err != nil {
		return false, err
	}
	return hex.EncodeToString(digest.Sum(nil)) == file.Sha256, nil
}

// A fetch's failure: unavailable, naming the file.
func safetyFetchFault(file *SafetyManifestFile, format string, a ...any) error {
	return safetyUnavailable("%s: %s", file.Name, fmt.Sprintf(format, a...))
}

// Takes one file whole into its directory (see the file comment): kept where it is in place on its pin, else fetched
// into its part, resumed where the part holds bytes, hashed whole and moved into place only on its pin. report hears
// the bytes done.
func (self *SafetyModelStore) fetchFile(ctx context.Context, store *safetyStoreFile, report func(done int64)) error {
	file := store.file
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		return safetyFetchFault(file, "its directory: %s", err)
	}
	path := store.path()
	matches, err := safetyFileMatches(path, file)
	if err != nil {
		return safetyFetchFault(file, "it does not read: %s", err)
	}
	if matches {
		report(file.ByteCount)
		return nil
	}
	// a file off its pin is deleted before anything is fetched over it
	if err := inferRemoveIfExists(path); err != nil {
		return safetyFetchFault(file, "%s", err)
	}
	part := path + safetyPartSuffix
	done := int64(0)
	if info, err := os.Stat(part); err == nil && info.Mode().IsRegular() && info.Size() < file.ByteCount {
		done = info.Size()
	} else if err := inferRemoveIfExists(part); err != nil {
		return safetyFetchFault(file, "%s", err)
	}
	needed := file.ByteCount - done + int64(float64(file.ByteCount)*self.settings.FetchFreeSpaceMarginFraction)
	if free, err := self.freeByteCount(store.directory); err != nil || free < needed {
		return safetyFetchFault(file, "its volume lacks %d bytes free", needed)
	}
	if done < file.ByteCount {
		if err := self.download(ctx, file, part, done, report); err != nil {
			return err
		}
	}
	matches, err = safetyFileMatches(part, file)
	if err != nil || !matches {
		// a part off its pin is never loaded: it goes, and the next fetch starts over
		os.Remove(part)
		return safetyFetchFault(file, "what the release host gave is not the release's file, so it was deleted")
	}
	if err := os.Rename(part, path); err != nil {
		os.Remove(part)
		return safetyFetchFault(file, "%s", err)
	}
	if err := inferSyncDirectory(store.directory); err != nil {
		return safetyFetchFault(file, "%s", err)
	}
	report(file.ByteCount)
	return nil
}

// Appends file's bytes from done on to part, by a Range request where done is past 0, held to the manifest's size; a
// cut keeps what was written, synced, for the next fetch.
func (self *SafetyModelStore) download(ctx context.Context, file *SafetyManifestFile, part string, done int64, report func(done int64)) error {
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.FetchTimeout, cancel)
	defer stop()
	target, err := url.Parse(file.Url)
	if err != nil || target.Scheme != "https" {
		return safetyFetchFault(file, "its url is not https")
	}
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return safetyFetchFault(file, "%s", err)
	}
	if 0 < done {
		request.Header.Set("Range", "bytes="+strconv.FormatInt(done, 10)+"-")
	}
	response, err := self.client.Do(request)
	if err != nil {
		return safetyFetchFault(file, "the release host did not answer")
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusPartialContent && 0 < done:
		want := fmt.Sprintf("bytes %d-%d/%d", done, file.ByteCount-1, file.ByteCount)
		if response.Header.Get("Content-Range") != want {
			return safetyFetchFault(file, "the release host answered another range")
		}
	case response.StatusCode == http.StatusOK:
		// the whole file: whatever the part held goes
		done = 0
	case response.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		os.Remove(part)
		return safetyFetchFault(file, "the release host has no bytes past the part, so the part was deleted")
	default:
		return safetyFetchFault(file, "the release host answered %d", response.StatusCode)
	}
	written, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return safetyFetchFault(file, "%s", err)
	}
	if err := written.Truncate(done); err == nil {
		_, err = written.Seek(done, io.SeekStart)
	}
	if err != nil {
		written.Close()
		return safetyFetchFault(file, "%s", err)
	}
	remaining := file.ByteCount - done
	counter := &safetyFetchCounter{done: done, report: report}
	// a byte past the manifest's size tells a longer answer from a whole one, which is refused, never cut
	copied, copyErr := io.Copy(io.MultiWriter(written, counter), io.LimitReader(response.Body, remaining+1))
	syncErr := written.Sync()
	closeErr := written.Close()
	switch {
	case remaining < copied:
		os.Remove(part)
		return safetyFetchFault(file, "the release host gave more than the release's %d bytes, so the part was deleted", file.ByteCount)
	case copyErr != nil || copied < remaining:
		if ctx.Err() != nil {
			return safetyUnavailable("%s", ctx.Err())
		}
		return safetyFetchFault(file, "the release host stopped after %d of %d bytes; the next fetch resumes", done+copied, file.ByteCount)
	case syncErr != nil || closeErr != nil:
		return safetyFetchFault(file, "%s", errors.Join(syncErr, closeErr))
	}
	return nil
}

// Counts the bytes written past done, reporting the count.
type safetyFetchCounter struct {
	done   int64
	report func(done int64)
}

// See io.Writer.
func (self *safetyFetchCounter) Write(data []byte) (int, error) {
	self.done += int64(len(data))
	self.report(self.done)
	return len(data), nil
}
