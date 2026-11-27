//go:build !ios_extension && !sidecar_http

// A device's labels and hides (DESIGN-COMPUTE §26.6's Hiding, §26.8's types, D-LSTN-12; LSTN-M13-04): the person's word
// for a port of theirs (`ur listeners label <port>[/udp] "<text>" [--type <service>|none]`, the app's Label) and what
// they keep to themselves (`ur listeners hide`, `--device`, the app's switches), kept in the device's own sealed local
// store (§5.9), never at a server and never in a file of the listeners repo.
//
//	labels  by protocol and port at the host's overlay address: the text, at most DescriptionMaxCharCount characters and
//	        cleaned as a description (R-LSTN-8), and the Bonjour type, a DNS-SD service type, "none", or empty for the
//	        port's own (§26.8); at most LabelMaxCount
//	hides   by protocol and port, and the device whole; on a host where DESIGN §17.7.1's discovery runs its hide set is
//	        the one both views honor (D-LSTN-12), which the daemon's wiring reads in place of these (LSTN-M13-13)
//
// Only the person's own act writes here: LSTN-M13-10's methods take a label and an unhide only as a confirmed act, a
// hide at once; this file keeps what they write. The file is JSON, versioned; a file that does not read, or a version
// this build does not know, is refused and kept, and the device then hides itself whole, the closed direction, until
// the person writes again (as discovery's state does). Safe for concurrent use.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// The file's name in its store, and its version.
const (
	listenersLabelsName    = "labels.json"
	listenersLabelsVersion = 1
)

// A label's Bonjour type that keeps its entry out of Bonjour browsers (§26.8's --type none).
const ListenersLabelTypeNone = "none"

// A write the labels refuse: past LabelMaxCount, a type that is no service type, or nothing to write to.
var ErrListenersLabelRefused = errors.New("listeners: that label or hide is refused")

// The person's word for one port.
type ListenersLabel struct {
	// the description the port's entry takes
	Text string `json:"text"`
	// a DNS-SD service type, ListenersLabelTypeNone, or empty for the port's own
	Type string `json:"type,omitempty"`
}

// What the list reads of the labels and hides (ListenersLabels, or the daemon's join of them with discovery's hides).
type ListenersLabelSet interface {
	// The label for proto and port, and whether there is one.
	Label(proto protocol.ListenersProtocol, port uint16) (*ListenersLabel, bool)
	// Whether the person hid proto and port.
	HidesPort(proto protocol.ListenersProtocol, port uint16) bool
	// Whether the person hid the device whole.
	HidesDevice() bool
}

// One label as the file keeps it.
type listenersLabelRow struct {
	Protocol string         `json:"protocol"`
	Port     uint16         `json:"port"`
	Label    ListenersLabel `json:"label"`
}

// One hide as the file keeps it.
type listenersHideRow struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// The file.
type listenersLabelsState struct {
	Version      int                  `json:"version"`
	HiddenDevice bool                 `json:"hidden_device,omitempty"`
	Labels       []*listenersLabelRow `json:"labels,omitempty"`
	Hides        []*listenersHideRow  `json:"hides,omitempty"`
}

// The labels and hides (the file's comment).
type ListenersLabels struct {
	store    SidecarStore
	settings *ListenersSettings

	stateLock sync.Mutex
	state     *listenersLabelsState
	// set while the file does not read: the device hides itself whole
	stateErr error
}

// The labels store holds, read now. A file that does not read is kept and answers hidden whole, and the error says
// why; a write of the person's then replaces it.
func OpenListenersLabels(store SidecarStore, settings *ListenersSettings) (*ListenersLabels, error) {
	if settings == nil {
		settings = DefaultListenersSettings()
	}
	self := &ListenersLabels{store: store, settings: settings}
	state, err := self.read()
	if err != nil {
		self.stateErr = err
		state = &listenersLabelsState{Version: listenersLabelsVersion}
	}
	self.state = state
	return self, err
}

// The file as the store holds it; an empty state where none is kept.
func (self *ListenersLabels) read() (*listenersLabelsState, error) {
	empty := &listenersLabelsState{Version: listenersLabelsVersion}
	if self.store == nil {
		return empty, nil
	}
	reader, err := self.store.Open(listenersLabelsName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return empty, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	state := &listenersLabelsState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("the listeners labels do not read: %w", err)
	}
	if state.Version != listenersLabelsVersion {
		return nil, fmt.Errorf("the listeners labels are of version %d", state.Version)
	}
	for _, row := range state.Labels {
		if row == nil {
			return nil, errors.New("the listeners labels hold an empty label")
		}
	}
	for _, row := range state.Hides {
		if row == nil {
			return nil, errors.New("the listeners labels hold an empty hide")
		}
	}
	return state, nil
}

// Writes the state whole; nothing shows until it commits.
func (self *ListenersLabels) writeWithLock(state *listenersLabelsState) error {
	if self.store == nil {
		return fmt.Errorf("%w: no store", ErrListenersLabelRefused)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(listenersLabelsName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Applies edit to a copy of the state and writes it; the state moves only once the write commits. A state that did
// not read starts again from empty, the person's write replacing it.
func (self *ListenersLabels) commit(edit func(state *listenersLabelsState) error) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	next := &listenersLabelsState{Version: listenersLabelsVersion}
	if self.stateErr == nil {
		next.HiddenDevice = self.state.HiddenDevice
		next.Labels = slices.Clone(self.state.Labels)
		next.Hides = slices.Clone(self.state.Hides)
	}
	if err := edit(next); err != nil {
		return err
	}
	if self.settings.LabelMaxCount < len(next.Labels) || self.settings.LabelMaxCount < len(next.Hides) {
		return fmt.Errorf("%w: past %d", ErrListenersLabelRefused, self.settings.LabelMaxCount)
	}
	if err := self.writeWithLock(next); err != nil {
		return err
	}
	self.state = next
	self.stateErr = nil
	return nil
}

// Sets the person's label for proto and port, or clears it with nil: its text cleaned as a description, its type a
// service type, "none" or empty.
func (self *ListenersLabels) SetLabel(proto protocol.ListenersProtocol, port uint16, label *ListenersLabel) error {
	word, ok := listenersProtocolWords[proto]
	if !ok || port == 0 {
		return fmt.Errorf("%w: not a protocol and port", ErrListenersLabelRefused)
	}
	var row *listenersLabelRow
	if label != nil {
		text := ListenersCleanDescription(label.Text, self.settings.DescriptionMaxCharCount)
		if text == "" {
			return fmt.Errorf("%w: a label with no text", ErrListenersLabelRefused)
		}
		if label.Type != "" && label.Type != ListenersLabelTypeNone && !protocol.ValidDnsSdServiceType(label.Type) {
			return fmt.Errorf("%w: not a service type", ErrListenersLabelRefused)
		}
		row = &listenersLabelRow{Protocol: word, Port: port, Label: ListenersLabel{Text: text, Type: label.Type}}
	}
	return self.commit(func(state *listenersLabelsState) error {
		state.Labels = slices.DeleteFunc(state.Labels, func(held *listenersLabelRow) bool {
			return held.Protocol == word && held.Port == port
		})
		if row != nil {
			state.Labels = append(state.Labels, row)
			slices.SortFunc(state.Labels, func(a *listenersLabelRow, b *listenersLabelRow) int {
				if a.Protocol != b.Protocol {
					return strings.Compare(a.Protocol, b.Protocol)
				}
				return int(a.Port) - int(b.Port)
			})
		}
		return nil
	})
}

// Hides proto and port, or with hidden false unhides it: an unhide is the person's confirmed act, which the caller
// holds it to (§26.6).
func (self *ListenersLabels) SetHidden(proto protocol.ListenersProtocol, port uint16, hidden bool) error {
	word, ok := listenersProtocolWords[proto]
	if !ok || port == 0 {
		return fmt.Errorf("%w: not a protocol and port", ErrListenersLabelRefused)
	}
	return self.commit(func(state *listenersLabelsState) error {
		state.Hides = slices.DeleteFunc(state.Hides, func(held *listenersHideRow) bool {
			return held.Protocol == word && held.Port == port
		})
		if hidden {
			state.Hides = append(state.Hides, &listenersHideRow{Protocol: word, Port: port})
			slices.SortFunc(state.Hides, func(a *listenersHideRow, b *listenersHideRow) int {
				if a.Protocol != b.Protocol {
					return strings.Compare(a.Protocol, b.Protocol)
				}
				return int(a.Port) - int(b.Port)
			})
		}
		return nil
	})
}

// Hides the device whole, or with hidden false unhides it.
func (self *ListenersLabels) SetDeviceHidden(hidden bool) error {
	return self.commit(func(state *listenersLabelsState) error {
		state.HiddenDevice = hidden
		return nil
	})
}

// See ListenersLabelSet.
func (self *ListenersLabels) Label(proto protocol.ListenersProtocol, port uint16) (*ListenersLabel, bool) {
	word := listenersProtocolWords[proto]
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, row := range self.state.Labels {
		if row.Protocol == word && row.Port == port {
			label := row.Label
			return &label, true
		}
	}
	return nil, false
}

// See ListenersLabelSet.
func (self *ListenersLabels) HidesPort(proto protocol.ListenersProtocol, port uint16) bool {
	word := listenersProtocolWords[proto]
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.ContainsFunc(self.state.Hides, func(row *listenersHideRow) bool {
		return row.Protocol == word && row.Port == port
	})
}

// See ListenersLabelSet. True while the file does not read, the closed direction.
func (self *ListenersLabels) HidesDevice() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stateErr != nil || self.state.HiddenDevice
}
