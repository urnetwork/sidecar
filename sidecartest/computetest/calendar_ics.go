// FakeCalendarServer's ICS front: feeds by secret address, as Google's, iCloud's, Fastmail's, Outlook's and
// Nextcloud's read-only links serve a calendar (§23.3, §23.7's ics row). A feed serves a calendar of the fake live,
// its objects' VEVENTs merged into one VCALENDAR with each VTIMEZONE once, X-WR-CALNAME and X-WR-TIMEZONE as Google's
// feeds carry them, or a fixed document as given, a golden, a hostile file or one past a cap. GET and HEAD alone,
// with no authentication, the address being the secret: an ETag over the body and Last-Modified at the calendar's last
// change (a fixed document's, when it was set), and a 304 for an If-None-Match naming the ETag, or, without one, an
// If-Modified-Since at or after Last-Modified (RFC 9110 §13.1). An address the fake does not hold, or one Reset
// replaced, answers 404.

package computetest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

// One feed (AddIcsFeed): a calendar of the fake's served live, or a fixed document.
type FakeIcsFeedArgs struct {
	// The calendar it serves, of any account's front.
	Account  string
	Calendar string
	// Or a fixed document, served as given, when Calendar is empty.
	Body []byte
}

// A feed's secret address and what it serves; the server's lock guards it.
type FakeIcsFeed struct {
	server *FakeCalendarServer
	// its path, the secret
	path     string
	account  string
	calendar string
	body     []byte
	bodySet  time.Time
}

// The feed's address, https://ics.calendar.example/calendar/ical/<id>/private-<secret>/basic.ics, the path carrying
// its secret as Google's does.
func (self *FakeIcsFeed) Url() string {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	return "https://" + FakeCalendarIcsHost + self.path
}

// Replaces a fixed feed's document, its Last-Modified now.
func (self *FakeIcsFeed) SetBody(body []byte) {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	self.body = slices.Clone(body)
	self.bodySet = self.server.now()
}

// A new secret address, as a person resetting it makes: the old one answers 404 from now on.
func (self *FakeIcsFeed) Reset() {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	delete(self.server.icsFeeds, self.path)
	self.path = self.server.icsPathWithLock(self.calendar)
	self.server.icsFeeds[self.path] = self
}

func (self *FakeCalendarServer) icsPathWithLock(calendar string) string {
	feedId := calendar
	if feedId == "" || strings.ContainsAny(feedId, "/?#%") {
		feedId = self.drawIdWithLock("ics feed id", 8)
	}
	return "/calendar/ical/" + feedId + "/private-" + self.drawIdWithLock("ics secret", 16) + "/basic.ics"
}

// Adds a feed at a secret address drawn from the seed.
func (self *FakeCalendarServer) AddIcsFeed(args *FakeIcsFeedArgs) (*FakeIcsFeed, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no feed", ErrFakeCalendarArgs)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	feed := &FakeIcsFeed{server: self, account: args.Account, calendar: args.Calendar}
	if args.Calendar != "" {
		if _, ok := self.calendars[fakeCalendarKey(args.Account, args.Calendar)]; !ok {
			return nil, fmt.Errorf("%w: calendar %q", ErrFakeCalendarUnknown, args.Calendar)
		}
	} else {
		feed.body = slices.Clone(args.Body)
		feed.bodySet = self.now()
	}
	feed.path = self.icsPathWithLock(args.Calendar)
	self.icsFeeds[feed.path] = feed
	return feed, nil
}

// A live feed's document: the calendar's VEVENTs, its CalDAV objects' or its Google or Graph events' as iCalendar,
// with each VTIMEZONE once.
func (self *FakeCalendarServer) icsDocumentWithLock(calendar *fakeCalendar) []byte {
	document := ical.NewCalendar()
	document.Props.SetText(ical.PropProductID, fakeCaldavProductId)
	document.Props.SetText(ical.PropVersion, "2.0")
	// as Google's feeds carry them, with no VALUE parameter
	for name, value := range map[string]string{"X-WR-CALNAME": calendar.args.Name, "X-WR-TIMEZONE": calendar.zone.String()} {
		prop := ical.NewProp(name)
		prop.Value = fakeIcalEscapeText(value)
		document.Props.Set(prop)
	}
	timezoneIds := []string{}
	names := make([]string, 0, len(calendar.objects))
	for name := range calendar.objects {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, child := range calendar.objects[name].data.Children {
			if child.Name == ical.CompTimezone {
				tzid, _ := child.Props.Text(ical.PropTimezoneID)
				if slices.Contains(timezoneIds, tzid) {
					continue
				}
				timezoneIds = append(timezoneIds, tzid)
			}
			document.Children = append(document.Children, child)
		}
	}
	for _, event := range self.googleIcsEventsWithLock(calendar) {
		document.Children = append(document.Children, event)
	}
	for _, event := range self.graphIcsEventsWithLock(calendar) {
		document.Children = append(document.Children, event)
	}
	if len(document.Children) == 0 {
		return []byte("BEGIN:VCALENDAR\r\nPRODID:" + fakeCaldavProductId + "\r\nVERSION:2.0\r\nX-WR-CALNAME:" +
			fakeIcalEscapeText(calendar.args.Name) + "\r\nX-WR-TIMEZONE:" + calendar.zone.String() + "\r\nEND:VCALENDAR\r\n")
	}
	var buffer bytes.Buffer
	if err := ical.NewEncoder(&buffer).Encode(document); err != nil {
		return []byte{}
	}
	return buffer.Bytes()
}

// RFC 5545 §3.3.11's TEXT escapes: backslash, semicolon, comma and a line break.
func fakeIcalEscapeText(value string) string {
	return strings.NewReplacer(`\`, `\\`, ";", `\;`, ",", `\,`, "\r\n", `\n`, "\n", `\n`).Replace(value)
}

// The ICS front (see the file header).
func (self *FakeCalendarServer) serveIcs(w *fakeCalendarWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var body []byte
	var lastModified time.Time
	found := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		feed, ok := self.icsFeeds[r.URL.Path]
		if !ok {
			return false
		}
		if feed.calendar == "" {
			body = slices.Clone(feed.body)
			lastModified = feed.bodySet
			return true
		}
		calendar, ok := self.calendars[fakeCalendarKey(feed.account, feed.calendar)]
		if !ok {
			return false
		}
		body = self.icsDocumentWithLock(calendar)
		lastModified = calendar.changed
		return true
	}()
	if !found {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	lastModified = lastModified.UTC().Truncate(time.Second)
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "private, max-age=0")
	notModified := false
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		for _, candidate := range strings.Split(ifNoneMatch, ",") {
			candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
			if candidate == etag || candidate == "*" {
				notModified = true
			}
		}
	} else if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if since, err := http.ParseTime(ifModifiedSince); err == nil && !lastModified.After(since) {
			notModified = true
		}
	}
	if notModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(body)
	}
}
