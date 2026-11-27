// FakeCalendarServer's Google front: the Calendar API v3 as the calendar tools use it (§23.7's google row), plain
// JSON under /calendar/v3 on FakeCalendarGoogleHost, each answer in Google's own form:
//
//	calendarList.list  GET users/me/calendarList: each calendar's id, summary, zone, access role and primary flag
//	events.list        GET calendars/{id}/events: timeMin and timeMax by overlap (an event's end after timeMin, its
//	                   start before timeMax), singleEvents expanding recurring events into instances, exceptions in
//	                   their place, orderBy=startTime only with singleEvents, showDeleted, iCalUID, q, maxResults and
//	                   pageToken
//	events.get         GET calendars/{id}/events/{eventId}: a cancelled event too, as Google returns removed events,
//	                   and an instance by its id, <master>_<yyyymmdd>T<hhmmss>Z or <master>_<yyyymmdd>
//	events.insert      POST calendars/{id}/events: a client-chosen id of 5 to 1,024 base32hex characters, refused 409
//	                   duplicate while any event, a cancelled one included, holds it
//	events.patch       PATCH calendars/{id}/events/{eventId}: If-Match on the etag, 412 conditionNotMet once the event
//	                   changed; an instance's patch makes its exception; forbiddenForNonOrganizer for a shared field of
//	                   an event the account does not organize
//	events.delete      DELETE calendars/{id}/events/{eventId}: If-Match, 410 deleted for an event already removed, an
//	                   instance's removal a cancelled exception
//	events.instances   GET calendars/{id}/events/{eventId}/instances
//
// primary names the account's default calendar. Bearer tokens alone, 401 authError otherwise; a token's scopes are
// checked where it has any (fakeCalendarScopesGrant); a read-only calendar refuses writes with requiredAccessLevel.
// sendUpdates decides the notices: all to every attendee, externalOnly to those outside the account's domain, none
// (the default, as Google's) to nobody. Fields the fake does not keep are dropped, not refused (a reading). Times keep
// the forms Google's documents give: RFC 3339 with an offset, or a date, and a timeZone, required on a recurring
// event's start.

package computetest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

const (
	fakeGoogleApiPrefix   = "/calendar/v3/"
	fakeGoogleIcalUidHost = "@google.example"
	fakeGoogleHtmlBase    = "https://calendar.google.example/calendar/event?eid="
)

// The scopes each kind of call takes, by their last path element (fakeCalendarScopesGrant).
var (
	fakeGoogleCalendarListScopes = []string{"calendar.calendarlist.readonly", "calendar.calendarlist", "calendar.readonly", "calendar"}
	fakeGoogleReadScopes         = []string{"calendar.events.owned", "calendar.events.owned.readonly", "calendar.events", "calendar.events.readonly", "calendar.readonly", "calendar"}
	fakeGoogleWriteScopes        = []string{"calendar.events.owned", "calendar.events", "calendar"}
)

// Google's messages, by reason, as its error guide words them.
var fakeGoogleReasonMessages = map[string]string{
	"authError":                "Invalid Credentials",
	"badRequest":               "Bad Request",
	"invalid":                  "Invalid Value",
	"required":                 "Required",
	"parseError":               "Parse Error",
	"timeRangeEmpty":           "The specified time range is empty.",
	"insufficientPermissions":  "Request had insufficient authentication scopes.",
	"requiredAccessLevel":      "You need to have writer access to this calendar.",
	"forbiddenForNonOrganizer": "Shared properties can only be changed by the organizer of the event.",
	"rateLimitExceeded":        "Rate Limit Exceeded",
	"userRateLimitExceeded":    "User Rate Limit Exceeded",
	"quotaExceeded":            "Calendar usage limits exceeded.",
	"dailyLimitExceeded":       "Daily Limit Exceeded",
	"notFound":                 "Not Found",
	"duplicate":                "The requested identifier already exists.",
	"deleted":                  "Resource has been deleted",
	"conditionNotMet":          "Precondition Failed",
	"backendError":             "Backend Error",
	"unserved":                 "computetest: the fake calendar server does not serve this request",
}

// The domain Google names beside a reason.
func fakeGoogleReasonDomain(reason string) string {
	switch reason {
	case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded":
		return "usageLimits"
	case "forbiddenForNonOrganizer", "requiredAccessLevel", "timeRangeEmpty":
		return "calendar"
	}
	return "global"
}

// A status's own reason, for a scripted failure that names none.
func fakeGoogleStatusReason(status int) string {
	switch status {
	case http.StatusTooManyRequests, http.StatusForbidden:
		return "rateLimitExceeded"
	case http.StatusInternalServerError, http.StatusServiceUnavailable:
		return "backendError"
	case http.StatusUnauthorized:
		return "authError"
	}
	return "badRequest"
}

// Google's error body: {"error": {"errors": [{domain, reason, message}], "code", "message"}}.
func fakeGoogleError(w http.ResponseWriter, status int, reason string) {
	message, ok := fakeGoogleReasonMessages[reason]
	if !ok {
		message = http.StatusText(status)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://accounts.google.example/", error="invalid_token"`)
	}
	body := map[string]any{
		"error": map[string]any{
			"errors":  []map[string]any{{"domain": fakeGoogleReasonDomain(reason), "reason": reason, "message": message}},
			"code":    status,
			"message": message,
		},
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func fakeGoogleJson(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// An event time as Google writes it: a date, or a date-time with an offset and its zone's name.
type fakeGoogleTime struct {
	Date     string `json:"date,omitempty"`
	DateTime string `json:"dateTime,omitempty"`
	TimeZone string `json:"timeZone,omitempty"`
}

// A person on an event: its organizer or creator.
type fakeGooglePerson struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Self        bool   `json:"self,omitempty"`
}

type fakeGoogleAttendee struct {
	Email          string `json:"email"`
	DisplayName    string `json:"displayName,omitempty"`
	Organizer      bool   `json:"organizer,omitempty"`
	Self           bool   `json:"self,omitempty"`
	Optional       bool   `json:"optional,omitempty"`
	ResponseStatus string `json:"responseStatus"`
}

type fakeGoogleReminderOverride struct {
	Method  string `json:"method"`
	Minutes int    `json:"minutes"`
}

type fakeGoogleReminders struct {
	UseDefault bool                          `json:"useDefault"`
	Overrides  []*fakeGoogleReminderOverride `json:"overrides,omitempty"`
}

// Google's event resource, the fields the fake keeps, in Google's names.
type fakeGoogleEvent struct {
	Kind              string                `json:"kind"`
	Etag              string                `json:"etag"`
	Id                string                `json:"id"`
	Status            string                `json:"status"`
	HtmlLink          string                `json:"htmlLink"`
	Created           string                `json:"created"`
	Updated           string                `json:"updated"`
	Summary           string                `json:"summary,omitempty"`
	Description       string                `json:"description,omitempty"`
	Location          string                `json:"location,omitempty"`
	Creator           *fakeGooglePerson     `json:"creator,omitempty"`
	Organizer         *fakeGooglePerson     `json:"organizer,omitempty"`
	Start             *fakeGoogleTime       `json:"start,omitempty"`
	End               *fakeGoogleTime       `json:"end,omitempty"`
	Recurrence        []string              `json:"recurrence,omitempty"`
	RecurringEventId  string                `json:"recurringEventId,omitempty"`
	OriginalStartTime *fakeGoogleTime       `json:"originalStartTime,omitempty"`
	IcalUid           string                `json:"iCalUID"`
	Sequence          int                   `json:"sequence"`
	Attendees         []*fakeGoogleAttendee `json:"attendees,omitempty"`
	Reminders         *fakeGoogleReminders  `json:"reminders,omitempty"`
	EventType         string                `json:"eventType"`
}

func (self *fakeGoogleEvent) clone() *fakeGoogleEvent {
	encoded, _ := json.Marshal(self)
	var clone fakeGoogleEvent
	json.Unmarshal(encoded, &clone)
	return &clone
}

// The fields only an event's organizer changes (forbiddenForNonOrganizer).
var fakeGoogleSharedFields = []string{"summary", "description", "location", "start", "end", "recurrence", "attendees", "status"}

// A time's instant, and whether it is a date, read in zone where it names none.
func fakeGoogleParseTime(value *fakeGoogleTime, zone *time.Location) (time.Time, bool, error) {
	if value == nil || (value.Date == "") == (value.DateTime == "") {
		return time.Time{}, false, fmt.Errorf("one of date and dateTime")
	}
	if value.TimeZone != "" {
		loaded, err := time.LoadLocation(value.TimeZone)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("a timeZone Go cannot load")
		}
		zone = loaded
	}
	if value.Date != "" {
		at, err := time.ParseInLocation(time.DateOnly, value.Date, zone)
		return at, true, err
	}
	at, err := time.Parse(time.RFC3339, value.DateTime)
	if err != nil && value.TimeZone != "" {
		at, err = time.ParseInLocation("2006-01-02T15:04:05", value.DateTime, zone)
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return at.In(zone), false, nil
}

// An instance's id: the master's and the instance's original start, as Google forms them.
func fakeGoogleInstanceId(masterId string, at time.Time, allDay bool) string {
	if allDay {
		return masterId + "_" + at.Format("20060102")
	}
	return masterId + "_" + at.UTC().Format("20060102T150405Z")
}

// The time an instance takes, in the master's form.
func fakeGoogleInstanceTime(master *fakeGoogleTime, at time.Time, allDay bool) *fakeGoogleTime {
	if allDay {
		return &fakeGoogleTime{Date: at.Format(time.DateOnly)}
	}
	return &fakeGoogleTime{DateTime: at.Format(time.RFC3339), TimeZone: master.TimeZone}
}

// A master as one VEVENT go-ical expands: its start, end and recurrence lines.
func fakeGoogleIcalEvent(event *fakeGoogleEvent, zone *time.Location) (*ical.Calendar, error) {
	start, allDay, err := fakeGoogleParseTime(event.Start, zone)
	if err != nil {
		return nil, err
	}
	end, _, err := fakeGoogleParseTime(event.End, zone)
	if err != nil {
		return nil, err
	}
	formatTime := func(name string, at time.Time, value *fakeGoogleTime) string {
		switch {
		case allDay:
			return name + ";VALUE=DATE:" + at.Format("20060102")
		case value.TimeZone != "":
			return name + ";TZID=" + value.TimeZone + ":" + at.Format("20060102T150405")
		}
		return name + ":" + at.UTC().Format("20060102T150405Z")
	}
	lines := []string{
		"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:" + fakeCaldavProductId, "BEGIN:VEVENT",
		"UID:" + event.IcalUid, "DTSTAMP:20000101T000000Z",
		formatTime("DTSTART", start, event.Start), formatTime("DTEND", end, event.End),
	}
	for _, line := range event.Recurrence {
		if strings.ContainsAny(line, "\r\n") {
			return nil, fmt.Errorf("a recurrence line with a line break")
		}
		lines = append(lines, line)
	}
	lines = append(lines, "END:VEVENT", "END:VCALENDAR", "")
	return ical.NewDecoder(strings.NewReader(strings.Join(lines, "\r\n"))).Decode()
}

// A recurring master's instances in window, as events: an exception in its instance's place, cancelled ones kept
// only with showDeleted.
func (self *FakeCalendarServer) googleInstancesWithLock(calendar *fakeCalendar, master *fakeGoogleEvent, window *fakeCalendarWindow, showDeleted bool) ([]*fakeGoogleEvent, error) {
	data, err := fakeGoogleIcalEvent(master, calendar.zone)
	if err != nil {
		return nil, err
	}
	_, allDay, _ := fakeGoogleParseTime(master.Start, calendar.zone)
	instances, _, err := fakeIcalInstances(data.Children[0], data, calendar.zone, window, self.settings.ExpandInstanceMaxCount)
	if err != nil {
		return nil, err
	}
	exceptions := map[string]*fakeGoogleEvent{}
	for _, event := range calendar.googleEvents {
		if event.RecurringEventId == master.Id {
			exceptions[event.Id] = event
		}
	}
	events := []*fakeGoogleEvent{}
	for _, instance := range instances {
		instanceId := fakeGoogleInstanceId(master.Id, instance.recurrenceId, allDay)
		if exception, ok := exceptions[instanceId]; ok {
			delete(exceptions, instanceId)
			if exception.Status != "cancelled" || showDeleted {
				events = append(events, exception)
			}
			continue
		}
		virtual := master.clone()
		virtual.Id = instanceId
		virtual.Recurrence = nil
		virtual.RecurringEventId = master.Id
		virtual.OriginalStartTime = fakeGoogleInstanceTime(master.Start, instance.recurrenceId, allDay)
		virtual.Start = fakeGoogleInstanceTime(master.Start, instance.start, allDay)
		virtual.End = fakeGoogleInstanceTime(master.End, instance.end, allDay)
		events = append(events, virtual)
	}
	// exceptions moved into the window from an instance outside it
	for _, exception := range exceptions {
		if exception.Status == "cancelled" && !showDeleted {
			continue
		}
		start, _, err1 := fakeGoogleParseTime(exception.Start, calendar.zone)
		end, _, err2 := fakeGoogleParseTime(exception.End, calendar.zone)
		if err1 == nil && err2 == nil && (window == nil || window.overlaps(start, end)) {
			events = append(events, exception)
		}
	}
	return events, nil
}

// An event the request names: stored, or a recurring master's instance not yet an exception; its master for an
// instance.
func (self *FakeCalendarServer) googleFindWithLock(calendar *fakeCalendar, eventId string) (*fakeGoogleEvent, *fakeGoogleEvent, bool) {
	if event, ok := calendar.googleEvents[eventId]; ok {
		var master *fakeGoogleEvent
		if event.RecurringEventId != "" {
			master = calendar.googleEvents[event.RecurringEventId]
		}
		return event, master, true
	}
	masterId, suffix, ok := strings.Cut(eventId, "_")
	if !ok {
		return nil, nil, false
	}
	master, ok := calendar.googleEvents[masterId]
	if !ok || len(master.Recurrence) == 0 {
		return nil, nil, false
	}
	// the instant the id names, so only the instance there is expanded
	at, err := time.Parse("20060102T150405Z", suffix)
	if err != nil {
		at, err = time.ParseInLocation("20060102", suffix, calendar.zone)
	}
	if err != nil {
		return nil, nil, false
	}
	instances, err := self.googleInstancesWithLock(calendar, master, &fakeCalendarWindow{start: at, end: at.Add(time.Second)}, true)
	if err != nil {
		return nil, nil, false
	}
	for _, instance := range instances {
		if instance.Id == eventId {
			return instance, master, true
		}
	}
	return nil, nil, false
}

// The calendar a Google path names, and whether the account may write it.
func (self *FakeCalendarServer) googleCalendarWithLock(account string, calendarId string) *fakeCalendar {
	if calendarId == "primary" {
		for _, candidateId := range self.accounts[account].calendarIds {
			calendar := self.calendars[fakeCalendarKey(account, candidateId)]
			if calendar.args.Default {
				return calendar
			}
		}
		return nil
	}
	return self.calendars[fakeCalendarKey(account, calendarId)]
}

// The Google front (see the file header).
func (self *FakeCalendarServer) serveGoogle(w *fakeCalendarWriter, r *http.Request) {
	account, scopes, ok := self.bearer(r, FakeCalendarGoogle)
	if !ok {
		fakeGoogleError(w, http.StatusUnauthorized, "authError")
		return
	}
	fakeCalendarExchangeOf(r.Context()).account = account
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), fakeGoogleApiPrefix)
	if !ok {
		fakeGoogleError(w, http.StatusNotFound, "notFound")
		return
	}
	segments := strings.Split(rest, "/")
	for i, segment := range segments {
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			fakeGoogleError(w, http.StatusBadRequest, "invalid")
			return
		}
		segments[i] = unescaped
	}
	switch {
	case len(segments) == 3 && segments[0] == "users" && segments[1] == "me" && segments[2] == "calendarList" && r.Method == http.MethodGet:
		if !fakeCalendarScopesGrant(scopes, fakeGoogleCalendarListScopes...) {
			fakeGoogleError(w, http.StatusForbidden, "insufficientPermissions")
			return
		}
		self.googleCalendarList(w, account)
	case len(segments) >= 3 && segments[0] == "calendars" && segments[2] == "events":
		calendar := func() *fakeCalendar {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.googleCalendarWithLock(account, segments[1])
		}()
		if calendar == nil {
			fakeGoogleError(w, http.StatusNotFound, "notFound")
			return
		}
		write := r.Method != http.MethodGet
		if (write && !fakeCalendarScopesGrant(scopes, fakeGoogleWriteScopes...)) || (!write && !fakeCalendarScopesGrant(scopes, fakeGoogleReadScopes...)) {
			fakeGoogleError(w, http.StatusForbidden, "insufficientPermissions")
			return
		}
		switch {
		case len(segments) == 3 && r.Method == http.MethodGet:
			self.googleList(w, r, calendar, "")
		case len(segments) == 3 && r.Method == http.MethodPost:
			self.googleInsert(w, r, calendar)
		case len(segments) == 4 && r.Method == http.MethodGet:
			self.googleGet(w, calendar, segments[3])
		case len(segments) == 4 && r.Method == http.MethodPatch:
			self.googlePatch(w, r, calendar, segments[3])
		case len(segments) == 4 && r.Method == http.MethodDelete:
			self.googleDelete(w, r, calendar, segments[3])
		case len(segments) == 5 && segments[4] == "instances" && r.Method == http.MethodGet:
			self.googleList(w, r, calendar, segments[3])
		default:
			fakeGoogleError(w, http.StatusNotImplemented, "unserved")
		}
	default:
		fakeGoogleError(w, http.StatusNotImplemented, "unserved")
	}
}

func (self *FakeCalendarServer) googleCalendarList(w http.ResponseWriter, account string) {
	self.stateLock.Lock()
	items := []map[string]any{}
	for _, calendarId := range self.accounts[account].calendarIds {
		calendar := self.calendars[fakeCalendarKey(account, calendarId)]
		accessRole := "owner"
		if calendar.args.ReadOnly {
			accessRole = "reader"
		}
		item := map[string]any{
			"kind":             "calendar#calendarListEntry",
			"etag":             fmt.Sprintf(`"%d"`, calendar.revision+1),
			"id":               calendar.args.Id,
			"summary":          calendar.args.Name,
			"timeZone":         calendar.zone.String(),
			"accessRole":       accessRole,
			"defaultReminders": []any{},
		}
		if calendar.args.Description != "" {
			item["description"] = calendar.args.Description
		}
		if calendar.args.Default {
			item["primary"] = true
		}
		items = append(items, item)
	}
	self.stateLock.Unlock()
	fakeGoogleJson(w, http.StatusOK, map[string]any{"kind": "calendar#calendarList", "etag": `"computetest"`, "items": items})
}

// events.list, or events.instances where masterId is set.
func (self *FakeCalendarServer) googleList(w http.ResponseWriter, r *http.Request, calendar *fakeCalendar, masterId string) {
	query := r.URL.Query()
	window := &fakeCalendarWindow{start: time.Unix(0, 0).UTC(), end: time.Date(9999, time.January, 1, 0, 0, 0, 0, time.UTC)}
	for name, into := range map[string]*time.Time{"timeMin": &window.start, "timeMax": &window.end} {
		if value := query.Get(name); value != "" {
			at, err := time.Parse(time.RFC3339, value)
			if err != nil {
				fakeGoogleError(w, http.StatusBadRequest, "badRequest")
				return
			}
			*into = at
		}
	}
	if !window.end.After(window.start) {
		fakeGoogleError(w, http.StatusBadRequest, "timeRangeEmpty")
		return
	}
	singleEvents := query.Get("singleEvents") == "true" || masterId != ""
	showDeleted := query.Get("showDeleted") == "true"
	if query.Get("orderBy") == "startTime" && !singleEvents {
		fakeGoogleError(w, http.StatusBadRequest, "invalid")
		return
	}
	maxResults := self.settings.GoogleListDefaultCount
	if value := query.Get("maxResults"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			fakeGoogleError(w, http.StatusBadRequest, "invalid")
			return
		}
		maxResults = min(parsed, self.settings.GoogleListMaxCount)
	}
	offset := 0
	if token := query.Get("pageToken"); token != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err == nil {
			offset, err = strconv.Atoi(string(decoded))
		}
		if err != nil || offset < 0 {
			fakeGoogleError(w, http.StatusBadRequest, "invalid")
			return
		}
	}
	type listed struct {
		event *fakeGoogleEvent
		start time.Time
	}
	items := []*listed{}
	var listErr error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		add := func(event *fakeGoogleEvent) {
			start, _, err1 := fakeGoogleParseTime(event.Start, calendar.zone)
			end, _, err2 := fakeGoogleParseTime(event.End, calendar.zone)
			if err1 != nil || err2 != nil || !window.overlaps(start, end) {
				return
			}
			if uid := query.Get("iCalUID"); uid != "" && event.IcalUid != uid {
				return
			}
			if q := strings.ToLower(query.Get("q")); q != "" &&
				!strings.Contains(strings.ToLower(event.Summary+"\n"+event.Description+"\n"+event.Location), q) {
				return
			}
			items = append(items, &listed{event: event.clone(), start: start})
		}
		if masterId != "" {
			master, ok := calendar.googleEvents[masterId]
			if !ok || len(master.Recurrence) == 0 {
				listErr = fmt.Errorf("notFound")
				return
			}
			instances, err := self.googleInstancesWithLock(calendar, master, window, showDeleted)
			if err != nil {
				listErr = err
				return
			}
			for _, instance := range instances {
				add(instance)
			}
			return
		}
		for _, event := range calendar.googleEvents {
			cancelled := event.Status == "cancelled"
			switch {
			case len(event.Recurrence) > 0 && singleEvents:
				if cancelled {
					continue
				}
				instances, err := self.googleInstancesWithLock(calendar, event, window, showDeleted)
				if err != nil {
					listErr = err
					return
				}
				for _, instance := range instances {
					add(instance)
				}
			case event.RecurringEventId != "" && singleEvents:
				// an exception: listed through its master's instances
			case len(event.Recurrence) > 0:
				if cancelled && !showDeleted {
					continue
				}
				data, err := fakeGoogleIcalEvent(event, calendar.zone)
				if err != nil {
					listErr = err
					return
				}
				instances, _, err := fakeIcalInstances(data.Children[0], data, calendar.zone, window, self.settings.ExpandInstanceMaxCount)
				if err != nil {
					listErr = err
					return
				}
				if len(instances) > 0 {
					start, _, _ := fakeGoogleParseTime(event.Start, calendar.zone)
					items = append(items, &listed{event: event.clone(), start: start})
				}
			default:
				if cancelled && !showDeleted {
					continue
				}
				add(event)
			}
		}
	}()
	if listErr != nil {
		if listErr.Error() == "notFound" {
			fakeGoogleError(w, http.StatusNotFound, "notFound")
		} else {
			fakeGoogleError(w, http.StatusBadRequest, "invalid")
		}
		return
	}
	slices.SortStableFunc(items, func(a *listed, b *listed) int {
		if order := a.start.Compare(b.start); order != 0 {
			return order
		}
		return strings.Compare(a.event.Id, b.event.Id)
	})
	page := []*fakeGoogleEvent{}
	for i := offset; i < len(items) && len(page) < maxResults; i += 1 {
		page = append(page, items[i].event)
	}
	accessRole := "owner"
	if calendar.args.ReadOnly {
		accessRole = "reader"
	}
	body := map[string]any{
		"kind":             "calendar#events",
		"etag":             fmt.Sprintf(`"%d"`, calendar.revision+1),
		"summary":          calendar.args.Name,
		"updated":          calendar.changed.UTC().Format("2006-01-02T15:04:05.000Z"),
		"timeZone":         calendar.zone.String(),
		"accessRole":       accessRole,
		"defaultReminders": []any{},
		"items":            page,
	}
	if offset+len(page) < len(items) {
		body["nextPageToken"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset + len(page))))
	}
	fakeGoogleJson(w, http.StatusOK, body)
}

func (self *FakeCalendarServer) googleGet(w http.ResponseWriter, calendar *fakeCalendar, eventId string) {
	self.stateLock.Lock()
	event, _, ok := self.googleFindWithLock(calendar, eventId)
	if ok {
		event = event.clone()
	}
	self.stateLock.Unlock()
	if !ok {
		fakeGoogleError(w, http.StatusNotFound, "notFound")
		return
	}
	fakeGoogleJson(w, http.StatusOK, event)
}

// Whether address is outside the account's domain, for sendUpdates=externalOnly.
func fakeGoogleExternal(account string, address string) bool {
	_, accountDomain, _ := strings.Cut(account, "@")
	_, domain, _ := strings.Cut(address, "@")
	return !strings.EqualFold(accountDomain, domain)
}

// The notices sendUpdates sends for an event's attendees.
func fakeGoogleNotices(accountAddress string, event *fakeGoogleEvent, sendUpdates string, method string, occurrence time.Time) []*FakeCalendarNotice {
	if sendUpdates != "all" && sendUpdates != "externalOnly" {
		return nil
	}
	notices := []*FakeCalendarNotice{}
	for _, attendee := range event.Attendees {
		address := strings.ToLower(attendee.Email)
		if address == strings.ToLower(accountAddress) || attendee.Organizer {
			continue
		}
		if sendUpdates == "externalOnly" && !fakeGoogleExternal(accountAddress, address) {
			continue
		}
		notices = append(notices, &FakeCalendarNotice{Method: method, To: address, Uid: event.IcalUid, Occurrence: occurrence})
	}
	return notices
}

// A new etag, Google's form: a quoted number.
func (self *FakeCalendarServer) googleEtagWithLock() string {
	self.revision += 1
	return fmt.Sprintf(`"%d"`, self.now().UnixMicro()*1000+int64(self.revision%1000))
}

func (self *FakeCalendarServer) googleTimestamp() string {
	return self.now().Format("2006-01-02T15:04:05.000Z")
}

// Whether every character is base32hex's, as Google's ids take.
func fakeGoogleIdValid(id string, minLength int, maxLength int) bool {
	if len(id) < minLength || len(id) > maxLength {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'v') {
			return false
		}
	}
	return true
}

// Validates an event's times: both present, of one form, the end after the start, and a recurring event's start
// zoned. Answers the reason to refuse with, or empty.
func fakeGoogleCheckTimes(event *fakeGoogleEvent, zone *time.Location) string {
	if event.Start == nil || event.End == nil {
		return "required"
	}
	start, startDate, err := fakeGoogleParseTime(event.Start, zone)
	if err != nil {
		return "invalid"
	}
	end, endDate, err := fakeGoogleParseTime(event.End, zone)
	if err != nil || startDate != endDate {
		return "invalid"
	}
	if !end.After(start) {
		return "timeRangeEmpty"
	}
	if len(event.Recurrence) > 0 && !startDate && event.Start.TimeZone == "" {
		return "required"
	}
	return ""
}

func (self *FakeCalendarServer) googleInsert(w *fakeCalendarWriter, r *http.Request, calendar *fakeCalendar) {
	exchange := fakeCalendarExchangeOf(r.Context())
	body, err := fakeCalendarReadBody(r)
	if err != nil {
		fakeGoogleError(w, http.StatusRequestEntityTooLarge, "badRequest")
		return
	}
	sendUpdates := r.URL.Query().Get("sendUpdates")
	write := &FakeCalendarWrite{
		Protocol:    FakeCalendarGoogle,
		Method:      http.MethodPost,
		Account:     calendar.account,
		Calendar:    calendar.args.Id,
		SendUpdates: sendUpdates,
		Body:        slices.Clone(body),
	}
	var event fakeGoogleEvent
	status, reason := 0, ""
	var answer *fakeGoogleEvent
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			if status != http.StatusOK {
				write.Status = status
				self.logWriteWithLock(exchange, write)
			}
		}()
		if err := json.Unmarshal(body, &event); err != nil {
			status, reason = http.StatusBadRequest, "parseError"
			return
		}
		write.Resource = event.Id
		if calendar.args.ReadOnly {
			status, reason = http.StatusForbidden, "requiredAccessLevel"
			return
		}
		if event.Id != "" && !fakeGoogleIdValid(event.Id, self.settings.GoogleEventIdMinLength, self.settings.GoogleEventIdMaxLength) {
			status, reason = http.StatusBadRequest, "invalid"
			return
		}
		if event.Id != "" {
			if _, exists := calendar.googleEvents[event.Id]; exists {
				status, reason = http.StatusConflict, "duplicate"
				return
			}
		}
		if refusal := fakeGoogleCheckTimes(&event, calendar.zone); refusal != "" {
			status, reason = http.StatusBadRequest, refusal
			return
		}
		if event.Id == "" {
			event.Id = self.drawIdWithLock("google event", 13)
		}
		account := self.accounts[calendar.account].args
		now := self.googleTimestamp()
		event.Kind = "calendar#event"
		event.Etag = self.googleEtagWithLock()
		if event.Status == "" || (event.Status != "tentative" && event.Status != "confirmed") {
			event.Status = "confirmed"
		}
		event.HtmlLink = fakeGoogleHtmlBase + base64.RawURLEncoding.EncodeToString([]byte(event.Id+" "+calendar.args.Id))
		event.Created = now
		event.Updated = now
		event.Creator = &fakeGooglePerson{Email: account.Address, Self: true}
		event.Organizer = &fakeGooglePerson{Email: account.Address, DisplayName: account.DisplayName, Self: true}
		if event.IcalUid == "" {
			event.IcalUid = event.Id + fakeGoogleIcalUidHost
		}
		event.Sequence = 0
		event.RecurringEventId = ""
		event.OriginalStartTime = nil
		event.EventType = "default"
		for _, attendee := range event.Attendees {
			attendee.Email = strings.ToLower(attendee.Email)
			if attendee.ResponseStatus == "" {
				attendee.ResponseStatus = "needsAction"
			}
			attendee.Self = attendee.Email == strings.ToLower(account.Address)
		}
		if event.Reminders == nil {
			event.Reminders = &fakeGoogleReminders{UseDefault: true}
		}
		calendar.googleEvents[event.Id] = &event
		self.touchWithLock(calendar)
		write.Resource = event.Id
		write.Uid = event.IcalUid
		write.Applied = true
		write.Status = http.StatusOK
		write.RevisionAfter = event.Etag
		write.Notices = fakeGoogleNotices(account.Address, &event, sendUpdates, FakeCalendarNoticeRequest, time.Time{})
		self.logWriteWithLock(exchange, write)
		status = http.StatusOK
		answer = event.clone()
	}()
	if status != http.StatusOK {
		fakeGoogleError(w, status, reason)
		return
	}
	fakeGoogleJson(w, http.StatusOK, answer)
}

// Applies a patch's fields to event; null clears one. Answers the names it touched.
func fakeGooglePatchFields(event *fakeGoogleEvent, patch map[string]json.RawMessage) ([]string, error) {
	touched := []string{}
	set := func(name string, into any) error {
		raw, ok := patch[name]
		if !ok {
			return nil
		}
		touched = append(touched, name)
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			switch typed := into.(type) {
			case *string:
				*typed = ""
			case **fakeGoogleTime:
				*typed = nil
			case *[]string:
				*typed = nil
			case *[]*fakeGoogleAttendee:
				*typed = nil
			case **fakeGoogleReminders:
				*typed = nil
			}
			return nil
		}
		return json.Unmarshal(raw, into)
	}
	for name, into := range map[string]any{
		"summary":     &event.Summary,
		"description": &event.Description,
		"location":    &event.Location,
		"status":      &event.Status,
		"start":       &event.Start,
		"end":         &event.End,
		"recurrence":  &event.Recurrence,
		"attendees":   &event.Attendees,
		"reminders":   &event.Reminders,
	} {
		if err := set(name, into); err != nil {
			return nil, err
		}
	}
	slices.Sort(touched)
	return touched, nil
}

func (self *FakeCalendarServer) googlePatch(w *fakeCalendarWriter, r *http.Request, calendar *fakeCalendar, eventId string) {
	exchange := fakeCalendarExchangeOf(r.Context())
	body, err := fakeCalendarReadBody(r)
	if err != nil {
		fakeGoogleError(w, http.StatusRequestEntityTooLarge, "badRequest")
		return
	}
	sendUpdates := r.URL.Query().Get("sendUpdates")
	ifMatch := r.Header.Get("If-Match")
	write := &FakeCalendarWrite{
		Protocol:    FakeCalendarGoogle,
		Method:      http.MethodPatch,
		Account:     calendar.account,
		Calendar:    calendar.args.Id,
		Resource:    eventId,
		IfMatch:     ifMatch,
		SendUpdates: sendUpdates,
		Body:        slices.Clone(body),
	}
	status, reason := 0, ""
	var answer *fakeGoogleEvent
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			if status != http.StatusOK {
				write.Status = status
				self.logWriteWithLock(exchange, write)
			}
		}()
		var patch map[string]json.RawMessage
		if err := json.Unmarshal(body, &patch); err != nil {
			status, reason = http.StatusBadRequest, "parseError"
			return
		}
		event, master, ok := self.googleFindWithLock(calendar, eventId)
		if !ok {
			status, reason = http.StatusNotFound, "notFound"
			return
		}
		write.Uid = event.IcalUid
		write.RevisionBefore = event.Etag
		if calendar.args.ReadOnly {
			status, reason = http.StatusForbidden, "requiredAccessLevel"
			return
		}
		if ifMatch != "" && ifMatch != "*" && ifMatch != event.Etag {
			status, reason = http.StatusPreconditionFailed, "conditionNotMet"
			return
		}
		updated := event.clone()
		touched, err := fakeGooglePatchFields(updated, patch)
		if err != nil {
			status, reason = http.StatusBadRequest, "parseError"
			return
		}
		organizes := event.Organizer == nil || event.Organizer.Self
		shared := slices.ContainsFunc(touched, func(name string) bool { return slices.Contains(fakeGoogleSharedFields, name) })
		if !organizes && shared {
			status, reason = http.StatusForbidden, "forbiddenForNonOrganizer"
			return
		}
		if refusal := fakeGoogleCheckTimes(updated, calendar.zone); refusal != "" {
			status, reason = http.StatusBadRequest, refusal
			return
		}
		if updated.Status != "confirmed" && updated.Status != "tentative" && updated.Status != "cancelled" {
			status, reason = http.StatusBadRequest, "invalid"
			return
		}
		accountAddress := strings.ToLower(self.accounts[calendar.account].args.Address)
		for _, attendee := range updated.Attendees {
			attendee.Email = strings.ToLower(attendee.Email)
			if attendee.ResponseStatus == "" {
				attendee.ResponseStatus = "needsAction"
			}
			attendee.Self = attendee.Email == accountAddress
		}
		updated.Etag = self.googleEtagWithLock()
		updated.Updated = self.googleTimestamp()
		if shared {
			updated.Sequence += 1
		}
		calendar.googleEvents[updated.Id] = updated
		self.touchWithLock(calendar)
		occurrence := time.Time{}
		if master != nil && updated.OriginalStartTime != nil {
			occurrence, _, _ = fakeGoogleParseTime(updated.OriginalStartTime, calendar.zone)
		}
		account := self.accounts[calendar.account].args
		write.Applied = true
		write.Status = http.StatusOK
		write.RevisionAfter = updated.Etag
		if organizes {
			write.Notices = fakeGoogleNotices(account.Address, updated, sendUpdates, FakeCalendarNoticeRequest, occurrence)
		}
		self.logWriteWithLock(exchange, write)
		status = http.StatusOK
		answer = updated.clone()
	}()
	if status != http.StatusOK {
		fakeGoogleError(w, status, reason)
		return
	}
	fakeGoogleJson(w, http.StatusOK, answer)
}

func (self *FakeCalendarServer) googleDelete(w *fakeCalendarWriter, r *http.Request, calendar *fakeCalendar, eventId string) {
	exchange := fakeCalendarExchangeOf(r.Context())
	sendUpdates := r.URL.Query().Get("sendUpdates")
	ifMatch := r.Header.Get("If-Match")
	write := &FakeCalendarWrite{
		Protocol:    FakeCalendarGoogle,
		Method:      http.MethodDelete,
		Account:     calendar.account,
		Calendar:    calendar.args.Id,
		Resource:    eventId,
		IfMatch:     ifMatch,
		SendUpdates: sendUpdates,
	}
	status, reason := 0, ""
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			write.Status = status
			if status != http.StatusNoContent {
				self.logWriteWithLock(exchange, write)
			}
		}()
		event, master, ok := self.googleFindWithLock(calendar, eventId)
		if !ok {
			status, reason = http.StatusNotFound, "notFound"
			return
		}
		write.Uid = event.IcalUid
		write.RevisionBefore = event.Etag
		if event.Status == "cancelled" {
			status, reason = http.StatusGone, "deleted"
			return
		}
		if calendar.args.ReadOnly {
			status, reason = http.StatusForbidden, "requiredAccessLevel"
			return
		}
		if ifMatch != "" && ifMatch != "*" && ifMatch != event.Etag {
			status, reason = http.StatusPreconditionFailed, "conditionNotMet"
			return
		}
		cancelled := event.clone()
		cancelled.Status = "cancelled"
		cancelled.Etag = self.googleEtagWithLock()
		cancelled.Updated = self.googleTimestamp()
		calendar.googleEvents[cancelled.Id] = cancelled
		self.touchWithLock(calendar)
		account := self.accounts[calendar.account].args
		occurrence := time.Time{}
		if master != nil && cancelled.OriginalStartTime != nil {
			occurrence, _, _ = fakeGoogleParseTime(cancelled.OriginalStartTime, calendar.zone)
		}
		if event.Organizer == nil || event.Organizer.Self {
			write.Notices = fakeGoogleNotices(account.Address, event, sendUpdates, FakeCalendarNoticeCancel, occurrence)
		} else if sendUpdates == "all" && event.Organizer != nil {
			write.Notices = []*FakeCalendarNotice{{
				Method:     FakeCalendarNoticeReply,
				To:         strings.ToLower(event.Organizer.Email),
				Uid:        event.IcalUid,
				Occurrence: occurrence,
				PartStat:   "DECLINED",
			}}
		}
		write.Applied = true
		write.RevisionAfter = cancelled.Etag
		status = http.StatusNoContent
		write.Status = status
		self.logWriteWithLock(exchange, write)
	}()
	if status != http.StatusNoContent {
		fakeGoogleError(w, status, reason)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Stores a Google event as a test's setup, outside any front, from its JSON in Google's names: an id drawn when it
// has none, an etag, created and updated now, the organizer the account unless the JSON names another (an
// invitation the account received). Answers the event's id and etag.
func (self *FakeCalendarServer) PutGoogleEvent(account string, calendarId string, eventJson []byte) (string, string, error) {
	var event fakeGoogleEvent
	if err := json.Unmarshal(eventJson, &event); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok || accountState.args.Protocol != FakeCalendarGoogle {
		return "", "", fmt.Errorf("%w: google account %q", ErrFakeCalendarUnknown, account)
	}
	calendar := self.googleCalendarWithLock(account, calendarId)
	if calendar == nil {
		return "", "", fmt.Errorf("%w: calendar %q", ErrFakeCalendarUnknown, calendarId)
	}
	if refusal := fakeGoogleCheckTimes(&event, calendar.zone); refusal != "" {
		return "", "", fmt.Errorf("%w: times %s", ErrFakeCalendarData, refusal)
	}
	if event.Id == "" {
		event.Id = self.drawIdWithLock("google event", 13)
	}
	now := self.googleTimestamp()
	event.Kind = "calendar#event"
	event.Etag = self.googleEtagWithLock()
	if event.Status == "" {
		event.Status = "confirmed"
	}
	event.HtmlLink = fakeGoogleHtmlBase + base64.RawURLEncoding.EncodeToString([]byte(event.Id+" "+calendar.args.Id))
	event.Created = now
	event.Updated = now
	if event.Organizer == nil {
		event.Organizer = &fakeGooglePerson{Email: accountState.args.Address, DisplayName: accountState.args.DisplayName, Self: true}
	}
	event.Organizer.Self = strings.EqualFold(event.Organizer.Email, accountState.args.Address)
	if event.Creator == nil {
		event.Creator = &fakeGooglePerson{Email: event.Organizer.Email, Self: event.Organizer.Self}
	}
	if event.IcalUid == "" {
		event.IcalUid = event.Id + fakeGoogleIcalUidHost
	}
	event.EventType = "default"
	for _, attendee := range event.Attendees {
		attendee.Email = strings.ToLower(attendee.Email)
		if attendee.ResponseStatus == "" {
			attendee.ResponseStatus = "needsAction"
		}
		attendee.Self = attendee.Email == strings.ToLower(accountState.args.Address)
	}
	calendar.googleEvents[event.Id] = &event
	self.touchWithLock(calendar)
	return event.Id, event.Etag, nil
}

// A stored Google event as Google's JSON would carry it, or false.
func (self *FakeCalendarServer) GoogleEvent(account string, calendarId string, eventId string) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.accounts[account]; !ok {
		return nil, false
	}
	calendar := self.googleCalendarWithLock(account, calendarId)
	if calendar == nil {
		return nil, false
	}
	event, ok := calendar.googleEvents[eventId]
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(event)
	return encoded, err == nil
}

// A Google calendar's events as VEVENTs for its ICS feed: each master and single, not cancelled.
func (self *FakeCalendarServer) googleIcsEventsWithLock(calendar *fakeCalendar) []*ical.Component {
	ids := make([]string, 0, len(calendar.googleEvents))
	for id := range calendar.googleEvents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	events := []*ical.Component{}
	for _, id := range ids {
		event := calendar.googleEvents[id]
		if event.Status == "cancelled" || event.RecurringEventId != "" {
			continue
		}
		data, err := fakeGoogleIcalEvent(event, calendar.zone)
		if err != nil {
			continue
		}
		component := data.Children[0]
		component.Props.SetText(ical.PropSummary, event.Summary)
		if event.Location != "" {
			component.Props.SetText(ical.PropLocation, event.Location)
		}
		if event.Description != "" {
			component.Props.SetText(ical.PropDescription, event.Description)
		}
		events = append(events, component)
	}
	return events
}
