// FakeCalendarServer's Microsoft front: Microsoft Graph's calendar endpoints as the calendar tools use them (§23.7's
// microsoft row), JSON under /v1.0 on FakeCalendarGraphHost, each answer in Graph's own form:
//
//	calendars     GET me/calendars, me/calendar and me/calendars/{id}
//	calendarView  GET me/calendarView, me/calendar/calendarView and me/calendars/{id}/calendarView: startDateTime and
//	              endDateTime required, single instances, occurrences and exceptions overlapping them, series masters
//	              never, $top and $skip with an @odata.nextLink
//	events        GET, PATCH and DELETE me/events/{id}, me/calendar/events/{id} and me/calendars/{cid}/events/{id};
//	              POST me/events, me/calendar/events and me/calendars/{cid}/events; GET me/events/{id}/instances
//
// A create with a transactionId already used in the account's mailbox answers the event that id made, creating
// nothing (Graph's guard against a retried create); Graph documents no conditional write on events, so If-Match is
// recorded and ignored, and a change keeps a changeKey that changes at every change, as @odata.etag carries it too.
// Graph mails an event's attendees on such writes and cannot be told not to: a write the account organizes sends
// REQUEST to each attendee, a removal CANCEL. Every id answers in the form the request asks: Prefer: IdType="ImmutableId"
// gives immutable ids, which never change, and none the default form; both forms resolve. Times answer in UTC, or in
// the zone Prefer: outlook.timezone names (an IANA name; Windows zone names are not read, a reading). Bearer tokens
// alone, InvalidAuthenticationToken otherwise; scopes checked where a token has any (Calendars.Read, Calendars.ReadWrite);
// a read-only calendar refuses writes with ErrorAccessDenied. Fields the fake does not keep are dropped, not refused (a
// reading).

package computetest

import (
	"bytes"
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
	fakeGraphApiPrefix        = "/v1.0/"
	fakeGraphImmutablePrefix  = "AAkALg"
	fakeGraphDefaultPrefix    = "AAMkAG"
	fakeGraphOccurrenceMarker = "."
	fakeGraphWebLinkBase      = "https://outlook.office.example/owa/?itemid="
	fakeGraphDateTimeLayout   = "2006-01-02T15:04:05.0000000"
)

var (
	fakeGraphReadScopes  = []string{"Calendars.Read", "Calendars.ReadWrite", "Calendars.Read.Shared", "Calendars.ReadWrite.Shared"}
	fakeGraphWriteScopes = []string{"Calendars.ReadWrite", "Calendars.ReadWrite.Shared"}
)

// A status's own code, for a scripted failure that names none.
func fakeGraphStatusCode(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusServiceUnavailable:
		return "ServiceNotAvailable"
	case http.StatusUnauthorized:
		return "InvalidAuthenticationToken"
	case http.StatusForbidden:
		return "ErrorAccessDenied"
	case http.StatusNotFound:
		return "ErrorItemNotFound"
	}
	return "ErrorInvalidRequest"
}

// Graph's error body: {"error": {"code", "message", "innerError"}}.
func fakeGraphError(w http.ResponseWriter, status int, code string, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="", authorization_uri="https://login.microsoftonline.example/common/oauth2/authorize"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code":       code,
		"message":    message,
		"innerError": map[string]any{"request-id": "00000000-0000-4000-8000-000000000000"},
	}})
}

func fakeGraphJson(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; odata.metadata=minimal; odata.streaming=true; IEEE754Compatible=false; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

type fakeGraphDateTime struct {
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

type fakeGraphEmail struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

type fakeGraphResponseStatus struct {
	Response string `json:"response"`
	Time     string `json:"time"`
}

type fakeGraphAttendee struct {
	Type         string                   `json:"type"`
	Status       *fakeGraphResponseStatus `json:"status,omitempty"`
	EmailAddress fakeGraphEmail           `json:"emailAddress"`
}

type fakeGraphBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type fakeGraphLocation struct {
	DisplayName string `json:"displayName"`
}

type fakeGraphPattern struct {
	Type           string   `json:"type"`
	Interval       int      `json:"interval"`
	Month          int      `json:"month"`
	DayOfMonth     int      `json:"dayOfMonth"`
	DaysOfWeek     []string `json:"daysOfWeek,omitempty"`
	FirstDayOfWeek string   `json:"firstDayOfWeek,omitempty"`
	Index          string   `json:"index,omitempty"`
}

type fakeGraphRange struct {
	Type                string `json:"type"`
	StartDate           string `json:"startDate"`
	EndDate             string `json:"endDate,omitempty"`
	RecurrenceTimeZone  string `json:"recurrenceTimeZone,omitempty"`
	NumberOfOccurrences int    `json:"numberOfOccurrences"`
}

type fakeGraphRecurrence struct {
	Pattern *fakeGraphPattern `json:"pattern"`
	Range   *fakeGraphRange   `json:"range"`
}

// One stored Graph event: a single instance, a series master or an exception.
type fakeGraphEvent struct {
	immutableId   string
	defaultId     string
	changeKey     string
	transactionId string
	created       time.Time
	modified      time.Time
	icalUid       string
	subject       string
	body          fakeGraphBody
	start         time.Time
	end           time.Time
	startZone     string
	endZone       string
	isAllDay      bool
	location      string
	attendees     []*fakeGraphAttendee
	organizer     fakeGraphEmail
	isOrganizer   bool
	recurrence    *fakeGraphRecurrence
	// an exception's master, by immutable id, and the start it replaces
	seriesMasterId string
	originalStart  time.Time
	// singleInstance, seriesMaster or exception
	eventType string
	// a master's removed occurrences, by original start
	cancelledOccurrences []time.Time
	reminderMinutes      int
	isReminderOn         bool
	showAs               string
}

func (self *fakeGraphEvent) clone() *fakeGraphEvent {
	clone := *self
	clone.attendees = nil
	for _, attendee := range self.attendees {
		attendeeClone := *attendee
		if attendee.Status != nil {
			status := *attendee.Status
			attendeeClone.Status = &status
		}
		clone.attendees = append(clone.attendees, &attendeeClone)
	}
	if self.recurrence != nil {
		recurrence := *self.recurrence
		if self.recurrence.Pattern != nil {
			pattern := *self.recurrence.Pattern
			pattern.DaysOfWeek = slices.Clone(self.recurrence.Pattern.DaysOfWeek)
			recurrence.Pattern = &pattern
		}
		if self.recurrence.Range != nil {
			recurrenceRange := *self.recurrence.Range
			recurrence.Range = &recurrenceRange
		}
		clone.recurrence = &recurrence
	}
	clone.cancelledOccurrences = slices.Clone(self.cancelledOccurrences)
	return &clone
}

// What a request asks of Graph by Prefer: immutable ids, and the zone to answer times in.
type fakeGraphPrefer struct {
	immutableIds bool
	zone         *time.Location
	zoneName     string
}

func fakeGraphParsePrefer(r *http.Request) (*fakeGraphPrefer, error) {
	prefer := &fakeGraphPrefer{zone: time.UTC, zoneName: "UTC"}
	for _, header := range r.Header.Values("Prefer") {
		for _, preference := range strings.Split(header, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(preference), "=")
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "idtype":
				prefer.immutableIds = value == "ImmutableId"
			case "outlook.timezone":
				zone, err := time.LoadLocation(value)
				if err != nil {
					return nil, err
				}
				prefer.zone = zone
				prefer.zoneName = value
			}
		}
	}
	return prefer, nil
}

// An event's id in the form prefer asks for.
func (self *fakeGraphEvent) id(prefer *fakeGraphPrefer) string {
	if prefer.immutableIds {
		return self.immutableId
	}
	return self.defaultId
}

// A Graph date-time and zone read as an instant: an IANA zone or UTC, the date-time with or without its fraction.
func fakeGraphParseDateTime(value *fakeGraphDateTime) (time.Time, string, error) {
	if value == nil || value.DateTime == "" {
		return time.Time{}, "", fmt.Errorf("a dateTime")
	}
	zoneName := value.TimeZone
	if zoneName == "" {
		zoneName = "UTC"
	}
	zone, err := time.LoadLocation(zoneName)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("a timeZone Go cannot load")
	}
	for _, layout := range []string{"2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if at, err := time.ParseInLocation(layout, value.DateTime, zone); err == nil {
			return at, zoneName, nil
		}
	}
	return time.Time{}, "", fmt.Errorf("a dateTime Graph's form does not read")
}

func fakeGraphFormatDateTime(at time.Time, prefer *fakeGraphPrefer) *fakeGraphDateTime {
	return &fakeGraphDateTime{DateTime: at.In(prefer.zone).Format(fakeGraphDateTimeLayout), TimeZone: prefer.zoneName}
}

func fakeGraphTimestamp(at time.Time) string {
	return at.UTC().Format("2006-01-02T15:04:05.0000000Z")
}

var fakeGraphWeekdays = map[string]string{
	"sunday": "SU", "monday": "MO", "tuesday": "TU", "wednesday": "WE", "thursday": "TH", "friday": "FR", "saturday": "SA",
}

var fakeGraphIndexes = map[string]string{"first": "1", "second": "2", "third": "3", "fourth": "4", "last": "-1"}

// A patternedRecurrence's RRULE (RFC 5545), read from Graph's pattern and range.
func fakeGraphRrule(recurrence *fakeGraphRecurrence, zone *time.Location) (string, error) {
	if recurrence == nil || recurrence.Pattern == nil || recurrence.Range == nil {
		return "", fmt.Errorf("a recurrence needs its pattern and range")
	}
	pattern := recurrence.Pattern
	interval := max(pattern.Interval, 1)
	parts := []string{}
	byDay := func() (string, error) {
		days := []string{}
		for _, day := range pattern.DaysOfWeek {
			code, ok := fakeGraphWeekdays[strings.ToLower(day)]
			if !ok {
				return "", fmt.Errorf("a day of week %q", day)
			}
			days = append(days, code)
		}
		if len(days) == 0 {
			return "", fmt.Errorf("a pattern with no daysOfWeek")
		}
		return strings.Join(days, ","), nil
	}
	switch pattern.Type {
	case "daily":
		parts = append(parts, "FREQ=DAILY")
	case "weekly":
		days, err := byDay()
		if err != nil {
			return "", err
		}
		firstDay := fakeGraphWeekdays[strings.ToLower(pattern.FirstDayOfWeek)]
		if firstDay == "" {
			firstDay = "SU"
		}
		parts = append(parts, "FREQ=WEEKLY", "BYDAY="+days, "WKST="+firstDay)
	case "absoluteMonthly":
		parts = append(parts, "FREQ=MONTHLY", "BYMONTHDAY="+strconv.Itoa(pattern.DayOfMonth))
	case "relativeMonthly", "relativeYearly":
		days, err := byDay()
		if err != nil {
			return "", err
		}
		index := fakeGraphIndexes[strings.ToLower(pattern.Index)]
		if index == "" {
			index = "1"
		}
		if pattern.Type == "relativeMonthly" {
			parts = append(parts, "FREQ=MONTHLY")
		} else {
			parts = append(parts, "FREQ=YEARLY", "BYMONTH="+strconv.Itoa(pattern.Month))
		}
		parts = append(parts, "BYDAY="+days, "BYSETPOS="+index)
	case "absoluteYearly":
		parts = append(parts, "FREQ=YEARLY", "BYMONTH="+strconv.Itoa(pattern.Month), "BYMONTHDAY="+strconv.Itoa(pattern.DayOfMonth))
	default:
		return "", fmt.Errorf("a pattern type %q", pattern.Type)
	}
	parts = append(parts, "INTERVAL="+strconv.Itoa(interval))
	recurrenceRange := recurrence.Range
	switch recurrenceRange.Type {
	case "endDate":
		rangeZone := zone
		if recurrenceRange.RecurrenceTimeZone != "" {
			loaded, err := time.LoadLocation(recurrenceRange.RecurrenceTimeZone)
			if err != nil {
				return "", fmt.Errorf("a recurrenceTimeZone Go cannot load")
			}
			rangeZone = loaded
		}
		endDate, err := time.ParseInLocation(time.DateOnly, recurrenceRange.EndDate, rangeZone)
		if err != nil {
			return "", fmt.Errorf("an endDate")
		}
		// the end date is the series' last day, whole
		parts = append(parts, "UNTIL="+endDate.AddDate(0, 0, 1).Add(-time.Second).UTC().Format("20060102T150405Z"))
	case "numbered":
		if recurrenceRange.NumberOfOccurrences < 1 {
			return "", fmt.Errorf("a numbered range of no occurrence")
		}
		parts = append(parts, "COUNT="+strconv.Itoa(recurrenceRange.NumberOfOccurrences))
	case "noEnd":
	default:
		return "", fmt.Errorf("a range type %q", recurrenceRange.Type)
	}
	return strings.Join(parts, ";"), nil
}

// An event as one VEVENT go-ical expands, and writes for an ICS feed.
func fakeGraphIcalEvent(event *fakeGraphEvent) (*ical.Calendar, error) {
	zone, err := time.LoadLocation(event.startZone)
	if err != nil {
		zone = time.UTC
	}
	lines := []string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:" + fakeCaldavProductId, "BEGIN:VEVENT",
		"UID:" + event.icalUid, "DTSTAMP:20000101T000000Z"}
	if event.isAllDay {
		lines = append(lines, "DTSTART;VALUE=DATE:"+event.start.In(zone).Format("20060102"), "DTEND;VALUE=DATE:"+event.end.In(zone).Format("20060102"))
	} else {
		lines = append(lines, "DTSTART;TZID="+zone.String()+":"+event.start.In(zone).Format("20060102T150405"),
			"DTEND;TZID="+zone.String()+":"+event.end.In(zone).Format("20060102T150405"))
	}
	if event.recurrence != nil {
		rule, err := fakeGraphRrule(event.recurrence, zone)
		if err != nil {
			return nil, err
		}
		lines = append(lines, "RRULE:"+rule)
	}
	lines = append(lines, "END:VEVENT", "END:VCALENDAR", "")
	return ical.NewDecoder(strings.NewReader(strings.Join(lines, "\r\n"))).Decode()
}

// An occurrence's id: its master's, in the form asked, and its original start.
func fakeGraphOccurrenceId(masterId string, originalStart time.Time) string {
	return masterId + fakeGraphOccurrenceMarker + originalStart.UTC().Format("20060102T150405Z")
}

// A master's occurrences in window, as events: exceptions in their occurrences' place, cancelled ones left out.
func (self *FakeCalendarServer) graphOccurrencesWithLock(calendar *fakeCalendar, master *fakeGraphEvent, window *fakeCalendarWindow) ([]*fakeGraphEvent, error) {
	data, err := fakeGraphIcalEvent(master)
	if err != nil {
		return nil, err
	}
	zone, err := time.LoadLocation(master.startZone)
	if err != nil {
		zone = time.UTC
	}
	instances, _, err := fakeIcalInstances(data.Children[0], data, zone, window, self.settings.ExpandInstanceMaxCount)
	if err != nil {
		return nil, err
	}
	exceptions := map[int64]*fakeGraphEvent{}
	for _, event := range calendar.graphEvents {
		if event.seriesMasterId == master.immutableId {
			exceptions[event.originalStart.UnixNano()] = event
		}
	}
	occurrences := []*fakeGraphEvent{}
	for _, instance := range instances {
		key := instance.recurrenceId.UnixNano()
		if slices.ContainsFunc(master.cancelledOccurrences, func(at time.Time) bool { return at.Equal(instance.recurrenceId) }) {
			continue
		}
		if exception, ok := exceptions[key]; ok {
			delete(exceptions, key)
			occurrences = append(occurrences, exception)
			continue
		}
		occurrence := master.clone()
		occurrence.immutableId = fakeGraphOccurrenceId(master.immutableId, instance.recurrenceId)
		occurrence.defaultId = fakeGraphOccurrenceId(master.defaultId, instance.recurrenceId)
		occurrence.recurrence = nil
		occurrence.cancelledOccurrences = nil
		occurrence.seriesMasterId = master.immutableId
		occurrence.originalStart = instance.recurrenceId
		occurrence.start = instance.start
		occurrence.end = instance.end
		occurrence.eventType = "occurrence"
		occurrences = append(occurrences, occurrence)
	}
	for _, exception := range exceptions {
		if window == nil || window.overlaps(exception.start, exception.end) {
			occurrences = append(occurrences, exception)
		}
	}
	return occurrences, nil
}

// The event an id names, in either form, an occurrence among them; and its master for an occurrence or exception.
func (self *FakeCalendarServer) graphFindWithLock(calendar *fakeCalendar, eventId string) (*fakeGraphEvent, *fakeGraphEvent, bool) {
	for _, event := range calendar.graphEvents {
		if event.immutableId == eventId || event.defaultId == eventId {
			var master *fakeGraphEvent
			if event.seriesMasterId != "" {
				master = calendar.graphEvents[event.seriesMasterId]
			}
			return event, master, true
		}
	}
	masterId, at, ok := strings.Cut(eventId, fakeGraphOccurrenceMarker)
	if !ok {
		return nil, nil, false
	}
	originalStart, err := time.Parse("20060102T150405Z", at)
	if err != nil {
		return nil, nil, false
	}
	for _, master := range calendar.graphEvents {
		if master.eventType != "seriesMaster" || (master.immutableId != masterId && master.defaultId != masterId) {
			continue
		}
		occurrences, err := self.graphOccurrencesWithLock(calendar, master, &fakeCalendarWindow{start: originalStart, end: originalStart.Add(time.Second)})
		if err != nil {
			return nil, nil, false
		}
		for _, occurrence := range occurrences {
			if occurrence.originalStart.Equal(originalStart) {
				return occurrence, master, true
			}
		}
	}
	return nil, nil, false
}

// An event as Graph answers it, its bodyPreview the body's first previewCount characters.
func (self *fakeGraphEvent) render(prefer *fakeGraphPrefer, calendar *fakeCalendar, previewCount int) map[string]any {
	id := self.id(prefer)
	preview := []rune(self.body.Content)
	if len(preview) > previewCount {
		preview = preview[:previewCount]
	}
	response := "none"
	if self.isOrganizer {
		response = "organizer"
	}
	attendees := self.attendees
	if attendees == nil {
		attendees = []*fakeGraphAttendee{}
	}
	rendered := map[string]any{
		"@odata.etag":                `W/"` + self.changeKey + `"`,
		"id":                         id,
		"createdDateTime":            fakeGraphTimestamp(self.created),
		"lastModifiedDateTime":       fakeGraphTimestamp(self.modified),
		"changeKey":                  self.changeKey,
		"categories":                 []any{},
		"originalStartTimeZone":      self.startZone,
		"originalEndTimeZone":        self.endZone,
		"iCalUId":                    self.icalUid,
		"uid":                        self.icalUid,
		"reminderMinutesBeforeStart": self.reminderMinutes,
		"isReminderOn":               self.isReminderOn,
		"hasAttachments":             false,
		"subject":                    self.subject,
		"bodyPreview":                string(preview),
		"importance":                 "normal",
		"sensitivity":                "normal",
		"isAllDay":                   self.isAllDay,
		"isCancelled":                false,
		"isOrganizer":                self.isOrganizer,
		"responseRequested":          true,
		"showAs":                     self.showAs,
		"type":                       self.eventType,
		"webLink":                    fakeGraphWebLinkBase + url.QueryEscape(id),
		"responseStatus":             &fakeGraphResponseStatus{Response: response, Time: "0001-01-01T00:00:00Z"},
		"body":                       &self.body,
		"start":                      fakeGraphFormatDateTime(self.start, prefer),
		"end":                        fakeGraphFormatDateTime(self.end, prefer),
		"location":                   map[string]any{"displayName": self.location, "locationType": "default", "uniqueIdType": "unknown"},
		"locations":                  []any{},
		"attendees":                  attendees,
		"organizer":                  map[string]any{"emailAddress": &self.organizer},
		"seriesMasterId":             nil,
		"recurrence":                 nil,
		"transactionId":              nil,
	}
	if self.transactionId != "" {
		rendered["transactionId"] = self.transactionId
	}
	if self.recurrence != nil {
		rendered["recurrence"] = self.recurrence
	}
	if self.seriesMasterId != "" {
		masterId := self.seriesMasterId
		if !prefer.immutableIds {
			if master, ok := calendar.graphEvents[self.seriesMasterId]; ok {
				masterId = master.defaultId
			}
		}
		rendered["seriesMasterId"] = masterId
		rendered["originalStart"] = self.originalStart.UTC().Format(time.RFC3339)
		if self.eventType == "occurrence" {
			rendered["id"] = fakeGraphOccurrenceId(masterId, self.originalStart)
		}
	}
	return rendered
}

// The account's calendar a Graph path names: its default for an empty id.
func (self *FakeCalendarServer) graphCalendarWithLock(account string, calendarId string) *fakeCalendar {
	if calendarId == "" {
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

// The calendar holding an event of the account, by either id form or an occurrence's.
func (self *FakeCalendarServer) graphEventCalendarWithLock(account string, eventId string) *fakeCalendar {
	for _, calendarId := range self.accounts[account].calendarIds {
		calendar := self.calendars[fakeCalendarKey(account, calendarId)]
		if _, _, ok := self.graphFindWithLock(calendar, eventId); ok {
			return calendar
		}
	}
	return nil
}

func fakeGraphCalendarRender(calendar *fakeCalendar, account *FakeCalendarAccountArgs) map[string]any {
	return map[string]any{
		"id":                  calendar.args.Id,
		"name":                calendar.args.Name,
		"color":               "auto",
		"hexColor":            "",
		"isDefaultCalendar":   calendar.args.Default,
		"changeKey":           strconv.FormatUint(calendar.revision+1, 10),
		"canShare":            !calendar.args.ReadOnly,
		"canViewPrivateItems": true,
		"canEdit":             !calendar.args.ReadOnly,
		"isRemovable":         !calendar.args.Default,
		"owner":               map[string]any{"name": account.DisplayName, "address": account.Address},
	}
}

// The Microsoft front (see the file header).
func (self *FakeCalendarServer) serveGraph(w *fakeCalendarWriter, r *http.Request) {
	account, scopes, ok := self.bearer(r, FakeCalendarMicrosoft)
	if !ok {
		fakeGraphError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token has expired or is not yet valid.")
		return
	}
	fakeCalendarExchangeOf(r.Context()).account = account
	prefer, err := fakeGraphParsePrefer(r)
	if err != nil {
		fakeGraphError(w, http.StatusBadRequest, "TimeZoneNotSupportedException", "A valid TimeZone value must be specified.")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), fakeGraphApiPrefix)
	if !ok {
		fakeGraphError(w, http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store.")
		return
	}
	segments := strings.Split(rest, "/")
	for i, segment := range segments {
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			fakeGraphError(w, http.StatusBadRequest, "ErrorInvalidRequest", "An id Graph cannot read.")
			return
		}
		segments[i] = unescaped
	}
	if len(segments) < 2 || segments[0] != "me" {
		fakeGraphError(w, http.StatusNotImplemented, "NotImplemented", ErrFakeCalendarUnserved.Error())
		return
	}
	segments = segments[1:]
	write := r.Method != http.MethodGet
	if (write && !fakeCalendarScopesGrant(scopes, fakeGraphWriteScopes...)) || (!write && !fakeCalendarScopesGrant(scopes, fakeGraphReadScopes...)) {
		fakeGraphError(w, http.StatusForbidden, "ErrorAccessDenied", "Access is denied. Check credentials and try again.")
		return
	}
	// me/calendars, me/calendar[/...], me/calendars/{id}[/...]: the calendar, and what follows it
	calendarId := ""
	calendarNamed := false
	switch segments[0] {
	case "calendars":
		if len(segments) == 1 {
			if r.Method != http.MethodGet {
				fakeGraphError(w, http.StatusNotImplemented, "NotImplemented", ErrFakeCalendarUnserved.Error())
				return
			}
			self.graphCalendars(w, account)
			return
		}
		calendarId = segments[1]
		calendarNamed = true
		segments = segments[2:]
	case "calendar":
		calendarNamed = true
		segments = segments[1:]
	}
	calendar := func() *fakeCalendar {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch {
		case calendarNamed:
			return self.graphCalendarWithLock(account, calendarId)
		case len(segments) >= 2 && segments[0] == "events":
			// me/events/{id}: the calendar that holds it
			return self.graphEventCalendarWithLock(account, segments[1])
		}
		return self.graphCalendarWithLock(account, "")
	}()
	if calendar == nil {
		fakeGraphError(w, http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store.")
		return
	}
	switch {
	case len(segments) == 0 && r.Method == http.MethodGet:
		self.stateLock.Lock()
		rendered := fakeGraphCalendarRender(calendar, &self.accounts[account].args)
		self.stateLock.Unlock()
		fakeGraphJson(w, http.StatusOK, rendered)
	case len(segments) == 1 && segments[0] == "calendarView" && r.Method == http.MethodGet:
		self.graphView(w, r, prefer, calendar, "")
	case len(segments) == 1 && segments[0] == "events" && r.Method == http.MethodPost:
		self.graphCreate(w, r, prefer, calendar)
	case len(segments) == 2 && segments[0] == "events" && r.Method == http.MethodGet:
		self.graphGet(w, prefer, calendar, segments[1])
	case len(segments) == 2 && segments[0] == "events" && r.Method == http.MethodPatch:
		self.graphPatch(w, r, prefer, calendar, segments[1])
	case len(segments) == 2 && segments[0] == "events" && r.Method == http.MethodDelete:
		self.graphDelete(w, r, calendar, segments[1])
	case len(segments) == 3 && segments[0] == "events" && segments[2] == "instances" && r.Method == http.MethodGet:
		self.graphView(w, r, prefer, calendar, segments[1])
	default:
		fakeGraphError(w, http.StatusNotImplemented, "NotImplemented", ErrFakeCalendarUnserved.Error())
	}
}

func (self *FakeCalendarServer) graphCalendars(w http.ResponseWriter, account string) {
	self.stateLock.Lock()
	accountState := self.accounts[account]
	calendars := []map[string]any{}
	for _, calendarId := range accountState.calendarIds {
		calendars = append(calendars, fakeGraphCalendarRender(self.calendars[fakeCalendarKey(account, calendarId)], &accountState.args))
	}
	self.stateLock.Unlock()
	fakeGraphJson(w, http.StatusOK, map[string]any{
		"@odata.context": "https://" + FakeCalendarGraphHost + "/v1.0/$metadata#users('" + account + "')/calendars",
		"value":          calendars,
	})
}

// calendarView, or a master's instances where masterId is set.
func (self *FakeCalendarServer) graphView(w http.ResponseWriter, r *http.Request, prefer *fakeGraphPrefer, calendar *fakeCalendar, masterId string) {
	query := r.URL.Query()
	parseBound := func(name string) (time.Time, bool) {
		value := query.Get(name)
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
			if at, err := time.Parse(layout, value); err == nil {
				return at, true
			}
		}
		return time.Time{}, false
	}
	start, startOk := parseBound("startDateTime")
	end, endOk := parseBound("endDateTime")
	if !startOk || !endOk {
		fakeGraphError(w, http.StatusBadRequest, "ErrorInvalidParameter",
			"This request requires a time window specified by the query string parameters StartDateTime and EndDateTime.")
		return
	}
	top := self.settings.GraphPageDefaultCount
	if value := query.Get("$top"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > self.settings.GraphPageMaxCount {
			fakeGraphError(w, http.StatusBadRequest, "ErrorInvalidRequest", "Invalid $top value.")
			return
		}
		top = parsed
	}
	skip := 0
	if value := query.Get("$skip"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			fakeGraphError(w, http.StatusBadRequest, "ErrorInvalidRequest", "Invalid $skip value.")
			return
		}
		skip = parsed
	}
	window := &fakeCalendarWindow{start: start, end: end}
	events := []map[string]any{}
	starts := []time.Time{}
	found := true
	var viewErr error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listed := []*fakeGraphEvent{}
		if masterId != "" {
			master, _, ok := self.graphFindWithLock(calendar, masterId)
			if !ok || master.eventType != "seriesMaster" {
				found = false
				return
			}
			occurrences, err := self.graphOccurrencesWithLock(calendar, master, window)
			if err != nil {
				viewErr = err
				return
			}
			listed = occurrences
		} else {
			for _, event := range calendar.graphEvents {
				switch event.eventType {
				case "seriesMaster":
					occurrences, err := self.graphOccurrencesWithLock(calendar, event, window)
					if err != nil {
						viewErr = err
						return
					}
					listed = append(listed, occurrences...)
				case "singleInstance":
					if window.overlaps(event.start, event.end) {
						listed = append(listed, event)
					}
				}
			}
		}
		slices.SortStableFunc(listed, func(a *fakeGraphEvent, b *fakeGraphEvent) int {
			if order := a.start.Compare(b.start); order != 0 {
				return order
			}
			return strings.Compare(a.immutableId, b.immutableId)
		})
		for _, event := range listed {
			events = append(events, event.render(prefer, calendar, self.settings.GraphBodyPreviewCharacterCount))
			starts = append(starts, event.start)
		}
	}()
	switch {
	case !found:
		fakeGraphError(w, http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store.")
		return
	case viewErr != nil:
		fakeGraphError(w, http.StatusInternalServerError, "ErrorInternalServerError", "computetest: "+viewErr.Error())
		return
	}
	page := []map[string]any{}
	for i := skip; i < len(events) && len(page) < top; i += 1 {
		page = append(page, events[i])
	}
	body := map[string]any{
		"@odata.context": "https://" + FakeCalendarGraphHost + "/v1.0/$metadata#Collection(event)",
		"value":          page,
	}
	if skip+len(page) < len(events) {
		next := url.Values{}
		for name, values := range query {
			next[name] = values
		}
		next.Set("$skip", strconv.Itoa(skip+len(page)))
		next.Set("$top", strconv.Itoa(top))
		body["@odata.nextLink"] = "https://" + FakeCalendarGraphHost + r.URL.EscapedPath() + "?" + next.Encode()
	}
	fakeGraphJson(w, http.StatusOK, body)
}

func (self *FakeCalendarServer) graphGet(w http.ResponseWriter, prefer *fakeGraphPrefer, calendar *fakeCalendar, eventId string) {
	self.stateLock.Lock()
	event, _, ok := self.graphFindWithLock(calendar, eventId)
	var rendered map[string]any
	if ok {
		rendered = event.render(prefer, calendar, self.settings.GraphBodyPreviewCharacterCount)
	}
	self.stateLock.Unlock()
	if !ok {
		fakeGraphError(w, http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store.")
		return
	}
	fakeGraphJson(w, http.StatusOK, rendered)
}

// Applies a create's or patch's fields to event; null clears one. Answers the names it touched, or why it refuses.
func fakeGraphApply(event *fakeGraphEvent, fields map[string]json.RawMessage) ([]string, string) {
	touched := []string{}
	isNull := func(raw json.RawMessage) bool {
		return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	}
	for name, raw := range fields {
		var err error
		switch name {
		case "subject":
			event.subject = ""
			if !isNull(raw) {
				err = json.Unmarshal(raw, &event.subject)
			}
		case "body":
			event.body = fakeGraphBody{ContentType: "text"}
			if !isNull(raw) {
				err = json.Unmarshal(raw, &event.body)
			}
		case "start", "end":
			var value fakeGraphDateTime
			if err = json.Unmarshal(raw, &value); err == nil {
				at, zoneName, parseErr := fakeGraphParseDateTime(&value)
				if parseErr != nil {
					return nil, "a " + name + " Graph cannot read"
				}
				if name == "start" {
					event.start, event.startZone = at, zoneName
				} else {
					event.end, event.endZone = at, zoneName
				}
			}
		case "isAllDay":
			err = json.Unmarshal(raw, &event.isAllDay)
		case "location":
			var location fakeGraphLocation
			if !isNull(raw) {
				err = json.Unmarshal(raw, &location)
			}
			event.location = location.DisplayName
		case "attendees":
			event.attendees = nil
			if !isNull(raw) {
				err = json.Unmarshal(raw, &event.attendees)
			}
		case "recurrence":
			event.recurrence = nil
			if !isNull(raw) {
				err = json.Unmarshal(raw, &event.recurrence)
			}
		case "reminderMinutesBeforeStart":
			err = json.Unmarshal(raw, &event.reminderMinutes)
		case "isReminderOn":
			err = json.Unmarshal(raw, &event.isReminderOn)
		case "showAs":
			err = json.Unmarshal(raw, &event.showAs)
		default:
			continue
		}
		if err != nil {
			return nil, "a " + name + " Graph cannot read"
		}
		touched = append(touched, name)
	}
	if !event.end.After(event.start) {
		return nil, "an end that is not after its start"
	}
	if event.isAllDay {
		startZone, err := time.LoadLocation(event.startZone)
		if err != nil {
			startZone = time.UTC
		}
		endZone, err := time.LoadLocation(event.endZone)
		if err != nil {
			endZone = time.UTC
		}
		startLocal := event.start.In(startZone)
		endLocal := event.end.In(endZone)
		if startLocal.Hour() != 0 || startLocal.Minute() != 0 || endLocal.Hour() != 0 || endLocal.Minute() != 0 {
			return nil, "an all-day event whose start and end are not midnight"
		}
	}
	for _, attendee := range event.attendees {
		attendee.EmailAddress.Address = strings.ToLower(attendee.EmailAddress.Address)
		if attendee.Type == "" {
			attendee.Type = "required"
		}
		if attendee.Status == nil {
			attendee.Status = &fakeGraphResponseStatus{Response: "none", Time: "0001-01-01T00:00:00Z"}
		}
	}
	slices.Sort(touched)
	return touched, ""
}

// The notices Graph sends for a write the account organizes: method to each attendee.
func fakeGraphNotices(event *fakeGraphEvent, method string, occurrence time.Time) []*FakeCalendarNotice {
	if !event.isOrganizer {
		return nil
	}
	notices := []*FakeCalendarNotice{}
	for _, attendee := range event.attendees {
		address := strings.ToLower(attendee.EmailAddress.Address)
		if address == strings.ToLower(event.organizer.Address) {
			continue
		}
		notices = append(notices, &FakeCalendarNotice{Method: method, To: address, Uid: event.icalUid, Occurrence: occurrence})
	}
	return notices
}

func (self *FakeCalendarServer) graphChangeKeyWithLock(label string) string {
	return self.nextRevisionWithLock("graph " + label)
}

func (self *FakeCalendarServer) graphCreate(w *fakeCalendarWriter, r *http.Request, prefer *fakeGraphPrefer, calendar *fakeCalendar) {
	exchange := fakeCalendarExchangeOf(r.Context())
	body, err := fakeCalendarReadBody(r)
	if err != nil {
		fakeGraphError(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", "The request body is too large.")
		return
	}
	write := &FakeCalendarWrite{
		Protocol: FakeCalendarMicrosoft,
		Method:   http.MethodPost,
		Account:  calendar.account,
		Calendar: calendar.args.Id,
		IfMatch:  r.Header.Get("If-Match"),
		Body:     slices.Clone(body),
	}
	status, code, message := 0, "", ""
	var rendered map[string]any
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			write.Status = status
			if status != http.StatusCreated || !write.Applied {
				self.logWriteWithLock(exchange, write)
			}
		}()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			status, code, message = http.StatusBadRequest, "RequestBodyRead", "The request body could not be read as JSON."
			return
		}
		if raw, ok := fields["transactionId"]; ok {
			json.Unmarshal(raw, &write.TransactionId)
		}
		if write.TransactionId != "" {
			for _, calendarId := range self.accounts[calendar.account].calendarIds {
				for _, existing := range self.calendars[fakeCalendarKey(calendar.account, calendarId)].graphEvents {
					if existing.transactionId == write.TransactionId {
						// Graph's guard against a retried create: the event the id made, nothing created
						write.Resource = existing.immutableId
						write.Uid = existing.icalUid
						status = http.StatusCreated
						rendered = existing.render(prefer, calendar, self.settings.GraphBodyPreviewCharacterCount)
						return
					}
				}
			}
		}
		if calendar.args.ReadOnly {
			status, code, message = http.StatusForbidden, "ErrorAccessDenied", "Access is denied. Check credentials and try again."
			return
		}
		if _, ok := fields["start"]; !ok {
			status, code, message = http.StatusBadRequest, "ErrorInvalidRequest", "An event needs its start and end."
			return
		}
		if _, ok := fields["end"]; !ok {
			status, code, message = http.StatusBadRequest, "ErrorInvalidRequest", "An event needs its start and end."
			return
		}
		account := self.accounts[calendar.account].args
		now := self.now()
		event := &fakeGraphEvent{
			immutableId:     fakeGraphImmutablePrefix + self.drawIdWithLock("graph immutable id", 20),
			defaultId:       fakeGraphDefaultPrefix + self.drawIdWithLock("graph default id", 20),
			transactionId:   write.TransactionId,
			created:         now,
			modified:        now,
			icalUid:         "040000008200e00074c5b7101a82e008" + self.drawIdWithLock("graph uid", 16),
			body:            fakeGraphBody{ContentType: "text"},
			organizer:       fakeGraphEmail{Address: strings.ToLower(account.Address), Name: account.DisplayName},
			isOrganizer:     true,
			eventType:       "singleInstance",
			reminderMinutes: int(self.settings.GraphDefaultReminder / time.Minute),
			isReminderOn:    true,
			showAs:          "busy",
		}
		if _, refusal := fakeGraphApply(event, fields); refusal != "" {
			status, code, message = http.StatusBadRequest, "ErrorInvalidRequest", refusal
			return
		}
		if event.recurrence != nil {
			if _, err := fakeGraphIcalEvent(event); err != nil {
				status, code, message = http.StatusBadRequest, "ErrorPatternedRecurrenceInvalid", err.Error()
				return
			}
			event.eventType = "seriesMaster"
		}
		event.changeKey = self.graphChangeKeyWithLock(event.immutableId)
		calendar.graphEvents[event.immutableId] = event
		self.touchWithLock(calendar)
		write.Resource = event.immutableId
		write.Uid = event.icalUid
		write.Applied = true
		write.Status = http.StatusCreated
		write.RevisionAfter = event.changeKey
		write.Notices = fakeGraphNotices(event, FakeCalendarNoticeRequest, time.Time{})
		self.logWriteWithLock(exchange, write)
		status = http.StatusCreated
		rendered = event.render(prefer, calendar, self.settings.GraphBodyPreviewCharacterCount)
	}()
	if status != http.StatusCreated {
		fakeGraphError(w, status, code, message)
		return
	}
	fakeGraphJson(w, http.StatusCreated, rendered)
}

func (self *FakeCalendarServer) graphPatch(w *fakeCalendarWriter, r *http.Request, prefer *fakeGraphPrefer, calendar *fakeCalendar, eventId string) {
	exchange := fakeCalendarExchangeOf(r.Context())
	body, err := fakeCalendarReadBody(r)
	if err != nil {
		fakeGraphError(w, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", "The request body is too large.")
		return
	}
	write := &FakeCalendarWrite{
		Protocol: FakeCalendarMicrosoft,
		Method:   http.MethodPatch,
		Account:  calendar.account,
		Calendar: calendar.args.Id,
		Resource: eventId,
		IfMatch:  r.Header.Get("If-Match"),
		Body:     slices.Clone(body),
	}
	status, code, message := 0, "", ""
	var rendered map[string]any
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			if status != http.StatusOK {
				write.Status = status
				self.logWriteWithLock(exchange, write)
			}
		}()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			status, code, message = http.StatusBadRequest, "RequestBodyRead", "The request body could not be read as JSON."
			return
		}
		event, master, ok := self.graphFindWithLock(calendar, eventId)
		if !ok {
			status, code, message = http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store."
			return
		}
		write.Uid = event.icalUid
		write.RevisionBefore = event.changeKey
		if calendar.args.ReadOnly {
			status, code, message = http.StatusForbidden, "ErrorAccessDenied", "Access is denied. Check credentials and try again."
			return
		}
		updated := event.clone()
		if _, refusal := fakeGraphApply(updated, fields); refusal != "" {
			status, code, message = http.StatusBadRequest, "ErrorInvalidRequest", refusal
			return
		}
		if updated.eventType == "occurrence" {
			// an occurrence's change makes its exception, keeping the occurrence's ids
			updated.eventType = "exception"
			updated.recurrence = nil
		}
		if updated.eventType == "seriesMaster" {
			if updated.recurrence == nil {
				updated.eventType = "singleInstance"
			} else if _, err := fakeGraphIcalEvent(updated); err != nil {
				status, code, message = http.StatusBadRequest, "ErrorPatternedRecurrenceInvalid", err.Error()
				return
			}
		}
		updated.modified = self.now()
		updated.changeKey = self.graphChangeKeyWithLock(updated.immutableId)
		calendar.graphEvents[updated.immutableId] = updated
		self.touchWithLock(calendar)
		occurrence := time.Time{}
		if master != nil {
			occurrence = updated.originalStart
		}
		write.Resource = updated.immutableId
		write.Applied = true
		write.Status = http.StatusOK
		write.RevisionAfter = updated.changeKey
		write.Notices = fakeGraphNotices(updated, FakeCalendarNoticeRequest, occurrence)
		self.logWriteWithLock(exchange, write)
		status = http.StatusOK
		rendered = updated.render(prefer, calendar, self.settings.GraphBodyPreviewCharacterCount)
	}()
	if status != http.StatusOK {
		fakeGraphError(w, status, code, message)
		return
	}
	fakeGraphJson(w, http.StatusOK, rendered)
}

func (self *FakeCalendarServer) graphDelete(w *fakeCalendarWriter, r *http.Request, calendar *fakeCalendar, eventId string) {
	exchange := fakeCalendarExchangeOf(r.Context())
	write := &FakeCalendarWrite{
		Protocol: FakeCalendarMicrosoft,
		Method:   http.MethodDelete,
		Account:  calendar.account,
		Calendar: calendar.args.Id,
		Resource: eventId,
		IfMatch:  r.Header.Get("If-Match"),
	}
	status, code, message := 0, "", ""
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		defer func() {
			if status != http.StatusNoContent {
				write.Status = status
				self.logWriteWithLock(exchange, write)
			}
		}()
		event, master, ok := self.graphFindWithLock(calendar, eventId)
		if !ok {
			status, code, message = http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store."
			return
		}
		write.Uid = event.icalUid
		write.RevisionBefore = event.changeKey
		if calendar.args.ReadOnly {
			status, code, message = http.StatusForbidden, "ErrorAccessDenied", "Access is denied. Check credentials and try again."
			return
		}
		occurrence := time.Time{}
		switch {
		case master != nil:
			// an occurrence or an exception: the occurrence leaves the series
			occurrence = event.originalStart
			updatedMaster := master.clone()
			updatedMaster.cancelledOccurrences = append(updatedMaster.cancelledOccurrences, event.originalStart)
			updatedMaster.changeKey = self.graphChangeKeyWithLock(master.immutableId)
			updatedMaster.modified = self.now()
			calendar.graphEvents[master.immutableId] = updatedMaster
			delete(calendar.graphEvents, event.immutableId)
		default:
			delete(calendar.graphEvents, event.immutableId)
			for id, other := range calendar.graphEvents {
				if other.seriesMasterId == event.immutableId {
					delete(calendar.graphEvents, id)
				}
			}
		}
		self.touchWithLock(calendar)
		write.Resource = event.immutableId
		write.Applied = true
		write.Notices = fakeGraphNotices(event, FakeCalendarNoticeCancel, occurrence)
		status = http.StatusNoContent
		write.Status = status
		self.logWriteWithLock(exchange, write)
	}()
	if status != http.StatusNoContent {
		fakeGraphError(w, status, code, message)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Stores a Graph event as a test's setup, outside any front, from its JSON in Graph's names (subject, body, start,
// end, isAllDay, location, attendees, recurrence, transactionId, and organizer for an invitation the account received).
// Answers its immutable id and changeKey.
func (self *FakeCalendarServer) PutGraphEvent(account string, calendarId string, eventJson []byte) (string, string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(eventJson, &fields); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	accountState, ok := self.accounts[account]
	if !ok || accountState.args.Protocol != FakeCalendarMicrosoft {
		return "", "", fmt.Errorf("%w: microsoft account %q", ErrFakeCalendarUnknown, account)
	}
	calendar := self.graphCalendarWithLock(account, calendarId)
	if calendar == nil {
		return "", "", fmt.Errorf("%w: calendar %q", ErrFakeCalendarUnknown, calendarId)
	}
	now := self.now()
	event := &fakeGraphEvent{
		immutableId:     fakeGraphImmutablePrefix + self.drawIdWithLock("graph immutable id", 20),
		defaultId:       fakeGraphDefaultPrefix + self.drawIdWithLock("graph default id", 20),
		created:         now,
		modified:        now,
		icalUid:         "040000008200e00074c5b7101a82e008" + self.drawIdWithLock("graph uid", 16),
		body:            fakeGraphBody{ContentType: "text"},
		organizer:       fakeGraphEmail{Address: strings.ToLower(accountState.args.Address), Name: accountState.args.DisplayName},
		eventType:       "singleInstance",
		reminderMinutes: int(self.settings.GraphDefaultReminder / time.Minute),
		isReminderOn:    true,
		showAs:          "busy",
	}
	if raw, ok := fields["transactionId"]; ok {
		json.Unmarshal(raw, &event.transactionId)
	}
	if raw, ok := fields["organizer"]; ok {
		var organizer struct {
			EmailAddress fakeGraphEmail `json:"emailAddress"`
		}
		if err := json.Unmarshal(raw, &organizer); err != nil {
			return "", "", fmt.Errorf("%w: organizer", ErrFakeCalendarData)
		}
		event.organizer = organizer.EmailAddress
		event.organizer.Address = strings.ToLower(event.organizer.Address)
	}
	event.isOrganizer = event.organizer.Address == strings.ToLower(accountState.args.Address)
	if _, refusal := fakeGraphApply(event, fields); refusal != "" {
		return "", "", fmt.Errorf("%w: %s", ErrFakeCalendarData, refusal)
	}
	if event.recurrence != nil {
		if _, err := fakeGraphIcalEvent(event); err != nil {
			return "", "", fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
		}
		event.eventType = "seriesMaster"
	}
	event.changeKey = self.graphChangeKeyWithLock(event.immutableId)
	calendar.graphEvents[event.immutableId] = event
	self.touchWithLock(calendar)
	return event.immutableId, event.changeKey, nil
}

// Whether a Graph event is stored by its immutable id, and its changeKey.
func (self *FakeCalendarServer) GraphEventChangeKey(account string, calendarId string, eventId string) (string, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.accounts[account]; !ok {
		return "", false
	}
	calendar := self.graphCalendarWithLock(account, calendarId)
	if calendar == nil {
		return "", false
	}
	event, ok := calendar.graphEvents[eventId]
	if !ok {
		return "", false
	}
	return event.changeKey, true
}

// The number of Graph events stored in a calendar, masters and exceptions counted alike.
func (self *FakeCalendarServer) GraphEventCount(account string, calendarId string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.accounts[account]; !ok {
		return 0
	}
	calendar := self.graphCalendarWithLock(account, calendarId)
	if calendar == nil {
		return 0
	}
	return len(calendar.graphEvents)
}

// A Graph calendar's events as VEVENTs for its ICS feed: each master and single.
func (self *FakeCalendarServer) graphIcsEventsWithLock(calendar *fakeCalendar) []*ical.Component {
	ids := make([]string, 0, len(calendar.graphEvents))
	for id := range calendar.graphEvents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	events := []*ical.Component{}
	for _, id := range ids {
		event := calendar.graphEvents[id]
		if event.eventType == "exception" {
			continue
		}
		data, err := fakeGraphIcalEvent(event)
		if err != nil {
			continue
		}
		component := data.Children[0]
		component.Props.SetText(ical.PropSummary, event.subject)
		if event.location != "" {
			component.Props.SetText(ical.PropLocation, event.location)
		}
		events = append(events, component)
	}
	return events
}
