package computetest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"

	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testCalendarCaldavUser     = "alice"
	testCalendarCaldavPassword = "app-password-synthetic"
	testCalendarGoogleUser     = "bob"
	testCalendarGoogleToken    = "google-token-synthetic"
	testCalendarGraphUser      = "carol"
	testCalendarGraphToken     = "graph-token-synthetic"
	testCalendarPersonalPath   = "/dav/alice/calendars/personal/"
)

// A server on a fake clock with a caldav account (alice: personal, and a read-only shared calendar), a google account
// (bob: primary) and a microsoft account (carol: the default calendar).
func newTestCalendarServer(t *testing.T, accountArgs *FakeCalendarAccountArgs) (*FakeCalendarServer, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server, err := NewFakeCalendarServer(&FakeCalendarServerArgs{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	if accountArgs == nil {
		accountArgs = &FakeCalendarAccountArgs{}
	}
	caldavArgs := *accountArgs
	caldavArgs.Protocol = FakeCalendarCaldav
	caldavArgs.Name = testCalendarCaldavUser
	caldavArgs.Password = testCalendarCaldavPassword
	for _, add := range []error{
		server.AddAccount(&caldavArgs),
		server.AddAccount(&FakeCalendarAccountArgs{Protocol: FakeCalendarGoogle, Name: testCalendarGoogleUser}),
		server.AddAccount(&FakeCalendarAccountArgs{Protocol: FakeCalendarMicrosoft, Name: testCalendarGraphUser}),
		server.AddToken(testCalendarGoogleUser, testCalendarGoogleToken, nil),
		server.AddToken(testCalendarGraphUser, testCalendarGraphToken, []string{"Calendars.ReadWrite"}),
	} {
		if add != nil {
			t.Fatal(add)
		}
	}
	for _, calendar := range []struct {
		account string
		args    *FakeCalendarArgs
	}{
		{account: testCalendarCaldavUser, args: &FakeCalendarArgs{Id: "personal", Name: "Personal", TimeZone: "Europe/Berlin"}},
		{account: testCalendarCaldavUser, args: &FakeCalendarArgs{Id: "shared", Name: "Shared", ReadOnly: true}},
		{account: testCalendarGoogleUser, args: &FakeCalendarArgs{Name: "Bob", TimeZone: "Europe/Berlin", Default: true}},
		{account: testCalendarGraphUser, args: &FakeCalendarArgs{Name: "Calendar", Default: true}},
	} {
		if _, err := server.AddCalendar(calendar.account, calendar.args); err != nil {
			t.Fatal(err)
		}
	}
	return server, clock
}

func newTestCaldavClient(t *testing.T, server *FakeCalendarServer, password string) *caldav.Client {
	t.Helper()
	url, err := server.CaldavUrl(testCalendarCaldavUser)
	if err != nil {
		t.Fatal(err)
	}
	client, err := caldav.NewClient(webdav.HTTPClientWithBasicAuth(server.HttpClient(), testCalendarCaldavUser, password), url)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// alice's Basic credentials, as a raw request carries them.
func testCaldavAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testCalendarCaldavUser+":"+testCalendarCaldavPassword))
}

func testIcal(t *testing.T, text string) *ical.Calendar {
	t.Helper()
	data, err := ical.NewDecoder(strings.NewReader(strings.ReplaceAll(text, "\n", "\r\n"))).Decode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testEvent(uid string, summary string, extra string) string {
	return "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//computetest//test//EN\nBEGIN:VEVENT\nUID:" + uid +
		"\nDTSTAMP:20260101T000000Z\nDTSTART:20260105T100000Z\nDTEND:20260105T110000Z\nSUMMARY:" + summary + "\n" + extra +
		"END:VEVENT\nEND:VCALENDAR\n"
}

// A request to a host of the server's, with its body and headers.
func testCalendarDo(t *testing.T, server *FakeCalendarServer, method string, url string, body string, header map[string]string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := server.HttpClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, answer
}

func TestFakeCalDavCreateOnlyPut(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	ctx := context.Background()
	objectPath := testCalendarPersonalPath + "lunch@calendar.example.ics"
	created, err := client.PutCalendarObject(ctx, objectPath, testIcal(t, testEvent("lunch@calendar.example", "Lunch", "")),
		&caldav.PutCalendarObjectOptions{IfNoneMatch: "*"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ETag == "" {
		t.Fatalf("a create answered no ETag")
	}
	// a retry of the same create writes no second copy
	_, err = client.PutCalendarObject(ctx, objectPath, testIcal(t, testEvent("lunch@calendar.example", "Lunch again", "")),
		&caldav.PutCalendarObjectOptions{IfNoneMatch: "*"})
	if err == nil || !strings.Contains(err.Error(), "412") {
		t.Fatalf("a second create-only PUT answered %v, not 412", err)
	}
	objects, err := server.CaldavObjects(testCalendarCaldavUser, "personal")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || !strings.Contains(objects[0].Ics, "SUMMARY:Lunch\r\n") {
		t.Fatalf("objects after the retry: %+v", objects)
	}
	writes := server.Writes()
	if len(writes) != 2 {
		t.Fatalf("%d writes logged, want 2", len(writes))
	}
	if !writes[0].Applied || writes[0].Status != http.StatusCreated || writes[0].IfNoneMatch != "*" || writes[0].Uid != "lunch@calendar.example" {
		t.Errorf("first write %+v", writes[0])
	}
	if writes[1].Applied || writes[1].Status != http.StatusPreconditionFailed || writes[1].IfNoneMatch != "*" ||
		writes[1].RevisionBefore != objects[0].Etag {
		t.Errorf("second write %+v", writes[1])
	}
	// a UID another resource holds is refused, no-uid-conflict
	_, err = client.PutCalendarObject(ctx, testCalendarPersonalPath+"other.ics", testIcal(t, testEvent("lunch@calendar.example", "Clash", "")), nil)
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a second resource with the same UID answered %v", err)
	}
}

func TestFakeCalDavIfMatchConflict(t *testing.T) {
	server, clock := newTestCalendarServer(t, nil)
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	ctx := context.Background()
	objectPath := testCalendarPersonalPath + "review@calendar.example.ics"
	created, err := client.PutCalendarObject(ctx, objectPath, testIcal(t, testEvent("review@calendar.example", "Review", "")),
		&caldav.PutCalendarObjectOptions{IfNoneMatch: "*"})
	if err != nil {
		t.Fatal(err)
	}
	firstEtag := `"` + created.ETag + `"`
	clock.Advance(time.Minute)
	// the event changes meanwhile, by another client
	changed, err := client.PutCalendarObject(ctx, objectPath, testIcal(t, testEvent("review@calendar.example", "Review, moved", "")),
		&caldav.PutCalendarObjectOptions{IfMatch: webdav.ConditionalMatch(firstEtag)})
	if err != nil {
		t.Fatal(err)
	}
	if changed.ETag == created.ETag {
		t.Fatalf("a change kept its ETag")
	}
	// a write on the ETag read before the change answers a conflict and writes nothing
	_, err = client.PutCalendarObject(ctx, objectPath, testIcal(t, testEvent("review@calendar.example", "Review, stale", "")),
		&caldav.PutCalendarObjectOptions{IfMatch: webdav.ConditionalMatch(firstEtag)})
	if err == nil || !strings.Contains(err.Error(), "412") {
		t.Fatalf("a stale If-Match answered %v", err)
	}
	if err := client.RemoveAll(ctx, objectPath, &webdav.RemoveAllOptions{IfMatch: webdav.ConditionalMatch(firstEtag)}); err == nil || !strings.Contains(err.Error(), "412") {
		t.Fatalf("a stale DELETE answered %v", err)
	}
	objects, err := server.CaldavObjects(testCalendarCaldavUser, "personal")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || !strings.Contains(objects[0].Ics, "SUMMARY:Review, moved") {
		t.Fatalf("the stale writes wrote: %+v", objects)
	}
	if err := client.RemoveAll(ctx, objectPath, &webdav.RemoveAllOptions{IfMatch: webdav.ConditionalMatch(`"` + changed.ETag + `"`)}); err != nil {
		t.Fatal(err)
	}
	statuses := []int{}
	for _, write := range server.Writes() {
		statuses = append(statuses, write.Status)
	}
	want := []int{http.StatusCreated, http.StatusNoContent, http.StatusPreconditionFailed, http.StatusPreconditionFailed, http.StatusNoContent}
	if len(statuses) != len(want) {
		t.Fatalf("statuses %v, want %v", statuses, want)
	}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
	}
	if writes := server.Writes(); writes[3].IfMatch != firstEtag || writes[3].Method != http.MethodDelete || writes[3].Applied {
		t.Errorf("the stale DELETE was logged as %+v", writes[3])
	}
}

const testWeeklyIcs = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//computetest//test//EN
BEGIN:VEVENT
UID:weekly@calendar.example
DTSTAMP:20260101T000000Z
DTSTART;TZID=Europe/Berlin:20260105T100000
DTEND;TZID=Europe/Berlin:20260105T110000
RRULE:FREQ=WEEKLY;COUNT=5
EXDATE;TZID=Europe/Berlin:20260112T100000
SUMMARY:Weekly
END:VEVENT
BEGIN:VEVENT
UID:weekly@calendar.example
DTSTAMP:20260101T000000Z
RECURRENCE-ID;TZID=Europe/Berlin:20260119T100000
DTSTART;TZID=Europe/Berlin:20260119T140000
DTEND;TZID=Europe/Berlin:20260119T150000
SUMMARY:Weekly moved
END:VEVENT
END:VCALENDAR
`

func TestFakeCalDavExpandsRecurrences(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	if _, err := server.AddCalendar(testCalendarCaldavUser, &FakeCalendarArgs{Id: "plain", Name: "Plain", NoExpand: true}); err != nil {
		t.Fatal(err)
	}
	for _, calendarId := range []string{"personal", "plain"} {
		if _, err := server.PutCaldavObject(testCalendarCaldavUser, calendarId, "weekly.ics", strings.ReplaceAll(testWeeklyIcs, "\n", "\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	ctx := context.Background()
	query := func(calendarPath string, start time.Time, end time.Time, expand bool) []caldav.CalendarObject {
		t.Helper()
		request := caldav.CalendarCompRequest{Name: ical.CompCalendar, AllProps: true, AllComps: true}
		if expand {
			request.Expand = &caldav.CalendarExpandRequest{Start: start, End: end}
		}
		objects, err := client.QueryCalendar(ctx, calendarPath, &caldav.CalendarQuery{
			CompRequest: request,
			CompFilter: caldav.CompFilter{Name: ical.CompCalendar, Comps: []caldav.CompFilter{
				{Name: ical.CompEvent, Start: start, End: end},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return objects
	}
	january := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	objects := query(testCalendarPersonalPath, january, january.AddDate(0, 2, 0), true)
	if len(objects) != 1 {
		t.Fatalf("%d objects, want 1", len(objects))
	}
	type instance struct {
		start        string
		recurrenceId string
		summary      string
	}
	got := []instance{}
	for _, event := range objects[0].Data.Events() {
		for _, banned := range []string{ical.PropRecurrenceRule, ical.PropExceptionDates, ical.PropRecurrenceDates} {
			if event.Props.Get(banned) != nil {
				t.Fatalf("an expanded instance carries %s", banned)
			}
		}
		summary, _ := event.Props.Text(ical.PropSummary)
		recurrenceId := ""
		if prop := event.Props.Get(ical.PropRecurrenceID); prop != nil {
			recurrenceId = prop.Value
		}
		got = append(got, instance{start: event.Props.Get(ical.PropDateTimeStart).Value, recurrenceId: recurrenceId, summary: summary})
	}
	// five weekly instances from Monday 10:00 in Berlin (09:00 UTC), the second excluded and the third moved to 14:00
	want := []instance{
		{start: "20260105T090000Z", recurrenceId: "20260105T090000Z", summary: "Weekly"},
		{start: "20260119T130000Z", recurrenceId: "20260119T090000Z", summary: "Weekly moved"},
		{start: "20260126T090000Z", recurrenceId: "20260126T090000Z", summary: "Weekly"},
		{start: "20260202T090000Z", recurrenceId: "20260202T090000Z", summary: "Weekly"},
	}
	if len(got) != len(want) {
		t.Fatalf("instances %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("instances %+v, want %+v", got, want)
		}
	}
	// a range holding only the excluded instance matches nothing; one holding the moved instance's new time matches
	excluded := time.Date(2026, time.January, 12, 8, 30, 0, 0, time.UTC)
	if objects := query(testCalendarPersonalPath, excluded, excluded.Add(time.Hour), false); len(objects) != 0 {
		t.Fatalf("the excluded instance matched %d objects", len(objects))
	}
	moved := time.Date(2026, time.January, 19, 13, 30, 0, 0, time.UTC)
	if objects := query(testCalendarPersonalPath, moved, moved.Add(time.Minute), false); len(objects) != 1 {
		t.Fatalf("the moved instance matched %d objects", len(objects))
	}
	// a server that does not expand answers the object whole, its RRULE for the device to expand
	objects = query("/dav/alice/calendars/plain/", january, january.AddDate(0, 2, 0), true)
	if len(objects) != 1 || len(objects[0].Data.Events()) != 2 || objects[0].Data.Events()[0].Props.Get(ical.PropRecurrenceRule) == nil {
		t.Fatalf("a NoExpand calendar answered %+v", objects)
	}
}

func TestFakeCalDavDiscovery(t *testing.T) {
	server, _ := newTestCalendarServer(t, &FakeCalendarAccountArgs{PartitionHost: "p07-caldav.calendar.example"})
	// the well-known redirect answers before authentication
	response, _ := testCalendarDo(t, server, "PROPFIND", "https://"+FakeCalendarCaldavHost+"/.well-known/caldav", "", nil)
	if response.StatusCode != http.StatusMovedPermanently || response.Header.Get("Location") != "/dav/" {
		t.Fatalf("well-known answered %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	ctx := context.Background()
	if _, err := newTestCaldavClient(t, server, "wrong-password").FindCurrentUserPrincipal(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong password answered %v", err)
	}
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	principal, err := client.FindCurrentUserPrincipal(ctx)
	if err != nil || principal != "/dav/alice/" {
		t.Fatalf("principal %q, %v", principal, err)
	}
	homeSet, err := client.FindCalendarHomeSet(ctx, principal)
	if err != nil {
		t.Fatal(err)
	}
	if homeSet != "/dav/alice/calendars/" {
		t.Fatalf("home set %q", homeSet)
	}
	// the home set lives on the partition host, by an absolute href
	_, body := testCalendarDo(t, server, "PROPFIND", "https://"+FakeCalendarCaldavHost+principal,
		`<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/><c:calendar-user-address-set/></d:prop></d:propfind>`,
		map[string]string{"Depth": "0", "Content-Type": "application/xml", "Authorization": testCaldavAuthorization()})
	for _, want := range []string{"https://p07-caldav.calendar.example/dav/alice/calendars/", "mailto:alice@calendar.example"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("the principal's PROPFIND holds no %q:\n%s", want, body)
		}
	}
	partition, err := caldav.NewClient(webdav.HTTPClientWithBasicAuth(server.HttpClient(), testCalendarCaldavUser, testCalendarCaldavPassword),
		"https://p07-caldav.calendar.example/")
	if err != nil {
		t.Fatal(err)
	}
	calendars, err := partition.FindCalendars(ctx, homeSet)
	if err != nil {
		t.Fatal(err)
	}
	if len(calendars) != 2 || calendars[0].Name != "Personal" || calendars[0].ReadOnly || calendars[1].Name != "Shared" || !calendars[1].ReadOnly {
		t.Fatalf("calendars %+v", calendars)
	}
	// the discovery host serves no calendar of an account with a partition host
	if _, err := client.FindCalendars(ctx, homeSet); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("calendars on the discovery host answered %v", err)
	}
}

func TestFakeCalDavReadOnlyNeedsPrivileges(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	response, body := testCalendarDo(t, server, http.MethodPut, "https://"+FakeCalendarCaldavHost+"/dav/alice/calendars/shared/x.ics",
		strings.ReplaceAll(testEvent("x@calendar.example", "X", ""), "\n", "\r\n"),
		map[string]string{"Content-Type": "text/calendar", "Authorization": testCaldavAuthorization()})
	if response.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("need-privileges")) || !bytes.Contains(body, []byte("<d:bind/>")) {
		t.Fatalf("a PUT to a read-only calendar answered %d:\n%s", response.StatusCode, body)
	}
	writes := server.Writes()
	if len(writes) != 1 || writes[0].Applied || writes[0].Status != http.StatusForbidden {
		t.Fatalf("writes %+v", writes)
	}
}

func TestFakeCalDavScheduling(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	ctx := context.Background()
	organized := "ORGANIZER:mailto:alice@calendar.example\nATTENDEE:mailto:dana@calendar.example\n" +
		"ATTENDEE;SCHEDULE-AGENT=CLIENT:mailto:eli@calendar.example\n"
	if _, err := client.PutCalendarObject(ctx, testCalendarPersonalPath+"meet.ics", testIcal(t, testEvent("meet@calendar.example", "Meet", organized)), nil); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveAll(ctx, testCalendarPersonalPath+"meet.ics", nil); err != nil {
		t.Fatal(err)
	}
	invited := "ORGANIZER:mailto:fay@calendar.example\nATTENDEE:mailto:alice@calendar.example\n"
	for _, name := range []string{"invite-one.ics", "invite-two.ics"} {
		uid := strings.TrimSuffix(name, ".ics") + "@calendar.example"
		if _, err := server.PutCaldavObject(testCalendarCaldavUser, "personal", name, strings.ReplaceAll(testEvent(uid, "Invite", invited), "\n", "\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	// removing a received invitation declines it to the organizer, unless Schedule-Reply: F
	authorization := testCaldavAuthorization()
	testCalendarDo(t, server, http.MethodDelete, "https://"+FakeCalendarCaldavHost+testCalendarPersonalPath+"invite-one.ics", "",
		map[string]string{"Authorization": authorization})
	testCalendarDo(t, server, http.MethodDelete, "https://"+FakeCalendarCaldavHost+testCalendarPersonalPath+"invite-two.ics", "",
		map[string]string{"Authorization": authorization, "Schedule-Reply": "F"})
	got := []string{}
	for _, notice := range server.Notices() {
		got = append(got, notice.Method+" "+notice.To+" "+notice.Uid+" "+notice.PartStat)
	}
	want := []string{
		"REQUEST dana@calendar.example meet@calendar.example ",
		"CANCEL dana@calendar.example meet@calendar.example ",
		"REPLY fay@calendar.example invite-one@calendar.example DECLINED",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("notices:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFakeCalDavSharingReported(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	for dialect, want := range map[FakeCalendarSharingDialect][]string{
		FakeCalendarSharingNextcloud: {"<oc:invite><oc:user><d:href>mailto:gus@calendar.example</d:href>", "<oc:read-write/>", "<cs:publish-url><d:href>https://cloud.calendar.example/public/x</d:href>"},
		FakeCalendarSharingIcloud:    {"<cs:invite><cs:organizer>", "<cs:user><d:href>mailto:gus@calendar.example</d:href>", "<cs:read-write/>"},
	} {
		if err := server.SetSharing(testCalendarCaldavUser, "personal", &FakeCalendarSharing{
			Dialect:    dialect,
			Sharees:    []*FakeCalendarSharee{{Href: "mailto:gus@calendar.example", CommonName: "Gus", ReadWrite: true, Accepted: true}},
			PublishUrl: "https://cloud.calendar.example/public/x",
		}); err != nil {
			t.Fatal(err)
		}
		_, body := testCalendarDo(t, server, "PROPFIND", "https://"+FakeCalendarCaldavHost+testCalendarPersonalPath,
			// the namespaces from the front's own constants: their URIs are identifiers, never hosts reached
			`<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:cs="`+fakeCalendarServerNs+`" xmlns:oc="`+fakeOwncloudNamespace+
				`"><d:prop><oc:invite/><cs:invite/><cs:publish-url/><d:current-user-privilege-set/></d:prop></d:propfind>`,
			map[string]string{"Depth": "0", "Content-Type": "application/xml", "Authorization": testCaldavAuthorization()})
		for _, fragment := range want {
			if !bytes.Contains(body, []byte(fragment)) {
				t.Fatalf("%s: no %q in:\n%s", dialect, fragment, body)
			}
		}
	}
}

func TestFakeIcsConditionalGet(t *testing.T) {
	server, clock := newTestCalendarServer(t, nil)
	if _, err := server.PutCaldavObject(testCalendarCaldavUser, "personal", "a.ics", strings.ReplaceAll(testEvent("a@calendar.example", "A", ""), "\n", "\r\n")); err != nil {
		t.Fatal(err)
	}
	feed, err := server.AddIcsFeed(&FakeIcsFeedArgs{Account: testCalendarCaldavUser, Calendar: "personal"})
	if err != nil {
		t.Fatal(err)
	}
	response, body := testCalendarDo(t, server, http.MethodGet, feed.Url(), "", nil)
	etag := response.Header.Get("ETag")
	if response.StatusCode != http.StatusOK || etag == "" || !bytes.Contains(body, []byte("SUMMARY:A")) || !bytes.Contains(body, []byte("X-WR-CALNAME:Personal")) {
		t.Fatalf("the feed answered %d %q:\n%s", response.StatusCode, etag, body)
	}
	if response, _ := testCalendarDo(t, server, http.MethodGet, feed.Url(), "", map[string]string{"If-None-Match": etag}); response.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match answered %d", response.StatusCode)
	}
	lastModified := response.Header.Get("Last-Modified")
	if response, _ := testCalendarDo(t, server, http.MethodGet, feed.Url(), "", map[string]string{"If-Modified-Since": lastModified}); response.StatusCode != http.StatusNotModified {
		t.Fatalf("If-Modified-Since answered %d", response.StatusCode)
	}
	clock.Advance(time.Hour)
	if _, err := server.PutCaldavObject(testCalendarCaldavUser, "personal", "b.ics", strings.ReplaceAll(testEvent("b@calendar.example", "B", ""), "\n", "\r\n")); err != nil {
		t.Fatal(err)
	}
	response, body = testCalendarDo(t, server, http.MethodGet, feed.Url(), "", map[string]string{"If-None-Match": etag})
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") == etag || !bytes.Contains(body, []byte("SUMMARY:B")) {
		t.Fatalf("a changed feed answered %d", response.StatusCode)
	}
	oldUrl := feed.Url()
	feed.Reset()
	if response, _ := testCalendarDo(t, server, http.MethodGet, oldUrl, "", nil); response.StatusCode != http.StatusNotFound {
		t.Fatalf("a reset address answered %d", response.StatusCode)
	}
}

// A request to Google's front with bob's token.
func testGoogleDo(t *testing.T, server *FakeCalendarServer, method string, path string, body string, header map[string]string) (*http.Response, []byte) {
	t.Helper()
	merged := map[string]string{"Authorization": "Bearer " + testCalendarGoogleToken, "Content-Type": "application/json"}
	for name, value := range header {
		merged[name] = value
	}
	return testCalendarDo(t, server, method, server.GoogleApiBase()+path, body, merged)
}

func testGoogleReason(t *testing.T, body []byte) string {
	t.Helper()
	var answer struct {
		Error struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || len(answer.Error.Errors) != 1 {
		t.Fatalf("not Google's error form: %s", body)
	}
	return answer.Error.Errors[0].Reason
}

func TestFakeGoogleInsertIsIdempotentByClientId(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	clientId := "0123456789abcdefghijklmnopqrstuv"
	event := `{"id": "` + clientId + `", "summary": "Standup", "start": {"dateTime": "2026-01-05T10:00:00+01:00"}, "end": {"dateTime": "2026-01-05T10:15:00+01:00"}}`
	response, body := testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events", event, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("insert answered %d: %s", response.StatusCode, body)
	}
	var inserted struct {
		Id   string `json:"id"`
		Etag string `json:"etag"`
	}
	if err := json.Unmarshal(body, &inserted); err != nil || inserted.Id != clientId || inserted.Etag == "" {
		t.Fatalf("insert answered %s", body)
	}
	// the retried insert finds the id taken and writes nothing
	response, body = testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events", event, nil)
	if response.StatusCode != http.StatusConflict || testGoogleReason(t, body) != "duplicate" {
		t.Fatalf("a retried insert answered %d: %s", response.StatusCode, body)
	}
	response, body = testGoogleDo(t, server, http.MethodGet, "/calendars/primary/events?timeMin=2026-01-01T00:00:00Z&timeMax=2026-02-01T00:00:00Z", "", nil)
	if response.StatusCode != http.StatusOK || strings.Count(string(body), `"id":"`+clientId+`"`) != 1 {
		t.Fatalf("list answered %d: %s", response.StatusCode, body)
	}
	// an id outside base32hex is refused, and a removed event's id stays taken
	invalid := strings.Replace(event, clientId, "0123456789ABCDEF", 1)
	if response, body := testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events", invalid, nil); response.StatusCode != http.StatusBadRequest || testGoogleReason(t, body) != "invalid" {
		t.Fatalf("an invalid id answered %d", response.StatusCode)
	}
	if response, _ := testGoogleDo(t, server, http.MethodDelete, "/calendars/primary/events/"+clientId, "", nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete answered %d", response.StatusCode)
	}
	if response, body := testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events", event, nil); response.StatusCode != http.StatusConflict || testGoogleReason(t, body) != "duplicate" {
		t.Fatalf("an insert on a removed event's id answered %d", response.StatusCode)
	}
	applied := 0
	for _, write := range server.Writes() {
		if write.Method == http.MethodPost && write.Applied {
			applied += 1
		}
	}
	if applied != 1 {
		t.Fatalf("%d inserts applied, want 1", applied)
	}
}

func TestFakeGooglePreconditionsAndRateLimits(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	attendees := `"attendees": [{"email": "dana@calendar.example"}]`
	_, body := testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events?sendUpdates=all",
		`{"summary": "Plan", "start": {"dateTime": "2026-01-06T09:00:00Z"}, "end": {"dateTime": "2026-01-06T10:00:00Z"}, `+attendees+`}`, nil)
	var inserted struct {
		Id   string `json:"id"`
		Etag string `json:"etag"`
	}
	if err := json.Unmarshal(body, &inserted); err != nil {
		t.Fatal(err)
	}
	patched, body := testGoogleDo(t, server, http.MethodPatch, "/calendars/primary/events/"+inserted.Id, `{"summary": "Plan B"}`, map[string]string{"If-Match": inserted.Etag})
	if patched.StatusCode != http.StatusOK {
		t.Fatalf("patch answered %d: %s", patched.StatusCode, body)
	}
	// the etag read before that change is refused, 412, and nothing is written
	stale, body := testGoogleDo(t, server, http.MethodPatch, "/calendars/primary/events/"+inserted.Id, `{"summary": "Plan C"}`, map[string]string{"If-Match": inserted.Etag})
	if stale.StatusCode != http.StatusPreconditionFailed || testGoogleReason(t, body) != "conditionNotMet" {
		t.Fatalf("a stale patch answered %d: %s", stale.StatusCode, body)
	}
	// Google's 403 rate limit, as Google words it, writes nothing
	server.FailNext(&FakeCalendarFailure{Protocol: FakeCalendarGoogle, Status: http.StatusForbidden, Reason: "rateLimitExceeded"})
	limited, body := testGoogleDo(t, server, http.MethodDelete, "/calendars/primary/events/"+inserted.Id, "", nil)
	if limited.StatusCode != http.StatusForbidden || testGoogleReason(t, body) != "rateLimitExceeded" || !bytes.Contains(body, []byte(`"usageLimits"`)) {
		t.Fatalf("a rate limit answered %d: %s", limited.StatusCode, body)
	}
	if response, _ := testGoogleDo(t, server, http.MethodDelete, "/calendars/primary/events/"+inserted.Id+"?sendUpdates=all", "", nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete answered %d", response.StatusCode)
	}
	again, body := testGoogleDo(t, server, http.MethodDelete, "/calendars/primary/events/"+inserted.Id, "", nil)
	if again.StatusCode != http.StatusGone || testGoogleReason(t, body) != "deleted" {
		t.Fatalf("a second delete answered %d: %s", again.StatusCode, body)
	}
	// a removed event is still read, cancelled
	_, body = testGoogleDo(t, server, http.MethodGet, "/calendars/primary/events/"+inserted.Id, "", nil)
	if !bytes.Contains(body, []byte(`"status":"cancelled"`)) {
		t.Fatalf("get of a removed event answered %s", body)
	}
	methods := []string{}
	for _, notice := range server.Notices() {
		methods = append(methods, notice.Method+" "+notice.To)
	}
	want := "REQUEST dana@calendar.example\nCANCEL dana@calendar.example"
	if strings.Join(methods, "\n") != want {
		t.Fatalf("notices %q, want %q", methods, want)
	}
	// no token, or another account's, is no credential here
	if response, body := testCalendarDo(t, server, http.MethodGet, server.GoogleApiBase()+"/calendars/primary/events", "",
		map[string]string{"Authorization": "Bearer " + testCalendarGraphToken}); response.StatusCode != http.StatusUnauthorized || testGoogleReason(t, body) != "authError" {
		t.Fatalf("another front's token answered %d", response.StatusCode)
	}
}

func TestFakeGoogleSingleEventsExpands(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	_, body := testGoogleDo(t, server, http.MethodPost, "/calendars/primary/events",
		`{"summary": "Daily", "start": {"dateTime": "2026-01-05T09:00:00", "timeZone": "Europe/Berlin"}, "end": {"dateTime": "2026-01-05T09:30:00", "timeZone": "Europe/Berlin"}, "recurrence": ["RRULE:FREQ=DAILY;COUNT=3"]}`, nil)
	var master struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(body, &master); err != nil || master.Id == "" {
		t.Fatalf("insert answered %s", body)
	}
	instanceId := master.Id + "_20260106T080000Z"
	if response, body := testGoogleDo(t, server, http.MethodPatch, "/calendars/primary/events/"+instanceId, `{"summary": "Daily, changed"}`, nil); response.StatusCode != http.StatusOK {
		t.Fatalf("an instance's patch answered %d: %s", response.StatusCode, body)
	}
	_, body = testGoogleDo(t, server, http.MethodGet, "/calendars/primary/events?singleEvents=true&orderBy=startTime&timeMin=2026-01-01T00:00:00Z&timeMax=2026-01-31T00:00:00Z", "", nil)
	var list struct {
		Items []struct {
			Id               string `json:"id"`
			Summary          string `json:"summary"`
			RecurringEventId string `json:"recurringEventId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, item := range list.Items {
		got = append(got, item.Id+" "+item.Summary)
		if item.RecurringEventId != master.Id {
			t.Fatalf("an instance with recurringEventId %q", item.RecurringEventId)
		}
	}
	want := []string{master.Id + "_20260105T080000Z Daily", instanceId + " Daily, changed", master.Id + "_20260107T080000Z Daily"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if response, body := testGoogleDo(t, server, http.MethodGet, "/calendars/primary/events?orderBy=startTime", "", nil); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("orderBy=startTime without singleEvents answered %d: %s", response.StatusCode, body)
	}
}

// A request to Graph's front with carol's token.
func testGraphDo(t *testing.T, server *FakeCalendarServer, method string, path string, body string, header map[string]string) (*http.Response, []byte) {
	t.Helper()
	merged := map[string]string{"Authorization": "Bearer " + testCalendarGraphToken, "Content-Type": "application/json"}
	for name, value := range header {
		merged[name] = value
	}
	return testCalendarDo(t, server, method, server.GraphApiBase()+path, body, merged)
}

func TestFakeGraphTransactionId(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	immutable := map[string]string{"Prefer": `IdType="ImmutableId"`}
	event := `{"subject": "Sync", "start": {"dateTime": "2026-01-07T15:00:00", "timeZone": "UTC"}, "end": {"dateTime": "2026-01-07T15:30:00", "timeZone": "UTC"}, "transactionId": "tx-0001"}`
	response, body := testGraphDo(t, server, http.MethodPost, "/me/events", event, immutable)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create answered %d: %s", response.StatusCode, body)
	}
	var created struct {
		Id            string `json:"id"`
		ChangeKey     string `json:"changeKey"`
		TransactionId string `json:"transactionId"`
	}
	if err := json.Unmarshal(body, &created); err != nil || !strings.HasPrefix(created.Id, fakeGraphImmutablePrefix) || created.TransactionId != "tx-0001" {
		t.Fatalf("create answered %s", body)
	}
	// the retried create answers the event the transactionId made, and creates nothing
	response, body = testGraphDo(t, server, http.MethodPost, "/me/events", event, immutable)
	var retried struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(body, &retried); err != nil || response.StatusCode != http.StatusCreated || retried.Id != created.Id {
		t.Fatalf("a retried create answered %d: %s", response.StatusCode, body)
	}
	if count := server.GraphEventCount(testCalendarGraphUser, ""); count != 1 {
		t.Fatalf("%d events after the retry, want 1", count)
	}
	writes := server.Writes()
	if len(writes) != 2 || !writes[0].Applied || writes[1].Applied || writes[1].TransactionId != "tx-0001" {
		t.Fatalf("writes %+v", writes)
	}
	// without the Prefer header the default form answers, and both forms reach the event
	_, body = testGraphDo(t, server, http.MethodGet, "/me/events/"+created.Id, "", nil)
	var defaultForm struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(body, &defaultForm); err != nil || !strings.HasPrefix(defaultForm.Id, fakeGraphDefaultPrefix) {
		t.Fatalf("get answered %s", body)
	}
	if response, _ := testGraphDo(t, server, http.MethodGet, "/me/events/"+defaultForm.Id, "", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("the default id answered %d", response.StatusCode)
	}
	// Graph documents no conditional write on events: a stale If-Match changes nothing about the patch
	response, body = testGraphDo(t, server, http.MethodPatch, "/me/events/"+created.Id, `{"subject": "Sync, moved"}`, map[string]string{"If-Match": `W/"stale"`})
	var patched struct {
		ChangeKey string `json:"changeKey"`
	}
	if err := json.Unmarshal(body, &patched); err != nil || response.StatusCode != http.StatusOK || patched.ChangeKey == created.ChangeKey {
		t.Fatalf("patch answered %d: %s", response.StatusCode, body)
	}
}

func TestFakeGraphCalendarViewOccurrences(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	immutable := map[string]string{"Prefer": `IdType="ImmutableId"`}
	_, body := testGraphDo(t, server, http.MethodPost, "/me/events",
		`{"subject": "Weekly", "start": {"dateTime": "2026-01-05T09:00:00", "timeZone": "UTC"}, "end": {"dateTime": "2026-01-05T10:00:00", "timeZone": "UTC"},
		  "attendees": [{"emailAddress": {"address": "dana@calendar.example"}, "type": "required"}],
		  "recurrence": {"pattern": {"type": "weekly", "interval": 1, "daysOfWeek": ["monday"]}, "range": {"type": "numbered", "startDate": "2026-01-05", "numberOfOccurrences": 4}}}`,
		immutable)
	var master struct {
		Id   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &master); err != nil || master.Type != "seriesMaster" {
		t.Fatalf("create answered %s", body)
	}
	view := func() []string {
		_, body := testGraphDo(t, server, http.MethodGet, "/me/calendarView?startDateTime=2026-01-01T00:00:00Z&endDateTime=2026-02-28T00:00:00Z", "", immutable)
		var answer struct {
			Value []struct {
				Id      string `json:"id"`
				Type    string `json:"type"`
				Subject string `json:"subject"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &answer); err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, event := range answer.Value {
			got = append(got, event.Type+" "+event.Subject)
		}
		return got
	}
	if got := view(); strings.Join(got, ",") != "occurrence Weekly,occurrence Weekly,occurrence Weekly,occurrence Weekly" {
		t.Fatalf("view %q", got)
	}
	second := fakeGraphOccurrenceId(master.Id, time.Date(2026, time.January, 12, 9, 0, 0, 0, time.UTC))
	third := fakeGraphOccurrenceId(master.Id, time.Date(2026, time.January, 19, 9, 0, 0, 0, time.UTC))
	if response, body := testGraphDo(t, server, http.MethodDelete, "/me/events/"+second, "", nil); response.StatusCode != http.StatusNoContent {
		t.Fatalf("an occurrence's delete answered %d: %s", response.StatusCode, body)
	}
	if response, body := testGraphDo(t, server, http.MethodPatch, "/me/events/"+third, `{"subject": "Weekly, changed"}`, nil); response.StatusCode != http.StatusOK {
		t.Fatalf("an occurrence's patch answered %d: %s", response.StatusCode, body)
	}
	if got := view(); strings.Join(got, "|") != "occurrence Weekly|exception Weekly, changed|occurrence Weekly" {
		t.Fatalf("view after the changes %q", got)
	}
	methods := []string{}
	for _, notice := range server.Notices() {
		methods = append(methods, notice.Method)
	}
	if strings.Join(methods, ",") != "REQUEST,CANCEL,REQUEST" {
		t.Fatalf("notices %q", methods)
	}
	if response, _ := testGraphDo(t, server, http.MethodGet, "/me/calendarView", "", nil); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("a view with no window answered %d", response.StatusCode)
	}
}

func TestFakeCalendarStopsAfterApplying(t *testing.T) {
	server, _ := newTestCalendarServer(t, nil)
	client := newTestCaldavClient(t, server, testCalendarCaldavPassword)
	ctx := context.Background()
	// the stop holds a CalDAV create once the server has stored it, and drops its answer
	stop := server.StopAfterApplying(&FakeCalendarStopMatch{Protocol: FakeCalendarCaldav, Uid: "index-0@calendar.example"})
	putDone := make(chan error, 1)
	go func() {
		_, err := client.PutCalendarObject(ctx, testCalendarPersonalPath+"index-0.ics", testIcal(t, testEvent("index-0@calendar.example", "Index 0", "")),
			&caldav.PutCalendarObjectOptions{IfNoneMatch: "*"})
		putDone <- err
	}()
	select {
	case <-stop.Reached():
	case err := <-putDone:
		t.Fatalf("the PUT ended before the stop: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatalf("the stop was never reached")
	}
	if write := stop.Write(); write == nil || !write.Applied || write.Uid != "index-0@calendar.example" {
		t.Fatalf("the stop holds %+v", write)
	}
	objects, err := server.CaldavObjects(testCalendarCaldavUser, "personal")
	if err != nil || len(objects) != 1 {
		t.Fatalf("the held write is not stored: %v %+v", err, objects)
	}
	stop.Drop()
	select {
	case err := <-putDone:
		if err == nil {
			t.Fatalf("a dropped answer reached the client")
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the dropped PUT never ended")
	}
	// recovery's read finds the write applied, and a second create-only PUT keeps one copy
	if _, err := client.GetCalendarObject(ctx, testCalendarPersonalPath+"index-0.ics"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutCalendarObject(ctx, testCalendarPersonalPath+"index-0.ics", testIcal(t, testEvent("index-0@calendar.example", "Index 0", "")),
		&caldav.PutCalendarObjectOptions{IfNoneMatch: "*"}); err == nil || !strings.Contains(err.Error(), "412") {
		t.Fatalf("the resend answered %v", err)
	}
	// a released stop lets its answer go
	released := server.StopAfterApplying(&FakeCalendarStopMatch{Protocol: FakeCalendarGoogle, Method: http.MethodPost})
	insertDone := make(chan int, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, server.GoogleApiBase()+"/calendars/primary/events",
			strings.NewReader(`{"id": "abcdefghij", "summary": "Held", "start": {"date": "2026-01-08"}, "end": {"date": "2026-01-09"}}`))
		request.Header.Set("Authorization", "Bearer "+testCalendarGoogleToken)
		response, err := server.HttpClient().Do(request)
		if err != nil {
			insertDone <- 0
			return
		}
		response.Body.Close()
		insertDone <- response.StatusCode
	}()
	select {
	case <-released.Reached():
	case <-time.After(30 * time.Second):
		t.Fatalf("the Google stop was never reached")
	}
	if _, ok := server.GoogleEvent(testCalendarGoogleUser, "primary", "abcdefghij"); !ok {
		t.Fatalf("the held insert is not stored")
	}
	released.Release()
	select {
	case status := <-insertDone:
		if status != http.StatusOK {
			t.Fatalf("the released insert answered %d", status)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the released insert never ended")
	}
	// a Graph create dropped after applying: the retry with its transactionId creates nothing more
	dropped := server.StopAfterApplying(&FakeCalendarStopMatch{Protocol: FakeCalendarMicrosoft})
	createDone := make(chan error, 1)
	event := `{"subject": "Once", "start": {"dateTime": "2026-01-09T08:00:00", "timeZone": "UTC"}, "end": {"dateTime": "2026-01-09T09:00:00", "timeZone": "UTC"}, "transactionId": "tx-held"}`
	go func() {
		request, _ := http.NewRequest(http.MethodPost, server.GraphApiBase()+"/me/events", strings.NewReader(event))
		request.Header.Set("Authorization", "Bearer "+testCalendarGraphToken)
		response, err := server.HttpClient().Do(request)
		if err == nil {
			response.Body.Close()
		}
		createDone <- err
	}()
	select {
	case <-dropped.Reached():
	case <-time.After(30 * time.Second):
		t.Fatalf("the Graph stop was never reached")
	}
	dropped.Drop()
	select {
	case err := <-createDone:
		if err == nil {
			t.Fatalf("a dropped Graph answer reached the client")
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the dropped create never ended")
	}
	if response, _ := testGraphDo(t, server, http.MethodPost, "/me/events", event, nil); response.StatusCode != http.StatusCreated {
		t.Fatalf("the retried create answered %d", response.StatusCode)
	}
	if count := server.GraphEventCount(testCalendarGraphUser, ""); count != 1 {
		t.Fatalf("%d Graph events after the retry, want 1", count)
	}
}
