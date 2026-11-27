// FakeCalendarServer's CalDAV front (RFC 4791, RFC 6638, RFC 6764): go-webdav's caldav.Handler over the fake's store
// serves REPORT (calendar-query, calendar-multiget), GET, HEAD, PUT and DELETE, and the front serves beside it what
// go-webdav's server leaves out:
//
//	discovery   /.well-known/caldav redirects to /dav/ before any authentication, by the account's status (301, as
//	            Nextcloud answers, unless its args say otherwise); PROPFIND answers current-user-principal on the root,
//	            and on the principal calendar-home-set (an absolute URL on the partition host where the account has
//	            one, as iCloud's), calendar-user-address-set and principal-URL
//	collections PROPFIND at depth 0 and 1 (infinity refused, propfind-finite-depth) answers each calendar's
//	            resourcetype, displayname, description, calendar-timezone (a VTIMEZONE built from Go's zone over the
//	            clock's year), supported component set and data, current-user-privilege-set (read alone for a read-only
//	            calendar, RFC 3744), owner, getctag and sync-token, max-resource-size, and its sharing and publishing:
//	            owncloud's invite (Nextcloud) or calendarserver's invite (iCloud), and calendarserver's publish-url;
//	            members' getetag, getcontenttype, getcontentlength and getlastmodified at depth 1
//	reads       REPORT's comp-filter time ranges matched by RFC 4791 §9.9 over each object's instances, overrides and
//	            EXDATEs applied; a calendar-data expand (§9.6.5), which go-webdav's server does not pass on, read here
//	            and answered as one VEVENT per instance in UTC with its RECURRENCE-ID and no recurrence properties,
//	            unless the calendar is NoExpand
//	writes      PUT's If-None-Match: * refuses a resource that exists, and PUT's and DELETE's If-Match an ETag that is
//	            not the resource's, 412 each; a new resource whose UID another holds, no-uid-conflict; data go-ical
//	            cannot read or write, or a component other than VEVENT, valid-calendar-object-resource and
//	            supported-calendar-component; a read-only calendar, 403 need-privileges; a replacing PUT answers 204 and
//	            a creating one 201
//	scheduling  RFC 6638 with the server as agent: a PUT the account organizes mails REQUEST to each attendee whose
//	            SCHEDULE-AGENT is the server's, and CANCEL to one an update removed; a DELETE it organizes, CANCEL; a
//	            DELETE of an event the account attends, a REPLY declining to the organizer unless Schedule-Reply: F
//	            (§8.1); each recorded as a notice. The stored data is kept as written, with no SCHEDULE-STATUS, so a PUT's
//	            ETag stays the resource's (a reading).
//
// Paths: /dav/<account>/ is the principal, /dav/<account>/calendars/ its home set, /dav/<account>/calendars/<id>/ a
// calendar and /dav/<account>/calendars/<id>/<name> an object, the layout go-webdav's server reads paths by. Every
// request but the well-known redirect authenticates by Basic; a path of another account answers 403, and a calendar
// path on an account's discovery host 404 where it has a partition host. MKCALENDAR, MKCOL, PROPPATCH, COPY, MOVE and
// sync-collection are not served (ErrFakeCalendarUnserved).

package computetest

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
)

// XML namespaces and their prefixes in the front's own answers (identifiers).
const (
	fakeDavNamespace          = "DAV:"
	fakeCaldavNamespace       = "urn:ietf:params:xml:ns:caldav"
	fakeCalendarServerNs      = "http://calendarserver.org/ns/"
	fakeOwncloudNamespace     = "http://owncloud.org/ns"
	fakeAppleIcalNamespace    = "http://apple.com/ns/ical/"
	fakeCaldavPathPrefix      = "/dav"
	fakeCaldavHomeSegment     = "calendars"
	fakeCaldavProductId       = "-//urnetwork//computetest fake calendar//EN"
	fakeCaldavRealm           = "computetest calendar"
	fakeCaldavSyncTokenPrefix = "data:,computetest-sync-"
)

var fakeDavPrefixes = map[string]string{
	fakeDavNamespace:       "d",
	fakeCaldavNamespace:    "c",
	fakeCalendarServerNs:   "cs",
	fakeOwncloudNamespace:  "oc",
	fakeAppleIcalNamespace: "ic",
}

// What a CalDAV path names.
type fakeCaldavPathKind int

const (
	fakeCaldavPathUnknown fakeCaldavPathKind = iota
	fakeCaldavPathRoot
	fakeCaldavPathPrincipal
	fakeCaldavPathHome
	fakeCaldavPathCalendar
	fakeCaldavPathObject
)

type fakeCaldavPath struct {
	kind     fakeCaldavPathKind
	account  string
	calendar string
	name     string
}

func fakeCaldavParsePath(requestPath string) *fakeCaldavPath {
	cleaned := path.Clean("/" + requestPath)
	if cleaned == "/" || cleaned == fakeCaldavPathPrefix {
		return &fakeCaldavPath{kind: fakeCaldavPathRoot}
	}
	rest, ok := strings.CutPrefix(cleaned, fakeCaldavPathPrefix+"/")
	if !ok {
		return &fakeCaldavPath{kind: fakeCaldavPathUnknown}
	}
	segments := strings.Split(rest, "/")
	parsed := &fakeCaldavPath{account: segments[0]}
	switch {
	case len(segments) == 1:
		parsed.kind = fakeCaldavPathPrincipal
	case segments[1] != fakeCaldavHomeSegment:
		parsed.kind = fakeCaldavPathUnknown
	case len(segments) == 2:
		parsed.kind = fakeCaldavPathHome
	case len(segments) == 3:
		parsed.kind = fakeCaldavPathCalendar
		parsed.calendar = segments[2]
	case len(segments) == 4:
		parsed.kind = fakeCaldavPathObject
		parsed.calendar = segments[2]
		parsed.name = segments[3]
	default:
		parsed.kind = fakeCaldavPathUnknown
	}
	return parsed
}

func fakeCaldavPrincipalPath(account string) string {
	return fakeCaldavPathPrefix + "/" + account + "/"
}

func fakeCaldavHomePath(account string) string {
	return fakeCaldavPathPrefix + "/" + account + "/" + fakeCaldavHomeSegment + "/"
}

func fakeCaldavCalendarPath(account string, calendarId string) string {
	return fakeCaldavHomePath(account) + calendarId + "/"
}

// One CalDAV object as stored: the data as written, re-encoded by go-ical so a GET's length is its bytes'.
type fakeCaldavObject struct {
	name     string
	uid      string
	data     *ical.Calendar
	encoded  []byte
	etag     string
	modified time.Time
}

// The ETag header's form of an ETag.
func fakeCaldavQuoted(etag string) string {
	if etag == "" {
		return ""
	}
	return `"` + etag + `"`
}

// The CalDAV front (see the file header).
func (self *FakeCalendarServer) serveCaldav(w *fakeCalendarWriter, r *http.Request) {
	exchange := fakeCalendarExchangeOf(r.Context())
	host := strings.ToLower(r.Host)
	if splitHost, _, ok := strings.Cut(host, ":"); ok {
		host = splitHost
	}
	if r.URL.Path == "/.well-known/caldav" {
		status := http.StatusMovedPermanently
		location := fakeCaldavPathPrefix + "/"
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, account := range self.accounts {
				if account.args.Protocol == FakeCalendarCaldav && (account.args.Host == host || account.args.PartitionHost == host) {
					status = account.args.WellKnownStatus
					if account.args.WellKnownLocation != "" {
						location = account.args.WellKnownLocation
					}
					return
				}
			}
		}()
		w.Header().Set("Location", location)
		w.WriteHeader(status)
		return
	}
	accountArgs, ok := self.caldavAuthenticate(r, host)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+fakeCaldavRealm+`", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	exchange.account = accountArgs.Name
	parsed := fakeCaldavParsePath(r.URL.Path)
	switch {
	case parsed.kind == fakeCaldavPathUnknown:
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	case parsed.kind != fakeCaldavPathRoot && parsed.account != accountArgs.Name:
		fakeDavNeedPrivileges(w, r.URL.Path, "read")
		return
	case parsed.kind >= fakeCaldavPathHome && accountArgs.PartitionHost != "" && host != accountArgs.PartitionHost:
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("DAV", "1, 3, access-control, calendar-access, calendar-auto-schedule")
		w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, GET, HEAD, PUT, DELETE")
		w.WriteHeader(http.StatusOK)
	case "PROPFIND":
		self.caldavPropfind(w, r, accountArgs, parsed, host)
	case "REPORT":
		if parsed.kind != fakeCaldavPathCalendar {
			http.Error(w, "computetest: the fake answers REPORT on a calendar alone", http.StatusForbidden)
			return
		}
		body, err := fakeCalendarReadBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		window, err := fakeCaldavExpandWindow(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		exchange.expand = window
		r.Body = readCloser{Reader: bytes.NewReader(body)}
		self.caldavHandler().ServeHTTP(w, r)
	case http.MethodGet, http.MethodHead:
		if parsed.kind != fakeCaldavPathObject {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		self.caldavHandler().ServeHTTP(w, r)
	case http.MethodPut, http.MethodDelete:
		if parsed.kind != fakeCaldavPathObject {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := fakeCalendarReadBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = readCloser{Reader: bytes.NewReader(body)}
		exchange.ifMatch = r.Header.Get("If-Match")
		exchange.scheduleReply = r.Header.Get("Schedule-Reply")
		if refused := self.caldavRefuseWrite(w, r, parsed, body); refused {
			return
		}
		self.caldavHandler().ServeHTTP(w, r)
		if !exchange.writeLogged {
			// refused by go-webdav's own checks (a Content-Type, data it cannot decode) before the store saw it
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.logWriteWithLock(exchange, &FakeCalendarWrite{
				Protocol:      FakeCalendarCaldav,
				Method:        r.Method,
				Account:       parsed.account,
				Calendar:      parsed.calendar,
				Resource:      parsed.name,
				IfNoneMatch:   r.Header.Get("If-None-Match"),
				IfMatch:       r.Header.Get("If-Match"),
				ScheduleReply: r.Header.Get("Schedule-Reply"),
				Status:        w.status,
				Body:          slices.Clone(body),
			})
		}
	default:
		http.Error(w, fmt.Sprintf("%v: %s", ErrFakeCalendarUnserved, r.Method), http.StatusNotImplemented)
	}
}

type readCloser struct {
	*bytes.Reader
}

func (self readCloser) Close() error {
	return nil
}

func (self *FakeCalendarServer) caldavHandler() http.Handler {
	return &caldav.Handler{Backend: &fakeCaldavBackend{server: self}, Prefix: fakeCaldavPathPrefix}
}

// The account Basic authentication names, on one of its own hosts.
func (self *FakeCalendarServer) caldavAuthenticate(r *http.Request, host string) (*FakeCalendarAccountArgs, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	account, ok := self.accounts[username]
	if !ok || account.args.Protocol != FakeCalendarCaldav || account.args.Password != password ||
		(account.args.Host != host && account.args.PartitionHost != host) {
		return nil, false
	}
	args := account.args
	return &args, true
}

// A write the front refuses before go-webdav sees it: a missing calendar, or a read-only one (403 need-privileges),
// logged as refused.
func (self *FakeCalendarServer) caldavRefuseWrite(w http.ResponseWriter, r *http.Request, parsed *fakeCaldavPath, body []byte) bool {
	status := 0
	privilege := ""
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		calendar, ok := self.calendars[fakeCalendarKey(parsed.account, parsed.calendar)]
		if !ok {
			status = http.StatusConflict
			if r.Method == http.MethodDelete {
				status = http.StatusNotFound
			}
		} else if calendar.args.ReadOnly {
			status = http.StatusForbidden
			_, exists := calendar.objects[parsed.name]
			switch {
			case r.Method == http.MethodDelete:
				privilege = "unbind"
			case exists:
				privilege = "write-content"
			default:
				privilege = "bind"
			}
		}
		if status == 0 {
			return
		}
		self.logWriteWithLock(fakeCalendarExchangeOf(r.Context()), &FakeCalendarWrite{
			Protocol:      FakeCalendarCaldav,
			Method:        r.Method,
			Account:       parsed.account,
			Calendar:      parsed.calendar,
			Resource:      parsed.name,
			IfNoneMatch:   r.Header.Get("If-None-Match"),
			IfMatch:       r.Header.Get("If-Match"),
			ScheduleReply: r.Header.Get("Schedule-Reply"),
			Status:        status,
			Body:          slices.Clone(body),
		})
	}()
	switch status {
	case 0:
		return false
	case http.StatusForbidden:
		fakeDavNeedPrivileges(w, r.URL.Path, privilege)
	default:
		http.Error(w, http.StatusText(status), status)
	}
	return true
}

// RFC 3744 §7.1.1's 403: the resource and the privilege it lacks.
func fakeDavNeedPrivileges(w http.ResponseWriter, href string, privilege string) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+
		`<d:error xmlns:d="DAV:"><d:need-privileges><d:resource><d:href>%s</d:href><d:privilege><d:%s/></d:privilege></d:resource></d:need-privileges></d:error>`,
		fakeXmlText(href), privilege)
}

// A REPORT body's calendar-data expand window (RFC 4791 §9.6.5), or nil without one.
func fakeCaldavExpandWindow(body []byte) (*fakeCalendarWindow, error) {
	type expandElement struct {
		Start string `xml:"start,attr"`
		End   string `xml:"end,attr"`
	}
	type calendarDataElement struct {
		Expand *expandElement `xml:"urn:ietf:params:xml:ns:caldav expand"`
	}
	type propElement struct {
		CalendarData *calendarDataElement `xml:"urn:ietf:params:xml:ns:caldav calendar-data"`
	}
	type reportElement struct {
		XMLName xml.Name
		Prop    *propElement `xml:"DAV: prop"`
	}
	var report reportElement
	if err := xml.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("computetest: a REPORT body the fake cannot read: %v", err)
	}
	if report.Prop == nil || report.Prop.CalendarData == nil || report.Prop.CalendarData.Expand == nil {
		return nil, nil
	}
	expand := report.Prop.CalendarData.Expand
	start, err := time.Parse("20060102T150405Z", expand.Start)
	if err != nil {
		return nil, fmt.Errorf("computetest: an expand start that is no UTC date-time: %q", expand.Start)
	}
	end, err := time.Parse("20060102T150405Z", expand.End)
	if err != nil || !end.After(start) {
		return nil, fmt.Errorf("computetest: an expand end that is no UTC date-time after its start: %q", expand.End)
	}
	return &fakeCalendarWindow{start: start, end: end}, nil
}

func fakeXmlText(text string) string {
	var buffer bytes.Buffer
	xml.EscapeText(&buffer, []byte(text))
	return buffer.String()
}

// One property of a PROPFIND answer: its name and the XML inside it, written with fakeDavPrefixes' prefixes.
type fakeDavProp struct {
	name  xml.Name
	inner string
}

func fakeDavOpen(name xml.Name) string {
	if prefix, ok := fakeDavPrefixes[name.Space]; ok {
		return "<" + prefix + ":" + name.Local + ">"
	}
	return `<x:` + name.Local + ` xmlns:x="` + fakeXmlText(name.Space) + `">`
}

func fakeDavClose(name xml.Name) string {
	if prefix, ok := fakeDavPrefixes[name.Space]; ok {
		return "</" + prefix + ":" + name.Local + ">"
	}
	return "</x:" + name.Local + ">"
}

func fakeDavEmpty(name xml.Name) string {
	if prefix, ok := fakeDavPrefixes[name.Space]; ok {
		return "<" + prefix + ":" + name.Local + "/>"
	}
	return `<x:` + name.Local + ` xmlns:x="` + fakeXmlText(name.Space) + `"/>`
}

func fakeDavHref(href string) string {
	return "<d:href>" + fakeXmlText(href) + "</d:href>"
}

// What a PROPFIND asks for: names, every property (allprop, or an empty body), or names alone (propname).
type fakeDavPropfindRequest struct {
	all      bool
	nameOnly bool
	names    []xml.Name
}

func fakeDavParsePropfind(body []byte) (*fakeDavPropfindRequest, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return &fakeDavPropfindRequest{all: true}, nil
	}
	type nameElement struct {
		XMLName xml.Name
	}
	type propElement struct {
		Names []nameElement `xml:",any"`
	}
	type propfindElement struct {
		XMLName  xml.Name     `xml:"DAV: propfind"`
		AllProp  *struct{}    `xml:"DAV: allprop"`
		PropName *struct{}    `xml:"DAV: propname"`
		Prop     *propElement `xml:"DAV: prop"`
	}
	var propfind propfindElement
	if err := xml.Unmarshal(body, &propfind); err != nil {
		return nil, err
	}
	request := &fakeDavPropfindRequest{all: propfind.AllProp != nil, nameOnly: propfind.PropName != nil}
	if propfind.Prop != nil {
		for _, name := range propfind.Prop.Names {
			request.names = append(request.names, name.XMLName)
		}
	}
	if !request.all && !request.nameOnly && propfind.Prop == nil {
		return nil, errors.New("a propfind with no prop, allprop or propname")
	}
	return request, nil
}

// One resource's response: the properties found, answered by request.
func fakeDavResponse(href string, props []*fakeDavProp, request *fakeDavPropfindRequest) string {
	var found strings.Builder
	var missing strings.Builder
	switch {
	case request.nameOnly:
		for _, prop := range props {
			found.WriteString(fakeDavEmpty(prop.name))
		}
	case request.all:
		for _, prop := range props {
			found.WriteString(fakeDavOpen(prop.name) + prop.inner + fakeDavClose(prop.name))
		}
	default:
		for _, name := range request.names {
			index := slices.IndexFunc(props, func(prop *fakeDavProp) bool { return prop.name == name })
			if index < 0 {
				missing.WriteString(fakeDavEmpty(name))
				continue
			}
			found.WriteString(fakeDavOpen(name) + props[index].inner + fakeDavClose(name))
		}
	}
	var response strings.Builder
	response.WriteString("<d:response>" + fakeDavHref(href))
	if found.Len() > 0 || missing.Len() == 0 {
		response.WriteString("<d:propstat><d:prop>" + found.String() + "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>")
	}
	if missing.Len() > 0 {
		response.WriteString("<d:propstat><d:prop>" + missing.String() + "</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>")
	}
	response.WriteString("</d:response>")
	return response.String()
}

func fakeDavName(space string, local string) xml.Name {
	return xml.Name{Space: space, Local: local}
}

// PROPFIND on every path (see the file header's discovery and collections rows).
func (self *FakeCalendarServer) caldavPropfind(w http.ResponseWriter, r *http.Request, account *FakeCalendarAccountArgs, parsed *fakeCaldavPath, host string) {
	depth := r.Header.Get("Depth")
	switch depth {
	case "0", "1":
	case "", "infinity":
		if parsed.kind != fakeCaldavPathObject {
			w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+`<d:error xmlns:d="DAV:"><d:propfind-finite-depth/></d:error>`)
			return
		}
	default:
		http.Error(w, "a Depth the fake does not read", http.StatusBadRequest)
		return
	}
	body, err := fakeCalendarReadBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	request, err := fakeDavParsePropfind(body)
	if err != nil {
		http.Error(w, "computetest: a PROPFIND body the fake cannot read", http.StatusBadRequest)
		return
	}
	principalPath := fakeCaldavPrincipalPath(account.Name)
	currentUserPrincipal := &fakeDavProp{name: fakeDavName(fakeDavNamespace, "current-user-principal"), inner: fakeDavHref(principalPath)}
	responses := []string{}
	notFound := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch parsed.kind {
		case fakeCaldavPathRoot:
			responses = append(responses, fakeDavResponse(r.URL.Path, []*fakeDavProp{
				{name: fakeDavName(fakeDavNamespace, "resourcetype"), inner: "<d:collection/>"},
				currentUserPrincipal,
			}, request))
		case fakeCaldavPathPrincipal:
			homeHref := fakeCaldavHomePath(account.Name)
			if account.PartitionHost != "" {
				homeHref = "https://" + account.PartitionHost + homeHref
			}
			responses = append(responses, fakeDavResponse(principalPath, []*fakeDavProp{
				{name: fakeDavName(fakeDavNamespace, "resourcetype"), inner: "<d:principal/>"},
				{name: fakeDavName(fakeDavNamespace, "displayname"), inner: fakeXmlText(account.DisplayName)},
				currentUserPrincipal,
				{name: fakeDavName(fakeDavNamespace, "principal-URL"), inner: fakeDavHref(principalPath)},
				{name: fakeDavName(fakeCaldavNamespace, "calendar-home-set"), inner: fakeDavHref(homeHref)},
				{name: fakeDavName(fakeCaldavNamespace, "calendar-user-address-set"), inner: fakeDavHref("mailto:"+account.Address) + fakeDavHref(principalPath)},
				{name: fakeDavName(fakeCaldavNamespace, "calendar-user-type"), inner: "INDIVIDUAL"},
			}, request))
		case fakeCaldavPathHome:
			responses = append(responses, fakeDavResponse(fakeCaldavHomePath(account.Name), []*fakeDavProp{
				{name: fakeDavName(fakeDavNamespace, "resourcetype"), inner: "<d:collection/>"},
				currentUserPrincipal,
				{name: fakeDavName(fakeDavNamespace, "owner"), inner: fakeDavHref(principalPath)},
			}, request))
			if depth == "1" {
				for _, calendarId := range self.accounts[account.Name].calendarIds {
					calendar := self.calendars[fakeCalendarKey(account.Name, calendarId)]
					responses = append(responses, fakeDavResponse(fakeCaldavCalendarPath(account.Name, calendarId),
						self.caldavCalendarPropsWithLock(calendar, currentUserPrincipal), request))
				}
			}
		case fakeCaldavPathCalendar:
			calendar, ok := self.calendars[fakeCalendarKey(account.Name, parsed.calendar)]
			if !ok {
				notFound = true
				return
			}
			responses = append(responses, fakeDavResponse(fakeCaldavCalendarPath(account.Name, parsed.calendar),
				self.caldavCalendarPropsWithLock(calendar, currentUserPrincipal), request))
			if depth == "1" {
				names := make([]string, 0, len(calendar.objects))
				for name := range calendar.objects {
					names = append(names, name)
				}
				slices.Sort(names)
				for _, name := range names {
					object := calendar.objects[name]
					responses = append(responses, fakeDavResponse(fakeCaldavCalendarPath(account.Name, parsed.calendar)+name,
						fakeCaldavObjectProps(object), request))
				}
			}
		case fakeCaldavPathObject:
			calendar, ok := self.calendars[fakeCalendarKey(account.Name, parsed.calendar)]
			if !ok {
				notFound = true
				return
			}
			object, ok := calendar.objects[parsed.name]
			if !ok {
				notFound = true
				return
			}
			responses = append(responses, fakeDavResponse(fakeCaldavCalendarPath(account.Name, parsed.calendar)+parsed.name,
				fakeCaldavObjectProps(object), request))
		}
	}()
	if notFound {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	var prefixes strings.Builder
	for _, space := range []string{fakeDavNamespace, fakeCaldavNamespace, fakeCalendarServerNs, fakeOwncloudNamespace, fakeAppleIcalNamespace} {
		prefixes.WriteString(` xmlns:` + fakeDavPrefixes[space] + `="` + space + `"`)
	}
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+`<d:multistatus`+prefixes.String()+`>`+strings.Join(responses, "")+`</d:multistatus>`)
}

func fakeCaldavObjectProps(object *fakeCaldavObject) []*fakeDavProp {
	return []*fakeDavProp{
		{name: fakeDavName(fakeDavNamespace, "resourcetype"), inner: ""},
		{name: fakeDavName(fakeDavNamespace, "getetag"), inner: fakeXmlText(fakeCaldavQuoted(object.etag))},
		{name: fakeDavName(fakeDavNamespace, "getcontenttype"), inner: "text/calendar; charset=utf-8; component=vevent"},
		{name: fakeDavName(fakeDavNamespace, "getcontentlength"), inner: strconv.Itoa(len(object.encoded))},
		{name: fakeDavName(fakeDavNamespace, "getlastmodified"), inner: object.modified.UTC().Format(http.TimeFormat)},
	}
}

// A calendar's properties, its sharing and publishing in its dialect.
func (self *FakeCalendarServer) caldavCalendarPropsWithLock(calendar *fakeCalendar, currentUserPrincipal *fakeDavProp) []*fakeDavProp {
	account := self.accounts[calendar.account].args
	privileges := "<d:privilege><d:read/></d:privilege><d:privilege><d:read-current-user-privilege-set/></d:privilege>"
	if !calendar.args.ReadOnly {
		privileges += "<d:privilege><d:write/></d:privilege><d:privilege><d:write-properties/></d:privilege>" +
			"<d:privilege><d:write-content/></d:privilege><d:privilege><d:bind/></d:privilege><d:privilege><d:unbind/></d:privilege>"
	}
	props := []*fakeDavProp{
		{name: fakeDavName(fakeDavNamespace, "resourcetype"), inner: "<d:collection/><c:calendar/>"},
		{name: fakeDavName(fakeDavNamespace, "displayname"), inner: fakeXmlText(calendar.args.Name)},
		currentUserPrincipal,
		{name: fakeDavName(fakeDavNamespace, "owner"), inner: fakeDavHref(fakeCaldavPrincipalPath(calendar.account))},
		{name: fakeDavName(fakeDavNamespace, "current-user-privilege-set"), inner: privileges},
		{name: fakeDavName(fakeDavNamespace, "sync-token"), inner: fakeXmlText(fakeCaldavSyncTokenPrefix + strconv.FormatUint(calendar.revision, 10))},
		{name: fakeDavName(fakeCalendarServerNs, "getctag"), inner: strconv.FormatUint(calendar.revision, 10)},
		{name: fakeDavName(fakeCaldavNamespace, "supported-calendar-component-set"), inner: `<c:comp name="VEVENT"/>`},
		{name: fakeDavName(fakeCaldavNamespace, "supported-calendar-data"), inner: `<c:calendar-data content-type="text/calendar" version="2.0"/>`},
		{name: fakeDavName(fakeCaldavNamespace, "calendar-timezone"), inner: fakeXmlText(fakeCaldavTimezone(calendar.zone, self.now()))},
	}
	if calendar.args.Description != "" {
		props = append(props, &fakeDavProp{name: fakeDavName(fakeCaldavNamespace, "calendar-description"), inner: fakeXmlText(calendar.args.Description)})
	}
	if calendar.args.MaxResourceByteCount > 0 {
		props = append(props, &fakeDavProp{name: fakeDavName(fakeCaldavNamespace, "max-resource-size"), inner: strconv.FormatInt(calendar.args.MaxResourceByteCount, 10)})
	}
	sharing := calendar.args.Sharing
	if sharing == nil {
		return props
	}
	if sharing.PublishUrl != "" {
		props = append(props, &fakeDavProp{name: fakeDavName(fakeCalendarServerNs, "publish-url"), inner: fakeDavHref(sharing.PublishUrl)})
	}
	switch sharing.Dialect {
	case FakeCalendarSharingNextcloud:
		var users strings.Builder
		for _, sharee := range sharing.Sharees {
			users.WriteString("<oc:user>" + fakeDavHref(sharee.Href) + "<oc:common-name>" + fakeXmlText(sharee.CommonName) + "</oc:common-name>")
			if sharee.Accepted {
				users.WriteString("<oc:invite-accepted/>")
			} else {
				users.WriteString("<oc:invite-noresponse/>")
			}
			if sharee.ReadWrite {
				users.WriteString("<oc:access><oc:read-write/></oc:access>")
			} else {
				users.WriteString("<oc:access><oc:read/></oc:access>")
			}
			users.WriteString("</oc:user>")
		}
		props = append(props, &fakeDavProp{name: fakeDavName(fakeOwncloudNamespace, "invite"), inner: users.String()})
	case FakeCalendarSharingIcloud:
		var users strings.Builder
		users.WriteString("<cs:organizer>" + fakeDavHref(fakeCaldavPrincipalPath(calendar.account)) +
			"<cs:common-name>" + fakeXmlText(account.DisplayName) + "</cs:common-name></cs:organizer>")
		for _, sharee := range sharing.Sharees {
			users.WriteString("<cs:user>" + fakeDavHref(sharee.Href) + "<cs:common-name>" + fakeXmlText(sharee.CommonName) + "</cs:common-name>")
			if sharee.Accepted {
				users.WriteString("<cs:invite-accepted/>")
			} else {
				users.WriteString("<cs:invite-noresponse/>")
			}
			if sharee.ReadWrite {
				users.WriteString("<cs:access><cs:read-write/></cs:access>")
			} else {
				users.WriteString("<cs:access><cs:read/></cs:access>")
			}
			users.WriteString("</cs:user>")
		}
		props = append(props, &fakeDavProp{name: fakeDavName(fakeCalendarServerNs, "invite"), inner: users.String()})
	}
	return props
}

// RFC 4791 §5.2.2's calendar-timezone: a VCALENDAR holding one VTIMEZONE for zone, its observances the offset changes
// Go's zone makes over now's year, found hour by hour, or one standard observance where it makes none.
func fakeCaldavTimezone(zone *time.Location, now time.Time) string {
	timezone := ical.NewComponent(ical.CompTimezone)
	timezone.Props.SetText(ical.PropTimezoneID, zone.String())
	formatOffset := func(seconds int) string {
		sign := "+"
		if seconds < 0 {
			sign = "-"
			seconds = -seconds
		}
		return fmt.Sprintf("%s%02d%02d", sign, seconds/3600, (seconds%3600)/60)
	}
	observance := func(at time.Time, fromOffset int) {
		name, offset := at.Zone()
		kind := ical.CompTimezoneStandard
		if at.IsDST() {
			kind = ical.CompTimezoneDaylight
		}
		component := ical.NewComponent(kind)
		// the wall time at the change in the offset it leaves, as RFC 5545 §3.6.5 has an observance's start
		start := ical.NewProp(ical.PropDateTimeStart)
		start.Value = at.UTC().Add(time.Duration(fromOffset) * time.Second).Format("20060102T150405")
		component.Props.Set(start)
		component.Props.SetText(ical.PropTimezoneOffsetFrom, formatOffset(fromOffset))
		component.Props.SetText(ical.PropTimezoneOffsetTo, formatOffset(offset))
		component.Props.SetText(ical.PropTimezoneName, name)
		timezone.Children = append(timezone.Children, component)
	}
	yearStart := time.Date(now.In(zone).Year(), time.January, 1, 0, 0, 0, 0, zone)
	_, previousOffset := yearStart.Zone()
	for at := yearStart; at.Before(yearStart.AddDate(1, 0, 0)); at = at.Add(time.Hour) {
		if _, offset := at.Zone(); offset != previousOffset {
			observance(at, previousOffset)
			previousOffset = offset
		}
	}
	if len(timezone.Children) == 0 {
		observance(time.Date(1970, time.January, 1, 0, 0, 0, 0, zone), previousOffset)
	}
	calendar := ical.NewCalendar()
	calendar.Props.SetText(ical.PropProductID, fakeCaldavProductId)
	calendar.Props.SetText(ical.PropVersion, "2.0")
	calendar.Children = append(calendar.Children, timezone)
	var buffer bytes.Buffer
	if err := ical.NewEncoder(&buffer).Encode(calendar); err != nil {
		return ""
	}
	return buffer.String()
}

// go-webdav's caldav.Backend over the fake's store: each method takes the lock for its own read or write, and the
// account is the one the front authenticated.
type fakeCaldavBackend struct {
	server *FakeCalendarServer
}

var _ caldav.Backend = (*fakeCaldavBackend)(nil)

func (self *fakeCaldavBackend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return fakeCaldavPrincipalPath(fakeCalendarExchangeOf(ctx).account), nil
}

func (self *fakeCaldavBackend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return fakeCaldavHomePath(fakeCalendarExchangeOf(ctx).account), nil
}

func (self *fakeCaldavBackend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, ErrFakeCalendarUnserved)
}

func (self *fakeCaldavBackend) caldavCalendarWithLock(account string, calendar *fakeCalendar) caldav.Calendar {
	return caldav.Calendar{
		Path:                  fakeCaldavCalendarPath(account, calendar.args.Id),
		Name:                  calendar.args.Name,
		Description:           calendar.args.Description,
		MaxResourceSize:       calendar.args.MaxResourceByteCount,
		SupportedComponentSet: []string{ical.CompEvent},
		ReadOnly:              calendar.args.ReadOnly,
	}
}

func (self *fakeCaldavBackend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	account := fakeCalendarExchangeOf(ctx).account
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	accountState, ok := self.server.accounts[account]
	if !ok {
		return nil, webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
	}
	calendars := []caldav.Calendar{}
	for _, calendarId := range accountState.calendarIds {
		calendars = append(calendars, self.caldavCalendarWithLock(account, self.server.calendars[fakeCalendarKey(account, calendarId)]))
	}
	return calendars, nil
}

// The calendar a path names, of the authenticated account.
func (self *fakeCaldavBackend) calendarWithLock(ctx context.Context, requestPath string) (*fakeCalendar, *fakeCaldavPath, error) {
	parsed := fakeCaldavParsePath(requestPath)
	if parsed.kind != fakeCaldavPathCalendar && parsed.kind != fakeCaldavPathObject {
		return nil, nil, webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
	}
	if parsed.account != fakeCalendarExchangeOf(ctx).account {
		return nil, nil, webdav.NewHTTPError(http.StatusForbidden, ErrFakeCalendarUnknown)
	}
	calendar, ok := self.server.calendars[fakeCalendarKey(parsed.account, parsed.calendar)]
	if !ok {
		return nil, nil, webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
	}
	return calendar, parsed, nil
}

func (self *fakeCaldavBackend) GetCalendar(ctx context.Context, requestPath string) (*caldav.Calendar, error) {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	calendar, parsed, err := self.calendarWithLock(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	answer := self.caldavCalendarWithLock(parsed.account, calendar)
	return &answer, nil
}

// An object as go-webdav answers it, expanded where the request asked and the calendar expands; nil where the expand
// window holds none of its instances, which go-ical cannot write as an empty VCALENDAR, so a query leaves the object
// out and a multiget answers it 404 (a reading).
func (self *fakeCaldavBackend) answer(ctx context.Context, calendar *fakeCalendar, object *fakeCaldavObject) (*caldav.CalendarObject, error) {
	answer := &caldav.CalendarObject{
		Path:          fakeCaldavCalendarPath(calendar.account, calendar.args.Id) + object.name,
		ModTime:       object.modified,
		ContentLength: int64(len(object.encoded)),
		ETag:          object.etag,
		Data:          object.data,
	}
	window := fakeCalendarExchangeOf(ctx).expand
	if window == nil || calendar.args.NoExpand {
		return answer, nil
	}
	expanded, err := fakeCaldavExpandObject(object.data, calendar.zone, window, self.server.settings.ExpandInstanceMaxCount)
	if err != nil {
		return nil, webdav.NewHTTPError(http.StatusInternalServerError, err)
	}
	if expanded == nil {
		return nil, nil
	}
	answer.Data = expanded
	answer.ContentLength = 0
	return answer, nil
}

func (self *fakeCaldavBackend) GetCalendarObject(ctx context.Context, requestPath string, request *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	calendar, object, err := func() (*fakeCalendar, *fakeCaldavObject, error) {
		self.server.stateLock.Lock()
		defer self.server.stateLock.Unlock()
		calendar, parsed, err := self.calendarWithLock(ctx, requestPath)
		if err != nil {
			return nil, nil, err
		}
		object, ok := calendar.objects[parsed.name]
		if !ok {
			return nil, nil, webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
		}
		return calendar, object, nil
	}()
	if err != nil {
		return nil, err
	}
	answer, err := self.answer(ctx, calendar, object)
	if err == nil && answer == nil {
		return nil, webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
	}
	return answer, err
}

// The objects of a calendar, by name, and the calendar.
func (self *fakeCaldavBackend) objects(ctx context.Context, requestPath string) (*fakeCalendar, []*fakeCaldavObject, error) {
	self.server.stateLock.Lock()
	defer self.server.stateLock.Unlock()
	calendar, _, err := self.calendarWithLock(ctx, requestPath)
	if err != nil {
		return nil, nil, err
	}
	objects := make([]*fakeCaldavObject, 0, len(calendar.objects))
	for _, object := range calendar.objects {
		objects = append(objects, object)
	}
	slices.SortFunc(objects, func(a *fakeCaldavObject, b *fakeCaldavObject) int { return strings.Compare(a.name, b.name) })
	return calendar, objects, nil
}

func (self *fakeCaldavBackend) ListCalendarObjects(ctx context.Context, requestPath string, request *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	calendar, objects, err := self.objects(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	answers := []caldav.CalendarObject{}
	for _, object := range objects {
		answer, err := self.answer(ctx, calendar, object)
		if err != nil {
			return nil, err
		}
		if answer != nil {
			answers = append(answers, *answer)
		}
	}
	return answers, nil
}

func (self *fakeCaldavBackend) QueryCalendarObjects(ctx context.Context, requestPath string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	calendar, objects, err := self.objects(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	answers := []caldav.CalendarObject{}
	for _, object := range objects {
		matched, err := fakeCaldavMatch(query.CompFilter, object.data, calendar.zone, self.server.settings.ExpandInstanceMaxCount)
		if err != nil {
			return nil, webdav.NewHTTPError(http.StatusInternalServerError, err)
		}
		if !matched {
			continue
		}
		answer, err := self.answer(ctx, calendar, object)
		if err != nil {
			return nil, err
		}
		if answer != nil {
			answers = append(answers, *answer)
		}
	}
	return answers, nil
}

// An object's VEVENTs: the master (no RECURRENCE-ID) and its overrides.
func fakeIcalEvents(data *ical.Calendar) (*ical.Component, []*ical.Component) {
	var master *ical.Component
	overrides := []*ical.Component{}
	for _, child := range data.Children {
		if child.Name != ical.CompEvent {
			continue
		}
		if child.Props.Get(ical.PropRecurrenceID) != nil {
			overrides = append(overrides, child)
		} else if master == nil {
			master = child
		}
	}
	return master, overrides
}

// One instance of an object, from its master or an override.
type fakeCaldavInstance struct {
	instance  *fakeCalendarInstance
	component *ical.Component
	override  bool
}

// An object's instances overlapping window (nil for all, up to the cap): the master's, each override taking the place
// of the instance its RECURRENCE-ID names.
func fakeCaldavInstances(data *ical.Calendar, zone *time.Location, window *fakeCalendarWindow, maxCount int) ([]*fakeCaldavInstance, error) {
	master, overrides := fakeIcalEvents(data)
	overridden := map[int64]bool{}
	instances := []*fakeCaldavInstance{}
	for _, override := range overrides {
		recurrenceId, ok := fakeIcalRecurrenceId(override, data, zone)
		if !ok {
			return nil, fmt.Errorf("%w: a RECURRENCE-ID", ErrFakeCalendarData)
		}
		overridden[recurrenceId.UnixNano()] = true
		own, _, err := fakeIcalInstances(override, data, zone, window, 1)
		if err != nil {
			return nil, err
		}
		for _, instance := range own {
			instance.recurrenceId = recurrenceId
			instances = append(instances, &fakeCaldavInstance{instance: instance, component: override, override: true})
		}
	}
	if master != nil {
		masterInstances, _, err := fakeIcalInstances(master, data, zone, window, maxCount)
		if err != nil {
			return nil, err
		}
		for _, instance := range masterInstances {
			if !instance.recurrenceId.IsZero() && overridden[instance.recurrenceId.UnixNano()] {
				continue
			}
			instances = append(instances, &fakeCaldavInstance{instance: instance, component: master})
		}
	}
	slices.SortStableFunc(instances, func(a *fakeCaldavInstance, b *fakeCaldavInstance) int {
		return a.instance.start.Compare(b.instance.start)
	})
	return instances, nil
}

// RFC 4791 §9.7's comp-filter over an object: VCALENDAR's VEVENT time range by §9.9 over the object's instances, and
// every other filter by go-webdav's own matcher.
func fakeCaldavMatch(filter caldav.CompFilter, data *ical.Calendar, zone *time.Location, maxCount int) (bool, error) {
	if filter.Name != ical.CompCalendar {
		return filter.IsNotDefined, nil
	}
	plain := caldav.CompFilter{Name: filter.Name, Props: filter.Props}
	for _, child := range filter.Comps {
		if child.Name == ical.CompEvent && !child.Start.IsZero() {
			end := child.End
			if end.IsZero() {
				end = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)
			}
			instances, err := fakeCaldavInstances(data, zone, &fakeCalendarWindow{start: child.Start, end: end}, maxCount)
			if err != nil {
				return false, err
			}
			if len(instances) == 0 {
				return false, nil
			}
			child.Start = time.Time{}
			child.End = time.Time{}
		}
		plain.Comps = append(plain.Comps, child)
	}
	return caldav.Match(plain, &caldav.CalendarObject{Data: data})
}

// RFC 4791 §9.6.5's expanded form of an object: one VEVENT per instance overlapping window, DTSTART and DTEND in UTC
// (dates staying dates), a recurring instance's RECURRENCE-ID in UTC, no RRULE, RDATE, EXDATE or EXRULE, and no
// VTIMEZONE; nil when window holds none of its instances.
func fakeCaldavExpandObject(data *ical.Calendar, zone *time.Location, window *fakeCalendarWindow, maxCount int) (*ical.Calendar, error) {
	instances, err := fakeCaldavInstances(data, zone, window, maxCount)
	if err != nil {
		return nil, err
	}
	expanded := ical.NewCalendar()
	for name, props := range data.Props {
		expanded.Props[name] = slices.Clone(props)
	}
	setTime := func(component *ical.Component, name string, at time.Time, allDay bool) {
		prop := ical.NewProp(name)
		if allDay {
			prop.SetDate(at)
		} else {
			prop.SetDateTime(at.UTC())
		}
		component.Props.Set(prop)
	}
	for _, instance := range instances {
		event := &ical.Component{Name: ical.CompEvent, Props: ical.Props{}, Children: instance.component.Children}
		for name, props := range instance.component.Props {
			switch name {
			case ical.PropRecurrenceRule, ical.PropRecurrenceDates, ical.PropExceptionDates, "EXRULE", ical.PropDuration:
				continue
			}
			event.Props[name] = slices.Clone(props)
		}
		setTime(event, ical.PropDateTimeStart, instance.instance.start, instance.instance.allDay)
		setTime(event, ical.PropDateTimeEnd, instance.instance.end, instance.instance.allDay)
		if !instance.instance.recurrenceId.IsZero() {
			setTime(event, ical.PropRecurrenceID, instance.instance.recurrenceId, instance.instance.allDay)
		}
		expanded.Children = append(expanded.Children, event)
	}
	if len(expanded.Children) == 0 {
		return nil, nil
	}
	return expanded, nil
}

// The mailto: address of a calendar address, lowercased.
func fakeCalendarAddress(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(value, "mailto:"), "MAILTO:"))
}

// Who an object's master names as organizer, and its attendees the server schedules (RFC 6638 §3.2: not the organizer,
// and none whose SCHEDULE-AGENT is CLIENT or NONE).
func fakeCaldavParties(data *ical.Calendar) (string, []string, bool) {
	master, overrides := fakeIcalEvents(data)
	component := master
	if component == nil && len(overrides) > 0 {
		component = overrides[0]
	}
	if component == nil {
		return "", nil, false
	}
	organizerProp := component.Props.Get(ical.PropOrganizer)
	if organizerProp == nil {
		return "", nil, false
	}
	organizer := fakeCalendarAddress(organizerProp.Value)
	serverAgent := func(prop *ical.Prop) bool {
		agent := strings.ToUpper(prop.Params.Get("SCHEDULE-AGENT"))
		return agent == "" || agent == "SERVER"
	}
	if !serverAgent(organizerProp) {
		return organizer, nil, false
	}
	attendees := []string{}
	for _, attendee := range component.Props.Values(ical.PropAttendee) {
		address := fakeCalendarAddress(attendee.Value)
		if address == organizer || !serverAgent(&attendee) || slices.Contains(attendees, address) {
			continue
		}
		attendees = append(attendees, address)
	}
	return organizer, attendees, true
}

func (self *fakeCaldavBackend) PutCalendarObject(ctx context.Context, requestPath string, data *ical.Calendar, options *caldav.PutCalendarObjectOptions) (*caldav.CalendarObject, error) {
	exchange := fakeCalendarExchangeOf(ctx)
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	calendar, parsed, err := self.calendarWithLock(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	previous := calendar.objects[parsed.name]
	write := &FakeCalendarWrite{
		Protocol:    FakeCalendarCaldav,
		Method:      http.MethodPut,
		Account:     parsed.account,
		Calendar:    parsed.calendar,
		Resource:    parsed.name,
		IfNoneMatch: string(options.IfNoneMatch),
		IfMatch:     string(options.IfMatch),
	}
	if previous != nil {
		write.RevisionBefore = fakeCaldavQuoted(previous.etag)
	}
	refuse := func(status int, err error) (*caldav.CalendarObject, error) {
		write.Status = status
		server.logWriteWithLock(exchange, write)
		return nil, err
	}
	eventType, uid, err := caldav.ValidateCalendarObject(data)
	write.Uid = uid
	switch {
	case err != nil || uid == "":
		return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionValidCalendarObjectResource))
	case eventType != ical.CompEvent:
		return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionSupportedCalendarComponent))
	}
	var encoded bytes.Buffer
	if err := ical.NewEncoder(&encoded).Encode(data); err != nil {
		return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionValidCalendarData))
	}
	write.Body = slices.Clone(encoded.Bytes())
	if calendar.args.MaxResourceByteCount > 0 && int64(encoded.Len()) > calendar.args.MaxResourceByteCount {
		return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionMaxResourceSize))
	}
	if options.IfNoneMatch.IsSet() && previous != nil {
		// *, or a list of ETags one of which is the resource's (RFC 9110 §13.1.2)
		matched := options.IfNoneMatch.IsWildcard()
		for _, candidate := range strings.Split(string(options.IfNoneMatch), ",") {
			if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == fakeCaldavQuoted(previous.etag) {
				matched = true
			}
		}
		if matched {
			return refuse(http.StatusPreconditionFailed, webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("the resource exists")))
		}
	}
	if options.IfMatch.IsSet() {
		matched := false
		if previous != nil {
			matched, _ = options.IfMatch.MatchETag(previous.etag)
		}
		if !matched {
			return refuse(http.StatusPreconditionFailed, webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("the ETag is not the resource's")))
		}
	}
	for name, other := range calendar.objects {
		if name != parsed.name && other.uid == uid {
			return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionNoUIDConflict))
		}
	}
	if previous != nil && previous.uid != uid {
		return refuse(http.StatusConflict, caldav.NewPreconditionError(caldav.PreconditionNoUIDConflict))
	}
	account := server.accounts[parsed.account].args
	organizer, attendees, scheduled := fakeCaldavParties(data)
	if scheduled && organizer == strings.ToLower(account.Address) {
		for _, attendee := range attendees {
			write.Notices = append(write.Notices, &FakeCalendarNotice{Method: FakeCalendarNoticeRequest, To: attendee, Uid: uid})
		}
		if previous != nil {
			_, previousAttendees, _ := fakeCaldavParties(previous.data)
			for _, attendee := range previousAttendees {
				if !slices.Contains(attendees, attendee) {
					write.Notices = append(write.Notices, &FakeCalendarNotice{Method: FakeCalendarNoticeCancel, To: attendee, Uid: uid})
				}
			}
		}
	}
	object := &fakeCaldavObject{
		name:     parsed.name,
		uid:      uid,
		data:     data,
		encoded:  slices.Clone(encoded.Bytes()),
		etag:     server.nextRevisionWithLock("caldav " + requestPath),
		modified: server.now(),
	}
	calendar.objects[parsed.name] = object
	server.touchWithLock(calendar)
	write.Applied = true
	write.RevisionAfter = fakeCaldavQuoted(object.etag)
	write.Status = http.StatusCreated
	if previous != nil {
		write.Status = http.StatusNoContent
		exchange.replaced = true
	}
	server.logWriteWithLock(exchange, write)
	return &caldav.CalendarObject{
		Path:          fakeCaldavCalendarPath(parsed.account, parsed.calendar) + parsed.name,
		ModTime:       object.modified,
		ContentLength: int64(len(object.encoded)),
		ETag:          object.etag,
		Data:          object.data,
	}, nil
}

func (self *fakeCaldavBackend) DeleteCalendarObject(ctx context.Context, requestPath string) error {
	exchange := fakeCalendarExchangeOf(ctx)
	server := self.server
	server.stateLock.Lock()
	defer server.stateLock.Unlock()
	calendar, parsed, err := self.calendarWithLock(ctx, requestPath)
	if err != nil {
		return err
	}
	ifMatch := webdav.ConditionalMatch(exchange.ifMatch)
	write := &FakeCalendarWrite{
		Protocol:      FakeCalendarCaldav,
		Method:        http.MethodDelete,
		Account:       parsed.account,
		Calendar:      parsed.calendar,
		Resource:      parsed.name,
		IfMatch:       exchange.ifMatch,
		ScheduleReply: exchange.scheduleReply,
	}
	object, ok := calendar.objects[parsed.name]
	if !ok {
		write.Status = http.StatusNotFound
		server.logWriteWithLock(exchange, write)
		return webdav.NewHTTPError(http.StatusNotFound, ErrFakeCalendarUnknown)
	}
	write.Uid = object.uid
	write.RevisionBefore = fakeCaldavQuoted(object.etag)
	if ifMatch.IsSet() {
		if matched, _ := ifMatch.MatchETag(object.etag); !matched {
			write.Status = http.StatusPreconditionFailed
			server.logWriteWithLock(exchange, write)
			return webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("the ETag is not the resource's"))
		}
	}
	account := server.accounts[parsed.account].args
	organizer, attendees, scheduled := fakeCaldavParties(object.data)
	if scheduled {
		if organizer == strings.ToLower(account.Address) {
			for _, attendee := range attendees {
				write.Notices = append(write.Notices, &FakeCalendarNotice{Method: FakeCalendarNoticeCancel, To: attendee, Uid: object.uid})
			}
		} else if slices.Contains(attendees, strings.ToLower(account.Address)) && !strings.EqualFold(exchange.scheduleReply, "F") {
			write.Notices = append(write.Notices, &FakeCalendarNotice{
				Method:   FakeCalendarNoticeReply,
				To:       organizer,
				Uid:      object.uid,
				PartStat: "DECLINED",
			})
		}
	}
	delete(calendar.objects, parsed.name)
	server.touchWithLock(calendar)
	write.Applied = true
	write.Status = http.StatusNoContent
	server.logWriteWithLock(exchange, write)
	return nil
}

// Stores an object as a test's setup, outside any front: no precondition, no notice, no write logged. Its name is the
// resource's, as <uid>.ics; it answers the object's ETag.
func (self *FakeCalendarServer) PutCaldavObject(account string, calendarId string, name string, icsText string) (string, error) {
	data, err := ical.NewDecoder(strings.NewReader(icsText)).Decode()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
	}
	_, uid, err := caldav.ValidateCalendarObject(data)
	if err != nil || uid == "" {
		return "", fmt.Errorf("%w: not one calendar object", ErrFakeCalendarData)
	}
	var encoded bytes.Buffer
	if err := ical.NewEncoder(&encoded).Encode(data); err != nil {
		return "", fmt.Errorf("%w: %v", ErrFakeCalendarData, err)
	}
	if name == "" || strings.ContainsAny(name, "/?#") {
		return "", fmt.Errorf("%w: a resource name %q", ErrFakeCalendarArgs, name)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calendar, ok := self.calendars[fakeCalendarKey(account, calendarId)]
	if !ok || self.accounts[account].args.Protocol != FakeCalendarCaldav {
		return "", fmt.Errorf("%w: caldav calendar %q", ErrFakeCalendarUnknown, calendarId)
	}
	object := &fakeCaldavObject{
		name:     name,
		uid:      uid,
		data:     data,
		encoded:  slices.Clone(encoded.Bytes()),
		etag:     self.nextRevisionWithLock("caldav setup " + account + " " + calendarId + " " + name),
		modified: self.now(),
	}
	calendar.objects[name] = object
	self.touchWithLock(calendar)
	return fakeCaldavQuoted(object.etag), nil
}

// One stored CalDAV object, as a test reads it.
type FakeCaldavObject struct {
	Name string
	Uid  string
	// The ETag header's form.
	Etag string
	// The data as stored, go-ical's encoding of what was written.
	Ics      string
	Modified time.Time
}

// The objects of a CalDAV calendar, by name.
func (self *FakeCalendarServer) CaldavObjects(account string, calendarId string) ([]*FakeCaldavObject, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calendar, ok := self.calendars[fakeCalendarKey(account, calendarId)]
	if !ok {
		return nil, fmt.Errorf("%w: calendar %q", ErrFakeCalendarUnknown, calendarId)
	}
	objects := []*FakeCaldavObject{}
	for _, object := range calendar.objects {
		objects = append(objects, &FakeCaldavObject{
			Name:     object.name,
			Uid:      object.uid,
			Etag:     fakeCaldavQuoted(object.etag),
			Ics:      string(object.encoded),
			Modified: object.modified,
		})
	}
	slices.SortFunc(objects, func(a *FakeCaldavObject, b *FakeCaldavObject) int { return strings.Compare(a.Name, b.Name) })
	return objects, nil
}
