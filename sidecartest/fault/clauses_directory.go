//go:build !ios_extension

// FS-99's evs clause, registered beside the build its builder is in (fs99_evs.go): the directory's ERASE, ?closure=1
// upload and slots/delete below admin, on the real engine and client, a clause of the entries case (format 1's
// directory), whose T3 run is server's root package's (RECORD-M6-25).

package fault

var registeredDirectoryClauses = []*ClauseRegistration{
	RegisterClause("FS-99", "entries", "evs scope", Fs99EvsScope, ClauseOnT3(".")),
}
