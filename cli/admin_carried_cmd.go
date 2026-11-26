// The carried ServiceSettings record's line in ur admin directory and ur admin scopes (D-TEAM-26; owner decision 699;
// QD-1207). The team directory's defaults and the Team scopes ride the config head's ServiceSettings record, which every
// reader holds under its first signer until an Owner or Admin files another. Where that signer no longer stands, each
// show lists the record as ur admin settings does (urAdminCarriedLine): its signer, the signer's member, why the signer
// no longer stands, and who files another with which command. Where the daemon could not read the head's records now,
// the show says so rather than saying nothing, which would read as a signer who stands.

package main

import (
	"context"

	"github.com/urnetwork/sidecar"
)

// The head's ServiceSettings record where its signer no longer stands (sidecar.CarriedConfigRecords): nil while its
// signer stands or the head holds none, and unknown where lister could not read the head's records now.
func urAdminCarriedServiceSettings(ctx context.Context, lister urAdminCarriedLister) (*sidecar.ConfigCarriedRecord, bool) {
	records, err := lister.CarriedConfigRecords(ctx)
	if err != nil {
		return nil, true
	}
	for _, record := range records {
		if record != nil && record.Record == sidecar.ConfigHeadServiceSettingsPath {
			return record, false
		}
	}
	return nil, false
}

// What a show prints of the ServiceSettings record holding what, the settings or scopes it showed: the carried record's
// line, that it is not known here, or "" while its signer stands.
func urAdminCarriedServiceSettingsLine(what string, carried *sidecar.ConfigCarriedRecord, unknown bool) string {
	switch {
	case unknown:
		return "whether the ServiceSettings record holding " + what + " stands under a standing signer is not known here, " +
			"since this device could not read the config head's records now"
	case carried != nil:
		return "the ServiceSettings record holding " + what + " stands under a signer who no longer stands until another is filed: " +
			urAdminCarriedLine(carried)
	}
	return ""
}
