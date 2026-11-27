// §17.2's controls at the broker (DESIGN-COMPUTE §17.2, D-CABUSE-1; CARCH-M12-01; QD-702): the abuse hold's projection,
// which the staff route's writer shares through model's settings, and the regions every admission refuses, each a
// field set only by DefaultComputeAbuseSettings, which ComputeEngineSettings.Abuse carries. The reason classes and the
// refusal codes are identifiers and stay constants (model's compute_abuse_hold.go, engine_refusal.go).

package computeservice

import (
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/model"
)

// The broker's abuse settings.
type ComputeAbuseSettings struct {
	// The abuse hold's projection, the same object the staff route's writer reads, so its life is set in one place.
	// nil: model.DefaultComputeAbuseHoldSettings.
	Hold *model.ComputeAbuseHoldSettings
	// The countries whose addresses every admission refuses (§17.2's sanctioned users), ISO 3166-1 alpha-2 in lower
	// case, as GeoLite2 City writes them: Cuba, Iran and North Korea, the countries under comprehensive US sanctions
	// on 2026-11-27, which counsel confirms before M12's exit (QD-1439, question carch-m12-01-refused-regions).
	// Empty refuses no country.
	RefusedCountryCodes []string
	// The subdivisions whose addresses every admission refuses, by the GeoNames id GeoLite2 City gives an address's
	// first subdivision, matched in any country, since GeoLite2 may file one region's addresses under either of two:
	// Crimea (703883), Sevastopol (694422), Donetsk Oblast (709716) and Luhansk Oblast (702657), the regions of Ukraine
	// under comprehensive US sanctions, refused by oblast, the finest GeoLite2 places an address (QD-1439). The rota
	// checks each id against the deployed GeoLite2 build. Empty refuses no subdivision.
	RefusedSubdivisionGeonameIds []uint32
}

// The defaults, each with its field's reason.
func DefaultComputeAbuseSettings() *ComputeAbuseSettings {
	return &ComputeAbuseSettings{
		Hold:                         model.DefaultComputeAbuseHoldSettings(),
		RefusedCountryCodes:          []string{"cu", "ir", "kp"},
		RefusedSubdivisionGeonameIds: []uint32{703883, 694422, 709716, 702657},
	}
}

// The hold's settings: Hold, or the defaults.
func (self *ComputeAbuseSettings) holdSettings() *model.ComputeAbuseHoldSettings {
	if self.Hold == nil {
		return model.DefaultComputeAbuseHoldSettings()
	}
	return self.Hold
}

// Whether the settings refuse an address region places: its country listed, or its first subdivision.
func (self *ComputeAbuseSettings) refusesRegion(region *ComputeRegion) bool {
	if region.CountryCode != "" && slices.Contains(self.RefusedCountryCodes, region.CountryCode) {
		return true
	}
	return region.SubdivisionGeonameId != 0 && slices.Contains(self.RefusedSubdivisionGeonameIds, region.SubdivisionGeonameId)
}

// An error for settings no broker could check under: a country code that is not two lower-case letters, which no
// lookup would ever match, so a typo refuses nothing silently; a subdivision id of 0, which means none.
func (self *ComputeAbuseSettings) Validate() error {
	for _, countryCode := range self.RefusedCountryCodes {
		if len(countryCode) != 2 || countryCode[0] < 'a' || 'z' < countryCode[0] || countryCode[1] < 'a' || 'z' < countryCode[1] {
			return fmt.Errorf("compute abuse: the refused country code %q is not two lower-case letters", countryCode)
		}
	}
	if slices.Contains(self.RefusedSubdivisionGeonameIds, 0) {
		return fmt.Errorf("compute abuse: a refused subdivision's GeoNames id is 0, which names none")
	}
	return nil
}
