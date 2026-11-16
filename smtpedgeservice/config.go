// config/<env>/smtpedge.yml as the smtpedge block reads it (SMTP-M9-20; §14.9, §14.14, §19.4, QD-489): the
// engine's settings (settings.go) with the block's own rules over them. Every HELO name sits under helo_domain,
// since each is a sending address's PTR name and FCrDNS holds only for names the operator publishes (owner
// decision 124: o<k>.out.bringyour.com in production); and each sending address carries the fwmark that
// source-routes a dial from it, a fwmark of 0 taking the block's own WARP_FWMARK, since warp hands one mark to a
// block and W7 adds the rules for any other (plan-SMTP-small-readings#18).
//
// The file holds no secret: X-UR-Ref keys come from the block's vault secret file, which the block lays over
// the settings after this (SmtpEdgeSettings.XUrRefKeys), never from here.

package smtpedgeservice

import (
	"fmt"
	"strings"
)

// The edge block's view of smtpedge.yml.
type SmtpEdgeConfig struct {
	Settings *SmtpEdgeSettings
	// The block's own mark, which a sending address of fwmark 0 takes.
	BlockFwmark int
}

// The config in data for a block whose WARP_FWMARK is blockFwmark (0 when warp set none). A file the engine's
// settings refuse is refused, and so is one without helo_domain, or with a HELO name not strictly under it. A
// refusal names the field, never its value.
func LoadSmtpEdgeConfig(data []byte, blockFwmark int) (*SmtpEdgeConfig, error) {
	settings, err := LoadSmtpEdgeSettings(data)
	if err != nil {
		return nil, err
	}
	if blockFwmark < 0 {
		return nil, fmt.Errorf("%w: the block's fwmark is negative", ErrSmtpEdgeSettingsRefused)
	}
	heloDomain := strings.ToLower(settings.HeloDomain)
	if !settings.ldhName(heloDomain) || !strings.Contains(heloDomain, ".") {
		return nil, fmt.Errorf("%w: helo_domain is not a dotted LDH name", ErrSmtpEdgeSettingsRefused)
	}
	for i := range settings.SendingAddresses {
		sendingAddress := &settings.SendingAddresses[i]
		if !strings.HasSuffix(strings.ToLower(sendingAddress.HeloName), "."+heloDomain) {
			return nil, fmt.Errorf("%w: a sending address's helo is not under helo_domain", ErrSmtpEdgeSettingsRefused)
		}
		if sendingAddress.Fwmark == 0 {
			sendingAddress.Fwmark = blockFwmark
		}
	}
	return &SmtpEdgeConfig{Settings: settings, BlockFwmark: blockFwmark}, nil
}
