// ur compute (DESIGN-COMPUTE §9, §15.1; BAL-M12-18): the compute balance from the terminal, over the daemon's compute
// methods (BAL-M12-17's DaemonComputeMethods, which cmd_compute_methods.go registers), each on the call's network:
//
//	ur compute status                         the balance, held, the state, both auto-renew modes (a threshold
//	                                          turned off says why), whether this person may buy and whether credits
//	                                          are on sale
//	ur compute buy <pack>                     a Stripe pack: Checkout's url, printed and opened in the browser,
//	                                          refused where this person may not buy or sales are closed (Q-BAL-13)
//	ur compute buy --monthly=<credits>        Stripe's monthly plan, through Checkout as a subscription
//	ur compute redeem <code>                  a promotion code: confirmed on /dev/tty, a Confirm method, refused to a
//	                                          caller with a harness process among its ancestors (§9.11); <code> -
//	                                          takes the code from /dev/tty unechoed, out of argv
//	ur compute auto-renew [threshold|monthly|off …]  §9.8's two modes, shown, or one changed after a yes on /dev/tty
//	ur compute charges                        a page of charges, each named on the device
//	ur compute statement --month=<YYYY-MM>    a UTC month's statement and its lots
//	ur compute refund <lot>                   a Stripe lot's unspent part (§9.12), confirmed on /dev/tty; an Owner's or a
//	                                          Billing admin's, which the server holds the caller to
//	ur compute budget [ls]                    the device's budgets and what is left of them: CACL's view (C§16.4)
//	ur compute budget raise …                 kind 21 for an agent's or a gateway grant's budget (§16.3), filed and
//	                                          waited on until a person decides on an approval-capable device
//	ur compute spend [--by=<dim>]             §9.13's spend view: each service's total since the first charge and its
//	                                          last 7 UTC days, by provider, model, enclave or member, or by agent for
//	                                          the 7 days alone
//
// One command, compute, whose usage is its subcommands', each registered through registerUrComputeSubcommand from its
// own file at init, so BAL-M13-03 adds terms in a file of its own. A refusal the server answers with a code prints the
// code and its fix, never a message the server wrote. Amounts print to the cent, "< $0.01" below one; the 7 days are
// UTC days, with their bounds in local time beside. A name from a source no signature vouches for prints between
// §9.13's untrusted-data markers, so a process a run binds reads it as untrusted. No card, token, store receipt or code
// reaches stdout; the only secret this command takes is a promotion code, whose plain form in argv is the residual
// `ur share get <link>` names (owner decision 336), and `ur compute redeem -` keeps it out of argv, ps and the
// shell's history.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// One credit, a US dollar, in nano-USD (D-BAL-2): a unit, not a limit.
const urComputeNanoUsdPerUsd int64 = 1_000_000_000

// Tunables of ur compute.
type urComputeSettings struct {
	// How long a budget raise waiting on its approval lets pass before it asks again: 2 s, as ur bridge's.
	ApprovalPollInterval time.Duration
	// How long it waits in all before it gives up, leaving the approval for a later run: 10 min, as ur bridge's.
	ApprovalWaitTimeout time.Duration
	// The longest promotion code taken: 32 characters, ComputeLedgerSettings' PromoCodeMaxCharacterCount.
	PromoCodeMaxCharacterCount int
	// The most decimal places an amount in dollars takes: 2, to the cent.
	UsdDecimalPlaceCount int
}

// The values above.
func defaultUrComputeSettings() *urComputeSettings {
	return &urComputeSettings{
		ApprovalPollInterval:       2 * time.Second,
		ApprovalWaitTimeout:        10 * time.Minute,
		PromoCodeMaxCharacterCount: 32,
		UsdDecimalPlaceCount:       2,
	}
}

// ur compute's settings, how it lets an interval pass and opens a url, and the device's budgets, each of which a test
// replaces.
var (
	urComputeCommandSettings = defaultUrComputeSettings()
	urComputeWait            = func(ctx context.Context, timeout time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return nil
		}
	}
	urComputeOpenBrowser = openUrcliBrowser
	// The device's budgets and what is left of them, CACL's view (C§16.4); until it lands, refused.
	urComputeBudgets = func(ctx context.Context, cli *urCli, network string) ([]*urComputeBudget, error) {
		return nil, errUrComputeBudgetsUnbuilt
	}
)

// Where the device's budget view is not built yet: CACL's (C§16.4).
var errUrComputeBudgetsUnbuilt = errors.New("the device's budgets are not built yet (CACL's view of §16.4): nothing to show or raise from")

// One of the device's budgets as CACL's view gives it.
type urComputeBudget struct {
	// agent, a gateway grant or the device; its id.
	Subject   string     `json:"subject"`
	SubjectId sidecar.Id `json:"subject_id"`
	// day, month or run.
	Period      string `json:"period"`
	CapNanoUsd  int64  `json:"cap_nano_usd"`
	LeftNanoUsd int64  `json:"left_nano_usd"`
}

// One `ur compute` subcommand.
type urComputeSubcommand struct {
	// The words after compute that select it, which docopt reads as commands: budget raise.
	words []string
	// Its docopt usage lines, each starting "ur compute <words>", without the "Usage:" heading.
	usage string
	run   func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// The subcommands, the longest words first, so budget raise is tried before budget. Written only at init.
var urComputeSubcommands = []*urComputeSubcommand{}

// ur compute itself: its usage is its subcommands', rebuilt as each registers.
var urComputeCommand = &urCommand{
	name:    "compute",
	summary: "the compute balance: status, buy, redeem, auto-renew, charges, statement, refund, budgets and spend",
	run:     runUrCompute,
}

// Adds a subcommand at init. One whose words another holds, or with no words, usage or run, is a programming error,
// found at start.
func registerUrComputeSubcommand(subcommand *urComputeSubcommand) {
	if subcommand == nil || len(subcommand.words) == 0 || subcommand.usage == "" || subcommand.run == nil {
		panic("a ur compute subcommand registered without its words, usage or run")
	}
	for _, other := range urComputeSubcommands {
		if slices.Equal(other.words, subcommand.words) {
			panic(fmt.Sprintf("ur compute %s registered twice", strings.Join(subcommand.words, " ")))
		}
	}
	urComputeSubcommands = append(urComputeSubcommands, subcommand)
	slices.SortStableFunc(urComputeSubcommands, func(a *urComputeSubcommand, b *urComputeSubcommand) int {
		return len(b.words) - len(a.words)
	})
	usages := []string{}
	for _, registered := range urComputeSubcommands {
		usages = append(usages, registered.usage)
	}
	urComputeCommand.usage = strings.Join(usages, "\n")
}

// Registers ur compute and its subcommands.
func init() {
	registerUrCommand(urComputeCommand)
	for _, subcommand := range []*urComputeSubcommand{
		{words: []string{"status"}, usage: "  ur compute status [--json] [--network=<net>]", run: runUrComputeStatus},
		{
			words: []string{"buy"},
			usage: "  ur compute buy <pack> [--auto-renew=<mode>] [--network=<net>]\n" +
				"  ur compute buy --monthly=<credits> [--network=<net>]",
			run: runUrComputeBuy,
		},
		{words: []string{"redeem"}, usage: "  ur compute redeem <code> [--network=<net>]", run: runUrComputeRedeem},
		{
			words: []string{"auto-renew"},
			usage: "  ur compute auto-renew [--json] [--network=<net>]\n" +
				"  ur compute auto-renew threshold [--below=<usd>] [--pack=<credits>] [--month-limit=<usd>] [--network=<net>]\n" +
				"  ur compute auto-renew monthly <credits> [--network=<net>]\n" +
				"  ur compute auto-renew off (threshold | monthly) [--network=<net>]",
			run: runUrComputeAutoRenew,
		},
		{words: []string{"charges"}, usage: "  ur compute charges [--cursor=<cursor>] [--json] [--network=<net>]", run: runUrComputeCharges},
		{words: []string{"statement"}, usage: "  ur compute statement --month=<month> [--json] [--network=<net>]", run: runUrComputeStatement},
		{words: []string{"refund"}, usage: "  ur compute refund <lot> [--network=<net>]", run: runUrComputeRefund},
		{words: []string{"budget"}, usage: "  ur compute budget [ls] [--json] [--network=<net>]", run: runUrComputeBudget},
		{
			words: []string{"budget", "raise"},
			usage: "  ur compute budget raise <agent> (--day=<usd> | --month=<usd> | --run=<usd>) [--network=<net>]\n" +
				"  ur compute budget raise --grant=<grant> (--day=<usd> | --month=<usd> | --run=<usd>) [--network=<net>]",
			run: runUrComputeBudgetRaise,
		},
		{words: []string{"spend"}, usage: "  ur compute spend [--by=<dim>] [--json] [--network=<net>]", run: runUrComputeSpend},
	} {
		registerUrComputeSubcommand(subcommand)
	}
}

// Runs the subcommand whose words docopt matched.
func runUrCompute(ctx context.Context, cli *urCli, options docopt.Opts) error {
	for _, subcommand := range urComputeSubcommands {
		matched := true
		for _, word := range subcommand.words {
			if on, _ := options[word].(bool); !on {
				matched = false
				break
			}
		}
		if matched {
			return subcommand.run(ctx, cli, options)
		}
	}
	return errors.New("no compute subcommand matched")
}

// A refusal the server answered with a code, as a compute method replies it.
type urComputeRefusalError struct {
	code         string
	retryAfterMs uint32
}

// The code and its fix, never a message the server wrote.
func (self *urComputeRefusalError) Error() string {
	text := "refused: " + self.code
	if fix := urComputeRefusalFix(self.code); fix != "" {
		text += ": " + fix
	}
	if 0 < self.retryAfterMs {
		text += fmt.Sprintf(" (ask again in %d ms)", self.retryAfterMs)
	}
	return text
}

// What a person does about each refusal code the compute routes answer (§14.3, §9.11), as the device's client reads
// them; a code this table does not have prints alone.
func urComputeRefusalFix(code string) string {
	switch code {
	case "may_not_buy":
		return "only an Owner, a Billing admin or a member the policy grants compute:buy buys, redeems or sets auto-renew (§9.10)"
	case "may_not_see":
		return "your role sees no charges or spend: an Owner, Billing admin, Admin, Network admin, IT admin or Auditor sees the network's, a Member their own (§9.10)"
	case "consented_device_required":
		return "the spend view answers only on your own consented device: untagged, neither ephemeral nor admitted by a Delegation (§14.3)"
	case "role_required":
		return "an Owner or a Billing admin refunds (§9.12)"
	case "credential_refused":
		return "these routes take no agent's or MCP credential: run ur at your own terminal"
	case "not_built":
		return "the server does not serve this route yet"
	case "bad_request":
		return "the request did not take the route's form: check the command's arguments"
	case "internal":
		return "the server failed: try again later"
	case "sales_closed":
		return "credits go on sale once something your network may use can spend them (Q-BAL-13)"
	case "code_unknown":
		return "no promotion code reads so: check it, case aside"
	case "code_ended":
		return "the code's campaign has ended or its redemptions are spent"
	case "code_redeemed":
		return "this network has redeemed this code already"
	case "redeemed_recently":
		return "a network redeems one code in 30 days (§9.11)"
	case "paid_lot_required":
		return "this code is for a network that has bought credit: buy a pack first"
	case "daily_limit":
		return "today's purchases and codes reach the daily limit: try again tomorrow, UTC"
	case "balance_cap":
		return "the balance would pass its $10,000 cap"
	case "rate_limited":
		return "five codes failed today: try again tomorrow, UTC"
	}
	return ""
}

// Calls a compute method and decodes its reply into result, a refusal with a code becoming a *urComputeRefusalError.
func callUrCompute(ctx context.Context, cli *urCli, method string, params any, confirmed bool, result any) error {
	raw := json.RawMessage{}
	if err := cli.callDaemon(ctx, method, params, confirmed, &raw); err != nil {
		return err
	}
	refusal := &sidecar.DaemonComputeRefusalReply{}
	if json.Unmarshal(raw, refusal) == nil && refusal.Refusal != nil && refusal.Refusal.Code != "" {
		return &urComputeRefusalError{code: refusal.Refusal.Code, retryAfterMs: refusal.Refusal.RetryAfterMs}
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("%s answered out of shape: %w", method, err)
	}
	return nil
}

// Prints value as indented JSON, for --json.
func printUrComputeJson(cli *urCli, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	cli.printf("%s\n", data)
	return nil
}

// An amount in dollars, "12.50" or "$12.50", to the cent at most, as nano-USD, in exact integer arithmetic.
func parseUrComputeUsd(text string) (int64, error) {
	places := urComputeCommandSettings.UsdDecimalPlaceCount
	value := strings.TrimPrefix(strings.TrimSpace(text), "$")
	whole, fraction, hasFraction := strings.Cut(value, ".")
	if whole == "" || (hasFraction && (fraction == "" || places < len(fraction))) {
		return 0, fmt.Errorf("%q is no amount in dollars to the cent", text)
	}
	for _, part := range []string{whole, fraction} {
		for _, c := range part {
			if c < '0' || '9' < c {
				return 0, fmt.Errorf("%q is no amount in dollars to the cent", text)
			}
		}
	}
	dollars, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || (1<<62)/urComputeNanoUsdPerUsd < dollars {
		return 0, fmt.Errorf("%q is out of range", text)
	}
	nanoUsd := dollars * urComputeNanoUsdPerUsd
	if fraction != "" {
		fractionNanoUsd, _ := strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
		nanoUsd += fractionNanoUsd
	}
	return nanoUsd, nil
}

// A count of credits, a positive whole number.
func parseUrComputeCredits(text string) (int64, error) {
	credits, err := strconv.ParseInt(text, 10, 64)
	if err != nil || credits <= 0 {
		return 0, fmt.Errorf("%q is no count of credits", text)
	}
	return credits, nil
}

// A name as ur prints it: plain where a signed source vouches for it, else between the untrusted-data markers with its
// writer, or unknown.
func urComputeName(name *sidecar.ComputeDisplayName) string {
	if name == nil {
		return "unknown"
	}
	return name.ModelText()
}

// The balance, the state and auto-renew.
func runUrComputeStatus(ctx context.Context, cli *urCli, options docopt.Opts) error {
	balance := &sidecar.ComputeBalance{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeBalance, &sidecar.DaemonComputeParams{Network: urOptionString(options, "--network")}, false, balance); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		return printUrComputeJson(cli, balance)
	}
	cli.printf("balance    %s, holds left out (%s held, %s available)\n", sidecar.ComputeMoneyText(balance.BalanceNanoUsd),
		sidecar.ComputeMoneyText(balance.HeldNanoUsd), sidecar.ComputeMoneyText(balance.AvailableNanoUsd))
	if 0 < balance.PromoNanoUsd {
		cli.printf("promotion  %s of it, which pays no web search\n", sidecar.ComputeMoneyText(balance.PromoNanoUsd))
	}
	cli.printf("state      %s\n", balance.State)
	printUrComputeAutoRenew(cli, balance.AutoRenew)
	switch {
	case !balance.MayBuy:
		cli.printf("buy        not this person: %s\n", urComputeRefusalFix("may_not_buy"))
	case !balance.SalesOpen:
		cli.printf("buy        closed: %s\n", urComputeRefusalFix("sales_closed"))
	default:
		cli.printf("buy        open to this person: ur compute buy <pack>\n")
	}
	if 0 < len(balance.AtRiskEnclaveIds) {
		cli.printf("at risk    %d enclaves a suspension would stop\n", len(balance.AtRiskEnclaveIds))
	}
	if balance.IndexerDaysLeft != nil {
		cli.printf("indexer    %d days of reserve and grace left\n", *balance.IndexerDaysLeft)
	}
	if !balance.UpdateTime.IsZero() {
		cli.printf("as of      %s, the last settlement\n", balance.UpdateTime.UTC().Format(time.RFC3339))
	}
	return nil
}

// Both auto-renew modes, a threshold turned off with why.
func printUrComputeAutoRenew(cli *urCli, autoRenew *sidecar.ComputeAutoRenew) {
	if autoRenew == nil {
		autoRenew = &sidecar.ComputeAutoRenew{}
	}
	switch threshold := autoRenew.Threshold; {
	case threshold == nil:
		cli.printf("threshold  off\n")
	case threshold.On:
		cli.printf("threshold  on: %d credits once the balance falls below %s, at most %s a month\n", threshold.PackCredits,
			sidecar.ComputeMoneyText(threshold.BelowNanoUsd), sidecar.ComputeMoneyText(threshold.MonthLimitNanoUsd))
	case threshold.OffReason != "":
		cli.printf("threshold  off: %s\n", urComputeOffReasonText(threshold.OffReason))
	default:
		cli.printf("threshold  off\n")
	}
	switch monthly := autoRenew.Monthly; {
	case monthly != nil && monthly.On:
		cli.printf("monthly    on: %d credits a month, through %s\n", monthly.Credits, monthly.Market)
	default:
		cli.printf("monthly    off\n")
	}
}

// Why threshold top-up turned off (§9.8), for a person.
func urComputeOffReasonText(reason string) string {
	switch reason {
	case sidecar.ComputeAutoRenewOffAuthenticationRequired:
		return "a top-up asked for the card's authentication: the emailed link turns it back on"
	case sidecar.ComputeAutoRenewOffFailed:
		return "three top-ups failed in a row: ur compute auto-renew threshold turns it back on"
	case sidecar.ComputeAutoRenewOffPayerLeft:
		return "the member whose card it charged left or lost the right to buy: another saves a card with ur compute buy <pack> --auto-renew=threshold"
	}
	return reason
}

// A pack through Checkout: the url printed and opened.
func runUrComputeBuy(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urOptionString(options, "--network")
	args := &sidecar.ComputeCheckoutArgs{}
	if monthly := urOptionString(options, "--monthly"); monthly != "" {
		credits, err := parseUrComputeCredits(monthly)
		if err != nil {
			return err
		}
		args.AutoRenew = sidecar.ComputeAutoRenewMonthly
		args.MonthlyCredits = credits
	} else {
		credits, err := parseUrComputeCredits(urOptionString(options, "<pack>"))
		if err != nil {
			return err
		}
		args.PackCredits = credits
		switch mode := urOptionString(options, "--auto-renew"); mode {
		case "":
		case string(sidecar.ComputeAutoRenewThreshold):
			args.AutoRenew = sidecar.ComputeAutoRenewThreshold
		default:
			return fmt.Errorf("--auto-renew=%s: a pack turns on threshold top-up alone; the monthly plan is ur compute buy --monthly=<credits>", mode)
		}
	}
	balance := &sidecar.ComputeBalance{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeBalance, &sidecar.DaemonComputeParams{Network: network}, false, balance); err != nil {
		return err
	}
	if !balance.MayBuy {
		return &urComputeRefusalError{code: "may_not_buy"}
	}
	if !balance.SalesOpen {
		return &urComputeRefusalError{code: "sales_closed"}
	}
	if 0 < args.PackCredits {
		packs := &sidecar.DaemonComputePacksReply{}
		if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputePacks, &sidecar.DaemonComputePacksParams{Network: network, Market: sidecar.ComputeMarketStripe.String()}, false, packs); err != nil {
			return err
		}
		sold := []string{}
		found := false
		for _, pack := range packs.Packs {
			if !pack.Monthly {
				sold = append(sold, strconv.FormatInt(pack.Credits, 10))
				found = found || pack.Credits == args.PackCredits
			}
		}
		if !found {
			return fmt.Errorf("no pack of %d credits: the packs are %s", args.PackCredits, strings.Join(sold, ", "))
		}
	}
	checkout := &sidecar.ComputeCheckout{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeCheckout, &sidecar.DaemonComputeCheckoutParams{Network: network, ComputeCheckoutArgs: *args}, false, checkout); err != nil {
		return err
	}
	cli.printf("checkout   %s\n", checkout.Url)
	if !checkout.ExpireTime.IsZero() {
		cli.printf("until      %s; the credit lands once the payment does\n", checkout.ExpireTime.UTC().Format(time.RFC3339))
	}
	if err := urComputeOpenBrowser(checkout.Url); err != nil {
		cli.printf("open the url above in a browser: %s\n", err)
	}
	return nil
}

// A promotion code, confirmed on /dev/tty: see the file header.
func runUrComputeRedeem(ctx context.Context, cli *urCli, options docopt.Opts) error {
	code := urOptionString(options, "<code>")
	if code == "-" {
		line, err := readPassFromTty(cli, "Promotion code: ")
		if err != nil {
			return err
		}
		code = string(line)
		clear(line)
	}
	code = strings.TrimSpace(code)
	if code == "" || urComputeCommandSettings.PromoCodeMaxCharacterCount < len(code) {
		return fmt.Errorf("a promotion code is 1 to %d letters and digits", urComputeCommandSettings.PromoCodeMaxCharacterCount)
	}
	for _, c := range code {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return errors.New("a promotion code is letters and digits alone")
		}
	}
	shown := code
	if 4 < len(code) {
		shown = "…" + code[len(code)-4:]
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Redeem the promotion code %s for this network?", shown))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: nothing was redeemed")
	}
	redemption := &sidecar.ComputeRedemption{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeRedeem, &sidecar.DaemonComputeRedeemParams{Network: urOptionString(options, "--network"), Code: code}, true, redemption); err != nil {
		return err
	}
	cli.printf("redeemed   %s of promotional credit, lot %s\n", sidecar.ComputeMoneyText(redemption.CreditNanoUsd), redemption.LotId)
	cli.printf("lapses     %s; it pays for inference and enclaves, never web search\n", redemption.ExpireTime.UTC().Format(time.RFC3339))
	return nil
}

// §9.8's modes, shown, or one changed after a yes on /dev/tty.
func runUrComputeAutoRenew(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urOptionString(options, "--network")
	threshold, _ := options["threshold"].(bool)
	monthly, _ := options["monthly"].(bool)
	off, _ := options["off"].(bool)
	if !threshold && !monthly {
		autoRenew := &sidecar.ComputeAutoRenew{}
		if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeAutoRenew, &sidecar.DaemonComputeParams{Network: network}, false, autoRenew); err != nil {
			return err
		}
		if on, _ := options["--json"].(bool); on {
			return printUrComputeJson(cli, autoRenew)
		}
		printUrComputeAutoRenew(cli, autoRenew)
		return nil
	}
	change := &sidecar.ComputeAutoRenewChange{On: !off}
	question := ""
	switch {
	case threshold:
		change.Mode = sidecar.ComputeAutoRenewThreshold
		if off {
			question = "Turn threshold top-up off for this network? Charges already sent to Stripe stand."
			break
		}
		var err error
		if below := urOptionString(options, "--below"); below != "" {
			if change.BelowNanoUsd, err = parseUrComputeUsd(below); err != nil {
				return err
			}
		}
		if pack := urOptionString(options, "--pack"); pack != "" {
			if change.PackCredits, err = parseUrComputeCredits(pack); err != nil {
				return err
			}
		}
		if limit := urOptionString(options, "--month-limit"); limit != "" {
			if change.MonthLimitNanoUsd, err = parseUrComputeUsd(limit); err != nil {
				return err
			}
		}
		question = "Turn threshold top-up on for this network, charging the card you saved for it?"
	case monthly:
		change.Mode = sidecar.ComputeAutoRenewMonthly
		if off {
			question = "Turn the monthly plan off for this network? Credits already granted stay."
			break
		}
		credits, err := parseUrComputeCredits(urOptionString(options, "<credits>"))
		if err != nil {
			return err
		}
		change.Credits = credits
		question = fmt.Sprintf("Turn the monthly plan on for this network at %d credits a month?", credits)
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: auto-renew is as it was")
	}
	autoRenew := &sidecar.ComputeAutoRenew{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeAutoRenewSet, &sidecar.DaemonComputeAutoRenewSetParams{Network: network, ComputeAutoRenewChange: *change}, true, autoRenew); err != nil {
		return err
	}
	printUrComputeAutoRenew(cli, autoRenew)
	return nil
}

// A page of charges, each named on the device.
func runUrComputeCharges(ctx context.Context, cli *urCli, options docopt.Opts) error {
	view := &sidecar.ComputeChargesView{}
	params := &sidecar.DaemonComputeChargesParams{Network: urOptionString(options, "--network"), Cursor: urOptionString(options, "--cursor")}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeCharges, params, false, view); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		return printUrComputeJson(cli, view)
	}
	for _, row := range view.Charges {
		charge := row.Charge
		cli.printf("%s  %s  %s\n", charge.StartTime.UTC().Format(time.RFC3339), charge.Kind, sidecar.ComputeMoneyText(charge.AmountNanoUsd))
		cli.printf("  model %s, provider %s, member %s, agent %s, sidecar %s\n", urComputeName(row.Names.Model), urComputeName(row.Names.Provider),
			urComputeName(row.Names.Member), urComputeName(row.Names.Agent), urComputeName(row.Names.Sidecar))
		if 0 < charge.AbsorbedNanoUsd {
			cli.printf("  URnetwork covered %s past the call's budget reservation\n", sidecar.ComputeMoneyText(charge.AbsorbedNanoUsd))
		}
	}
	if view.NextCursor != "" {
		cli.printf("more: ur compute charges --cursor=%s\n", view.NextCursor)
	}
	return nil
}

// A UTC month's statement and its lots.
func runUrComputeStatement(ctx context.Context, cli *urCli, options docopt.Opts) error {
	view := &sidecar.ComputeStatementView{}
	params := &sidecar.DaemonComputeStatementParams{Network: urOptionString(options, "--network"), Month: urOptionString(options, "--month")}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeStatement, params, false, view); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		return printUrComputeJson(cli, view)
	}
	cli.printf("statement %s, UTC days; Stripe's and the stores' receipts are the tax documents\n", view.Month)
	for _, row := range view.Rows {
		line := fmt.Sprintf("%s  %s  %s, %d charges", row.Row.Day, row.Row.Kind, sidecar.ComputeMoneyText(row.Row.AmountNanoUsd), row.Row.Count)
		if 0 < row.Row.RefundedNanoUsd {
			line += fmt.Sprintf(", after %s refunded", sidecar.ComputeMoneyText(row.Row.RefundedNanoUsd))
		}
		cli.printf("%s\n", line)
		cli.printf("  model %s, member %s, agent %s, enclave %s\n", urComputeName(row.Names.Model), urComputeName(row.Names.Member),
			urComputeName(row.Names.Agent), urComputeName(row.Names.Enclave))
	}
	for _, lot := range view.Lots {
		line := fmt.Sprintf("lot %s  %s through %s, %s, %s left", lot.LotId, urComputeLotKindText(lot.Kind), lot.Market, sidecar.ComputeMoneyText(lot.AmountNanoUsd), sidecar.ComputeMoneyText(lot.RemainingNanoUsd))
		if lot.LapsedNanoUsd != nil && 0 < *lot.LapsedNanoUsd {
			line += fmt.Sprintf(", %s lapsed", sidecar.ComputeMoneyText(*lot.LapsedNanoUsd))
		}
		cli.printf("%s\n", line)
	}
	return nil
}

// A lot's kind, as §9.4 names it.
func urComputeLotKindText(kind sidecar.ComputeLotKind) string {
	switch kind {
	case sidecar.ComputeLotKindPurchase:
		return "purchase"
	case sidecar.ComputeLotKindSubscription:
		return "subscription grant"
	case sidecar.ComputeLotKindPromotion:
		return "promotion"
	case sidecar.ComputeLotKindAdjustment:
		return "adjustment"
	}
	return fmt.Sprintf("lot kind %d", kind)
}

// A Stripe lot's unspent part, after a yes on /dev/tty.
func runUrComputeRefund(ctx context.Context, cli *urCli, options docopt.Opts) error {
	lotId, err := sidecar.ParseId(urOptionString(options, "<lot>"))
	if err != nil {
		return fmt.Errorf("<lot> is a lot's id, as ur compute statement lists it")
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Refund what is unspent of lot %s to its card? What it paid for stays charged.", lotId))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: nothing was refunded")
	}
	refund := &sidecar.ComputeRefund{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeRefund, &sidecar.DaemonComputeRefundParams{Network: urOptionString(options, "--network"), LotId: &lotId}, true, refund); err != nil {
		return err
	}
	cli.printf("refunded   %s of lot %s to its card\n", sidecar.ComputeMoneyText(refund.RefundedNanoUsd), refund.LotId)
	return nil
}

// The device's budgets and what is left of them.
func runUrComputeBudget(ctx context.Context, cli *urCli, options docopt.Opts) error {
	budgets, err := urComputeBudgets(ctx, cli, urOptionString(options, "--network"))
	if err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		return printUrComputeJson(cli, budgets)
	}
	for _, budget := range budgets {
		cli.printf("%-8s %s  %s a %s, %s left\n", budget.Subject, budget.SubjectId, sidecar.ComputeMoneyText(budget.CapNanoUsd), budget.Period,
			sidecar.ComputeMoneyText(budget.LeftNanoUsd))
	}
	return nil
}

// Files kind 21 for a raise and waits for its approval: see the file header.
func runUrComputeBudgetRaise(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urOptionString(options, "--network")
	args := &sidecar.ComputeBudgetRaiseArgs{}
	subject := "agent"
	var subjectId sidecar.Id
	if grant := urOptionString(options, "--grant"); grant != "" {
		id, err := sidecar.ParseId(grant)
		if err != nil {
			return errors.New("--grant names a gateway grant's id")
		}
		args.GrantId = &id
		subject, subjectId = "grant", id
	} else {
		id, err := sidecar.ParseId(urOptionString(options, "<agent>"))
		if err != nil {
			return errors.New("<agent> is an agent's id")
		}
		args.AgentId = &id
		subjectId = id
	}
	for _, period := range []string{"day", "month", "run"} {
		if amount := urOptionString(options, "--"+period); amount != "" {
			nanoUsd, err := parseUrComputeUsd(amount)
			if err != nil {
				return err
			}
			args.Period = period
			args.AmountNanoUsd = nanoUsd
		}
	}
	// the current amount, which the approver sees beside the new one, from the device's budgets
	budgets, err := urComputeBudgets(ctx, cli, network)
	if err != nil {
		return fmt.Errorf("%w; nothing was filed", err)
	}
	current := (*urComputeBudget)(nil)
	for _, budget := range budgets {
		if budget.Subject == subject && budget.SubjectId == subjectId && budget.Period == args.Period {
			current = budget
		}
	}
	if current == nil {
		return fmt.Errorf("the device holds no %s budget of that %s: nothing was filed", args.Period, subject)
	}
	args.CurrentNanoUsd = current.CapNanoUsd
	if args.AmountNanoUsd <= args.CurrentNanoUsd {
		return fmt.Errorf("a raise is above the budget's %s: nothing was filed", sidecar.ComputeMoneyText(args.CurrentNanoUsd))
	}
	params := &sidecar.DaemonComputeBudgetRaiseParams{Network: network, ComputeBudgetRaiseArgs: *args}
	settings := urComputeCommandSettings
	waited := time.Duration(0)
	prompted := false
	for {
		result := &sidecar.ComputeBudgetRaiseResult{}
		if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeBudgetRaise, params, false, result); err != nil {
			return err
		}
		if result.Outcome == sidecar.ComputeBudgetRaiseDone {
			cli.printf("raised     the %s's %s budget from %s to %s\n", subject, args.Period, sidecar.ComputeMoneyText(args.CurrentNanoUsd), sidecar.ComputeMoneyText(args.AmountNanoUsd))
			return nil
		}
		if result.Outcome != sidecar.ComputeBudgetRaisePending || result.ApprovalId == nil {
			return fmt.Errorf("the raise answered %q", result.Outcome)
		}
		if !prompted {
			cli.printf("approval pending: run ur approve %s on an approval-capable device; waiting\n", result.ApprovalId)
			prompted = true
		}
		if settings.ApprovalWaitTimeout <= waited {
			return &urExitError{code: urExitFailed, err: fmt.Errorf("approval %s is still pending: run this again once it is decided", result.ApprovalId)}
		}
		if err := urComputeWait(ctx, settings.ApprovalPollInterval); err != nil {
			return err
		}
		waited += max(settings.ApprovalPollInterval, time.Millisecond)
	}
}

// §9.13's spend view: see the file header.
func runUrComputeSpend(ctx context.Context, cli *urCli, options docopt.Opts) error {
	by := urOptionString(options, "--by")
	if _, err := sidecar.ParseComputeSpendBy(by); err != nil {
		return fmt.Errorf("--by is provider, model, enclave, member or agent")
	}
	view := &sidecar.ComputeSpendView{}
	if err := callUrCompute(ctx, cli, sidecar.DaemonMethodComputeSpend, &sidecar.DaemonComputeSpendParams{Network: urOptionString(options, "--network"), By: by}, false, view); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		return printUrComputeJson(cli, view)
	}
	printUrComputeSpend(cli, view)
	return nil
}

// The figures' sum of days.
func urComputeDaysSum(days []*sidecar.ComputeSpendFigures) int64 {
	sum := int64(0)
	for _, day := range days {
		if day != nil {
			sum += day.AmountNanoUsd
		}
	}
	return sum
}

// A figure with its refunds beside, as §9.13 shows them.
func urComputeFigureText(figures *sidecar.ComputeSpendFigures) string {
	if figures == nil {
		return sidecar.ComputeMoneyText(0)
	}
	text := sidecar.ComputeMoneyText(figures.AmountNanoUsd)
	if 0 < figures.RefundedNanoUsd {
		text += " after " + sidecar.ComputeMoneyText(figures.RefundedNanoUsd) + " refunded"
	}
	return text
}

// Prints view: every service together, then each line, its total since the first charge and its 7 days, then its rows;
// by agent, a row's 7 days alone, since no total keeps an agent (Q-BAL-10).
func printUrComputeSpend(cli *urCli, view *sidecar.ComputeSpendView) {
	since := view.FirstChargeDay
	if since == "" {
		since = "no charge yet"
	}
	if window := sidecar.ComputeSpendWindowText(view, time.Local); window != "" {
		cli.printf("7 days     %s\n", window)
	}
	cli.printf("since      %s; exact as of %s\n", since, view.UpdateTime.UTC().Format(time.RFC3339))
	cli.printf("all        %s in all, %s in the 7 days, %s held apart\n", urComputeFigureText(view.AllTotal),
		sidecar.ComputeMoneyText(urComputeDaysSum(view.AllDays)), sidecar.ComputeMoneyText(view.HeldNanoUsd))
	for _, line := range view.Lines {
		cli.printf("%s (%s)  %s in all, %s in the 7 days\n", line.Service, line.Kind, urComputeFigureText(line.Total),
			sidecar.ComputeMoneyText(urComputeDaysSum(line.Days)))
		for _, row := range line.Rows {
			if view.By == sidecar.ComputeSpendByAgent {
				cli.printf("  %s  %s in the 7 days\n", urComputeName(row.Name), sidecar.ComputeMoneyText(urComputeDaysSum(row.Row.Days)))
				continue
			}
			cli.printf("  %s  %s in all, %s in the 7 days\n", urComputeName(row.Name), urComputeFigureText(row.Row.Total),
				sidecar.ComputeMoneyText(urComputeDaysSum(row.Row.Days)))
		}
	}
	for _, service := range view.WithoutCharge {
		cli.printf("%s  no charge: its bytes count toward the transfer balance\n", service)
	}
}
