// §15's census probe of outbound coverage (SMTP-M7-01, D-SMTP-16, D-MAIL-9): for each domain in a
// list, one JSON row naming only the domain, its TLS version and suite, covered or not, and CHUNKING
// and PIPELINING before and after TLS. It sends no MAIL and no mail. Run it from a host with outbound
// TCP 25 whose PTR names the -helo name, as FCrDNS asks; the domain list, such as a ranking's top
// domains, is the operator's input and is never kept in the repository.
//
//	mxprobe -helo <name> -domains <file> [-stop <file>] [-interval 10s] [-timeout 60s] [-mx 3] > rows.jsonl
//
// Touching the stop file ends the run before its next domain.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/urnetwork/sidecar/smtpproof"
)

func main() {
	defaults := smtpproof.DefaultMxProbeSettings()
	helo := flag.String("helo", "", "the EHLO name, which the probing address's PTR names")
	domainsPath := flag.String("domains", "", "a file of domains, one a line, # starting a comment")
	stop := flag.String("stop", "", "a path whose file, once it exists, ends the run")
	interval := flag.Duration("interval", defaults.DestinationInterval, "the least time between two dials into one /24")
	timeout := flag.Duration("timeout", defaults.MxTimeout, "how long one MX's exchange may take")
	mxCount := flag.Int("mx", defaults.MxCount, "the most MXs tried per domain")
	flag.Parse()
	if *helo == "" || *domainsPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: mxprobe -helo <name> -domains <file> [-stop <file>] [-interval 10s] [-timeout 60s] [-mx 3]")
		os.Exit(64)
	}
	file, err := os.Open(*domainsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mxprobe: %v\n", err)
		os.Exit(1)
	}
	domains := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if domain := strings.TrimSpace(line); domain != "" {
			domains = append(domains, domain)
		}
	}
	file.Close()
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "mxprobe: %v\n", err)
		os.Exit(1)
	}
	settings := defaults
	settings.HeloName = *helo
	settings.StopFile = *stop
	settings.DestinationInterval = *interval
	settings.MxTimeout = *timeout
	settings.MxCount = *mxCount
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	err = smtpproof.ProbeMx(ctx, domains, settings, func(result *smtpproof.MxProbeResult) {
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "mxprobe: %v\n", err)
			os.Exit(1)
		}
	})
	if errors.Is(err, smtpproof.ErrMxProbeStopped) {
		fmt.Fprintln(os.Stderr, "mxprobe: stopped by the stop file")
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mxprobe: %v\n", err)
		os.Exit(1)
	}
}
