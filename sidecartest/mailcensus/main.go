// mailcensus (MAIL-M7-26; D-MAIL-9, QD-118): the inbound census's table, from a run's three records, each a
// JSON file:
//
//	mailcensus -sends sends.json -counters counters.json -received received.json
//
// sends.json is the census list's sends, []CensusSend; counters.json the router's urnetwork_mxedge_*
// scrapes across the run, []CensusCounterSnapshot (ParseCensusCounterText reads a scrape); received.json
// the test receiver's view, []CensusReceived. The table goes to standard output, one row a sender and the
// SNI loss against D-MAIL-9's proposed bar, which the owner accepts or refuses. It sends nothing, and it
// writes out no address. Exit 0 with a table, 1 when an input cannot be read, 2 on a usage error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	sendsPath := flag.String("sends", "", "the census list's sends, as JSON")
	countersPath := flag.String("counters", "", "the router's counter scrapes across the run, as JSON")
	receivedPath := flag.String("received", "", "the test receiver's view, as JSON")
	flag.Parse()
	if *sendsPath == "" || *countersPath == "" || *receivedPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	sends := []*CensusSend{}
	snapshots := []*CensusCounterSnapshot{}
	received := []*CensusReceived{}
	for path, into := range map[string]any{*sendsPath: &sends, *countersPath: &snapshots, *receivedPath: &received} {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mailcensus: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, into); err != nil {
			// the file's name, never its content, which holds test addresses
			fmt.Fprintf(os.Stderr, "mailcensus: %s does not decode\n", path)
			os.Exit(1)
		}
	}
	table, err := BuildCensus(DefaultCensusSettings(), sends, snapshots, received)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mailcensus: %v\n", err)
		os.Exit(1)
	}
	if err := table.WriteText(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mailcensus: %v\n", err)
		os.Exit(1)
	}
}
