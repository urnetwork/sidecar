# PiG's fixtures in the Harness's goldens

github.com/MichaelKinsy/PiG v0.7.0 (h1:afCNB1Jg/m67tKonylq7vfLe5zFCGRzqAl0bL1iOiEg=, Pi 1.5.0 at f9a26365),
a Go port of Mario Zechner's Pi coding agent, is the pinned source of the Pi 1.5.0 goldens the Harness's
formats are held to (DESIGN-COMPUTE.md §7.3, HARN-M11-01, QD-1255). No code of it is in this repository and no
go.mod requires it: only lines of its fixtures and of the Pi 1.5.0 documentation it embeds, copied unchanged
into testdata/harness/pi-1.5.0/, which testdata/harness/pi-1.5.0/SOURCES.md lists line by line. They are under
PiG's MIT license, in LICENSE beside this file, Copyright Michael Kinsy; the Pi documentation PiG embeds is
Pi's, under the MIT license, Copyright (c) 2025 Mario Zechner, as PiG's NOTICE says.

The proxy serves v0.7.0, not main's 40b509fb, which the design names: a release was retracted for passing Go's
module size limit, and the newest the proxy serves is taken (QD-1255). Pi's formats are re-checked against
PiG's main at M11's and M14's entries (§19.8, §7.15).
