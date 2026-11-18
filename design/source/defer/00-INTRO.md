# Deferred decisions

Every decision the sidecar design defers, one entry each (owner decision 587): a feature, mechanism, row or task that the owner or the design moves to Later, past launch or to a later version. [DESIGN.md](DESIGN.md) says what is built; this document says what is not built yet, why, what stands in its place, and what bringing it back would take.

This file is generated, as DESIGN.md is. Its entries are in `design/source/defer/`, one file per DESIGN.md section, and `design/source/build.sh` assembles and checks them; `design/source/README.md` says how. Never edit this file by hand.

## How to read an entry

The stages are §23.4's. **v0** is what personal networks get at launch: milestones M0-M5 and M7-M9, with app hosts at M8. **v1** is M6, M10 and M7-M9's Team items; it is built in the same run as v0, on the same branches, and ships behind its milestones' gates. **Later** is everything outside M0-M10: it has no milestone, and unless its entry says otherwise it has no task and no code.

Each entry gives seven things:

- **Deferred.** What is deferred, with its ids: owner decisions, D-, Q- and R- items, the build's ledger ids (QD-), tasks and FS rows.
- **Why.** The reason the owner or the design gave. Where DESIGN.md gives none, the entry says so.
- **Launch instead.** What launch does in its place.
- **Lost.** What a user or an operator goes without until it returns.
- **Dark in code.** What is already built and switched off, and where, or the seam and the check that keep the place for it.
- **Held.** Tasks and tracks that wait on it.
- **To bring back.** What it would take: the design still to write, the decision to make, the trigger to watch, the switch to turn.

Under each entry's title are its stage and the subsections of DESIGN.md that point at it. A section points at an entry with one line where it describes the deferred thing.

## What is not here

- What the design rules out. §1.7's non-goals and each section's rejected alternatives are decisions, not deferrals.
- App, console and extension screens. Owner rule 6 puts the apps' UI out of scope, and the design gives the seams it uses.
- Work the build's review phase finishes before launch. That work is inside M0-M10.
- A reversal. A mechanism the owner removes has no entry; the owner decision that removes it says what went.

## Adding an entry

A design-records pass that folds a deferral adds its entry here in the same change: the entry in `design/source/defer/`, under the section that owns the deferred thing, and a pointer in each DESIGN.md section the deferral touches. The build fails on an entry that lacks a field, on an entry no section points at, on a pointer to an entry that does not exist, and on an entry that cites an R-, D- or Q- item or a subsection DESIGN.md does not hold. When a deferred thing is built, its entry is deleted with its pointers, and the owner decision that brings it back says so.
