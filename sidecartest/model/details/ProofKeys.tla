------------------------------ MODULE ProofKeys ------------------------------
(* DESIGN-DETAILS.md section 3.2.7: a prover host's proving keys across key sets, releases and its cache, and
   the key sets an edge accepts.

   A key set is the published record of one ceremony: per shape a transcript and the keys it fixes, named by
   hash in keyset.json, whose own hash is the set's id. One shape stands for all here. What a set really is
   does not depend on what anyone believes: setCirc[s] is the circuit its ceremony ran over, and setWf[s]
   whether its keys have the form zero knowledge needs. Both are chosen freely at the start, because the
   party that ran the ceremony and pinned the set is the edge, which zero knowledge does not trust: a pinned
   set may be malformed, or be for another circuit than the release that pins it compiles.

   A release is a build: the circuit its source compiles and the sets it pins. Any build may be installed
   over any other at any time, a careless one included. The host's own check of a set's transcript against
   the circuit its build compiles passes exactly when the set is well formed and is for that circuit. What it
   passes it writes to the cache under another name and then renames; a crash between leaves a torn file.

   The design keys a cache entry by the set and by the digest of the circuit it was checked against, and a
   build takes only the entry of its own circuit. A proof under a key that is malformed, torn, or of another
   circuit than the one proving is not zero knowledge, whatever the edge then does with it.

   The edge accepts the sets its configuration lists. A connection declares one set in its preamble, the edge
   admits it only if that set is accepted then, and every part of the connection verifies under that set.
   Retiring a set is a configuration change, which restarts the edge and ends its connections.

   What is checked:
     ZkSafe          every proof was made under a well-formed, whole key of the circuit that proved
     AcceptedAtOpen  no connection opens under a set the edge does not accept at that moment
     OneSet          every part of a connection verified under the set its preamble declared

   Twin selects one rule to break:
     TrustPublished  the host caches a set's published key by its hash, with no transcript check
     PartialStands   a torn file left by a crash is taken as a cache entry
     AcceptRetired   the edge admits any set it still holds keys for
     MixedSets       a part names its own set, and the edge verifies it under that one

   Written is the cache as it landed (setup_keys.go): an entry is named by the proving key's hash alone, and
   a shape whose file exists is neither checked again nor matched to the circuit that will prove with it.

   Left out: the download, whose every file is checked against keyset.json's hashes before it is read, so a
   wrong file is a missing file; the shapes of a set, each of which is one more copy of this; soundness of
   the edge's own keys, which rests on the ceremony it ran. *)
EXTENDS Integers, FiniteSets

CONSTANTS
    Twin,
    Written,    \* TRUE: the cache as it landed
    MaxProofs   \* parts proven over the run

Sets == {"A", "B"}
Circs == {"c1", "c2"}
Builds == [circ : Circs, pins : (SUBSET Sets) \ {{}}]
None == [none |-> TRUE]

VARIABLES
    setCirc, setWf,     \* what each published set really is
    build,              \* the host's installed build
    cache,              \* entries its check wrote: [set, circ, torn]
    writing,            \* a checked key between the write and the rename, or None
    accept, retired,    \* the edge's accepted sets, and those it has retired
    conn,               \* the open connection: [set, safe, open], or None
    proofs,             \* history: [set, safe] of every part proven
    opened,             \* history: whether each connection's set was accepted when it opened
    mixed,              \* history: a part verified under a set its connection did not declare
    count

vars == <<setCirc, setWf, build, cache, writing, accept, retired, conn, proofs, opened, mixed, count>>

Init ==
    /\ setCirc \in [Sets -> Circs]
    /\ setWf \in [Sets -> BOOLEAN]
    /\ build \in Builds
    /\ cache = {} /\ writing = None
    /\ accept = {"A"} /\ retired = {}
    /\ conn = None /\ proofs = {} /\ opened = {} /\ mixed = FALSE /\ count = 0

(* A release replaces another: a new process, which abandons a write in flight and a connection. *)
Install(b) ==
    /\ b # build
    /\ build' = b
    /\ writing' = None /\ conn' = None
    /\ UNCHANGED <<setCirc, setWf, cache, accept, retired, proofs, opened, mixed, count>>

CheckPasses(s) == Twin = "TrustPublished" \/ (setWf[s] /\ setCirc[s] = build.circ)

(* The entry this build would take for set s. *)
Usable(s) ==
    {e \in cache : /\ e.set = s
                   /\ (Written \/ e.circ = build.circ)
                   /\ (Twin = "PartialStands" \/ ~e.torn)}

(* The host's check, at idle: the transcript against the circuit this build compiles. *)
BeginVerify(s) ==
    /\ s \in build.pins
    /\ writing = None
    \* as landed, a shape whose file exists is skipped whatever it was checked against
    /\ IF Written THEN ~\E e \in cache : e.set = s ELSE Usable(s) = {}
    /\ CheckPasses(s)
    /\ writing' = [set |-> s, circ |-> build.circ]
    /\ UNCHANGED <<setCirc, setWf, build, cache, accept, retired, conn, proofs, opened, mixed, count>>

FinishVerify ==
    /\ writing # None
    /\ cache' = cache \cup {[set |-> writing.set, circ |-> writing.circ, torn |-> FALSE]}
    /\ writing' = None
    /\ UNCHANGED <<setCirc, setWf, build, accept, retired, conn, proofs, opened, mixed, count>>

(* The process dies mid-write. *)
Crash ==
    /\ writing # None
    /\ cache' = cache \cup {[set |-> writing.set, circ |-> writing.circ, torn |-> TRUE]}
    /\ writing' = None /\ conn' = None
    /\ UNCHANGED <<setCirc, setWf, build, accept, retired, proofs, opened, mixed, count>>

(* Whether a proof by this build under entry e is zero knowledge: ground truth, not belief. *)
Safe(e) == setWf[e.set] /\ setCirc[e.set] = build.circ /\ ~e.torn

(* A send: the preamble declares the set, and the edge admits it or answers that it holds no such keys. *)
Open(s, e) ==
    /\ conn = None
    /\ s \in build.pins
    /\ e \in Usable(s)
    /\ (Twin = "AcceptRetired" \/ s \in accept)
    /\ conn' = [set |-> s, safe |-> Safe(e)]
    /\ opened' = opened \cup {s \in accept}
    /\ UNCHANGED <<setCirc, setWf, build, cache, writing, accept, retired, proofs, mixed, count>>

Prove(s) ==
    /\ conn # None
    /\ count < MaxProofs
    /\ IF Twin = "MixedSets" THEN \E e \in Usable(s) : TRUE ELSE s = conn.set
    /\ proofs' = proofs \cup {[set |-> s, safe |-> IF s = conn.set THEN conn.safe ELSE \A e \in Usable(s) : Safe(e)]}
    /\ mixed' = (mixed \/ s # conn.set)
    /\ count' = count + 1
    /\ UNCHANGED <<setCirc, setWf, build, cache, writing, accept, retired, conn, opened>>

Close ==
    /\ conn # None
    /\ conn' = None
    /\ UNCHANGED <<setCirc, setWf, build, cache, writing, accept, retired, proofs, opened, mixed, count>>

(* The edge's configuration changes, which restarts it. *)
Add(s) ==
    /\ s \notin accept /\ s \notin retired
    /\ accept' = accept \cup {s}
    /\ conn' = None
    /\ UNCHANGED <<setCirc, setWf, build, cache, writing, retired, proofs, opened, mixed, count>>

Retire(s) ==
    /\ s \in accept
    /\ accept' = accept \ {s}
    /\ retired' = retired \cup {s}
    /\ conn' = None
    /\ UNCHANGED <<setCirc, setWf, build, cache, writing, proofs, opened, mixed, count>>

Next ==
    \/ \E b \in Builds : Install(b)
    \/ \E s \in Sets : BeginVerify(s) \/ Prove(s) \/ Add(s) \/ Retire(s)
    \/ \E s \in Sets, e \in cache : Open(s, e)
    \/ FinishVerify \/ Crash \/ Close

Spec == Init /\ [][Next]_vars

ZkSafe == \A p \in proofs : p.safe
AcceptedAtOpen == FALSE \notin opened
OneSet == ~mixed

(* Reach: a host proves. *)
NoProof == proofs = {}
(* Reach: a host that proved under A holds an open connection under B after the edge retired A. *)
NotRotated == ~("A" \in retired /\ conn # None /\ conn.set = "B" /\ conn.safe /\ \E p \in proofs : p.set = "A" /\ p.safe)
=============================================================================
