------------------------------ MODULE ProofParts ------------------------------
(* DESIGN-DETAILS.md section 3.2.5: the edge's record gate over one connection whose parts are bound to one
   key part.

   The sidecar is the adversary. It holds the session's real keys and every plaintext, authors the client
   records, and may submit any part it likes; its records all sit at the gate from the start, so only the gate
   decides what the MX receives. A proof is modelled by what it can establish: a part verifies exactly when
   its statement, built from the gate's own state, is true of the real connection.

     the key part      verifies only if its commitment commits to the keys the handshake fixed (Z1). A
                       commitment is modelled by the value it commits to, which is what binding gives.
     a later part      opens the commitment its statement names. Under the handshake's keys it verifies only
                       if every record it opens holds what its template asks, the header scan it claims is
                       the real one from its statement's carry, and the server records it covers are exactly
                       the replies it counts, each accepting. Under any other keys it verifies whatever it
                       claims: that is the key substitution the binding exists to stop.

   The connection is fixed and small: client records 1 EHLO, 2 MAIL, 3 RCPT, 4 the header block's first
   record with BDAT's command, 5 its second record, 6 QUIT. The MX answers records 1 to 3, late if it
   likes, and may send one more record that no part can prove once it has answered them all. The
   sidecar's choices of content: whether RCPT names another domain (envGood false), and whether the header's
   second record passes only when scanned from a fresh state (restNeeds "fresh"), as a field name split across
   the two records would. It may also have a part open a ciphertext for record 4 that is not the one on the
   stream (fake), and claim any scan state for it.

   What is checked:
     ContentSound    the MX reads RCPT only if a verified part proved its content
     HeaderSound     the MX reads the whole header block only if the real scan of both records accepts
     EnvelopeProven  the MX reads a message record only after it sent all three replies, each accepting
     HeldUntilCovered no message record is released while a relayed server record is uncovered
     OneKey          every part verified under the commitment the key part fixed

   Twin selects one rule to break:
     KeyFromPart      a later part names its own commitment, as if each part bound its own keys
     CarryFromPart    a part names the scan state it starts from, where the gate should supply it
     NoReplyTotal     the first message record needs no count of proven replies
     ReleaseUncovered a message record does not wait for server records relayed after its part verified
     NoCommitRecheck  a part that verified while another landed is committed all the same

   A part here may open both header records, which the design's shapes do not allow; the invariants hold for
   that wider gate too.

   Left out: the handshake and E1 and E2, which fix the keys; the unopened body and its count; DATA mode,
   whose body parts carry a scan state exactly as record 5 does; tickets, which a part covers with a count of
   zero; hiding, which no state machine shows. *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Twin,
    MaxInFlight     \* parts verifying at once

VARIABLES
    envGood,        \* record 3's real content fits its template
    restNeeds,      \* "any": record 5 passes from the real state; "fresh": only from the start state
    srv,            \* the MX's replies as relayed, in order: TRUE accepts
    junk,           \* the MX sent a record no part can prove, after its replies
    mxGot,          \* client records the MX has received, 1..mxGot
    parts,          \* verified parts, in the order they landed
    inflight,       \* parts between the order checks and the commit
    commits,
    gkey,           \* the commitment the key part fixed: "none", "k" (the handshake's keys) or "x"
    nextRec, covered, proven, cmds,
    carry,          \* the scan state after the last header record a verified part opened
    ended,
    badRelease      \* history: a message record left while a relayed server record was uncovered

vars == <<envGood, restNeeds, srv, junk, mxGot, parts, inflight, commits, gkey, nextRec, covered, proven, cmds,
          carry, ended, badRelease>>

LastRec == 6
Command(r) == r \in {1, 2, 3}
Message(r) == r \in {4, 5}
Replies == 3
Relayed == Len(srv) + (IF junk THEN 1 ELSE 0)
Commands(a, b) == Cardinality({r \in a..b : Command(r)})
Min(a, b) == IF a < b THEN a ELSE b

(* The real scan: record 4 leaves "open", a field name unfinished at its end; record 5 from there. *)
RestAccepts(from) == restNeeds = "any" \/ from = "start"

Init ==
    /\ envGood \in BOOLEAN
    /\ restNeeds \in {"any", "fresh"}
    /\ srv = <<>> /\ junk = FALSE /\ mxGot = 0
    /\ parts = <<>> /\ inflight = {} /\ commits = 0
    /\ gkey = "none" /\ nextRec = 1 /\ covered = 0 /\ proven = 0 /\ cmds = 0
    /\ carry = "none" /\ ended = FALSE /\ badRelease = FALSE

(* The MX answers the next command it has received. It accepts EHLO and MAIL, and RCPT or not. *)
Reply(ok) ==
    /\ Len(srv) < Commands(1, mxGot)
    /\ ~junk
    /\ (Len(srv) < 2) => ok
    /\ srv' = Append(srv, ok)
    /\ UNCHANGED <<envGood, restNeeds, junk, mxGot, parts, inflight, commits, gkey, nextRec, covered, proven, cmds,
                   carry, ended, badRelease>>

(* A record no part can prove: a 421, or anything else that is no reply the flow expects. *)
Junk ==
    /\ Len(srv) = Replies /\ ~junk
    /\ junk' = TRUE
    /\ UNCHANGED <<envGood, restNeeds, srv, mxGot, parts, inflight, commits, gkey, nextRec, covered, proven, cmds,
                   carry, ended, badRelease>>

(* What the statement of part p says, from the gate's state when its order checks ran. *)
StatementKey(p) == IF p.idx = 1 \/ Twin = "KeyFromPart" THEN p.key ELSE gkey
StatementCarry(p) == IF Twin = "CarryFromPart" THEN p.cin ELSE carry

Opens(p, r) == p.first <= r /\ r <= p.last

Verifies(p) ==
    IF p.idx = 1 THEN p.key = "k"
    ELSE IF StatementKey(p) # "k" THEN TRUE
    ELSE /\ Opens(p, 3) => envGood
         /\ (Opens(p, 4) /\ ~p.fake) => p.cout4 = "open"
         /\ Opens(p, 5) => RestAccepts(IF Opens(p, 4) THEN p.cout4 ELSE StatementCarry(p))
         \* the server records it covers are the replies it counts, each accepting; junk is never one
         /\ p.srv <= Len(srv)
         /\ p.rc = p.srv - covered
         /\ \A i \in (covered + 1)..p.srv : srv[i]

(* The order checks, under the gate's lock. *)
Admissible(p) ==
    /\ p.idx = Len(parts) + 1
    /\ IF p.idx = 1
       THEN p.first = 1 /\ p.last = 1 /\ p.srv = 0 /\ p.rc = 0
       ELSE /\ p.first = nextRec
            /\ p.last >= p.first - 1 /\ p.last <= LastRec
            \* a part that opens no record covers a server record
            /\ (p.last = p.first - 1) => p.srv > covered
            /\ p.srv >= covered /\ p.srv <= Relayed
            /\ p.rc <= cmds - proven
            \* the EHLO reply is proven before MAIL is covered
            /\ Opens(p, 2) => proven + p.rc >= 1
            \* every reply is proven before the first message record is covered
            /\ (Opens(p, 4) /\ Twin # "NoReplyTotal") => proven + p.rc = Replies
            \* a record that continues the header needs the state its predecessor left
            /\ (Opens(p, 5) /\ ~Opens(p, 4)) => carry # "none"

Part(idx, last, s, rc, key, cin, cout4, fake) ==
    [idx |-> idx, first |-> IF idx = 1 THEN 1 ELSE nextRec, last |-> last, srv |-> s, rc |-> rc, key |-> key,
     cin |-> cin, cout4 |-> cout4, fake |-> fake]

(* A part that fails its order checks or its proof ends the connection where it stands, so only parts that pass
   both are followed: the states after a refusal are the states before it. *)
Submit(p) ==
    /\ ~ended
    /\ Cardinality(inflight) < MaxInFlight
    /\ Admissible(p) /\ Verifies(p)
    /\ inflight' = inflight \cup {[p |-> p, at |-> commits]}
    /\ UNCHANGED <<envGood, restNeeds, srv, junk, mxGot, parts, commits, gkey, nextRec, covered, proven, cmds, carry,
                   ended, badRelease>>

(* The first verified part that covers a record is the one whose ciphertext the stream must repeat. A stream
   record that is not that ciphertext is a cut, which ends the connection: here it is simply never released. *)
Covering(ps, r) == {i \in 1..Len(ps) : Opens(ps[i], r)}
First(S) == CHOOSE i \in S : \A j \in S : i <= j
CanRelease(ps, cov, r) ==
    /\ Covering(ps, r) # {}
    /\ ~(r = 4 /\ ps[First(Covering(ps, r))].fake)
    /\ (Message(r) /\ Twin # "ReleaseUncovered") => cov = Relayed
(* E3 runs when a part lands: every held record that is now clear goes, in order. *)
Released(ps, cov) ==
    LET ok == {m \in mxGot..LastRec : \A r \in (mxGot + 1)..m : CanRelease(ps, cov, r)}
    IN CHOOSE m \in ok : \A n \in ok : n <= m

(* The commit, under the lock again. Another part may have landed while this one verified. *)
Commit(f) ==
    /\ f \in inflight
    /\ ~ended
    /\ IF f.at # commits /\ Twin # "NoCommitRecheck"
       THEN \* its order checks ran against what no longer stands: the connection ends
            /\ ended' = TRUE
            /\ inflight' = {}
            /\ UNCHANGED <<parts, commits, gkey, nextRec, covered, proven, cmds, carry, mxGot, badRelease>>
       ELSE LET ps == Append(parts, f.p)
                got == Released(ps, f.p.srv)
            IN
            /\ inflight' = inflight \ {f}
            /\ parts' = ps
            /\ commits' = commits + 1
            /\ gkey' = IF f.p.idx = 1 THEN f.p.key ELSE gkey
            /\ nextRec' = f.p.last + 1
            /\ covered' = f.p.srv
            /\ proven' = proven + f.p.rc
            /\ cmds' = cmds + Commands(f.p.first, f.p.last)
            /\ carry' = IF Opens(f.p, 5) THEN "done" ELSE IF Opens(f.p, 4) THEN f.p.cout4 ELSE carry
            /\ mxGot' = got
            /\ badRelease' = (badRelease \/ \E r \in (mxGot + 1)..got : Message(r) /\ f.p.srv < Relayed)
            /\ UNCHANGED ended
    /\ UNCHANGED <<envGood, restNeeds, srv, junk>>

Next ==
    \/ \E ok \in BOOLEAN : Reply(ok)
    \/ Junk
    \/ \E idx \in 1..5, last \in 0..LastRec, s \in 0..4, rc \in 0..Replies, key \in {"k", "x"},
          cin \in {"start", "open"}, cout4 \in {"start", "open"}, fake \in BOOLEAN :
          /\ idx = Len(parts) + 1
          /\ LET p == Part(idx, last, s, rc, key, cin, cout4, fake) IN
             \* fields a part does not carry are held to one value, so equal parts are one state
             /\ (idx # 1 /\ Twin # "KeyFromPart") => key = "k"
             /\ (Twin # "CarryFromPart" \/ ~Opens(p, 5) \/ Opens(p, 4)) => cin = "start"
             /\ ~Opens(p, 4) => (cout4 = "start" /\ ~fake)
             /\ Submit(p)
    \/ \E f \in inflight : Commit(f)

Spec == Init /\ [][Next]_vars

ContentSound == mxGot >= 3 => envGood
HeaderSound == mxGot >= 5 => restNeeds = "any"
EnvelopeProven == mxGot >= 4 => (Len(srv) = Replies /\ \A i \in 1..Replies : srv[i])
HeldUntilCovered == ~badRelease
OneKey == gkey \in {"none", "k"}

(* Reach: an honest send is delivered whole. *)
NotDelivered == mxGot < LastRec
=============================================================================
