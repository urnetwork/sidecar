------------------------------ MODULE RemoteCursor ------------------------------
(* DESIGN-DETAILS.md section 7: the pages of one remote search between a requester and one indexer
   (7.2.4, 7.2.5). The indexer holds a cursor over its candidates, newest first, and checks each
   against its text. A page checks some candidates and returns the hits that fit, with
   checked_through: the time of the newest candidate it has not yet accounted for. Requests and replies
   may be lost, delayed and repeated. An erasure ends the cursor. The requester reopens an ended search
   once, resuming below what was already checked.

   What is checked. SpanSound: every candidate newer than the requester's checked_through that the
   indexer has not erased is among the requester's hits exactly when it matches, which is what lets
   the requester fold away its own possible matches there (7.2.6). RepeatEqual: every answer the
   indexer gives for one page of one search is the same answer, until the cursor ends. NoLeak: no page
   sent after an erasure holds the erased document.

   Twin breaks one rule:
     RepeatAdvances        a repeated request for the page just served is answered with the next
     WatermarkPastHeld     checked_through follows what was verified, though a verified hit that did
                           not fit the page is still held for the next
     KeepReplyAcrossErase  an erasure leaves the cursor and its last reply
     ResumeBelow           a reopened search resumes strictly below checked_through
     ReopenSameId          the indexer forgets a search it ended, so a late repeat of that search's
                           page 0 opens a new cursor under the old id

   Left out: sizes, the query, more than one repo, the second cursor a requester may hold, and who the
   indexer is (RemoteAsk.tla). *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,          \* candidates, 1 the newest
    Time,       \* candidate -> its time; never rising with the rank
    PageHits,   \* the most hits a page returns
    MaxRetries, \* repeats of one request
    Twin

VARIABLES
    match,      \* the candidates whose text holds the query
    erased,     \* candidates erased at the indexer
    cur,        \* the indexer's cursor: [live, id, page, until, pos, done, last]
    ended,      \* the ids of the searches whose cursors it ended
    reqs,       \* requests in flight: [id, page, until]
    reps,       \* replies in flight
    sid,        \* the requester's search id
    asked,      \* the page it waits for; NoPage while idle
    next,       \* the next page it will ask
    until,      \* its current search's upper bound, Inf for none
    got,        \* the hits it holds
    through,    \* its checked_through: Inf before any page
    reopened,   \* it has reopened once
    over,       \* it has stopped: complete, or failed
    retries,
    said,       \* every answer given: <<id, page, answer>>
    leak        \* a page sent after an erasure held the erased candidate

vars == <<match, erased, cur, ended, reqs, reps, sid, asked, next, until, got, through, reopened, over, retries, said, leak>>

Cands == 1..N
Inf == 99
NoPage == 99
NoCur == [live |-> FALSE, id |-> 0, page |-> 0, until |-> 0, pos |-> 0, done |-> FALSE, last |-> [st |-> "none"]]

(* The candidates of a search bounded above by u, in rank order, the erased ones left out. *)
List(u) == {c \in Cands : Time[c] <= u /\ c \notin erased}
(* The newest candidate of the list at or after rank p, or 0. *)
NextFrom(u, p) == LET s == {c \in List(u) : c >= p} IN IF s = {} THEN 0 ELSE CHOOSE c \in s : \A e \in s : c <= e
TimeOf(c) == IF c = 0 THEN 0 ELSE Time[c]

Init ==
    /\ match \in SUBSET Cands
    /\ erased = {} /\ cur = NoCur /\ ended = {}
    /\ reqs = {[id |-> 1, page |-> 0, until |-> Inf]} /\ reps = {}
    /\ sid = 1 /\ asked = 0 /\ next = 1 /\ until = Inf /\ got = {} /\ through = Inf
    /\ reopened = FALSE /\ over = FALSE /\ retries = 0
    /\ said = {} /\ leak = FALSE

(* One page: the indexer checks candidates from pos up to some rank q, and returns at most PageHits of
   the matches it found. The first match that did not fit stays with the cursor: the next page starts
   there, and checked_through is the time of the newest candidate not yet accounted for. *)
Page(c0, q, k) ==
    LET u == c0.until
        seen == {c \in List(u) : c >= c0.pos /\ c <= q}
        hits == seen \cap match
        ret == {c \in hits : Cardinality({e \in hits : e < c}) < k}
        rest == hits \ ret
        stop == IF rest = {} THEN q + 1 ELSE CHOOSE c \in rest : \A e \in rest : c <= e
        mark == IF Twin = "WatermarkPastHeld" THEN q + 1 ELSE stop
    IN  [hits |-> ret, pos |-> stop, through |-> TimeOf(NextFrom(u, mark)), done |-> NextFrom(u, stop) = 0]

Answer(r, a) ==
    /\ reps' = reps \cup {[id |-> r.id, page |-> r.page, a |-> a]}
    /\ said' = said \cup {<<r.id, r.page, a>>}
    /\ leak' = (leak \/ (a.st = "ok" /\ a.hits \cap erased # {}))

(* The indexer takes a request. *)
Serve(r) ==
    /\ r \in reqs
    /\ \/ \* page 0 of a search it holds no cursor for: a new cursor, and its first page
          /\ r.page = 0 /\ ~(cur.live /\ cur.id = r.id) /\ r.id \notin ended
          /\ \E q \in 0..N, k \in 1..PageHits :
                LET c0 == [pos |-> 1, until |-> r.until]
                    p == Page(c0, q, k)
                    a == [st |-> "ok", hits |-> p.hits, through |-> p.through, done |-> p.done]
                IN  /\ q >= 1 \/ List(r.until) = {}
                    /\ cur' = [live |-> TRUE, id |-> r.id, page |-> 0, until |-> r.until, pos |-> p.pos,
                               done |-> p.done, last |-> a]
                    /\ Answer(r, a)
       \/ \* the page it served last: the same reply again
          /\ cur.live /\ cur.id = r.id /\ r.page = cur.page /\ Twin # "RepeatAdvances"
          /\ cur' = cur
          /\ Answer(r, cur.last)
       \/ \* the next page
          /\ cur.live /\ cur.id = r.id /\ ~cur.done
          /\ r.page = cur.page + 1 \/ (Twin = "RepeatAdvances" /\ r.page = cur.page)
          /\ \E q \in cur.pos..N, k \in 1..PageHits :
                LET p == Page(cur, q, k)
                    a == [st |-> "ok", hits |-> p.hits, through |-> p.through, done |-> p.done]
                IN  /\ cur' = [cur EXCEPT !.page = r.page, !.pos = p.pos, !.done = p.done, !.last = a]
                    /\ Answer(r, a)
       \/ \* a page of a search whose cursor has ended, or that it never held
          /\ ~(cur.live /\ cur.id = r.id) /\ (r.page > 0 \/ r.id \in ended)
          /\ cur' = cur
          /\ Answer(r, [st |-> "expired"])
       \/ \* any other page of the search it holds: refused, and the cursor is not touched
          /\ cur.live /\ cur.id = r.id /\ r.page # cur.page /\ ~(r.page = cur.page + 1 /\ ~cur.done)
          /\ cur' = cur
          /\ Answer(r, [st |-> "invalid"])
    /\ reqs' = reqs \ {r}
    /\ ended' = IF cur.live /\ cur'.live /\ cur'.id # cur.id THEN ended \cup {cur.id} ELSE ended
    /\ UNCHANGED <<match, erased, sid, asked, next, until, got, through, reopened, over, retries>>

(* An ERASE or a CUT in the cursor's scope: the cursor and its last reply go. *)
Erase(c) ==
    /\ erased = {} /\ c \in Cands
    /\ erased' = {c}
    /\ cur' = IF Twin = "KeepReplyAcrossErase" THEN cur ELSE NoCur
    /\ ended' = IF cur.live /\ Twin \notin {"KeepReplyAcrossErase", "ReopenSameId"} THEN ended \cup {cur.id} ELSE ended
    /\ UNCHANGED <<match, reqs, reps, sid, asked, next, until, got, through, reopened, over, retries, said, leak>>

(* The requester takes the reply to the page it waits for. Any other reply is dropped. *)
Receive(m) ==
    /\ m \in reps /\ reps' = reps \ {m}
    /\ IF over \/ m.id # sid \/ m.page # asked
         THEN UNCHANGED <<reqs, sid, asked, next, until, got, through, reopened, over, retries>>
         ELSE CASE m.a.st = "ok" ->
                     /\ got' = got \cup m.a.hits
                     /\ through' = m.a.through
                     /\ over' = m.a.done
                     /\ asked' = NoPage /\ retries' = 0
                     /\ UNCHANGED <<reqs, sid, next, until, reopened>>
                [] m.a.st = "expired" /\ ~reopened ->
                     \* reopen once, below what the ended cursor accounted for
                     /\ reopened' = TRUE /\ sid' = sid + 1 /\ asked' = 0 /\ next' = 1 /\ retries' = 0
                     /\ until' = IF Twin = "ResumeBelow" /\ through > 0 /\ through # Inf THEN through - 1 ELSE through
                     /\ reqs' = reqs \cup {[id |-> sid + 1, page |-> 0, until |-> until']}
                     /\ UNCHANGED <<got, through, over>>
                [] OTHER ->
                     /\ over' = TRUE
                     /\ UNCHANGED <<reqs, sid, asked, next, until, got, through, reopened, retries>>
    /\ UNCHANGED <<match, erased, cur, ended, said, leak>>

(* The app asks for more. *)
More ==
    /\ ~over /\ asked = NoPage
    /\ asked' = next /\ next' = next + 1
    /\ reqs' = reqs \cup {[id |-> sid, page |-> next, until |-> until]}
    /\ UNCHANGED <<match, erased, cur, ended, reps, sid, until, got, through, reopened, over, retries, said, leak>>

(* No reply in time: the same request again. *)
Retry ==
    /\ ~over /\ asked # NoPage /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ reqs' = reqs \cup {[id |-> sid, page |-> asked, until |-> until]}
    /\ UNCHANGED <<match, erased, cur, ended, reps, sid, asked, next, until, got, through, reopened, over, said, leak>>

LoseRequest(r) == r \in reqs /\ reqs' = reqs \ {r} /\ UNCHANGED <<match, erased, cur, ended, reps, sid, asked, next, until, got, through, reopened, over, retries, said, leak>>
LoseReply(m) == m \in reps /\ reps' = reps \ {m} /\ UNCHANGED <<match, erased, cur, ended, reqs, sid, asked, next, until, got, through, reopened, over, retries, said, leak>>

Next ==
    \/ \E r \in reqs : Serve(r) \/ LoseRequest(r)
    \/ \E m \in reps : Receive(m) \/ LoseReply(m)
    \/ \E c \in Cands : Erase(c)
    \/ More \/ Retry

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------------------
(* Every candidate newer than the requester's checked_through, and not erased, is one of its hits
   exactly when it matches. *)
SpanSound ==
    \A c \in Cands \ erased : Time[c] > through => (c \in got <=> c \in match)

NoInvention == got \subseteq match

RepeatEqual ==
    \A x, y \in said : (x[1] = y[1] /\ x[2] = y[2] /\ x[3].st = "ok" /\ y[3].st = "ok") => x[3] = y[3]

NoLeak == ~leak
(* The times the configurations name: two candidates of one time, then an older one. *)
Times == <<2, 2, 1>>
==========================================================================================
