------------------------------- MODULE Pacing -------------------------------
(* DESIGN-DETAILS.md section 13.2.1: one network's closure pacing. Time is counted in cells, 1/R of a second,
   so a second holds R cells and R uploads. Each asking eraser holds one seat, a cell at the tail. In the
   design a seat is good from its cell to the end of its second and lapses with it, a seat is handed out only
   in a second that still has a free cell, and an eraser whose seat is due takes: nothing else is checked, so
   the order in which asks reach Redis decides nothing.

   An eraser outside Wild is obedient: it asks when it was told to (lift), and time does not pass while it
   has an ask due. A Wild eraser asks whenever it likes, or never again, which covers hammering, late
   arrivals and abandoned seats. The model starts at Start, with every eraser holding a seat that came due
   while it was away, as after allowance refusals that all lift at 00:00 UTC.

   What is checked: no second takes more than R (Rate), no second is promised more than R (Cells), and an
   obedient eraser takes within Bound cells of its last take, whatever the others do (Turn).

   Twin selects the admission to break:
     Arrival  the landed pacing (reading 19 as built): a seat stays good past its second, and a bucket of R
              a second admits whoever asks first; a refused eraser keeps its seat and returns next second
     Tail     question quota-m2-03-pacing-boundary-order's option 2: as Arrival, but an eraser the bucket
              refuses takes a new seat at the tail

   Left out: the eraser's own 60 a minute and daily allowance, which are counters beside this, and Redis
   loss, which empties the state. *)
EXTENDS Integers, FiniteSets

CONSTANTS
    Erasers,
    Wild,       \* erasers that ask at any time, or stop asking
    R,          \* uploads a second, and cells a second
    Start,      \* when the erasers come back; a multiple of R, at least the number of erasers
    MaxTime,
    Bound,      \* the longest an obedient eraser goes between takes, in cells
    Twin

VARIABLES
    now,
    tail,   \* the latest seat handed out
    seat,   \* each eraser's seat, or None
    taken,  \* uploads taken in the second of now
    lift,   \* when each eraser was last told to ask again
    since   \* when each eraser last took, or began asking

vars == <<now, tail, seat, taken, lift, since>>

None == -1
SecOf(t) == t \div R
Max(a, b) == IF a > b THEN a ELSE b

(* The seat the script finds for e. In the design the first step of every call drops the seats of earlier
   seconds, so such a seat reads as none. *)
Held(e) ==
    IF Twin = "none" /\ seat[e] # None /\ seat[e] < SecOf(now) * R THEN None ELSE seat[e]

OtherSeats(e) == {Held(x) : x \in Erasers \ {e}} \ {None}
CellsIn(C, seats) == Cardinality({s \in seats : SecOf(s) = C})

(* A new seat: the cell after the tail and never before now. The design then counts the cells its second has
   already promised or spent, and moves to the start of the next second when none is free. No seat lies past
   the tail, so that second is empty. *)
NextSeat(tl, seats, tk) ==
    LET c == Max(tl + 1, now)
        C == SecOf(c)
        used == CellsIn(C, seats) + (IF C = SecOf(now) THEN tk ELSE 0)
    IN  IF Twin = "none" /\ used >= R THEN (C + 1) * R ELSE c

Ask(e) ==
    /\ (e \in Wild \/ lift[e] <= now)
    /\ LET had == Held(e)
           s == IF had = None THEN NextSeat(tail, OtherSeats(e), taken) ELSE had
           tl == IF had = None THEN s ELSE tail
       IN  IF now < s
             THEN \* before its turn: it keeps the seat and is told when it comes
                  /\ seat' = [seat EXCEPT ![e] = s]
                  /\ tail' = tl
                  /\ lift' = [lift EXCEPT ![e] = s]
                  /\ UNCHANGED <<taken, since>>
           ELSE IF Twin # "none" /\ taken >= R
             THEN \* the landed bucket is full this second
                  IF Twin = "Tail"
                    THEN LET n == Max(tl + 1, (SecOf(now) + 1) * R) IN
                         /\ seat' = [seat EXCEPT ![e] = n]
                         /\ tail' = n
                         /\ lift' = [lift EXCEPT ![e] = n]
                         /\ UNCHANGED <<taken, since>>
                    ELSE /\ seat' = [seat EXCEPT ![e] = s]
                         /\ tail' = tl
                         /\ lift' = [lift EXCEPT ![e] = (SecOf(now) + 1) * R]
                         /\ UNCHANGED <<taken, since>>
           ELSE \* its turn: it takes, and takes its next seat at the tail
                LET n == NextSeat(tl, OtherSeats(e), taken + 1) IN
                /\ taken' = taken + 1
                /\ seat' = [seat EXCEPT ![e] = n]
                /\ tail' = n
                /\ lift' = [lift EXCEPT ![e] = n]
                /\ since' = [since EXCEPT ![e] = now]
    /\ UNCHANGED now

(* Time passes only once every obedient eraser with an ask due has asked. *)
Tick ==
    /\ now < MaxTime
    /\ \A e \in Erasers \ Wild : lift[e] > now
    /\ now' = now + 1
    /\ taken' = IF SecOf(now + 1) # SecOf(now) THEN 0 ELSE taken
    /\ UNCHANGED <<tail, seat, lift, since>>

(* Every eraser holds a seat handed out before it went away, all of them due by Start. *)
EarlierSeat == CHOOSE f \in [Erasers -> 0..(Cardinality(Erasers) - 1)] : \A a, b \in Erasers : a # b => f[a] # f[b]

Init ==
    /\ now = Start
    /\ tail = Cardinality(Erasers) - 1
    /\ seat = EarlierSeat
    /\ taken = 0
    /\ lift = [e \in Erasers |-> Start]
    /\ since = [e \in Erasers |-> Start]

Next == Tick \/ \E e \in Erasers : Ask(e)

Spec == Init /\ [][Next]_vars

(* The network takes at most R uploads in any second. *)
Rate == taken <= R

(* No second is promised more than it can take: the seats in it, with what it has already taken. *)
Cells ==
    \A C \in SecOf(now)..(SecOf(MaxTime) + Cardinality(Erasers) + 2) :
        CellsIn(C, {Held(x) : x \in Erasers} \ {None}) + (IF C = SecOf(now) THEN taken ELSE 0) <= R

(* No obedient eraser is starved or passed over: it takes within Bound cells of its last take. *)
Turn == \A e \in Erasers \ Wild : now - since[e] <= Bound
=============================================================================
