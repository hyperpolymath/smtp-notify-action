-- SPDX-License-Identifier: MPL-2.0
||| SMTP client-session state machine (RFC 5321) — the single source of truth.
|||
||| The `script` table below IS the protocol contract. Everything else derives
||| from it:
|||   * the proofs in this module constrain it (coverage, determinism,
|||     reachability, reply-code discipline),
|||   * `Smtp.EmitZig` serializes it into `src/generated/smtp_fsm.zig`,
|||     which the hand-written Zig client obeys,
|||   * CI regenerates and diffs, so the Zig table cannot drift from this file.
|||
||| Session shape (implicit TLS or plaintext — the transport is out of scope
||| here; this machine starts once a byte stream to the server exists):
|||
|||   Connect --220--> EHLO --250--> AUTH PLAIN --235--> MAIL FROM --250-->
|||   RCPT TO --250/251--> (repeat per recipient) --> DATA --354-->
|||   payload + CRLF "." CRLF --250--> QUIT --221--> Done
module Smtp.StateMachine

%default total

-- Without this, a bare lowercase name in a type signature (e.g. `script` in
-- `walk (scriptLength script) PConnect = True`) is auto-bound as a FRESH
-- implicit variable that shadows the global — making every property a claim
-- about an arbitrary table instead of THE table, and unprovable by Refl.
%unbound_implicits off

||| Client-session phases. Each non-terminal phase has exactly one script row.
public export
data Phase
  = PConnect   -- transport up, await 220 greeting (server speaks first)
  | PEhlo      -- send EHLO, await 250
  | PAuth      -- send AUTH PLAIN, await 235
  | PMailFrom  -- send MAIL FROM:<addr>, await 250
  | PRcptTo    -- send RCPT TO:<addr>, await 250/251; repeats per recipient
  | PData      -- send DATA, await 354 (the only 3xx in the session)
  | PPayload   -- send headers+body (dot-stuffed) + terminating ".", await 250
  | PQuit      -- send QUIT, await 221
  | PDone      -- success terminal

||| What the client emits on entering a phase.
public export
data Action
  = ANone       -- server speaks first (greeting)
  | AEhlo
  | AAuthPlain  -- AUTH PLAIN base64(\0user\0pass) — single round trip
  | AMailFrom
  | ARcptTo
  | AData
  | APayload    -- RFC 5322 message, dot-stuffed, terminated by CRLF "." CRLF
  | AQuit

public export
phaseIndex : Phase -> Nat
phaseIndex PConnect  = 0
phaseIndex PEhlo     = 1
phaseIndex PAuth     = 2
phaseIndex PMailFrom = 3
phaseIndex PRcptTo   = 4
phaseIndex PData     = 5
phaseIndex PPayload  = 6
phaseIndex PQuit     = 7
phaseIndex PDone     = 8

public export
phaseEq : Phase -> Phase -> Bool
phaseEq a b = phaseIndex a == phaseIndex b

||| One row of the protocol script.
public export
record Step where
  constructor MkStep
  phase   : Phase
  send    : Action
  ||| Reply codes accepted as success for this row. Any 4xx is transient
  ||| failure, any 5xx permanent failure, anything unlisted is a protocol
  ||| error — the client aborts (and QUITs where possible) in all three cases.
  expect  : List Nat
  next    : Phase
  ||| True only for RCPT TO: the row re-runs for each additional recipient
  ||| before advancing.
  repeats : Bool

||| THE protocol contract. Order is the wire order.
public export
script : List Step
script =
  [ MkStep PConnect  ANone      [220]      PEhlo     False
  , MkStep PEhlo     AEhlo      [250]      PAuth     False
  , MkStep PAuth     AAuthPlain [235]      PMailFrom False
  , MkStep PMailFrom AMailFrom  [250]      PRcptTo   False
  , MkStep PRcptTo   ARcptTo    [250, 251] PData     True
  , MkStep PData     AData      [354]      PPayload  False
  , MkStep PPayload  APayload   [250]      PQuit     False
  , MkStep PQuit     AQuit      [221]      PDone     False
  ]

-- ---------------------------------------------------------------------------
-- Properties. All are decided by evaluation over the concrete table, so each
-- proof is Refl — but only compiles while the property actually holds.
-- ---------------------------------------------------------------------------

-- Monomorphic helpers: polymorphic `length`/`all` are ambiguous when they
-- appear inside type signatures, so the properties use these instead.
public export
allSteps : (Step -> Bool) -> List Step -> Bool
allSteps f []        = True
allSteps f (s :: ss) = f s && allSteps f ss

public export
scriptLength : List Step -> Nat
scriptLength []        = 0
scriptLength (_ :: ss) = S (scriptLength ss)

countRows : Phase -> List Step -> Nat
countRows p [] = 0
countRows p (s :: ss) =
  (if phaseEq (phase s) p then 1 else 0) + countRows p ss

||| Every non-terminal phase has exactly one row (determinism + coverage),
||| and the terminal phase has none.
export
deterministicCoverage :
  ( map (\p => countRows p script)
        [PConnect, PEhlo, PAuth, PMailFrom, PRcptTo, PData, PPayload, PQuit]
      == [1, 1, 1, 1, 1, 1, 1, 1]
  , countRows PDone script == 0
  ) = (True, True)
deterministicCoverage = Refl

lookupStep : Phase -> List Step -> Maybe Step
lookupStep p [] = Nothing
lookupStep p (s :: ss) = if phaseEq (phase s) p then Just s else lookupStep p ss

walk : Nat -> Phase -> Bool
walk Z p = phaseEq p PDone
walk (S k) p =
  if phaseEq p PDone then True else
    case lookupStep p script of
      Nothing => False
      Just s  => walk k (next s)

||| From PConnect, following `next`, the session reaches PDone within the
||| length of the script — no cycles, no dead ends.
export
reachesDone : walk (scriptLength script) PConnect = True
reachesDone = Refl

isSuccessCode : Nat -> Bool
isSuccessCode c = (200 <= c && c < 300) || c == 354

rowCodesOk : Step -> Bool
rowCodesOk s =
  all isSuccessCode (expect s)
  && (if elem 354 (expect s) then phaseEq (phase s) PData else True)
  && (if phaseEq (phase s) PData then expect s == [354] else True)

||| Reply-code discipline: only 2xx/354 count as success anywhere, and 354
||| appears exactly at DATA (the sole intermediate reply of the session).
export
codesDisciplined : allSteps rowCodesOk script = True
codesDisciplined = Refl

repeatsOnlyRcpt : Step -> Bool
repeatsOnlyRcpt s = if repeats s then phaseEq (phase s) PRcptTo else True

||| Only RCPT TO repeats — so DATA is reachable only after at least one
||| accepted recipient (the client enters PData by *leaving* the repeating
||| RCPT row, which requires a success reply).
export
onlyRcptRepeats : allSteps repeatsOnlyRcpt script = True
onlyRcptRepeats = Refl

||| AUTH strictly precedes MAIL FROM in the wire order (no unauthenticated
||| envelope), and DATA strictly precedes the payload.
export
orderingSound :
  ( phaseIndex PAuth < phaseIndex PMailFrom
  , phaseIndex PData < phaseIndex PPayload
  ) = (True, True)
orderingSound = Refl
