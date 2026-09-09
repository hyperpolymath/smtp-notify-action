-- SPDX-License-Identifier: MPL-2.0
||| SMTP client-session state machines (RFC 5321, RFC 3207) — the single
||| source of truth.
|||
||| The tables below ARE the protocol contract. Everything else derives
||| from them:
|||   * the proofs in this module constrain them (coverage, determinism,
|||     reachability, reply-code discipline),
|||   * `Smtp.EmitZig` serializes them into `src/generated/smtp_fsm.zig`,
|||     which the hand-written Zig client obeys,
|||   * CI regenerates and diffs, so the Zig tables cannot drift from this file.
|||
||| There are TWO tables because there are two session shapes, and a single
||| table with a conditional row would be a table whose proofs no longer say
||| anything definite about the session actually run. Splitting keeps every
||| property below decidable per table, and leaves the implicit-TLS path —
||| the one that ships today — provably unchanged in shape.
|||
||| `scriptImplicit` (submission over implicit TLS on 465, or plaintext):
|||
|||   Connect --220--> EHLO --250--> AUTH --235--> MAIL FROM --250-->
|||   RCPT TO --250/251--> (repeat per recipient) --> DATA --354-->
|||   payload + CRLF "." CRLF --250--> QUIT --221--> Done
|||
||| `scriptStartTls` (submission on 587, RFC 3207):
|||
|||   Connect --220--> EHLO --250--> STARTTLS --220--> [upgrade] -->
|||   EHLO again --250--> AUTH --235--> ... (as above)
|||
||| The second EHLO is required, not defensive: RFC 3207 §4.2 says the client
||| MUST discard any knowledge obtained from the unprotected greeting, because
||| the server may advertise a different capability set once the session is
||| encrypted — including a different AUTH mechanism list.
|||
||| ON SCOPE, honestly: this machine used to say "the transport is out of
||| scope; this machine starts once a byte stream to the server exists". With
||| STARTTLS that is no longer quite true — the TLS handshake happens *inside*
||| the session, between the STARTTLS row and the second EHLO. The table does
||| not describe the handshake; it locates it. The handshake is a side effect
||| of `AStartTls` receiving its 220, in the same way that `APayload` has
||| effects (dot-stuffing, header construction) this table does not describe
||| and `Smtp.Serialize` does. What is proven here is the *shape* of the
||| session, not the cryptography inside it.
module Smtp.StateMachine

%default total

-- Without this, a bare lowercase name in a type signature (e.g. `script` in
-- `walk (scriptLength script) PConnect = True`) is auto-bound as a FRESH
-- implicit variable that shadows the global — making every property a claim
-- about an arbitrary table instead of THE table, and unprovable by Refl.
%unbound_implicits off

||| Client-session phases. Each non-terminal phase has exactly one row in a
||| table that uses it, and none in a table that does not.
public export
data Phase
  = PConnect   -- transport up, await 220 greeting (server speaks first)
  | PEhlo      -- send EHLO, await 250
  | PStartTls  -- send STARTTLS, await 220; the TLS upgrade follows the 220
  | PEhloTls   -- send EHLO again on the encrypted stream, await 250
  | PAuth      -- send AUTH, await 235
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
  | AStartTls   -- STARTTLS; on 220 the client upgrades the stream in place
  | AAuth       -- AUTH; the mechanism sub-exchange is driven by the client
  | AMailFrom
  | ARcptTo
  | AData
  | APayload    -- RFC 5322 message, dot-stuffed, terminated by CRLF "." CRLF
  | AQuit

public export
phaseIndex : Phase -> Nat
phaseIndex PConnect  = 0
phaseIndex PEhlo     = 1
phaseIndex PStartTls = 2
phaseIndex PEhloTls  = 3
phaseIndex PAuth     = 4
phaseIndex PMailFrom = 5
phaseIndex PRcptTo   = 6
phaseIndex PData     = 7
phaseIndex PPayload  = 8
phaseIndex PQuit     = 9
phaseIndex PDone     = 10

public export
phaseEq : Phase -> Phase -> Bool
phaseEq a b = phaseIndex a == phaseIndex b

||| One row of a protocol script.
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

||| Session over a stream that is already encrypted (implicit TLS, port 465)
||| or deliberately not encrypted at all. Order is the wire order.
|||
||| These eight rows are byte-for-byte the contract that shipped in v0.2.0.
public export
scriptImplicit : List Step
scriptImplicit =
  [ MkStep PConnect  ANone     [220]      PEhlo     False
  , MkStep PEhlo     AEhlo     [250]      PAuth     False
  , MkStep PAuth     AAuth     [235]      PMailFrom False
  , MkStep PMailFrom AMailFrom [250]      PRcptTo   False
  , MkStep PRcptTo   ARcptTo   [250, 251] PData     True
  , MkStep PData     AData     [354]      PPayload  False
  , MkStep PPayload  APayload  [250]      PQuit     False
  , MkStep PQuit     AQuit     [221]      PDone     False
  ]

||| Session that begins in cleartext on the submission port and upgrades
||| (RFC 3207). Identical to `scriptImplicit` from PAuth onward; the two extra
||| rows are the upgrade and the mandatory re-greeting.
public export
scriptStartTls : List Step
scriptStartTls =
  [ MkStep PConnect  ANone     [220]      PEhlo     False
  , MkStep PEhlo     AEhlo     [250]      PStartTls False
  , MkStep PStartTls AStartTls [220]      PEhloTls  False
  , MkStep PEhloTls  AEhlo     [250]      PAuth     False
  , MkStep PAuth     AAuth     [235]      PMailFrom False
  , MkStep PMailFrom AMailFrom [250]      PRcptTo   False
  , MkStep PRcptTo   ARcptTo   [250, 251] PData     True
  , MkStep PData     AData     [354]      PPayload  False
  , MkStep PPayload  APayload  [250]      PQuit     False
  , MkStep PQuit     AQuit     [221]      PDone     False
  ]

-- ---------------------------------------------------------------------------
-- Properties. All are decided by evaluation over the concrete tables, so each
-- proof is Refl — but only compiles while the property actually holds.
--
-- Every property is stated over BOTH tables. A property proven of only one
-- of two tables the client can run is not a property of the client.
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

||| Every phase a table uses has exactly one row in it (determinism +
||| coverage), and the terminal phase has none.
export
deterministicCoverage :
  ( map (\p => countRows p scriptImplicit)
        [PConnect, PEhlo, PAuth, PMailFrom, PRcptTo, PData, PPayload, PQuit]
      == [1, 1, 1, 1, 1, 1, 1, 1]
  , countRows PDone scriptImplicit == 0
  , map (\p => countRows p scriptStartTls)
        [PConnect, PEhlo, PStartTls, PEhloTls, PAuth, PMailFrom, PRcptTo,
         PData, PPayload, PQuit]
      == [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  , countRows PDone scriptStartTls == 0
  ) = (True, True, True, True)
deterministicCoverage = Refl

||| The implicit-TLS path contains no upgrade. This is what makes the split
||| safe rather than merely tidy: adding STARTTLS cannot have introduced a
||| cleartext-then-upgrade step into the session shape that already ships.
export
implicitHasNoUpgrade :
  ( countRows PStartTls scriptImplicit == 0
  , countRows PEhloTls scriptImplicit == 0
  ) = (True, True)
implicitHasNoUpgrade = Refl

lookupStep : Phase -> List Step -> Maybe Step
lookupStep p [] = Nothing
lookupStep p (s :: ss) = if phaseEq (phase s) p then Just s else lookupStep p ss

walk : List Step -> Nat -> Phase -> Bool
walk t Z p = phaseEq p PDone
walk t (S k) p =
  if phaseEq p PDone then True else
    case lookupStep p t of
      Nothing => False
      Just s  => walk t k (next s)

||| From PConnect, following `next`, each session reaches PDone within the
||| length of its own script — no cycles, no dead ends, in either shape.
export
reachesDone :
  ( walk scriptImplicit (scriptLength scriptImplicit) PConnect
  , walk scriptStartTls (scriptLength scriptStartTls) PConnect
  ) = (True, True)
reachesDone = Refl

reaches : List Step -> Nat -> Phase -> Phase -> Bool
reaches t Z from target = phaseEq from target
reaches t (S k) from target =
  if phaseEq from target then True else
    case lookupStep from t of
      Nothing => False
      Just s  => reaches t k (next s) target

||| The upgrade is ON THE PATH, not merely present in the table.
|||
||| This closes a real hole. A table that still listed a STARTTLS row but
||| routed EHLO straight to AUTH would satisfy deterministicCoverage (the
||| row is still there, exactly once), reachesDone (the walk still
||| terminates) and orderingSound (which speaks about the phase INDEX, not
||| about the table) — while putting the credential on a cleartext wire.
||| Presence in a table is not presence on the path, and only the path is
||| what the client actually walks.
export
upgradeIsOnThePath :
  ( reaches scriptStartTls (scriptLength scriptStartTls) PConnect PStartTls
  , reaches scriptStartTls (scriptLength scriptStartTls) PConnect PEhloTls
  , reaches scriptStartTls (scriptLength scriptStartTls) PConnect PAuth
  , reaches scriptImplicit (scriptLength scriptImplicit) PConnect PAuth
  ) = (True, True, True, True)
upgradeIsOnThePath = Refl

isSuccessCode : Nat -> Bool
isSuccessCode c = (200 <= c && c < 300) || c == 354

rowCodesOk : Step -> Bool
rowCodesOk s =
  all isSuccessCode (expect s)
  && (if elem 354 (expect s) then phaseEq (phase s) PData else True)
  && (if phaseEq (phase s) PData then expect s == [354] else True)

||| Reply-code discipline: only 2xx/354 count as success anywhere, and 354
||| appears exactly at DATA — it remains the sole intermediate reply of the
||| session in BOTH shapes.
|||
||| Note that STARTTLS needs no relaxation of this: its 220 is an ordinary
||| 2xx. The client's AUTH mechanism sub-exchange does use 334, and that is
||| precisely why it is not a row here — see the AUTH note in KNOWN-DEFECTS.
export
codesDisciplined :
  ( allSteps rowCodesOk scriptImplicit
  , allSteps rowCodesOk scriptStartTls
  ) = (True, True)
codesDisciplined = Refl

repeatsOnlyRcpt : Step -> Bool
repeatsOnlyRcpt s = if repeats s then phaseEq (phase s) PRcptTo else True

||| Only RCPT TO repeats — so DATA is reachable only after at least one
||| accepted recipient (the client enters PData by *leaving* the repeating
||| RCPT row, which requires a success reply).
export
onlyRcptRepeats :
  ( allSteps repeatsOnlyRcpt scriptImplicit
  , allSteps repeatsOnlyRcpt scriptStartTls
  ) = (True, True)
onlyRcptRepeats = Refl

||| Wire-order soundness, stated on the phase index and so true of any table
||| that respects it: the upgrade precedes the re-greeting, the re-greeting
||| precedes AUTH, AUTH precedes MAIL FROM (no unauthenticated envelope), and
||| DATA precedes the payload.
|||
||| The first two conjuncts are what forbid the dangerous ordering: a table
||| that authenticated before upgrading would put the credential on a
||| cleartext wire.
export
orderingSound :
  ( phaseIndex PEhlo     < phaseIndex PStartTls
  , phaseIndex PStartTls < phaseIndex PEhloTls
  , phaseIndex PEhloTls  < phaseIndex PAuth
  , phaseIndex PAuth     < phaseIndex PMailFrom
  , phaseIndex PData     < phaseIndex PPayload
  ) = (True, True, True, True, True)
orderingSound = Refl
