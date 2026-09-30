-- SPDX-License-Identifier: MPL-2.0
||| Message-serialization contract: DATA dot-stuffing (RFC 5321 §4.5.2),
||| CRLF rejection in header-bound inputs (header-injection defense), and the
||| Content-Language value grammar (RFC 3282 list of RFC 5646 tags).
|||
||| The Zig implementation (`src/message.zig`) mirrors these rules and is
||| tested against golden vectors that `Smtp.EmitZig` computes FROM THIS MODEL
||| at generation time — so the implementation is checked against the spec's
||| own evaluation, not against a hand-written copy of it.
module Smtp.Serialize

import Data.List   -- drop, split
import Data.List1  -- forget

%default total

||| A body line beginning with '.' must be transmitted with the dot doubled;
||| otherwise a line consisting of just "." would terminate DATA early
||| (silent message truncation — the classic unstuffed-dot bug).
public export
startsWithDot : List Char -> Bool
startsWithDot []       = False
startsWithDot (c :: _) = c == '.'

stuffLineB : Bool -> List Char -> List Char
stuffLineB True  cs = '.' :: cs
stuffLineB False cs = cs

||| Transmit-encode one body line.
public export
stuffLine : List Char -> List Char
stuffLine cs = stuffLineB (startsWithDot cs) cs

||| Safety predicate: a transmitted line may begin with '.' only if the very
||| next character is also '.' — i.e. it can never be mistaken for the DATA
||| terminator, and the receiver's un-stuffing recovers the original line.
public export
safeOnWire : List Char -> Bool
safeOnWire cs = if startsWithDot cs then startsWithDot (drop 1 cs) else True

lemmaStuff : (b : Bool) -> (cs : List Char) -> startsWithDot cs = b
          -> safeOnWire (stuffLineB b cs) = True
lemmaStuff True  cs h = h
lemmaStuff False cs h = rewrite h in Refl

||| THEOREM (all inputs, structural): every stuffed line is safe on the wire.
export
stuffSafe : (cs : List Char) -> safeOnWire (stuffLine cs) = True
stuffSafe cs = lemmaStuff (startsWithDot cs) cs Refl

||| Header-injection defense: a value interpolated into a header line (From,
||| To, Subject) must contain no CR and no LF. A CRLF smuggled into `subject`
||| would otherwise let the caller append arbitrary headers or start the body
||| early. The client REJECTS (aborts), never sanitizes — silent rewriting of
||| a subject is how injection bugs hide.
public export
headerValueOk : List Char -> Bool
headerValueOk = all (\c => c /= '\r' && c /= '\n')

-- ---------------------------------------------------------------------------
-- Content-Language (RFC 3282), carrying RFC 5646 language tags.
--
-- This is a WELL-FORMEDNESS check, not registry validation: it accepts the
-- shape of a tag (subtags of 1-8 ASCII alphanumerics joined by '-', the first
-- subtag alphabetic) without consulting the IANA subtag registry. A tag that
-- passes may still name no real language; a tag that fails cannot be a tag.
-- A value is a comma-separated list of such tags, optional spaces around
-- each, as RFC 3282 allows ("en, cy" for a bilingual English/Welsh message).
--
-- The value is REJECTED, never repaired — the same rule as every other
-- header-bound input.
-- ---------------------------------------------------------------------------

isAsciiAlpha : Char -> Bool
isAsciiAlpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')

isAsciiAlphaNum : Char -> Bool
isAsciiAlphaNum c = isAsciiAlpha c || (c >= '0' && c <= '9')

subtagOk : List Char -> Bool
subtagOk cs = length cs >= 1 && length cs <= 8 && all isAsciiAlphaNum cs

primaryOk : List Char -> Bool
primaryOk cs = subtagOk cs && all isAsciiAlpha cs

||| One RFC 5646 tag, by shape: primary subtag alphabetic, every subtag 1-8
||| alphanumerics, no empty subtag (so no leading, trailing or doubled '-').
public export
langTagOk : List Char -> Bool
langTagOk cs = case forget (split (== '-') cs) of
  []          => False
  (p :: rest) => primaryOk p && all subtagOk rest

trimSpaces : List Char -> List Char
trimSpaces = reverse . dropWhile (== ' ') . reverse . dropWhile (== ' ')

||| An RFC 3282 Content-Language value: one or more tags, comma-separated.
public export
langListOk : List Char -> Bool
langListOk cs = all (langTagOk . trimSpaces) (forget (split (== ',') cs))

||| What the client accepts into the Content-Language header: a well-formed
||| tag list AND a value that passes the header-injection predicate. The
||| second conjunct is implied by the first in fact (no tag character is CR
||| or LF), but it is stated rather than argued, so the theorem below holds
||| by construction and survives any future loosening of the tag grammar.
public export
contentLanguageOk : List Char -> Bool
contentLanguageOk cs = langListOk cs && headerValueOk cs

andRight : (a, b : Bool) -> (a && b) = True -> b = True
andRight True  _ prf = prf
andRight False _ prf = absurd prf

||| THEOREM (all inputs, structural): nothing the client accepts as a
||| Content-Language value can inject a header. Removing the injection
||| conjunct from `contentLanguageOk` breaks this proof, not a test.
export
contentLanguageNoInjection : (cs : List Char) -> contentLanguageOk cs = True
                          -> headerValueOk cs = True
contentLanguageNoInjection cs prf = andRight (langListOk cs) (headerValueOk cs) prf

-- ---------------------------------------------------------------------------
-- Golden vectors. EmitZig evaluates `stuffLine`/`headerValueOk` over these
-- and emits (input, expected) pairs into the generated Zig, where unit tests
-- assert the Zig implementation agrees byte-for-byte.
-- ---------------------------------------------------------------------------

public export
stuffCorpus : List (List Char)
stuffCorpus =
  [ unpack ""
  , unpack "."
  , unpack ".."
  , unpack ". leading dot with text"
  , unpack ".hidden"
  , unpack "ordinary line"
  , unpack " . dot after space is untouched"
  , unpack "trailing dot ."
  , unpack "...."
  ]

public export
headerCorpus : List (List Char)
headerCorpus =
  [ unpack "[repo] push to main by owner"
  , unpack "ordinary subject"
  , unpack "bad\r\ninjected: header"
  , unpack "bare\rcr"
  , unpack "bare\nlf"
  , unpack ""
  ]

public export
langCorpus : List (List Char)
langCorpus =
  [ unpack "en"
  , unpack "en-GB"
  , unpack "cy"
  , unpack "zh-Hant-TW"
  , unpack "de-1996"
  , unpack "x-private"
  , unpack "en, cy"
  , unpack "en,cy"
  , unpack " en "
  , unpack ""
  , unpack "en_GB"
  , unpack "en-"
  , unpack "-en"
  , unpack "en--GB"
  , unpack "en,"
  , unpack "en GB"
  , unpack "12"
  , unpack "toolongtag"
  , unpack "en-abcdefghi"
  , unpack "en\r\nBcc: victim@example.org"
  , unpack "en\nX-Injected: 1"
  , unpack "caf\233"
  ]
