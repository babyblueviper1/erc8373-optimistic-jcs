# Optimistic JCS anchoring for ERC-8373 statements

Checking that a statement is in RFC 8785 (JCS) canonical form on chain costs about 240 to 270 gas per byte ([Zexo's probe](https://gist.github.com/zexoverz/4667ae105581352fca3520b02bdf76e0)). For the ML-DSA-65 binding statement (4120 bytes) that is close to a million gas. Jimmy Shi suggested a hash-based challenge for this in the TAWG thread. This repo builds that design and measures it.

`OptimisticJcsAnchor` anchors `sha256(raw)` without checking the form. Anyone can then prove, within a window, that the anchored bytes are not canonical. The full check runs only when someone challenges.

- `anchor(raw)`: takes the statement as calldata, so every watcher can read the exact bytes from the transaction. It costs one sha256 and one storage slot, plus a fixed bond.
- `challenge(digest, raw)`: succeeds only if `sha256(raw) == digest` and `JcsFlatProfile.isCanonical(raw)` is false. The anchor is then rejected and the bond goes to the challenger. A challenge against a canonical statement reverts, at the challenger's cost.
- `isAccepted(digest)`: true once the window has closed with no successful challenge.

**Trust assumption: one honest watcher.** A non-canonical statement that nobody challenges before the window closes is accepted. `test_nonCanonicalUnchallengedIsAccepted_trustAssumption` pins this down. If your use cannot accept that, check the form on chain (the "checked" column below).

## Results

Execution gas, measured around an external call. Calldata is listed separately because both paths take the same bytes.

| statement (pinned in recompute-kit) | bytes | calldata | optimistic anchor | check, then anchor | total, optimistic | total, checked |
|---|---|---|---|---|---|---|
| `invinoveritas-pq-key-binding-v1-live` (ML-DSA-65) | 4120 | 65,920 | 40,299 | 999,444 | 106,219 | 1,065,364 |
| `kya-l4-pq-key-binding-v0-slh-dsa` | 293 | 4,688 | 32,820 | 96,893 | 37,508 | 101,581 |
| `kya-l4-pq-key-binding-v0-rotation-1-slh-dsa` | 409 | 6,544 | 32,903 | 127,092 | 39,447 | 133,636 |
| `kya-example-binding-v0-slh-dsa` | 293 | 4,688 | 32,825 | 96,894 | 37,513 | 101,582 |
| `kya-key-revocation-v0-of-example` | 259 | 4,144 | 32,802 | 88,327 | 36,946 | 92,471 |

That makes it about 10x cheaper for the ML-DSA statement and about 2.5x for the SLH-DSA ones. The optimistic path is roughly flat in size: the storage write dominates, not the hash. The 21k base cost is not included in either path.

What a challenger pays depends on where the first violation is, because the checker stops there:

- a violation near the start: 14,743 gas
- a violation at the last byte of the 4121-byte statement: 982,073 gas

The bond has to cover the worst case at the gas price the deployment expects. The tests use 0.01 ether.

The digest of each pinned statement equals the `canonical_content_sha256` that recompute-kit pins (asserted in `test_gasOnPinnedStatements`).

## What the optimistic tests check

7 tests, all passing:

- all five pinned statements anchor and match their pinned digests;
- a canonical statement cannot be challenged and is accepted after the window;
- a non-canonical statement is rejected and the challenger is paid;
- a challenge must carry the exact anchored bytes;
- an unchallenged non-canonical statement is accepted (the trust assumption);
- bond, withdrawal and double-anchor rules;
- the worst-case challenge gas.

Each guard was removed in turn to check the tests can fail: the canonical check, the digest match, the window and the submitter check. Every removal turns one test red.

## Pinpoint challenge (`PinpointJcsAnchor`)

Echo (8373 author) suggested making the challenge "pinpoint rather than re-execute", so the bond can be derived instead of covering the worst case. Echo also named the hard part: not every JCS violation can be decided locally. Member ordering and duplicate names depend on the previous member, and whether a byte is a violation depends on whether it sits inside a string. A bare "index of the first bad byte" is therefore not checkable on its own.

`PinpointJcsAnchor` solves this by having the anchorer commit the missing state:

- `anchor(raw, trace)`: `trace` is a list of packed parser states (checkpoints), at most `MAX_SEG` bytes apart, from INIT at byte 1 to DONE at byte n. The contract stores `sha256(raw)` and `keccak256(trace)`. Both are calldata, so every watcher has them. `traceOf(raw)` (eth_call) returns the honest trace.
- `challenge(digest, raw, trace, j)`: re-runs only segment j, i.e. from checkpoint j for at most `MAX_SEG` bytes, and wins if the run does not land exactly on checkpoint j+1. It also wins if the trace does not start at INIT or end at DONE(n), or if any segment is longer than `MAX_SEG`.
- Why that is sound: if checkpoint 0 is INIT, the last is DONE(n), and every segment is valid, then by induction every checkpoint is the true parser state at its offset, and the bytes are canonical. So a non-canonical statement always has a provable bad segment, whatever trace the anchorer picked. The same holds for a wrong trace.
- What rejection means: the bytes are not canonical, OR the anchorer's trace is wrong. A wrong trace costs the anchorer the bond, and the bytes can be re-anchored with a correct trace.
- One profile change: member names are capped at `MAX_KEY` = 64 escaped bytes. This keeps the ordering check, the only rule that is not local, bounded within a segment. Values stay unbounded. The longest name in the 4693 vectors is 27 bytes, and `test_longMemberNameIsOutsideProfile` pins the difference.

Measured with `MAX_SEG` = 256, on the 4120-byte ML-DSA-65 statement (execution gas, calldata for `raw` excluded as above):

| | optimistic (full re-run) | pinpoint |
|---|---|---|
| anchor | 40,299 | 60,615 + 3,500 trace calldata (18 segments) |
| challenge, violation at byte 13 | 14,743 | 16,820 |
| challenge, violation at byte 2060 | n/a | 17,549 |
| challenge, violation at the last byte | 982,073 | 115,771 |
| anchorer submits one segment for the whole document | n/a | 16,716 (rejected on length alone) |

The worst-case challenge is now bounded by one `MAX_SEG` segment plus one 64-byte name comparison, plus `sha256` and keccak over the calldata, which grow at a few gas per byte. It no longer depends on where the violation is, so a bond can be computed from `MAX_SEG` and a declared maximum statement size. The cost is one extra storage slot at anchor time (about 20k gas). For the SLH-DSA statements that brings the anchor to about 56k against 33k for the plain optimistic path. Pick `MAX_SEG` to trade the anchor's trace calldata against the challenge bound.

What the pinpoint tests check (10, all passing):

- Differential: on all 4693 vectors, at `MAX_SEG` 256 and 32, the honest trace succeeds exactly when Zexo's `isCanonical` does. No segment of an honest trace can be challenged. Every non-canonical input, under the trace an anchorer would most plausibly submit (its valid prefix, then a claimed DONE), has a provable bad segment. 1235 of the honest traces split into more than one segment.
- Tampering: flipping bits in checkpoints is caught at the adjacent segment (1305 cases). The 87 uncaught flips all only move the offset within the same string, which produces a different but valid trace, and the test asserts that.
- A trace that starts after the violation is caught at checkpoint 0. A one-segment trace is caught on length. A wrong trace on canonical bytes loses the bond and can be re-anchored. Plus the guard tests (digest, trace hash, window, submitter).
- Seven guards were each removed in turn: end-state match, segment-length cap, INIT, DONE, trace hash, digest, member ordering. Every removal turns at least one test red.

`src/JcsTrace.sol` ports Zexo's character, integer and UTF-16 ordering code unchanged into a resumable step function. `JcsFlatProfile.sol` itself is untouched.

## Not covered

- Fractions, exponents, nested objects, arrays, booleans and null. Zexo's profile rejects all of them on purpose, and so does this.
- Which window and bond an ERC deployment should use.
- Whether the statement should carry a hash of the post-quantum key instead of the key itself. That would cap statement size, and therefore the worst-case challenge, for every key type. It is a spec change, so it is for the 8373 authors to decide.

## Run

```
forge install foundry-rs/forge-std --no-git
forge test -vv
```

## Credit

`src/JcsFlatProfile.sol` and `vectors.json` are Zexo's (CC0), taken unchanged from the gist above. The hash-challenge direction is Jimmy Shi's (TAWG, 2026-10-09). The pinpoint direction is Echo's (TAWG, 2026-10-09). The anchor contracts, `JcsTrace`, tests and measurements are by invinoveritas (babyblueviper1). CC0.
