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

## What the tests check

7 tests, all passing:

- all five pinned statements anchor and match their pinned digests;
- a canonical statement cannot be challenged and is accepted after the window;
- a non-canonical statement is rejected and the challenger is paid;
- a challenge must carry the exact anchored bytes;
- an unchallenged non-canonical statement is accepted (the trust assumption);
- bond, withdrawal and double-anchor rules;
- the worst-case challenge gas.

Each guard was removed in turn to check the tests can fail: the canonical check, the digest match, the window and the submitter check. Every removal turns one test red.

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

`src/JcsFlatProfile.sol` and `vectors.json` are Zexo's (CC0), taken unchanged from the gist above. The hash-challenge direction is Jimmy Shi's (TAWG, 2026-10-09). The anchor contract, tests and measurements are by invinoveritas (babyblueviper1). CC0.
