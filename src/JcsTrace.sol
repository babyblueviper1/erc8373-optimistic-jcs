// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @notice The JcsFlatProfile grammar as a resumable state machine, so a canonical-form check can be split
/// into bounded segments and one segment re-run on chain.
///
/// A trace is a list of packed parser states ("checkpoints"), from INIT at byte 1 to DONE at byte n, at most
/// maxSeg bytes apart. A segment is valid when running the machine from checkpoint j lands exactly on
/// checkpoint j+1. If checkpoint 0 is INIT, the last is DONE(n) and every segment is valid, then by induction
/// every checkpoint is the true parser state at its offset and the bytes are canonical. So a non-canonical
/// statement, or a wrong trace, always has one invalid segment, and showing it costs at most maxSeg bytes of
/// re-execution (plus one member-name comparison of at most MAX_KEY bytes) instead of the whole document.
///
/// Why checkpoints and not just "the index of the first bad byte": whether a byte is a violation depends on
/// state the byte does not show (inside a string or not, the previous member name for the ordering rule).
/// The checkpoint is that state, committed by the anchorer, so the challenger does not have to prove it.
///
/// The predicate is JcsFlatProfile.isCanonical with ONE addition: member names are at most MAX_KEY escaped
/// bytes. That bound is what keeps the ordering check, the only non-local rule, bounded per segment. Values
/// are unbounded. The character and integer rules are ported from Zexo's JcsFlatProfile unchanged
/// (test_differentialAgainstIsCanonical runs both over the 4693 vectors).
library JcsTrace {
    uint256 internal constant MAX_KEY = 64; // escaped bytes per member name
    uint256 internal constant MAX_STEP = 24; // most bytes one step can consume (a name end + 16-digit integer + ",")

    uint256 internal constant M_OPEN = 1; // at byte 1, just after "{"
    uint256 internal constant M_MEMBER = 2; // just after ","
    uint256 internal constant M_KEY = 3; // inside a member name
    uint256 internal constant M_VALUE = 4; // inside a string value
    uint256 internal constant M_DONE = 5; // past the final "}"

    struct S {
        uint256 pos;
        uint256 mode;
        uint256 prevKs; // previous member name, [prevKs, prevKe) of escaped bytes; prevKe == 0 means none
        uint256 prevKe;
        uint256 curKs; // start of the current member name, only in M_KEY
    }

    function pack(S memory s) internal pure returns (uint256) {
        return s.pos | (s.mode << 32) | (s.prevKs << 40) | (s.prevKe << 72) | (s.curKs << 104);
    }

    function unpack(uint256 w) internal pure returns (S memory s) {
        s.pos = uint32(w);
        s.mode = uint8(w >> 32);
        s.prevKs = uint32(w >> 40);
        s.prevKe = uint32(w >> 72);
        s.curKs = uint32(w >> 104);
    }

    function initState() internal pure returns (uint256) {
        return pack(S(1, M_OPEN, 0, 0, 0));
    }

    function doneState(uint256 n) internal pure returns (uint256) {
        return pack(S(n, M_DONE, 0, 0, 0));
    }

    /// True if running the machine from `fromW` lands exactly on `toW`, at most maxSeg bytes later.
    function segmentOk(bytes calldata b, uint256 fromW, uint256 toW, uint256 maxSeg) internal pure returns (bool) {
        S memory s = unpack(fromW);
        uint256 end = uint32(toW);
        if (end <= s.pos || end - s.pos > maxSeg) return false;
        while (s.pos < end) {
            if (!step(b, s)) return false;
        }
        return s.pos == end && pack(s) == toW;
    }

    /// The honest trace an anchorer submits. ok == false means the bytes are not canonical under this profile;
    /// the leaves are then the valid prefix, which is what a test needs to build an adversarial trace.
    function trace(bytes calldata b, uint256 maxSeg) internal pure returns (bool ok, uint256[] memory leaves) {
        require(maxSeg > MAX_STEP, "maxSeg too small");
        uint256 cap = b.length / (maxSeg - MAX_STEP) + 2;
        leaves = new uint256[](cap);
        S memory s = unpack(initState());
        leaves[0] = initState();
        uint256 m = 1;
        uint256 last = 1;
        ok = true;
        while (s.mode != M_DONE) {
            if (!step(b, s)) {
                ok = false;
                break;
            }
            if (s.mode == M_DONE || s.pos - last > maxSeg - MAX_STEP) {
                leaves[m++] = pack(s);
                last = s.pos;
            }
        }
        assembly {
            mstore(leaves, m)
        }
    }

    /// One step. Every step advances pos; false means a violation (or input ending) at s.pos.
    function step(bytes calldata b, S memory s) internal pure returns (bool) {
        uint256 n = b.length;
        uint256 i = s.pos;
        if (i >= n) return false;
        uint256 mode = s.mode;
        bytes1 c = b[i];
        if (mode == M_OPEN || mode == M_MEMBER) {
            if (mode == M_OPEN) {
                if (b[0] != "{") return false;
                if (c == "}") {
                    if (i != n - 1) return false;
                    s.pos = n;
                    s.mode = M_DONE;
                    return true;
                }
            }
            if (c != '"') return false;
            s.curKs = i + 1;
            s.pos = i + 1;
            s.mode = M_KEY;
            return true;
        }
        if (mode == M_KEY) {
            if (c != '"') return _char(b, s, i, n);
            if (i - s.curKs > MAX_KEY) return false;
            if (s.prevKe != 0 && !_lessUtf16(b, s.prevKs, s.prevKe, s.curKs, i)) return false;
            (s.prevKs, s.prevKe, s.curKs) = (s.curKs, i, 0);
            i++;
            if (i >= n || b[i] != ":") return false;
            i++;
            if (i >= n) return false;
            if (b[i] == '"') {
                s.pos = i + 1;
                s.mode = M_VALUE;
                return true;
            }
            bool ok;
            (ok, i) = _scanInteger(b, i, n);
            if (!ok) return false;
            return _afterValue(b, s, i, n);
        }
        if (mode == M_VALUE) {
            if (c != '"') return _char(b, s, i, n);
            return _afterValue(b, s, i + 1, n);
        }
        return false;
    }

    function _afterValue(bytes calldata b, S memory s, uint256 i, uint256 n) private pure returns (bool) {
        if (i >= n) return false;
        if (b[i] == ",") {
            if (i + 1 >= n) return false;
            s.pos = i + 1;
            s.mode = M_MEMBER;
            return true;
        }
        if (b[i] == "}" && i == n - 1) {
            (s.pos, s.mode, s.prevKs, s.prevKe) = (n, M_DONE, 0, 0);
            return true;
        }
        return false;
    }

    /// @dev One character of string content at i (not the closing quote). Ported from JcsFlatProfile._scanString.
    function _char(bytes calldata b, S memory s, uint256 i, uint256 n) private pure returns (bool) {
        unchecked {
            uint8 c = uint8(b[i]);
            if (c < 0x20) return false;
            if (c == 0x5c) {
                if (i + 1 >= n) return false;
                uint8 d = uint8(b[i + 1]);
                if (d == 0x22 || d == 0x5c || d == 0x62 || d == 0x66 || d == 0x6e || d == 0x72 || d == 0x74) {
                    s.pos = i + 2;
                    return true;
                }
                if (d != 0x75) return false;
                if (i + 5 >= n) return false;
                if (b[i + 2] != "0" || b[i + 3] != "0") return false;
                uint8 h = uint8(b[i + 4]);
                uint8 l = uint8(b[i + 5]);
                if (h != 0x30 && h != 0x31) return false;
                uint256 lo;
                if (l >= 0x30 && l <= 0x39) lo = l - 0x30;
                else if (l >= 0x61 && l <= 0x66) lo = l - 0x61 + 10;
                else return false;
                uint256 v = (uint256(h - 0x30) << 4) | lo;
                if (v == 0x08 || v == 0x09 || v == 0x0a || v == 0x0c || v == 0x0d) return false;
                s.pos = i + 6;
                return true;
            }
            if (c < 0x80) {
                s.pos = i + 1;
                return true;
            }
            uint256 need;
            uint8 lo2 = 0x80;
            uint8 hi2 = 0xbf;
            if (c >= 0xc2 && c <= 0xdf) {
                need = 1;
            } else if (c >= 0xe0 && c <= 0xef) {
                need = 2;
                if (c == 0xe0) lo2 = 0xa0;
                else if (c == 0xed) hi2 = 0x9f;
            } else if (c >= 0xf0 && c <= 0xf4) {
                need = 3;
                if (c == 0xf0) lo2 = 0x90;
                else if (c == 0xf4) hi2 = 0x8f;
            } else {
                return false;
            }
            if (i + need >= n) return false;
            uint8 c2 = uint8(b[i + 1]);
            if (c2 < lo2 || c2 > hi2) return false;
            for (uint256 k = 2; k <= need; k++) {
                if (uint8(b[i + k]) & 0xc0 != 0x80) return false;
            }
            s.pos = i + need + 1;
            return true;
        }
    }

    /// @dev Ported from JcsFlatProfile._scanInteger unchanged.
    function _scanInteger(bytes calldata b, uint256 i, uint256 n) private pure returns (bool, uint256) {
        unchecked {
            bool negative = b[i] == "-";
            if (negative) {
                i++;
                if (i >= n) return (false, 0);
            }
            uint8 c = uint8(b[i]);
            if (c == 0x30) return (!negative, i + 1);
            if (c < 0x31 || c > 0x39) return (false, 0);
            uint256 v;
            uint256 digits;
            while (i < n) {
                c = uint8(b[i]);
                if (c < 0x30 || c > 0x39) break;
                v = v * 10 + (c - 0x30);
                if (++digits > 16) return (false, 0);
                i++;
            }
            if (v > 9007199254740991) return (false, 0);
            return (true, i);
        }
    }

    /// @dev Ported from JcsFlatProfile._lessUtf16 unchanged.
    function _lessUtf16(bytes calldata b, uint256 ai, uint256 ae, uint256 bi, uint256 be) private pure returns (bool) {
        unchecked {
            uint256 ap;
            uint256 bp;
            while (true) {
                bool aDone = ai == ae && ap == 0;
                bool bDone = bi == be && bp == 0;
                if (aDone || bDone) return aDone && !bDone;
                uint256 ua;
                uint256 ub;
                (ua, ai, ap) = _nextUnit(b, ai, ap);
                (ub, bi, bp) = _nextUnit(b, bi, bp);
                if (ua != ub) return ua < ub;
            }
        }
        return false;
    }

    /// @dev Ported from JcsFlatProfile._nextUnit unchanged.
    function _nextUnit(bytes calldata b, uint256 i, uint256 pending)
        private
        pure
        returns (uint256 unit, uint256 next, uint256 newPending)
    {
        unchecked {
            if (pending != 0) return (pending, i, 0);
            uint256 c = uint8(b[i]);
            if (c == 0x5c) {
                uint256 d = uint8(b[i + 1]);
                if (d == 0x75) {
                    uint256 h = uint8(b[i + 4]) - 0x30;
                    uint256 l = uint8(b[i + 5]);
                    l = l <= 0x39 ? l - 0x30 : l - 0x61 + 10;
                    return ((h << 4) | l, i + 6, 0);
                }
                if (d == 0x62) return (0x08, i + 2, 0);
                if (d == 0x74) return (0x09, i + 2, 0);
                if (d == 0x6e) return (0x0a, i + 2, 0);
                if (d == 0x66) return (0x0c, i + 2, 0);
                if (d == 0x72) return (0x0d, i + 2, 0);
                return (d, i + 2, 0);
            }
            if (c < 0x80) return (c, i + 1, 0);
            if (c < 0xe0) return (((c & 0x1f) << 6) | (uint8(b[i + 1]) & 0x3f), i + 2, 0);
            if (c < 0xf0) {
                return
                    (((c & 0x0f) << 12) | ((uint256(uint8(b[i + 1])) & 0x3f) << 6) | (uint8(b[i + 2]) & 0x3f), i + 3, 0);
            }
            uint256 cp = ((c & 0x07) << 18) | ((uint256(uint8(b[i + 1])) & 0x3f) << 12)
                | ((uint256(uint8(b[i + 2])) & 0x3f) << 6) | (uint8(b[i + 3]) & 0x3f);
            cp -= 0x10000;
            return (0xd800 | (cp >> 10), i + 4, 0xdc00 | (cp & 0x3ff));
        }
    }
}
