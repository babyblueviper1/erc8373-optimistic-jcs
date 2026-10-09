// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @notice Checks that a byte string is ALREADY the RFC 8785 (JCS) serialization of a flat JSON
/// object whose member values are strings or safe integers. It verifies canonical form. It does not
/// produce it.
///
/// Accepted grammar, with nothing between tokens:
///   object  = "{" [ member *( "," member ) ] "}"
///   member  = string ":" ( string | integer )
///   integer = "0" / [ "-" ] nonzero-digit *digit      with |value| <= 2^53 - 1
///
/// Rules enforced, each one a way two different byte strings could otherwise mean the same object:
///   1. no whitespace anywhere outside a string
///   2. member names strictly ascending by UTF-16 code unit (RFC 8785 3.2.3), so no duplicates
///   3. strings escaped exactly as ECMAScript JSON.stringify does (RFC 8785 3.2.2.2): the two-char
///      forms for backspace, tab, LF, FF, CR, quote and backslash, lowercase \u00xx for the other
///      controls below 0x20, and every other character literal. So no "\/", no "A".
///   4. well-formed UTF-8: no overlong forms, no encoded surrogates, nothing above U+10FFFF
///   5. integers in shortest decimal form: no "+", no leading zero, no "-0", no fraction, no exponent
///
/// Out of scope on purpose: fractions and exponents (the ECMAScript shortest-round-trip number
/// formatting that makes full JCS impractical on chain), integers beyond 2^53 - 1, booleans, null,
/// arrays and nested objects. Any of those returns false.
library JcsFlatProfile {
    uint256 private constant MAX_SAFE_INTEGER = 9007199254740991; // 2^53 - 1

    function isCanonical(bytes calldata b) internal pure returns (bool) {
        uint256 n = b.length;
        if (n < 2 || b[0] != "{" || b[n - 1] != "}") return false;
        if (n == 2) return true;

        uint256 i = 1;
        uint256 prevStart;
        uint256 prevEnd;
        bool hasPrev;
        unchecked {
            while (true) {
                // member name
                if (b[i] != '"') return false; // i <= n - 1 always holds here
                uint256 ks = i + 1;
                (bool ok, uint256 ke) = _scanString(b, ks, n);
                if (!ok) return false;
                if (hasPrev && !_lessUtf16(b, prevStart, prevEnd, ks, ke)) return false;
                (prevStart, prevEnd, hasPrev) = (ks, ke, true);

                // name separator; ke < n so ke + 1 <= n
                i = ke + 1;
                if (i >= n || b[i] != ":") return false;
                i++;
                if (i >= n) return false;

                // value
                if (b[i] == '"') {
                    (ok, ke) = _scanString(b, i + 1, n);
                    if (!ok) return false;
                    i = ke + 1;
                } else {
                    (ok, i) = _scanInteger(b, i, n);
                    if (!ok) return false;
                }

                if (i >= n) return false;
                if (b[i] == ",") {
                    i++;
                    if (i >= n) return false;
                    continue;
                }
                // the only "}" allowed outside a string is the final byte
                return i == n - 1;
            }
        }
        return false;
    }

    /// @dev Scans string content starting just after the opening quote. Returns the index of the
    /// closing quote. False if the content is not in canonical form or the input ends first.
    function _scanString(bytes calldata b, uint256 i, uint256 n) private pure returns (bool, uint256) {
        unchecked {
            while (i < n) {
                uint8 c = uint8(b[i]);
                if (c == 0x22) return (true, i);
                if (c < 0x20) return (false, 0); // a raw control character must be escaped
                if (c == 0x5c) {
                    if (i + 1 >= n) return (false, 0);
                    uint8 d = uint8(b[i + 1]);
                    // \" \\ \b \f \n \r \t
                    if (d == 0x22 || d == 0x5c || d == 0x62 || d == 0x66 || d == 0x6e || d == 0x72 || d == 0x74) {
                        i += 2;
                        continue;
                    }
                    if (d != 0x75) return (false, 0); // "\/" and anything else is not canonical
                    // \u00xx, lowercase hex, only for controls that have no two-char form
                    if (i + 5 >= n) return (false, 0);
                    if (b[i + 2] != "0" || b[i + 3] != "0") return (false, 0);
                    uint8 h = uint8(b[i + 4]);
                    uint8 l = uint8(b[i + 5]);
                    if (h != 0x30 && h != 0x31) return (false, 0); // value must be below 0x20
                    uint256 lo;
                    if (l >= 0x30 && l <= 0x39) lo = l - 0x30;
                    else if (l >= 0x61 && l <= 0x66) lo = l - 0x61 + 10; // uppercase is not canonical
                    else return (false, 0);
                    uint256 v = (uint256(h - 0x30) << 4) | lo;
                    if (v == 0x08 || v == 0x09 || v == 0x0a || v == 0x0c || v == 0x0d) return (false, 0);
                    i += 6;
                    continue;
                }
                if (c < 0x80) {
                    i++;
                    continue;
                }
                // multi-byte UTF-8
                uint256 need;
                uint8 lo2 = 0x80;
                uint8 hi2 = 0xbf;
                if (c >= 0xc2 && c <= 0xdf) {
                    need = 1;
                } else if (c >= 0xe0 && c <= 0xef) {
                    need = 2;
                    if (c == 0xe0) lo2 = 0xa0; // overlong
                    else if (c == 0xed) hi2 = 0x9f; // surrogates
                } else if (c >= 0xf0 && c <= 0xf4) {
                    need = 3;
                    if (c == 0xf0) lo2 = 0x90; // overlong
                    else if (c == 0xf4) hi2 = 0x8f; // above U+10FFFF
                } else {
                    return (false, 0); // stray continuation byte, 0xc0, 0xc1, 0xf5..0xff
                }
                if (i + need >= n) return (false, 0);
                uint8 c2 = uint8(b[i + 1]);
                if (c2 < lo2 || c2 > hi2) return (false, 0);
                for (uint256 k = 2; k <= need; k++) {
                    if (uint8(b[i + k]) & 0xc0 != 0x80) return (false, 0);
                }
                i += need + 1;
            }
            return (false, 0);
        }
    }

    /// @dev Scans an integer starting at i. Returns the index one past its last digit.
    function _scanInteger(bytes calldata b, uint256 i, uint256 n) private pure returns (bool, uint256) {
        unchecked {
            bool negative = b[i] == "-";
            if (negative) {
                i++;
                if (i >= n) return (false, 0);
            }
            uint8 c = uint8(b[i]);
            if (c == 0x30) {
                // a lone "0"; "-0" serializes as "0", and a leading zero is never canonical.
                // Whatever follows is checked by the caller, so "01", "0.5" and "0e1" all fail there.
                return (!negative, i + 1);
            }
            if (c < 0x31 || c > 0x39) return (false, 0);
            uint256 v;
            uint256 digits;
            while (i < n) {
                c = uint8(b[i]);
                if (c < 0x30 || c > 0x39) break;
                v = v * 10 + (c - 0x30);
                if (++digits > 16) return (false, 0); // 2^53 - 1 has 16 digits
                i++;
            }
            if (v > MAX_SAFE_INTEGER) return (false, 0);
            return (true, i);
        }
    }

    /// @dev Strict less-than over the UTF-16 code units of two already-validated member names,
    /// given as [start, end) ranges of their escaped bytes. Byte order is not enough: a name holding
    /// U+10000 or above sorts BELOW one holding U+E000..U+FFFF in UTF-16, and above it in UTF-8.
    function _lessUtf16(bytes calldata b, uint256 ai, uint256 ae, uint256 bi, uint256 be)
        private
        pure
        returns (bool)
    {
        unchecked {
            uint256 ap; // pending low surrogate for a
            uint256 bp;
            while (true) {
                bool aDone = ai == ae && ap == 0;
                bool bDone = bi == be && bp == 0;
                if (aDone || bDone) return aDone && !bDone; // a proper prefix sorts first
                uint256 ua;
                uint256 ub;
                (ua, ai, ap) = _nextUnit(b, ai, ap);
                (ub, bi, bp) = _nextUnit(b, bi, bp);
                if (ua != ub) return ua < ub;
            }
        }
        return false;
    }

    /// @dev Next UTF-16 code unit of a validated string. No bounds or form checks: _scanString ran.
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
                return (d, i + 2, 0); // \" and \\
            }
            if (c < 0x80) return (c, i + 1, 0);
            if (c < 0xe0) return (((c & 0x1f) << 6) | (uint8(b[i + 1]) & 0x3f), i + 2, 0);
            if (c < 0xf0) {
                return (((c & 0x0f) << 12) | ((uint256(uint8(b[i + 1])) & 0x3f) << 6) | (uint8(b[i + 2]) & 0x3f), i + 3, 0);
            }
            uint256 cp = ((c & 0x07) << 18) | ((uint256(uint8(b[i + 1])) & 0x3f) << 12)
                | ((uint256(uint8(b[i + 2])) & 0x3f) << 6) | (uint8(b[i + 3]) & 0x3f);
            cp -= 0x10000;
            return (0xd800 | (cp >> 10), i + 4, 0xdc00 | (cp & 0x3ff));
        }
    }
}
