// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {PinpointJcsAnchor} from "../src/PinpointJcsAnchor.sol";
import {OptimisticJcsAnchor} from "../src/OptimisticJcsAnchor.sol";
import {JcsFlatProfile} from "../src/JcsFlatProfile.sol";
import {JcsTrace} from "../src/JcsTrace.sol";

contract ProfileHarness {
    function isCanonical(bytes calldata b) external pure returns (bool) {
        return JcsFlatProfile.isCanonical(b);
    }
}

library JcsTraceHarness {
    function segmentOk(bytes calldata b, uint256 fromW, uint256 toW, uint256 maxSeg) external pure returns (bool) {
        return JcsTrace.segmentOk(b, fromW, toW, maxSeg);
    }
}

contract PinpointJcsAnchorTest is Test {
    uint256 constant WINDOW = 1 days;
    uint256 constant BOND = 0.01 ether;
    PinpointJcsAnchor pa; // MAX_SEG 256, the deployment the gas numbers are for
    PinpointJcsAnchor tiny; // MAX_SEG 32, so even the short vectors split into many segments
    OptimisticJcsAnchor oa;
    ProfileHarness h;
    bytes[] real;
    bytes32[] digests;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        pa = new PinpointJcsAnchor(WINDOW, BOND, 256);
        tiny = new PinpointJcsAnchor(WINDOW, BOND, 32);
        oa = new OptimisticJcsAnchor(WINDOW, BOND);
        h = new ProfileHarness();
        string memory json = vm.readFile("vectors.json");
        bytes[] memory r = vm.parseJsonBytesArray(json, ".realInputs");
        bytes32[] memory d = vm.parseJsonBytes32Array(json, ".realDigests");
        for (uint256 i; i < r.length; i++) {
            real.push(r[i]);
            digests.push(d[i]);
        }
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
    }

    /// The honest trace is accepted exactly when Zexo's isCanonical accepts, on all 4693 vectors, at two
    /// segment sizes. Every segment of every honest trace is valid; for every rejected input, the trace an
    /// anchorer would most plausibly submit (valid prefix, then a claimed DONE) has a provable bad segment.
    function test_differentialAgainstIsCanonical() public view {
        string memory json = vm.readFile("vectors.json");
        bytes[] memory inputs = vm.parseJsonBytesArray(json, ".inputs");
        bool[] memory expected = vm.parseJsonBoolArray(json, ".expected");
        uint256 accepted;
        uint256 splitTraces;
        for (uint256 k; k < inputs.length; k++) {
            bytes memory b = inputs[k];
            assertEq(h.isCanonical(b), expected[k], "vector expectation");
            for (uint256 t; t < 2; t++) {
                PinpointJcsAnchor a = t == 0 ? pa : tiny;
                (bool ok, uint256[] memory tr) = a.traceOf(b);
                assertEq(ok, expected[k], "trace verdict != isCanonical");
                if (ok) {
                    if (tr.length > 2) splitTraces++;
                    for (uint256 j; j + 1 < tr.length; j++) {
                        assertFalse(a.isFraud(b, tr, j), "honest segment flagged");
                    }
                } else {
                    assertTrue(_someFraud(a, b, _claimDone(tr, b.length)), "non-canonical with no provable segment");
                }
            }
            if (expected[k]) accepted++;
        }
        console2.log("vectors", inputs.length, "canonical", accepted);
        console2.log("honest traces with 2+ segments", splitTraces);
    }

    /// A changed checkpoint is either caught at the segment before or after it, or it is the true parser state
    /// at its (new) offset, in which case the whole trace is still valid. Offsets are the anchorer's choice, so
    /// that second case is not a miss: e.g. pos 10 -> 11 inside a member name.
    function test_tamperedTraceIsCaughtOrStillValid() public view {
        uint256 caught;
        uint256 stillValid;
        for (uint256 i; i < real.length; i++) {
            (bool ok, uint256[] memory tr) = tiny.traceOf(real[i]);
            assertTrue(ok);
            for (uint256 j = 1; j + 1 < tr.length; j += 7) {
                for (uint256 bit; bit < 136; bit += 9) {
                    uint256[] memory bad = _copy(tr);
                    bad[j] ^= uint256(1) << bit;
                    if (tiny.isFraud(real[i], bad, j - 1) || tiny.isFraud(real[i], bad, j)) {
                        caught++;
                    } else {
                        // every other segment is unchanged from the honest trace, so the whole trace is valid;
                        // that can only happen by moving the offset (bits 0-31) inside the same string
                        assertLt(bit, 32, "a changed state field went uncaught");
                        stillValid++;
                    }
                }
            }
        }
        console2.log("tampered checkpoints caught", caught, "still a valid trace", stillValid);
    }

    function test_gasOnPinnedStatements() public {
        for (uint256 i; i < real.length; i++) {
            bytes memory s = real[i];
            (bool ok, uint256[] memory tr) = pa.traceOf(s);
            assertTrue(ok);
            vm.prank(alice);
            uint256 g0 = gasleft();
            bytes32 d = pa.anchor{value: BOND}(s, tr);
            uint256 gPin = g0 - gasleft();
            assertEq(d, digests[i]);
            vm.prank(alice);
            g0 = gasleft();
            oa.anchor{value: BOND}(s);
            uint256 gOpt = g0 - gasleft();
            console2.log("bytes", s.length, "segments", tr.length - 1);
            console2.log("  pinpoint anchor", gPin, "optimistic anchor", gOpt);
            console2.log("  trace calldata gas", _calldataGas(abi.encodePacked(tr)));
        }
    }

    function test_canonicalCannotBeChallengedAndIsAccepted() public {
        for (uint256 i; i < real.length; i++) {
            (, uint256[] memory tr) = pa.traceOf(real[i]);
            vm.prank(alice);
            bytes32 d = pa.anchor{value: BOND}(real[i], tr);
            for (uint256 j; j + 1 < tr.length; j++) {
                vm.prank(bob);
                vm.expectRevert(PinpointJcsAnchor.NoFraud.selector);
                pa.challenge(d, real[i], tr, j);
            }
            vm.warp(block.timestamp + WINDOW);
            assertTrue(pa.isAccepted(d));
        }
    }

    /// The point of the construction: the challenge costs about the same wherever the violation is.
    /// OptimisticJcsAnchor measured 14,743 (violation near the start) to 982,073 (last byte) on this statement.
    function test_challengeGasIsFlatInViolationPosition() public {
        bytes memory s = real[0];
        uint256[3] memory at = [uint256(13), s.length / 2, s.length - 1];
        for (uint256 v; v < 3; v++) {
            bytes memory bad = _insertTab(s, at[v]);
            (bool ok, uint256[] memory tr) = pa.traceOf(bad);
            assertFalse(ok);
            tr = _claimDone(tr, bad.length);
            vm.prank(alice);
            bytes32 d = pa.anchor{value: BOND}(bad, tr);
            uint256 j = _firstFraud(pa, bad, tr);
            uint256 before = bob.balance;
            vm.prank(bob);
            uint256 g0 = gasleft();
            pa.challenge(d, bad, tr, j);
            console2.log("violation at byte", at[v], "challenge gas", g0 - gasleft());
            assertEq(bob.balance, before + BOND);
            (PinpointJcsAnchor.Status st,) = pa.statusOf(d);
            assertEq(uint8(st), uint8(PinpointJcsAnchor.Status.Rejected));
        }
    }

    /// The anchorer cannot hide a violation behind a trace that skips it: every invalid segment is provable,
    /// and a wrong trace on canonical bytes loses the bond but the bytes can be re-anchored correctly.
    function test_wrongTraceLosesBondThenReanchor() public {
        bytes memory s = real[1];
        (, uint256[] memory tr) = pa.traceOf(s);
        uint256[] memory bad = _copy(tr);
        bad[bad.length - 1] = JcsTrace.doneState(s.length - 1);
        vm.prank(alice);
        bytes32 d = pa.anchor{value: BOND}(s, bad);
        vm.prank(bob);
        pa.challenge(d, s, bad, 0);
        vm.prank(alice);
        pa.anchor{value: BOND}(s, tr);
        vm.warp(block.timestamp + WINDOW);
        assertTrue(pa.isAccepted(d));
    }

    /// A segment longer than MAX_SEG is fraud by itself, even over canonical bytes. Without this the anchorer
    /// could submit [INIT, DONE] and push the challenger back to re-running the whole document.
    function test_oversizedSegmentIsFraud() public {
        bytes memory s = real[0];
        uint256[] memory tr = new uint256[](2);
        tr[0] = JcsTrace.initState();
        tr[1] = JcsTrace.doneState(s.length);
        vm.prank(alice);
        bytes32 d = pa.anchor{value: BOND}(s, tr);
        vm.prank(bob);
        uint256 g0 = gasleft();
        pa.challenge(d, s, tr, 0);
        console2.log("oversized-segment challenge gas", g0 - gasleft());
    }

    /// A trace that starts after the violation (true states from there on, shifted) is caught at checkpoint 0.
    function test_traceMustStartAtInit() public {
        bytes memory bad = _insertTab(real[1], 13);
        (, uint256[] memory tr) = tiny.traceOf(real[1]);
        uint256 k = 1;
        while (uint32(tr[k]) <= 13) k++;
        uint256[] memory skip = new uint256[](tr.length - k);
        for (uint256 i; i < skip.length; i++) {
            JcsTrace.S memory st = JcsTrace.unpack(tr[k + i]);
            if (st.pos >= 13) st.pos++;
            if (st.prevKs >= 13) st.prevKs++;
            if (st.prevKe >= 13) st.prevKe++;
            if (st.curKs >= 13) st.curKs++;
            skip[i] = JcsTrace.pack(st);
        }
        for (uint256 j; j + 1 < skip.length; j++) {
            assertTrue(JcsTraceHarness.segmentOk(bad, skip[j], skip[j + 1], 32), "suffix segments are valid");
        }
        vm.prank(alice);
        bytes32 d = tiny.anchor{value: BOND}(bad, skip);
        vm.prank(bob);
        tiny.challenge(d, bad, skip, 0);
    }

    function test_challengeGuards() public {
        bytes memory s = real[1];
        (, uint256[] memory tr) = pa.traceOf(s);
        vm.prank(alice);
        bytes32 d = pa.anchor{value: BOND}(s, tr);
        uint256[] memory other = _copy(tr);
        other[0] ^= 1;
        vm.prank(bob);
        vm.expectRevert(PinpointJcsAnchor.TraceMismatch.selector);
        pa.challenge(d, s, other, 0);
        vm.prank(bob);
        vm.expectRevert(PinpointJcsAnchor.DigestMismatch.selector);
        pa.challenge(d, real[2], tr, 0);
        vm.prank(alice);
        vm.expectRevert(PinpointJcsAnchor.AlreadyAnchored.selector);
        pa.anchor{value: BOND}(s, tr);
        vm.prank(alice);
        vm.expectRevert(PinpointJcsAnchor.WindowOpen.selector);
        pa.withdrawBond(d);
        vm.warp(block.timestamp + WINDOW);
        vm.prank(bob);
        vm.expectRevert(PinpointJcsAnchor.WindowClosed.selector);
        pa.challenge(d, s, tr, 0);
        vm.prank(bob);
        vm.expectRevert(PinpointJcsAnchor.NotSubmitter.selector);
        pa.withdrawBond(d);
        uint256 before = alice.balance;
        vm.prank(alice);
        pa.withdrawBond(d);
        assertEq(alice.balance, before + BOND);
    }

    /// Member names over MAX_KEY bytes: the one place this profile is stricter than isCanonical.
    function test_longMemberNameIsOutsideProfile() public view {
        bytes memory k = new bytes(JcsTrace.MAX_KEY + 1);
        for (uint256 i; i < k.length; i++) {
            k[i] = "a";
        }
        bytes memory b = abi.encodePacked('{"', k, '":1}');
        assertTrue(h.isCanonical(b));
        (bool ok,) = pa.traceOf(b);
        assertFalse(ok);
    }

    function _someFraud(PinpointJcsAnchor a, bytes memory b, uint256[] memory tr) internal view returns (bool) {
        if (tr.length < 2) return a.isFraud(b, tr, 0);
        for (uint256 j; j + 1 < tr.length; j++) {
            if (a.isFraud(b, tr, j)) return true;
        }
        return false;
    }

    function _firstFraud(PinpointJcsAnchor a, bytes memory b, uint256[] memory tr) internal view returns (uint256) {
        for (uint256 j; j + 1 < tr.length; j++) {
            if (a.isFraud(b, tr, j)) return j;
        }
        revert("no fraud");
    }

    /// Valid prefix of checkpoints, then DONE(n): the trace that claims the whole statement is fine.
    function _claimDone(uint256[] memory tr, uint256 n) internal pure returns (uint256[] memory out) {
        out = new uint256[](tr.length + 1);
        for (uint256 i; i < tr.length; i++) {
            out[i] = tr[i];
        }
        out[tr.length] = JcsTrace.doneState(n);
    }

    function _copy(uint256[] memory a) internal pure returns (uint256[] memory out) {
        out = new uint256[](a.length);
        for (uint256 i; i < a.length; i++) {
            out[i] = a[i];
        }
    }

    function _insertTab(bytes memory s, uint256 at) internal pure returns (bytes memory out) {
        out = new bytes(s.length + 1);
        for (uint256 i; i < at; i++) {
            out[i] = s[i];
        }
        out[at] = 0x09; // a raw tab: not canonical inside a string or between tokens
        for (uint256 i = at; i < s.length; i++) {
            out[i + 1] = s[i];
        }
    }

    function _calldataGas(bytes memory s) internal pure returns (uint256 g) {
        for (uint256 i; i < s.length; i++) {
            g += s[i] == 0 ? 4 : 16;
        }
    }
}
