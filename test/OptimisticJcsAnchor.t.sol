// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {OptimisticJcsAnchor} from "../src/OptimisticJcsAnchor.sol";
import {JcsFlatProfile} from "../src/JcsFlatProfile.sol";

/// Baseline from Zexo's probe: check canonical form, then hash, all on chain.
contract CheckedAnchor {
    mapping(bytes32 => uint256) public anchoredAt;

    function anchor(bytes calldata raw) external returns (bytes32 digest) {
        require(JcsFlatProfile.isCanonical(raw), "not canonical");
        digest = sha256(raw);
        require(anchoredAt[digest] == 0, "already");
        anchoredAt[digest] = block.timestamp;
    }
}

contract OptimisticJcsAnchorTest is Test {
    uint256 constant WINDOW = 1 days;
    uint256 constant BOND = 0.01 ether;
    OptimisticJcsAnchor oa;
    CheckedAnchor ca;
    bytes[] real;
    string[] names;
    bytes32[] digests;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        oa = new OptimisticJcsAnchor(WINDOW, BOND);
        ca = new CheckedAnchor();
        string memory json = vm.readFile("vectors.json");
        bytes[] memory r = vm.parseJsonBytesArray(json, ".realInputs");
        string[] memory n = vm.parseJsonStringArray(json, ".realNames");
        bytes32[] memory d = vm.parseJsonBytes32Array(json, ".realDigests");
        for (uint256 i; i < r.length; i++) {
            real.push(r[i]);
            names.push(n[i]);
            digests.push(d[i]);
        }
        vm.deal(alice, 10 ether);
        vm.deal(bob, 1 ether);
    }

    /// The five pinned ERC-8373 statements: execution gas of each path (excludes 21k base and calldata).
    function test_gasOnPinnedStatements() public {
        assertEq(real.length, 5);
        for (uint256 i; i < real.length; i++) {
            bytes memory s = real[i]; // copy out of storage BEFORE timing (a storage copy is ~2.1k gas/word)
            vm.prank(alice);
            uint256 g0 = gasleft();
            bytes32 d = oa.anchor{value: BOND}(s);
            uint256 gOpt = g0 - gasleft();
            assertEq(d, digests[i], "digest != recompute-kit pin");
            g0 = gasleft();
            ca.anchor(s);
            uint256 gChk = g0 - gasleft();
            console2.log(names[i]);
            console2.log("  bytes", real[i].length, "calldata gas (16/nonzero,4/zero)", _calldataGas(real[i]));
            console2.log("  optimistic anchor", gOpt, "check-then-anchor", gChk);
        }
    }

    function test_canonicalStatementCannotBeChallengedAndIsAccepted() public {
        for (uint256 i; i < real.length; i++) {
            vm.prank(alice);
            bytes32 d = oa.anchor{value: BOND}(real[i]);
            vm.prank(bob);
            vm.expectRevert(OptimisticJcsAnchor.IsCanonical.selector);
            oa.challenge(d, real[i]);
            assertFalse(oa.isAccepted(d));
            vm.warp(block.timestamp + WINDOW);
            assertTrue(oa.isAccepted(d));
        }
    }

    function test_nonCanonicalIsRejectedAndChallengerPaid() public {
        bytes memory bad = _withSpace(real[1]); // same object, a space after the first ':' -> not canonical
        vm.prank(alice);
        bytes32 d = oa.anchor{value: BOND}(bad);
        uint256 before = bob.balance;
        vm.prank(bob);
        uint256 g0 = gasleft();
        oa.challenge(d, bad);
        console2.log("challenge gas, violation at byte ~13 (checker stops at the first violation)", g0 - gasleft());
        assertEq(bob.balance, before + BOND);
        vm.warp(block.timestamp + WINDOW);
        assertFalse(oa.isAccepted(d));
        (OptimisticJcsAnchor.Status st,) = oa.statusOf(d);
        assertEq(uint8(st), uint8(OptimisticJcsAnchor.Status.Rejected));
    }

    function test_nonCanonicalUnchallengedIsAccepted_trustAssumption() public {
        bytes memory bad = _withSpace(real[1]);
        vm.prank(alice);
        bytes32 d = oa.anchor{value: BOND}(bad);
        vm.warp(block.timestamp + WINDOW);
        assertTrue(oa.isAccepted(d), "one-honest-watcher assumption: unchallenged = accepted");
        vm.prank(bob);
        vm.expectRevert(OptimisticJcsAnchor.WindowClosed.selector);
        oa.challenge(d, bad);
    }

    /// Worst case for a challenger: the violation is the LAST byte, so the checker scans the whole ML-DSA statement.
    function test_challengeWorstCaseGas() public {
        bytes memory s = real[0];
        bytes memory bad = new bytes(s.length + 1);
        for (uint256 i; i < s.length - 1; i++) bad[i] = s[i];
        bad[s.length - 1] = " "; // whitespace before the closing brace
        bad[s.length] = "}";
        vm.prank(alice);
        bytes32 d = oa.anchor{value: BOND}(bad);
        vm.prank(bob);
        uint256 g0 = gasleft();
        oa.challenge(d, bad);
        console2.log("challenge gas, violation at the last byte of the 4121-byte statement", g0 - gasleft());
        (OptimisticJcsAnchor.Status st,) = oa.statusOf(d); // challenge succeeded => checker found it non-canonical
        assertEq(uint8(st), uint8(OptimisticJcsAnchor.Status.Rejected));
    }

    function test_challengeNeedsTheExactBytes() public {
        bytes memory bad = _withSpace(real[1]);
        vm.prank(alice);
        bytes32 d = oa.anchor{value: BOND}(bad);
        vm.prank(bob);
        vm.expectRevert(OptimisticJcsAnchor.DigestMismatch.selector);
        oa.challenge(d, _withSpace(real[2]));
    }

    function test_bondAndWithdraw() public {
        vm.prank(alice);
        vm.expectRevert(OptimisticJcsAnchor.WrongBond.selector);
        oa.anchor{value: 0}(real[0]);
        vm.prank(alice);
        bytes32 d = oa.anchor{value: BOND}(real[0]);
        vm.prank(alice);
        vm.expectRevert(OptimisticJcsAnchor.WindowOpen.selector);
        oa.withdrawBond(d);
        vm.warp(block.timestamp + WINDOW);
        vm.prank(bob);
        vm.expectRevert(OptimisticJcsAnchor.NotSubmitter.selector);
        oa.withdrawBond(d);
        uint256 before = alice.balance;
        vm.prank(alice);
        oa.withdrawBond(d);
        assertEq(alice.balance, before + BOND);
        assertTrue(oa.isAccepted(d));
        vm.prank(alice);
        vm.expectRevert(OptimisticJcsAnchor.AlreadyAnchored.selector);
        oa.anchor{value: BOND}(real[0]);
    }

    function _withSpace(bytes memory s) internal pure returns (bytes memory out) {
        uint256 k;
        for (; k < s.length; k++) if (s[k] == ":") break;
        out = new bytes(s.length + 1);
        for (uint256 i; i <= k; i++) out[i] = s[i];
        out[k + 1] = " ";
        for (uint256 i = k + 1; i < s.length; i++) out[i + 1] = s[i];
    }

    function _calldataGas(bytes memory s) internal pure returns (uint256 g) {
        for (uint256 i; i < s.length; i++) g += s[i] == 0 ? 4 : 16;
    }
}
