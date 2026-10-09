// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {JcsFlatProfile} from "./JcsFlatProfile.sol";

/// @notice Anchors the sha256 of a JSON statement WITHOUT checking its canonical (RFC 8785 / JCS) form on chain,
/// and lets anyone prove within a window that the anchored bytes are NOT canonical. The full check
/// (JcsFlatProfile.isCanonical, ~240-270 gas/byte) is paid only by a challenger, and only on dispute.
///
/// Trust assumption, stated plainly: one honest watcher. A non-canonical statement that nobody challenges
/// before the window closes is accepted. Data availability is handled by taking the statement as calldata in
/// anchor(), so every watcher can read the exact bytes from the transaction.
///
/// What this does and does not establish:
/// - accepted  => the bytes were public for WINDOW seconds and no one showed them non-canonical.
/// - rejected  => someone showed sha256(raw) == digest and isCanonical(raw) == false (a checked fact).
/// - it says nothing about what the statement asserts, only that its bytes are the canonical form.
contract OptimisticJcsAnchor {
    uint256 public immutable WINDOW; // seconds a statement stays challengeable
    uint256 public immutable BOND; // wei the anchorer posts; paid to a successful challenger

    // One storage slot per anchor: submitter (160) | anchoredAt (64) | status (8).
    enum Status {
        None,
        Pending,
        Rejected,
        Withdrawn
    }

    mapping(bytes32 => uint256) private _slot;

    event Anchored(bytes32 indexed digest, address indexed submitter, uint64 anchoredAt);
    event Rejected(bytes32 indexed digest, address indexed challenger);
    event BondReturned(bytes32 indexed digest, address indexed submitter);

    error AlreadyAnchored();
    error WrongBond();
    error NotPending();
    error WindowClosed();
    error WindowOpen();
    error DigestMismatch();
    error IsCanonical();
    error NotSubmitter();

    constructor(uint256 window, uint256 bond) {
        WINDOW = window;
        BOND = bond;
    }

    /// Anchor a statement. Costs one sha256 over the bytes and one storage write; no canonical-form check.
    function anchor(bytes calldata raw) external payable returns (bytes32 digest) {
        if (msg.value != BOND) revert WrongBond();
        digest = sha256(raw);
        if (_slot[digest] != 0) revert AlreadyAnchored();
        _slot[digest] = _pack(msg.sender, uint64(block.timestamp), Status.Pending);
        emit Anchored(digest, msg.sender, uint64(block.timestamp));
    }

    /// Prove an anchored statement is not canonical. Reverts (costing only the challenger) if it is canonical.
    function challenge(bytes32 digest, bytes calldata raw) external {
        (, uint64 t0, Status st) = _unpack(_slot[digest]);
        if (st != Status.Pending) revert NotPending();
        if (block.timestamp >= uint256(t0) + WINDOW) revert WindowClosed();
        if (sha256(raw) != digest) revert DigestMismatch();
        if (JcsFlatProfile.isCanonical(raw)) revert IsCanonical();
        _slot[digest] = _pack(address(0), t0, Status.Rejected);
        emit Rejected(digest, msg.sender);
        (bool ok,) = msg.sender.call{value: BOND}("");
        require(ok, "bond transfer failed");
    }

    /// After an unchallenged window the submitter takes the bond back; the anchor stays accepted.
    function withdrawBond(bytes32 digest) external {
        (address who, uint64 t0, Status st) = _unpack(_slot[digest]);
        if (st != Status.Pending) revert NotPending();
        if (msg.sender != who) revert NotSubmitter();
        if (block.timestamp < uint256(t0) + WINDOW) revert WindowOpen();
        _slot[digest] = _pack(who, t0, Status.Withdrawn);
        emit BondReturned(digest, who);
        (bool ok,) = who.call{value: BOND}("");
        require(ok, "bond transfer failed");
    }

    /// True once the window has closed with no successful challenge.
    function isAccepted(bytes32 digest) external view returns (bool) {
        (, uint64 t0, Status st) = _unpack(_slot[digest]);
        if (st == Status.Withdrawn) return true;
        return st == Status.Pending && block.timestamp >= uint256(t0) + WINDOW;
    }

    function statusOf(bytes32 digest) external view returns (Status st, uint64 anchoredAt) {
        (, anchoredAt, st) = _unpack(_slot[digest]);
    }

    function _pack(address who, uint64 t0, Status st) private pure returns (uint256) {
        return uint256(uint160(who)) | (uint256(t0) << 160) | (uint256(uint8(st)) << 224);
    }

    function _unpack(uint256 s) private pure returns (address who, uint64 t0, Status st) {
        who = address(uint160(s));
        t0 = uint64(s >> 160);
        st = Status(uint8(s >> 224));
    }
}
