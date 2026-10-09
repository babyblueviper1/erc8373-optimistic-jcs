// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {JcsTrace} from "./JcsTrace.sol";

/// @notice OptimisticJcsAnchor with a pinpoint challenge: the challenger re-runs ONE segment of at most MAX_SEG
/// bytes instead of the whole canonical-form check, so the worst-case challenge cost, and therefore the bond,
/// can be derived from MAX_SEG and the statement size instead of from where the violation happens to sit.
///
/// The anchorer submits the statement and its trace (JcsTrace checkpoints, one per <= MAX_SEG bytes) as
/// calldata; the contract stores sha256(raw) and keccak256(trace). Both are public in the transaction, so
/// any watcher can rebuild them. Same trust assumption as OptimisticJcsAnchor: one honest watcher.
///
/// What rejection means here: the bytes are not canonical under JcsTrace's profile, OR the anchorer's trace
/// is wrong. A wrong trace is the anchorer's fault and costs the bond; the statement can be re-anchored with
/// a correct one.
contract PinpointJcsAnchor {
    uint256 public immutable WINDOW;
    uint256 public immutable BOND;
    uint256 public immutable MAX_SEG; // bytes per segment
    /// Profile size cap (pq_key_binding.v1/canonicalization): a statement longer than this is refused AT ADMISSION, so the bond
    /// only ever has to cover statements the profile admits. Derived from the largest admitted key family, never a protocol constant.
    uint256 public immutable MAX_STATEMENT;

    enum Status {
        None,
        Pending,
        Rejected,
        Withdrawn
    }

    mapping(bytes32 => uint256) private _slot; // submitter (160) | anchoredAt (64) | status (8)
    mapping(bytes32 => bytes32) public traceHash;

    event Anchored(bytes32 indexed digest, address indexed submitter, uint64 anchoredAt, bytes32 traceHash);
    event Rejected(bytes32 indexed digest, address indexed challenger, uint256 segment);
    event BondReturned(bytes32 indexed digest, address indexed submitter);

    error AlreadyAnchored();
    error WrongBond();
    error TooLarge();
    error NotPending();
    error WindowClosed();
    error WindowOpen();
    error DigestMismatch();
    error TraceMismatch();
    error NoFraud();
    error NotSubmitter();

    constructor(uint256 window, uint256 bond, uint256 maxSeg, uint256 maxStatement) {
        require(maxSeg > JcsTrace.MAX_STEP, "maxSeg too small");
        require(maxStatement > 0 && maxStatement < 1 << 32, "bad maxStatement");
        WINDOW = window;
        BOND = bond;
        MAX_SEG = maxSeg;
        MAX_STATEMENT = maxStatement;
    }

    /// Anchor a statement with its trace. No canonical-form check runs here.
    function anchor(bytes calldata raw, uint256[] calldata trace) external payable returns (bytes32 digest) {
        if (msg.value != BOND) revert WrongBond();
        if (raw.length > MAX_STATEMENT) revert TooLarge(); // size cap: a rejection rule at admission
        digest = sha256(raw);
        (,, Status st) = _unpack(_slot[digest]);
        if (st != Status.None && st != Status.Rejected) revert AlreadyAnchored();
        bytes32 th = keccak256(abi.encodePacked(trace));
        _slot[digest] = _pack(msg.sender, uint64(block.timestamp), Status.Pending);
        traceHash[digest] = th;
        emit Anchored(digest, msg.sender, uint64(block.timestamp), th);
    }

    /// Show that segment j of the anchored trace is invalid (or that the trace does not start at INIT and end
    /// at DONE). Reverts with NoFraud, at the challenger's cost, if it is valid.
    function challenge(bytes32 digest, bytes calldata raw, uint256[] calldata trace, uint256 j) external {
        (, uint64 t0, Status st) = _unpack(_slot[digest]);
        if (st != Status.Pending) revert NotPending();
        if (block.timestamp >= uint256(t0) + WINDOW) revert WindowClosed();
        if (sha256(raw) != digest) revert DigestMismatch();
        if (keccak256(abi.encodePacked(trace)) != traceHash[digest]) revert TraceMismatch();
        if (!isFraud(raw, trace, j)) revert NoFraud();
        _slot[digest] = _pack(address(0), t0, Status.Rejected);
        emit Rejected(digest, msg.sender, j);
        (bool ok,) = msg.sender.call{value: BOND}("");
        require(ok, "bond transfer failed");
    }

    /// The fraud predicate, exposed so a watcher can find a winning j with eth_call before sending.
    function isFraud(bytes calldata raw, uint256[] calldata trace, uint256 j) public view returns (bool) {
        uint256 m = trace.length;
        if (m < 2 || trace[0] != JcsTrace.initState() || trace[m - 1] != JcsTrace.doneState(raw.length)) return true;
        if (j + 1 >= m) return false;
        return !JcsTrace.segmentOk(raw, trace[j], trace[j + 1], MAX_SEG);
    }

    /// The trace an honest anchorer submits (eth_call). ok == false: the bytes are not canonical, do not anchor.
    function traceOf(bytes calldata raw) external view returns (bool ok, uint256[] memory trace) {
        return JcsTrace.trace(raw, MAX_SEG);
    }

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
