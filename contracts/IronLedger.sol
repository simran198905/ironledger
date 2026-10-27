// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IronLedger - Immutable ICS/SCADA Forensic Evidence Layer
 * @author IronLedger Security Core
 * @notice Smart contract for anchoring cryptographic state hashes of SCADA commands & sensor events.
 */
contract IronLedger {
    address public owner;
    uint256 public totalEvents;
    bytes32 public lastHash;

    struct ICSEvent {
        uint256 eventId;
        bytes32 eventHash;       // Deterministic SHA-256 fingerprint of event data
        bytes32 previousHash;    // Cryptographic link to previous block event
        uint256 timestamp;       // Block timestamp
        address recordedBy;      // Signer wallet address
    }

    // Mapping from event ID to on-chain event record
    mapping(uint256 => ICSEvent) public events;
    // Mapping from event hash to event ID (prevents replay/duplicates)
    mapping(bytes32 => uint256) public hashToEventId;

    event EventAnchored(
        uint256 indexed eventId,
        bytes32 indexed eventHash,
        bytes32 indexed previousHash,
        uint256 timestamp,
        string source,
        string commandType,
        string entityId,
        address recordedBy
    );

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can record events");
        _;
    }

    constructor(bytes32 _genesisHash) {
        owner = msg.sender;
        totalEvents = 0;
        lastHash = _genesisHash != bytes32(0) ? _genesisHash : keccak256("IRONLEDGER_GENESIS_ROOT");
    }

    /**
     * @notice Records an ICS command or telemetry state hash onto the immutable ledger.
     * @dev Enforces strict chain linkage against lastHash and prevents duplicates.
     */
    function recordEvent(
        bytes32 _eventHash,
        bytes32 _previousHash,
        string calldata _source,
        string calldata _commandType,
        string calldata _entityId
    ) external onlyOwner returns (uint256) {
        require(_eventHash != bytes32(0), "Invalid event hash");
        require(_previousHash == lastHash, "Broken chain link: previousHash does not match lastHash");
        require(hashToEventId[_eventHash] == 0, "Duplicate event: hash already anchored");

        uint256 newId = ++totalEvents;

        events[newId] = ICSEvent({
            eventId: newId,
            eventHash: _eventHash,
            previousHash: _previousHash,
            timestamp: block.timestamp,
            recordedBy: msg.sender
        });

        hashToEventId[_eventHash] = newId;
        lastHash = _eventHash;

        emit EventAnchored(
            newId,
            _eventHash,
            _previousHash,
            block.timestamp,
            _source,
            _commandType,
            _entityId,
            msg.sender
        );

        return newId;
    }

    /**
     * @notice Verifies whether a submitted event metadata hash matches the immutable on-chain record.
     */
    function verifyHash(uint256 _eventId, bytes32 _submittedHash)
        external
        view
        returns (bool isValid, bytes32 storedHash, uint256 blockTimestamp)
    {
        require(_eventId > 0 && _eventId <= totalEvents, "Event does not exist");
        ICSEvent memory ev = events[_eventId];
        return (ev.eventHash == _submittedHash, ev.eventHash, ev.timestamp);
    }

    /**
     * @notice Fetch an event by ID for forensic reconstruction.
     */
    function getEvent(uint256 _eventId) external view returns (ICSEvent memory) {
        require(_eventId > 0 && _eventId <= totalEvents, "Event does not exist");
        return events[_eventId];
    }

    /**
     * @notice Transfer contract ownership to a new admin address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
