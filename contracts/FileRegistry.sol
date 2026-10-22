// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract FileRegistry {
    enum Status { Active, Superseded, Removed }
    struct Record {
        bytes32 groupId;
        bytes32 uploaderId;
        bytes32 contentMac;
        bytes32 ctHash;
        string cid;
        uint32 keyVersion;
        uint64 size;
        uint64 timestamp;
        uint256 supersedes;
        uint256 supersededBy;
        Status status;
        bytes uploaderSig;
    }
    address public immutable proxy;
    uint256 public recordCount;
    mapping(uint256 => Record) private records;
    mapping(bytes32 => uint256[]) private groupRecords;
    event FileRecorded(uint256 indexed recordId, bytes32 indexed groupId, string cid, uint32 keyVersion);
    event FileSuperseded(uint256 indexed oldId, uint256 indexed newId);
    event FileRemoved(uint256 indexed recordId, bytes32 requesterId);
    event GroupEvent(bytes32 indexed groupId, uint8 kind, bytes32 subjectId, uint32 keyVersion);
    modifier onlyProxy() { require(msg.sender == proxy, "ONLY_PROXY"); _; }
    constructor(address proxy_) { require(proxy_ != address(0)); proxy = proxy_; }
    function getRecord(uint256 id) external view returns (Record memory) {
        require(id > 0 && id <= recordCount, "NO_RECORD");
        return records[id];
    }
    function getGroupRecords(bytes32 groupId) external view returns (uint256[] memory) {
        return groupRecords[groupId];
    }
    function addRecord(bytes32 groupId, bytes32 uploaderId, bytes32 contentMac, bytes32 ctHash,
        string calldata cid, uint32 keyVersion, uint64 size, bytes calldata uploaderSig)
        external onlyProxy returns (uint256 id) {
        require(keyVersion > 0 && size >= 29 && bytes(cid).length > 0, "BAD_RECORD");
        id = ++recordCount;
        records[id] = Record(groupId, uploaderId, contentMac, ctHash, cid, keyVersion, size,
            uint64(block.timestamp), 0, 0, Status.Active, uploaderSig);
        groupRecords[groupId].push(id);
        emit FileRecorded(id, groupId, cid, keyVersion);
    }
    function supersede(uint256 oldId, string calldata cid, uint32 version, bytes32 ctHash, uint64 size)
        external onlyProxy returns (uint256 id) {
        require(oldId > 0 && oldId <= recordCount, "NO_RECORD");
        Record storage old = records[oldId];
        require(old.status == Status.Active && version > old.keyVersion, "NOT_ACTIVE_OR_NEWER");
        id = ++recordCount;
        records[id] = Record(old.groupId, old.uploaderId, old.contentMac, ctHash, cid, version,
            size, uint64(block.timestamp), oldId, 0, Status.Active, "");
        old.status = Status.Superseded;
        old.supersededBy = id;
        groupRecords[old.groupId].push(id);
        emit FileRecorded(id, old.groupId, cid, version);
        emit FileSuperseded(oldId, id);
    }
    function markRemoved(uint256 id, bytes32 requesterId) external onlyProxy {
        require(id > 0 && id <= recordCount && records[id].status == Status.Active, "NOT_ACTIVE");
        records[id].status = Status.Removed;
        emit FileRemoved(id, requesterId);
    }
    function logGroupEvent(bytes32 groupId, uint8 kind, bytes32 subjectId, uint32 version) external onlyProxy {
        require(kind <= 8, "BAD_KIND");
        emit GroupEvent(groupId, kind, subjectId, version);
    }
}
