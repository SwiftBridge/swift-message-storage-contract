// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title MessageStorage
 * @dev A contract for storing and retrieving messages with IPFS integration
 * @author Swift v2 Team
 */
contract MessageStorage is ReentrancyGuard, Ownable {
    using Counters for Counters.Counter;

    // Events
    event MessageStored(
        uint256 indexed messageId,
        address indexed sender,
        string ipfsHash,
        uint256 timestamp
    );

    event MessageRetrieved(
        uint256 indexed messageId,
        address indexed requester,
        string ipfsHash
    );

    event MessageDeleted(
        uint256 indexed messageId,
        address indexed deleter
    );

    event StorageQuotaUpdated(
        address indexed user,
        uint256 newQuota
    );

    // Structs
    struct Message {
        uint256 id;
        address sender;
        string ipfsHash;
        string messageType;
        uint256 timestamp;
        bool isDeleted;
        mapping(address => bool) accessList;
    }

    struct UserStorage {
        uint256 usedStorage;
        uint256 storageQuota;
        uint256 messageCount;
        bool isActive;
    }

    // State variables
    Counters.Counter private _messageIdCounter;
    
    mapping(uint256 => Message) public messages;
    mapping(address => UserStorage) public userStorage;
    mapping(address => uint256[]) public userMessages;
    mapping(string => uint256) public ipfsToMessageId;
    mapping(address => bool) public authorizedContracts;

    // Constants
    uint256 public constant DEFAULT_STORAGE_QUOTA = 100 * 1024 * 1024; // 100MB
    uint256 public constant MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB
    uint256 public constant STORAGE_FEE = 0.000003 ether; // ~$0.009 at $3000 ETH

    // Modifiers
    modifier onlyAuthorized() {
        require(
            authorizedContracts[msg.sender] || msg.sender == owner(),
            "Not authorized to access storage"
        );
        _;
    }

    modifier validMessageSize(string memory _ipfsHash) {
        require(bytes(_ipfsHash).length > 0, "IPFS hash required");
        _;
    }

    modifier messageExists(uint256 _messageId) {
        require(_messageId > 0 && _messageId <= _messageIdCounter.current(), "Message does not exist");
        _;
    }

    constructor() {
        _messageIdCounter.increment();
    }

    /**
     * @dev Store a message with IPFS hash
     * @param _sender Address of the message sender
     * @param _ipfsHash IPFS hash of the message content
     * @param _messageType Type of message
     * @return messageId ID of the stored message
     */
    function storeMessage(
        address _sender,
        string memory _ipfsHash,
        string memory _messageType
    ) 
        external 
        payable 
        nonReentrant 
        onlyAuthorized 
        validMessageSize(_ipfsHash)
        returns (uint256 messageId) 
    {
        require(msg.value >= STORAGE_FEE, "Insufficient storage fee");
        require(ipfsToMessageId[_ipfsHash] == 0, "Message already stored");

        messageId = _messageIdCounter.current();
        _messageIdCounter.increment();

        Message storage message = messages[messageId];
        message.id = messageId;
        message.sender = _sender;
        message.ipfsHash = _ipfsHash;
        message.messageType = _messageType;
        message.timestamp = block.timestamp;
        message.isDeleted = false;
        message.accessList[_sender] = true;

        ipfsToMessageId[_ipfsHash] = messageId;
        userMessages[_sender].push(messageId);
        userStorage[_sender].messageCount++;
        userStorage[_sender].usedStorage += MAX_MESSAGE_SIZE; // Estimate

        emit MessageStored(messageId, _sender, _ipfsHash, block.timestamp);
    }

    /**
     * @dev Retrieve message IPFS hash
     * @param _messageId ID of the message
     * @return ipfsHash IPFS hash of the message
     */
    function retrieveMessage(uint256 _messageId) 
        external 
        view 
        messageExists(_messageId)
        returns (string memory ipfsHash) 
    {
        Message storage message = messages[_messageId];
        require(!message.isDeleted, "Message deleted");
        require(
            message.accessList[msg.sender] || 
            message.sender == msg.sender ||
            msg.sender == owner(),
            "No access to message"
        );

        return message.ipfsHash;
    }

    /**
     * @dev Delete a message (only sender can delete)
     * @param _messageId ID of the message to delete
     */
    function deleteMessage(uint256 _messageId) 
        external 
        messageExists(_messageId)
    {
        Message storage message = messages[_messageId];
        require(message.sender == msg.sender, "Only sender can delete message");
        require(!message.isDeleted, "Message already deleted");

        message.isDeleted = true;
        userStorage[message.sender].usedStorage -= MAX_MESSAGE_SIZE;
        userStorage[message.sender].messageCount--;

        emit MessageDeleted(_messageId, msg.sender);
    }

    /**
     * @dev Grant access to a message
     * @param _messageId ID of the message
     * @param _user Address to grant access to
     */
    function grantMessageAccess(uint256 _messageId, address _user) 
        external 
        messageExists(_messageId)
    {
        Message storage message = messages[_messageId];
        require(message.sender == msg.sender, "Only sender can grant access");
        require(!message.isDeleted, "Message deleted");

        message.accessList[_user] = true;
    }

    /**
     * @dev Revoke access to a message
     * @param _messageId ID of the message
     * @param _user Address to revoke access from
     */
    function revokeMessageAccess(uint256 _messageId, address _user) 
        external 
        messageExists(_messageId)
    {
        Message storage message = messages[_messageId];
        require(message.sender == msg.sender, "Only sender can revoke access");

        message.accessList[_user] = false;
    }

    /**
     * @dev Get user's storage info
     * @param _user Address of the user
     * @return usedStorage Amount of storage used
     * @return storageQuota Storage quota
     * @return messageCount Number of messages
     * @return isActive Whether user storage is active
     */
    function getUserStorageInfo(address _user)
        external
        view
        returns (
            uint256 usedStorage,
            uint256 storageQuota,
            uint256 messageCount,
            bool isActive
        )
    {
        UserStorage storage userStorageData = userStorage[_user];
        return (
            userStorageData.usedStorage,
            userStorageData.storageQuota,
            userStorageData.messageCount,
            userStorageData.isActive
        );
    }

    /**
     * @dev Update user storage quota
     * @param _user Address of the user
     * @param _newQuota New storage quota
     */
    function updateStorageQuota(address _user, uint256 _newQuota) external onlyOwner {
        require(_newQuota > 0, "Invalid quota");
        
        userStorage[_user].storageQuota = _newQuota;
        emit StorageQuotaUpdated(_user, _newQuota);
    }

    /**
     * @dev Initialize user storage
     * @param _user Address of the user
     */
    function initializeUserStorage(address _user) external onlyAuthorized {
        UserStorage storage userStorageData = userStorage[_user];
        if (!userStorageData.isActive) {
            userStorageData.storageQuota = DEFAULT_STORAGE_QUOTA;
            userStorageData.isActive = true;
        }
    }

    /**
     * @dev Get message details
     */
    function getMessage(uint256 _messageId) 
        external 
        view 
        messageExists(_messageId)
        returns (
            uint256 id,
            address sender,
            string memory ipfsHash,
            string memory messageType,
            uint256 timestamp,
            bool isDeleted
        ) 
    {
        Message storage message = messages[_messageId];
        return (
            message.id,
            message.sender,
            message.ipfsHash,
            message.messageType,
            message.timestamp,
            message.isDeleted
        );
    }

    /**
     * @dev Get user's messages
     * @param _user Address of the user
     * @param _offset Starting index
     * @param _limit Number of messages to return
     * @return Array of message IDs
     */
    function getUserMessages(
        address _user,
        uint256 _offset,
        uint256 _limit
    ) external view returns (uint256[] memory) {
        uint256[] memory userMessageIds = userMessages[_user];
        uint256 length = userMessageIds.length;
        
        if (_offset >= length) {
            return new uint256[](0);
        }

        uint256 end = _offset + _limit;
        if (end > length) {
            end = length;
        }

        uint256[] memory result = new uint256[](end - _offset);
        for (uint256 i = _offset; i < end; i++) {
            result[i - _offset] = userMessageIds[i];
        }

        return result;
    }

    /**
     * @dev Authorize a contract to access storage
     * @param _contract Address of the contract
     */
    function authorizeContract(address _contract) external onlyOwner {
        authorizedContracts[_contract] = true;
    }

    /**
     * @dev Revoke contract authorization
     * @param _contract Address of the contract
     */
    function revokeContractAuthorization(address _contract) external onlyOwner {
        authorizedContracts[_contract] = false;
    }

    /**
     * @dev Get total message count
     * @return Total number of messages
     */
    function getTotalMessageCount() external view returns (uint256) {
        return _messageIdCounter.current() - 1;
    }

    /**
     * @dev Check if user has access to message
     * @param _messageId ID of the message
     * @param _user Address of the user
     * @return True if user has access
     */
    function hasMessageAccess(uint256 _messageId, address _user) 
        external 
        view 
        messageExists(_messageId)
        returns (bool) 
    {
        Message storage message = messages[_messageId];
        return message.accessList[_user] || message.sender == _user;
    }

    /**
     * @dev Withdraw contract balance (only owner)
     */
    function withdraw() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        require(balance > 0, "No balance to withdraw");

        (bool success, ) = payable(owner()).call{value: balance}("");
        require(success, "Withdraw failed");
    }
}
