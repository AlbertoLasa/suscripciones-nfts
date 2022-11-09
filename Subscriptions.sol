// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

interface IERC5643 {
    event SubscriptionUpdate(uint256 indexed tokenId, uint64 expiration);
    function renewSubscription(uint256 tokenId, uint64 duration) external payable;
    function cancelSubscription(uint256 tokenId) external payable;
    function expiresAt(uint256 tokenId) external view returns(uint64);
    function isRenewable(uint256 tokenId) external view returns(bool);
}

contract Subscriptions is ERC721, IERC5643, ERC721Enumerable, ERC721URIStorage, Pausable, Ownable, ERC721Burnable {
    //////////////////////////////////////////////////////////////////////////////////////////////////
    // State
    //////////////////////////////////////////////////////////////////////////////////////////////////
    using Counters for Counters.Counter;
    Counters.Counter private s_tokenIdCounter;

    mapping(uint256 => uint64) private s_expirations;
    mapping(uint256 => bool) private s_notRenewable;
    mapping(uint256 => uint256) public s_valuesOneSecond;

    mapping(bytes => bool) private s_signatures; 

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    //////////////////////////////////////////////////////////////////////////////////////////////////
    constructor(string memory p_name, string memory p_symbol) ERC721(p_name, p_symbol) {}

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Public functions
    ////////////////////////////////////////////////////////////////////////////////////////////////// 

    // => View functions
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return interfaceId == type(IERC5643).interfaceId || super.supportsInterface(interfaceId);
    }

    function expiresAt(uint256 tokenId) public view override returns(uint64) {
        return s_expirations[tokenId];
    }

    // => Set functions
    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function safeMint(
        address p_to, 
        string memory p_uri, 
        uint64 p_duration, 
        bool p_renewable, 
        uint256 p_value,
        uint256 p_timeStamp,
        bytes memory p_signature
    ) public payable {
        bytes32 message = keccak256(abi.encodePacked(p_to, p_uri, p_duration, p_renewable, p_value, p_timeStamp, address(this)));
        require(!s_signatures[p_signature], "Error signature");
        require(owner() == _recoverSigner(message, p_signature), "Error signature signer");
        require(p_timeStamp <= block.timestamp + 5 minutes, "Error signature time");
        s_signatures[p_signature] = true;

        require(msg.value == p_value, "Error value");
        payable(owner()).transfer(msg.value);

        uint256 tokenId = s_tokenIdCounter.current();
        s_tokenIdCounter.increment();

        s_valuesOneSecond[tokenId] = msg.value / p_duration;
        s_expirations[tokenId] = uint64(block.timestamp) + p_duration;
        if (!p_renewable) { s_notRenewable[tokenId] = true; }

        _safeMint(p_to, tokenId);
        _setTokenURI(tokenId, p_uri);
    }

    function renewSubscription(uint256 tokenId, uint64 duration) public payable override {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Caller is not owner nor approved");
        require(s_expirations[tokenId] <= uint64(block.timestamp), "Subscription expired");

        payable(owner()).transfer(s_valuesOneSecond[tokenId] * duration);

        uint64 currentExpiration = s_expirations[tokenId];
        uint64 newExpiration;
        if (currentExpiration == 0 || currentExpiration <= uint64(block.timestamp)) {
            if (s_notRenewable[tokenId]) { revert('Not renewable'); }
            newExpiration = uint64(block.timestamp) + duration;
        } else {
            newExpiration = currentExpiration + duration;
        }

        s_expirations[tokenId] = newExpiration;

        emit SubscriptionUpdate(tokenId, newExpiration);
    }

    function cancelSubscription(uint256 tokenId) public payable override {
        require(_isApprovedOrOwner(msg.sender, tokenId) || msg.sender == owner(), "Caller is not owner nor approved");

        delete s_expirations[tokenId];
        delete s_notRenewable[tokenId];
        delete s_valuesOneSecond[tokenId];

        emit SubscriptionUpdate(tokenId, 0);
    }

    function isRenewable(uint256 tokenId) public view override returns(bool) {
        return s_notRenewable[tokenId] == false;
    }

    function notRenewable(uint256 p_tokenId) public onlyOwner {
        s_notRenewable[p_tokenId] = true;
    }

    function renewable(uint256 p_tokenId) public onlyOwner {
        delete s_notRenewable[p_tokenId];
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Internal functions
    //////////////////////////////////////////////////////////////////////////////////////////////////
    function _baseURI() internal pure override returns (string memory) {
        return "https://ipfs.io/ipfs/";
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize)
        internal
        whenNotPaused
        override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);

        delete s_expirations[tokenId];
        delete s_notRenewable[tokenId];
        delete s_valuesOneSecond[tokenId];
    }

    function _recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = _splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    function _splitSignature(bytes memory sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    
        return (v, r, s);
    }
}