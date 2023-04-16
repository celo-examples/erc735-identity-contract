// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/AccessControl.sol";

contract Identity is AccessControl {
    bytes32 public constant CLAIM_ISSUER_ROLE = keccak256("CLAIM_ISSUER_ROLE");
    bytes32 public constant CLAIM_DELEGATE_ROLE = keccak256("CLAIM_DELEGATE_ROLE");

    struct Claim {
        uint256 topic;
        uint256 scheme;
        address issuer;
        bytes signature;
        bytes data;
        string uri;
    }

    mapping(bytes32 => Claim) public claims;
    mapping(uint256 => bytes32[]) public claimsByTopic;

    event ClaimAdded(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRemoved(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);
    event ClaimRequested(bytes32 indexed claimId, uint256 indexed topic, address indexed issuer);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function getClaim(bytes32 _claimId) external view returns (uint256 topic, uint256 scheme, address issuer, bytes memory signature, bytes memory data, string memory uri) {
        Claim memory claim = claims[_claimId];
        return (claim.topic, claim.scheme, claim.issuer, claim.signature, claim.data, claim.uri);
    }

    function addClaim(uint256 _topic, uint256 _scheme, address _issuer, bytes calldata _signature, bytes calldata _data, string calldata _uri) external onlyRole(CLAIM_ISSUER_ROLE) returns (bytes32 claimRequestId) {
        bytes32 claimId = keccak256(abi.encodePacked(_issuer, _topic));

        claims[claimId] = Claim(_topic, _scheme, _issuer, _signature, _data, _uri);
        claimsByTopic[_topic].push(claimId);

        emit ClaimAdded(claimId, _topic, _issuer);
        return claimId;
    }

    function removeClaim(bytes32 _claimId) external onlyRole(CLAIM_ISSUER_ROLE) {
        uint256 topic = claims[_claimId].topic;
        address issuer = claims[_claimId].issuer;

        delete claims[_claimId];

        bytes32[] storage claimIds = claimsByTopic[topic];
        for (uint256 i = 0; i < claimIds.length; i++) {
            if (claimIds[i] == _claimId) {
                claimIds[i] = claimIds[claimIds.length - 1];
                claimIds.pop();
                break;
            }
        }

        emit ClaimRemoved(_claimId, topic, issuer);
    }

    function requestClaim(bytes32 _claimId) external onlyRole(CLAIM_DELEGATE_ROLE) {
        emit ClaimRequested(_claimId, claims[_claimId].topic, claims[_claimId].issuer);
    }

    function setClaimIssuer(address _account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(CLAIM_ISSUER_ROLE, _account);
    }

    function setClaimDelegate(address _account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(CLAIM_DELEGATE_ROLE, _account);
    }

    function removeClaimIssuer(address _account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(CLAIM_ISSUER_ROLE, _account);
    }

    function removeClaimDelegate(address _account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(CLAIM_DELEGATE_ROLE, _account);
    }
}
