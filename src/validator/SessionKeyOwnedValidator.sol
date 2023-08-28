// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/ValidatorHelper.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";

struct SessionKeyStorage {
    uint48 validUntil;
    uint48 validAfter;
    bytes32 merkleRoot;
}

contract SessionKeyOwnedValidator is IKernelValidator {
    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    event SessionKeyRegistered(address sessionKey, address owner,
        uint48 validUntil, uint48 validAfter, bytes32 merkleRoot);

    event SessionKeyRevoked(address sessionKey, address owner);

    event UserOpValidatedWithSessionKey(address sessionKey, address owner,
        bytes32 hash, uint256 validationResult);

    mapping(address sessionKey => mapping(address kernel => SessionKeyStorage)) public sessionKeyStorage;

    function disable(bytes calldata _data) external override {
        address sessionKey = address(bytes20(_data[0:20]));
        delete sessionKeyStorage[sessionKey][msg.sender];

        emit SessionKeyRevoked(sessionKey, msg.sender);
    }

    function enable(bytes calldata _data) external override {
        address sessionKey = address(bytes20(_data[0:20]));
        uint48 validUntil = uint48(bytes6(_data[20:26]));
        uint48 validAfter = uint48(bytes6(_data[26:32]));

        bytes32 merkleRoot = bytes32(bytes6(_data[32:64]));

        require(validUntil > validAfter, "SessionKeyOwnedValidator: invalid validUntil/validAfter"); // we do not allow validUntil == 0 here use validUntil == 2**48-1 instead
        sessionKeyStorage[sessionKey][msg.sender] = SessionKeyStorage(validUntil, validAfter, merkleRoot);

        emit SessionKeyRegistered(sessionKey, msg.sender, validUntil, validAfter, merkleRoot);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        view
        override
        returns (uint256 validationData)
    {
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, _userOp.signature);

        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        bytes32 merkleRoot = sessionKey.merkleRoot;

        if (sessionKey.validUntil == 0 ) { // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }

        uint256 validateExpiry = _packValidationData(false, sessionKey.validUntil, sessionKey.validAfter);
        bool validateMerkleRoot = _validateMerkleData(_userOp.signature[72:], merkleRoot);

        if (validateMerkleRoot == false) {
            return SIG_MERKLE_PROOF_FAILED;
        }

        return validateExpiry;
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (uint256) {
        bytes32 ethhash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethhash, signature);

        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (sessionKey.validUntil == 0 ) { // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, sessionKey.validUntil, sessionKey.validAfter);
    }
}
