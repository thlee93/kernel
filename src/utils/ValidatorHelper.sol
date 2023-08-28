// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

function _validateMerkleData(bytes calldata signature, bytes32 merkleRoot) 
		pure returns (bool){
	uint8 leafLength = uint8(bytes1(signature[0]));
	bytes32[] memory proof;

	bytes32 leaf = keccak256(signature[1:1+leafLength]);
	proof = abi.decode(signature[1+leafLength:], (bytes32[]));
	return MerkleProof.verify(proof, merkleRoot, leaf);
}
