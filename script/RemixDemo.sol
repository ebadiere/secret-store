// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SecretStore} from "../src/SecretStore.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title RemixDemo
 * @notice This contract helps deploy and interact with SecretStore in Remix
 * @dev Follow these steps in Remix:
 * 1. Deploy SecretStore implementation
 * 2. Deploy RemixDemo with the implementation address
 * 3. Call initialize() on RemixDemo
 * 4. Use the proxy address returned by getProxy() to interact with SecretStore
 */
contract RemixDemo {
    SecretStore public implementation;
    ERC1967Proxy public proxy;
    SecretStore public secretStore;
    
    constructor(address _implementation) {
        implementation = SecretStore(_implementation);
    }
    
    function initialize(address admin) external returns (address) {
        require(address(proxy) == address(0), "Already initialized");
        
        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            implementation.initialize.selector,
            admin
        );
        
        // Deploy proxy
        proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        
        // Create interface for easier interaction
        secretStore = SecretStore(address(proxy));
        
        return address(proxy);
    }
    
    function getProxy() external view returns (address) {
        return address(proxy);
    }
    
    function registerSecret(
        bytes32 secretHash,
        address partyA,
        address partyB,
        bytes memory signatureA,
        bytes memory signatureB
    ) external {
        secretStore.registerSecret(
            secretHash,
            partyA,
            partyB,
            signatureA,
            signatureB
        );
    }
    
    function revealSecret(
        string memory secret,
        bytes32 salt,
        bytes32 secretHash
    ) external {
        secretStore.revealSecret(secret, salt, secretHash);
    }
}
