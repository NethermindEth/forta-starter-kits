# Asset Drained Bot

## Description

This bot detects if a contract has had 99% or more of its assets drained within a block. It monitors ERC20 and native tokens transfers from contracts and raises an alert when a contract has its balance decrease by 99% or more from one block to the next.

## Supported Chains

- Ethereum
- Optimism
- BNB Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche

## Alerts

- ASSET-DRAINED
  - Fired when a contract has 99% or more of its assets drained
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata:
    - contract - the contract's address
    - asset - the asset's address
    - initiators - the EOA(s) that initiated the transaction(s)
    - txHashes - the hash(es) of the transaction(s) in which the contract was drained
    - blockNumber - the block number at the time of the contract drain
  - Addresses contain the list of addresses that received the assets from the drained contract

## Test Data

### Ethereum Mainnet

The bot behaviour can be verified by running:

- `npm run block 13499798,13499799` (CREAM exploit).
- `npm run block 15572488,15572489` (WinterMute exploit).
- `npm run block 15794364,15794365` (OlympusDAO exploit).

Every block we process the transactions from the previous one so when testing you should provide the exploit block and the next one.
