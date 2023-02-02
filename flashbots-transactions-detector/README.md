# Flashbots Transactions Detection Bot

## Description

This bot detects flashbots transactions.

## Supported Chains

- Ethereum

## Alerts

- FLASHBOTS-TRANSACTIONS
  - Fired when the Flashbots API flags a transaction as a flashbots transaction
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata:
    - from - the address that initiated the tx
    - to - the address that was interacted with
    - hash - the transaction hash
    - blockNumber - the block number of the tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `FLASHBOTS-TRANSACTIONS` out of the total number of transactions processed by this bot.
  - Addresses contain the list of contracts that were impacted
  - Label:
    - `entityType`: The type of the entity, always set to "Transaction"
    - `entity`: The Flashbots' transaction hash
    - `label`: The type of the label, always set to "Flashbots Transaction"
    - `confidence`: The confidence level of the transaction being suspicious (0-1). Always set to `0.7`.

## Test Data

In order to test the bot's behavior, replace `flashbotsUrl` variable in `agent.js` at L4, with one of the following urls and run `npm start`.

- `https://blocks.flashbots.net/v1/blocks?block_number=15725067` [Temple DAO Exploit](https://etherscan.io/tx/0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5)
- `https://blocks.flashbots.net/v1/blocks?block_number=15794364` [Olympus DAO Exploit](https://etherscan.io/tx/0x3ed75df83d907412af874b7998d911fdf990704da87c2b1a8cf95ca5d21504cf)
