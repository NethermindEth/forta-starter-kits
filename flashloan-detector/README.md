# Flashloan Detection Bot

## Description

This bot detects if a transaction contains a flashloan and the borrower made significant profit. The percentage threshold is set to 2%.

## Supported Chains

- Ethereum
- Optimism
- Binance Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche

## Alerts

Describe each of the type of alerts fired by this agent

- FLASHLOAN-ATTACK

  - Fired when a transaction contains a flashoan and the borrower made significant profit
  - Severity is always set to "low"
  - Type is always set to "exploit"
  - Metadata:
    - `profit` - profit made from the flashloan
    - `tokens` - array of all tokens involved in the transaction
  - Labels
    - Label:
      - `entityType`: The type of the entity, always set to "Address"
      - `entity`: The attacker's address
      - `label`: The type of the label, always set to "Attacker"
      - `confidence`: The confidence level of the address being an attacker (0-1)
    - Label:
      - `entityType`: The type of the entity, always set to "Transaction"
      - `entity`: The transaction hash
      - `label`: The type of the label, always set to "Flashloan Transaction"
      - `confidence`: The confidence level of the transaction being a flashloan (0-1)
      

- FLASHLOAN-ATTACK-WITH-HIGH-PROFIT
  - Fired when a transaction contains a flashoan and the borrower made significant profit
  - Severity is always set to "high"
  - Type is always set to "exploit"
  - Metadata:
    - `profit` - profit made from the flashloan
    - `tokens` - array of all tokens involved in the transaction
  - Labels
    - Label 01:
      - `entityType`: The type of the entity, always set to "Address"
      - `entity`: The attacker's address
      - `label`: The type of the label, always set to "Attacker"
      - `confidence`: The confidence level of the address being an attacker (0-1)
    - Label 0:
      - `entityType`: The type of the entity, always set to "Transaction"
      - `entity`: The transaction hash
      - `label`: The type of the label, always set to "Flashloan Transaction"
      - `confidence`: The confidence level of the transaction being a flashloan (0-1)

## Test Data

The bot behaviour can be verified with the following transactions:

- [0xe7e0474793aad11875c131ebd7582c8b73499dd3c5a473b59e6762d4e373d7b8](https://etherscan.io/tx/0xe7e0474793aad11875c131ebd7582c8b73499dd3c5a473b59e6762d4e373d7b8) (SaddleFinance exploit)
- [0x47c7ab4a9e829415322c8933cf17261cd666dbeb875f0d559ca2785d21cae661](https://etherscan.io/tx/0x47c7ab4a9e829415322c8933cf17261cd666dbeb875f0d559ca2785d21cae661) (Curve Finance exploit)
  - To test this exploit transaction, lower `PERCENTAGE_THRESHOLD` in `agent.js` (L19) to `1.75`, as currently the transaction does not clear the percentage threshold of `2`.