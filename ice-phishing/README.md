# Ice Phishing Bot

## Description

This bot detects if an account (EOA with low nonce or unverified contract with low number of transactions) gains a high number of approvals or an ERC20 permission and if it transfers the approved funds. It also does the same checks for EOAs with high nonce or verified contracts with low number of transactions and emits an alert of lower severity. Lastly, it checks if an account from the [ScamSniffer DB](https://github.com/scamsniffer/scam-database) or a contract, or contract creator, from a [Malicious Smart Contract ML Bot v2](https://explorer.forta.network/bot/0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91) alert is involved in an `Approval`/`Transfer`/`permit`.

> The `permit` function signatures detected by the bot are from EIP-2612 and MakerDAO's DAI.

## Supported Chains

- Ethereum
- Optimism
- Binance Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche

## Alerts

- ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS

  - Fired when an account gains high number of ERC-20 approvals
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS` out of the total number of ERC-20 approvals detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.3"
    - Label 2:
      - `entity`: The first approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC20 token approval, always set to "1"
    - Label 3:
      - `entity`: The last approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC20 token approval, always set to "1"

- ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS

  - Fired when an account gains high number of ERC-721 approvals
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS` out of the total number of ERC-721 approvals detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.3"
    - Label 2:
      - `entity`: The first approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 token approval, always set to "1"
    - Label 3:
      - `entity`: The last approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 token approval, always set to "1"

- ICE-PHISHING-ERC721-APPROVAL-FOR-ALL

  - Fired when an account gains approval for all ERC-721s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC721-APPROVAL-FOR-ALL` out of the total number of ERC-721 `ApprovalForAll`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.2"
    - Label 2:
      - `entity`: The `ApprovalForAll` transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 `ApprovalForAll`, always set to "1"

- ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL

  - Fired when an account gains approval for all ERC-1155s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL` out of the total number of ERC-1155 `ApprovalForAll`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.2"
    - Label 2:
      - `entity`: The `ApprovalForAll` transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC1155 `ApprovalForAll`, always set to "1"

- ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains high number of ERC-20 approvals
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO` out of the total number of ERC-20 approvals detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.25"
    - Label 2:
      - `entity`: The first approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC20 token approval, always set to "1"
    - Label 3:
      - `entity`: The last approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC20 token approval, always set to "1"

- ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains high number of ERC-721 approvals
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO` out of the total number of ERC-721 approvals detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.25"
    - Label 2:
      - `entity`: The first approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 token approval, always set to "1"
    - Label 3:
      - `entity`: The last approval transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 token approval, always set to "1"

- ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains approval for all ERC-721s
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO` out of the total number of ERC-721 `ApprovalForAll`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.15"
    - Label 2:
      - `entity`: The `ApprovalForAll` transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC721 `ApprovalForAll`, always set to "1"

- ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains approval for all ERC-1155s
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO` out of the total number of ERC-1155 `ApprovalForAll`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.15"
    - Label 2:
      - `entity`: The `ApprovalForAll` transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Approval"
      - `confidence`: The confidence level of the transaction being an ERC1155 `ApprovalForAll`, always set to "1"

- ICE-PHISHING-ERC20-PERMIT

  - Fired when an account (unverified contract with low number of transactions or EOA with low nonce) gives permission to another account for a victim's ERC-20s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `msgSender` - the account that called the asset's `permit` function
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC20-PERMIT` out of the total number of `Permit`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.3"
    - Label 2:
      - `entity`: The `Permit`'s transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Permit"
      - `confidence`: The confidence level of the transaction being an ERC20 `Permit`, always set to "1"

- ICE-PHISHING-ERC20-PERMIT-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gives permission to another account for a victim's ERC-20s
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `msgSender` - the account that called the asset's `permit` function
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-ERC20-PERMIT-INFO` out of the total number of `Permit`s detected by this bot.
  - Addresses contain the approved asset address
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.2"
    - Label 2:
      - `entity`: The `Permit`'s transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Permit"
      - `confidence`: The confidence level of the transaction being an ERC20 `Permit`, always set to "1"

- ICE-PHISHING-ERC20-SCAM-PERMIT

  - Fired when a known scam address is involved in an ERC-20 permission.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the permission
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-ERC20-SCAM-PERMIT` out of the total number of `Permit`s detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - First Label(s):
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.9"
      - Last Label :
        - `entity`: The `Permit`'s transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Permit"
        - `confidence`: The confidence level of the transaction being an ERC20 `Permit`, always set to "1"

- ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT

  - Fired when a verified contract, created by a scam account, is involved in an ERC-20 permission.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the permission
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT` out of the total number of `Permit`s detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - Label 1:
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.9"
      - Label 2:
        - `entity`: The `Permit`'s transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Permit"
        - `confidence`: The confidence level of the transaction being an ERC20 `Permit`, always set to "1"

- ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT

  - Fired when a known scam address is involved in an ERC-20 permission.
    - Severity is always set to "medium"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousContract` - The address of the suspicious contract
      - `suspiciousContractCreator` - The address of the suspicious contract creator
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT` out of the total number of `Permit`s detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - Label 1:
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.5"
      - Label 2:
        - `entity`: The `Permit`'s transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Permit"
        - `confidence`: The confidence level of the transaction being an ERC20 `Permit`, always set to "1"

- ICE-PHISHING-SCAM-APPROVAL

  - Fired when a known scam address gets approval to spend assets.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamDomains` - The list of domains related to the scam addresses
      - `scamSpender` - the account that received the approval
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SCAM-APPROVAL` out of the total number of token approvals detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - Label 1:
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.9"
      - Label 2:
        - `entity`: The approval transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Approval"
        - `confidence`: The confidence level of the transaction being a token approval, always set to "1"

- ICE-PHISHING-SCAM-CREATOR-APPROVAL

  - Fired when a verified contract, created by a known scam address, gets approval to spend assets.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamDomains` - The list of domains related to the scam addresses
      - `scamCreator` - The scam address that created the contract
      - `spender` - the contract that received the approval
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SCAM-CREATOR-APPROVAL` out of the total number of token approvals detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - Label 1:
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.9"
      - Label 2:
        - `entity`: The approval transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Approval"
        - `confidence`: The confidence level of the transaction being a token approval, always set to "1"

- ICE-PHISHING-SUSPICIOUS-APPROVAL

  - Fired when a known scam address gets approval to spend assets.
    - Severity is always set to "medium"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousSpender` - the address of the suspicious spender
      - `suspiciousContractCreator` - the address of the suspicious contract creator
      - `owner` - the owner of the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SUSPICIOUS-APPROVAL` out of the total number of token approvals detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - Label 1:
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.5"
      - Label 2:
        - `entity`: The approval transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Approval"
        - `confidence`: The confidence level of the transaction being a token approval, always set to "1"

- ICE-PHISHING-SCAM-TRANSFER

  - Fired when a known scam address is involved in an asset transfer.
    - Severity is always set to "critical"
    - Type is always set to "exploit"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the transfer
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SCAM-TRANSFERS` out of the total number of token transfers detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - First Label(s):
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.95"
      - Last Label :
        - `entity`: The transfer transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Transfer"
        - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-SCAM-CREATOR-TRANSFER

  - Fired when a verified contract, created by a known scam address, is involved in an asset transfer.
    - Severity is always set to "critical"
    - Type is always set to "exploit"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the transfer
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SCAM-CREATOR-TRANSFERS` out of the total number of token transfers detected by this bot.
    - Addresses contain the approved asset address
    - Labels:
      - First Label(s):
        - `entity`: The attacker's address
        - `entityType`: The type of the entity, always set to "Address"
        - `label`: The type of the label, always set to "Ice Phishing Attacker"
        - `confidence`: The confidence level of the address being an attacker, always set to "0.95"
      - Last Label :
        - `entity`: The transfer transaction hash
        - `entityType`: The type of the entity, always set to "Transaction"
        - `label`: The type of the label, always set to "Transfer"
        - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-SUSPICIOUS-TRANSFER

  - Fired when a suspicious contract is involved in an asset transfer.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousContract` - The address of the suspicious contract
      - `suspiciousContractCreator` - The address of the suspicious contract creator
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
      - `anomalyScore` - score of how anomalous the alert is (0-1)
        - Score calculated by finding amount of `ICE-PHISHING-SUSPICIOUS-TRANSFERS` out of the total number of token transfers detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's contract address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.6"
    - Label 2:
      - `entity`: The attacker's EOA address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.6"
    - Label 3:
      - `entity`: The transfer transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS

  - Fired when an account that gained high number of approvals starts transfering the approved assets
  - Severity is always set to "high"
  - Type is always set to "exploit"
  - Metadata:
    - `firstTxHash` - hash of the first transfer tx
    - `lastTxHash` - hash of the last transfer tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by amount of transfers resulting in `ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS` alerts out of the total number of token transfers detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.4"
    - Label 2:
      - `entity`: The first transfer's transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"
    - Label 3:
      - `entity`: The last transfer's transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) that gained high number of approvals starts transfering the approved assets
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first transfer tx
    - `lastTxHash` - hash of the last transfer tx
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by amount of transfers resulting in `ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW` alerts out of the total number of token transfers detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.25"
    - Label 2:
      - `entity`: The first transfer's transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"
    - Label 3:
      - `entity`: The last transfer's transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-PERMITTED-ERC20-TRANSFER

  - Fired when an account transfers tokens for which it was previously granted permission.
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Metadata:
    - `spender` - the account that transferred the tokens
    - `owner` - the owner of the assets
    - `receiver` - the account that received the tokens
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-PERMITTED-ERC20-TRANSFER` out of the total number of token transfers detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.4"
    - Label 2:
      - `entity`: The transfer transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

- ICE-PHISHING-PERMITTED-ERC20-TRANSFER-MEDIUM

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) transfers tokens for which it was previously granted permission.
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that transferred the tokens
    - `owner` - the owner of the assets
    - `receiver` - the account that received the tokens
    - `anomalyScore` - score of how anomalous the alert is (0-1)
      - Score calculated by finding amount of `ICE-PHISHING-PERMITTED-ERC20-TRANSFER-MEDIUM` out of the total number of token transfers detected by this bot.
  - Addresses contain an array of the impacted assets
  - Labels:
    - Label 1:
      - `entity`: The attacker's address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Ice Phishing Attacker"
      - `confidence`: The confidence level of the address being an attacker, always set to "0.3"
    - Label 2:
      - `entity`: The transfer transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Transfer"
      - `confidence`: The confidence level of the transaction being a token transfer, always set to "1"

## Test Data

The bot behaviour can be verified with the following transactions on Ethereum:

- npm run tx [0xc45f426dbae8cfa1f96722d5fccfe8036a356b6be2259ac9b1836a9c3286000f](https://etherscan.io/tx/0xc45f426dbae8cfa1f96722d5fccfe8036a356b6be2259ac9b1836a9c3286000f),[0x70842e12f8698a3a12f8a015579c4152d6e65841d1c18a23e85b5127144a5490](https://etherscan.io/tx/0x70842e12f8698a3a12f8a015579c4152d6e65841d1c18a23e85b5127144a5490),[0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34](https://etherscan.io/tx/0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34),[0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869](https://etherscan.io/tx/0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869),[0x36ee80b32a4248c4f1ca70fc78989b3ffe0def0a6824cb8591aff8110170769c](https://etherscan.io/tx/0x36ee80b32a4248c4f1ca70fc78989b3ffe0def0a6824cb8591aff8110170769c),[0xe01969b2c7dea539497d0413cf3b53f80a6f793f63637e6747991405e20dcaf4](https://etherscan.io/tx/0xe01969b2c7dea539497d0413cf3b53f80a6f793f63637e6747991405e20dcaf4) - BadgerDAO attack (In order for `Approval` alerts to be raised, set the `approveCountThreshold` in `bot-config.json` to `0` or `1`)
- npm run tx [0x4ac7bb723c430d47b6871cc475da2661f9f2d848f6d9a220d125f33bc8850f7c](https://ethersca.io/tx/0x4ac7bb723c430d47b6871cc475da2661f9f2d848f6d9a220d125f33bc8850f7c),[0x8f13bcbd56ef6c4ebdf1c18388ae4510be358b516aef4347b7d989b0340a1ae8](https://etherscan.io/tx/0x8f13bcbd56ef6c4ebdf1c18388ae4510be358b516aef4347b7d989b0340a1ae8),[0x43337dadfd774ffdbb883f0935f1ba368d9fceb24a161e157cf4402e824dfbfd](https://etherscan.io/tx/0x43337dadfd774ffdbb883f0935f1ba368d9fceb24a161e157cf4402e824dfbfd),[0x519802e340fe178bb573b6ad840a2eb56ba2638cffc5791860aa4af2fa05b398](https://etherscsan.io/tx/0x519802e340fe178bb573b6ad840a2eb56ba2638cffc5791860aa4af2fa05b398) - Uniswap V3 attack (In order for an `ApprovalForAll`alert to be raised, set the`approveForAllCountThreshold`in`bot-config.json`to`0`)
