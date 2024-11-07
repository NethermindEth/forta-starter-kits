# Sneak Governance Proposal Approval

## Description

This bot detects whether there is a sneak governance proposal about to be approved or is already approved

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon
- Avalanche
- Optimism
- Fantom
- Arbitrum

## Alerts

- SNEAK-GOVT-PROPOSAL-APPROVAL-PASSED

  - Fired when a sneak proposal is passed
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata Fields:
    - ACCOUNTS (accounts involved in the vote)

- SNEAK-GOVT-PROPOSAL-APPROVAL-ABOUT-TO-PASS
  - Fired when a sneak proposal is about to pass
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata Fields:
    - ACCOUNTS (accounts involved in the vote)

## Test Data

The bot behvaiour can be verified with the supplied unit tests or with these blocks:

- `yarn block 14879134,14883382,14884348,14884491,14896539,14897168,14897208,14897450,14897729` (need to use example configuration and expected behaviour is to return no findings, ethereum)
