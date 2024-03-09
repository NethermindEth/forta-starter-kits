# Malicious Governance Proposal Bot

## Description

This bot detects if a proposal gets submitted with unreasonable parameters

## Bot Setup Walkthrough

The following steps will take you from a completely blank template to a functional bot.

address (required) - The governance contract address

type (required) - The bot only supports `comp` and `aragon` governance types

parameters (required) - Array with params. It should be different based on the type:
- For comp contracts each param has:
  - signature - The function that is monitored
  - thresholds
    - name - The parameter's name
    - min - The minimum value
    - max - The maximum value
- For aragon contracts each param has:
  - string - A string that is used for creating a regular expression. The '*' is used for capturing the value we monitor. The '_' is used to ignore part of the text. Example: 'fund _ with * LDO' will detect funding to every contract.
  - min - The minimum value
  - max - The maximum value
