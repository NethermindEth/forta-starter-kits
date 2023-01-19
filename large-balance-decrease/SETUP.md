# Large Balance Decrease Bot

## Description

Detects if the balance of a protocol decreases significantly.

## Bot Setup Walkthrough

The following steps will take you from a completely blank template to a functional bot.

- Set in `bot-config.json`:
  - `aggregationTimePeriod` (required) - The duration of one period (in seconds). Most of the big treasuries send assets less than once a week so we recommend a period of at least one week (604800 seconds).
  - `contractAddress` (required) - The monitored contract
- Set in `agent.js`:
  - `ALL_REMOVED_KEY`, `PORTION_REMOVED_KEY` and `TOTAL_TRANSFERS_KEY` should be uniquely set for each deployed instance of the bot.
- Set in `package.json`:
  - `chainIds` array should only include the monitored chains per instance.

The monitored tokens will update automatically when the contract sends or receives a transfer.
