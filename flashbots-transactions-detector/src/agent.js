const {
  Finding,
  FindingSeverity,
  FindingType,
  getTransactionReceipt,
  Label,
  EntityType,
  getEthersProvider,
} = require("forta-agent");
const { PersistenceHelper } = require("./persistence.helper");
const { default: axios } = require("axios");
const { default: calculateAlertRate } = require("bot-alert-rate");
const { ScanCountType } = require("bot-alert-rate");
const { getSecrets } = require("./storage");

const flashbotsUrl = "https://blocks.flashbots.net/v1/blocks?limit=4";
let lastBlockNumber = 0;

const DATABASE_URL = "https://research.forta.network/database/bot/";

const FLASHBOTS_TXS_KEY = "nm-flashbots-bot-txs-key-1";
const SWAP_FLASHBOTS_TXS_KEY = "nm-swap-flashbots-bot-txs-key-1";

let totalFlashbotsTxns = 0;
let totalSwapFlashbotsTxns = 0;
let chainId;
let apiKeys;
const BOT_ID = "0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5";

function provideInitialize(provider, persistenceHelper, flashbotsKey, swapFlashbotsKey) {
  return async () => {
    totalFlashbotsTxns = await persistenceHelper.load(flashbotsKey);
    totalSwapFlashbotsTxns = await persistenceHelper.load(swapFlashbotsKey);

    ({ chainId } = await provider.getNetwork());
    apiKeys = await getSecrets();
    process.env["ZETTABLOCK_API_KEY"] = apiKeys.generalApiKeys.ZETTABLOCK[0];
  };
}

function provideHandleBlock(
  calculateAlertRate,
  provider,
  getTransactionReceipt,
  persistenceHelper,
  flashbotsKey,
  swapFlashbotsKey
) {
  let cachedFindings = [];
  return async (blockEvent) => {
    if (cachedFindings.length >= 10) {
      cachedFindings.splice(0, 10);
    } else {
      cachedFindings = [];
    }
    let result;
    try {
      result = await axios.get(flashbotsUrl);
    } catch (e) {
      console.log("Error:", e.code);
      return [];
    }

    const { blocks } = result.data;

    // Get findings for every new flashbots block and combine them
    let findings = await Promise.all(
      blocks.map(async (block) => {
        const { transactions, block_number: blockNumber } = block;
        let currentBlockFindings;

        // Only process blocks that aren't processed
        if (blockNumber > lastBlockNumber) {
          // Create finding for every flashbots transaction in the block
          currentBlockFindings = await Promise.all(
            transactions
              .filter((transaction) => transaction.bundle_type !== "mempool")
              .filter(async (transaction) => {
                const code = await provider.getCode(transaction.to_address);
                return code !== "0x";
              })
              .map(async (transaction) => {
                const {
                  eoa_address: from,
                  to_address: to,
                  transaction_hash: hash,
                  total_miner_reward: reward,
                } = transaction;

                // Use the tx logs to get the impacted contracts
                const { logs } = await getTransactionReceipt(hash);

                let alertId = "";

                if (reward == "0") {
                  alertId = "FLASHBOTS-TRANSACTIONS-NO-REWARD";
                } else {
                  alertId = "FLASHBOTS-TRANSACTIONS";
                }

                let addresses = logs.map((log) => {
                  // Check if the transaction is a swap
                  // 0xd78ad95... is the swap topic for Uniswap v2 & 0xc42079f... is the swap topic for Uniswap v3
                  if (logs.length < 10) {
                    if (
                      log.topics.includes("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822") ||
                      log.topics.includes("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67")
                    ) {
                      if (reward === "0") {
                        alertId = "FLASHBOTS-SWAP-TRANSACTIONS-NO-REWARD";
                      } else {
                        alertId = "FLASHBOTS-SWAP-TRANSACTIONS";
                      }
                    }
                  }

                  return log.address.toLowerCase();
                });

                let anomalyScore;

                if (alertId === "FLASHBOTS-TRANSACTIONS") {
                  totalFlashbotsTxns += 1;

                  anomalyScore = await calculateAlertRate(
                    Number(chainId),
                    BOT_ID,
                    alertId,
                    ScanCountType.TransferCount,
                    totalFlashbotsTxns // No issue in passing 0 for non-relevant chains
                  );
                } else {
                  totalSwapFlashbotsTxns += 1;

                  anomalyScore = await calculateAlertRate(
                    Number(chainId),
                    BOT_ID,
                    alertId,
                    ScanCountType.TransferCount,
                    totalSwapFlashbotsTxns // No issue in passing 0 for non-relevant chains
                  );
                }

                addresses = [...new Set(addresses)];

                return Finding.fromObject({
                  name: "Flashbots transactions",
                  description: `${from} interacted with ${to} in a flashbots transaction`,
                  alertId: alertId,
                  severity: FindingSeverity.Low,
                  type: FindingType.Info,
                  addresses,
                  metadata: {
                    from,
                    to,
                    hash,
                    blockNumber,
                    anomalyScore: anomalyScore.toString(),
                  },
                  labels: [
                    Label.fromObject({
                      entity: from,
                      entityType: EntityType.Address,
                      label: "Attacker",
                      confidence: 0.6,
                    }),
                    Label.fromObject({
                      entity: hash,
                      entityType: EntityType.Transaction,
                      label: "Suspicious",
                      confidence: 0.7,
                    }),
                  ],
                });
              })
          );

          lastBlockNumber = blockNumber;
        }

        return currentBlockFindings;
      })
    );

    findings = findings.flat().filter((f) => !!f);

    cachedFindings.push(...findings);

    if (blockEvent.blockNumber % 240 === 0) {
      await persistenceHelper.persist(totalFlashbotsTxns, flashbotsKey);
      await persistenceHelper.persist(totalSwapFlashbotsTxns, swapFlashbotsKey);
    }

    return cachedFindings.slice(0, 10);
  };
}

module.exports = {
  provideHandleBlock,
  handleBlock: provideHandleBlock(
    calculateAlertRate,
    getEthersProvider(),
    getTransactionReceipt,
    new PersistenceHelper(DATABASE_URL),
    FLASHBOTS_TXS_KEY,
    SWAP_FLASHBOTS_TXS_KEY
  ),
  provideInitialize,
  initialize: provideInitialize(
    getEthersProvider(),
    new PersistenceHelper(DATABASE_URL),
    FLASHBOTS_TXS_KEY,
    SWAP_FLASHBOTS_TXS_KEY
  ),
  resetLastBlockNumber: () => {
    lastBlockNumber = 0;
  }, // Exported for unit tests
};
