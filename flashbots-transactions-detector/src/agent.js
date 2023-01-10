const { Finding, FindingSeverity, FindingType, getTransactionReceipt } = require("forta-agent");
const { default: axios } = require("axios");

const flashbotsUrl = "https://blocks.flashbots.net/v1/blocks?limit=10";
let lastBlockNumber = 0;

function provideHandleBlock(getTransactionReceipt) {
  let cachedFindings = [];
  return async () => {
    if (cachedFindings.length >= 4) {
      cachedFindings.splice(0, 4);
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
        console.log(lastBlockNumber);
        // Only process blocks that aren't processed
        if (blockNumber > lastBlockNumber) {
          // Create finding for every flashbots transaction in the block
          currentBlockFindings = await Promise.all(
            transactions
              .filter((transaction) => transaction.bundle_type !== "mempool")
              .map(async (transaction) => {
                const { eoa_address: from, to_address: to, transaction_hash: hash } = transaction;

                // Use the tx logs to get the impacted contracts
                const { logs } = await getTransactionReceipt(hash);
                let addresses = logs.map((log) => log.address.toLowerCase());
                addresses = [...new Set(addresses)];

                return Finding.fromObject({
                  name: "Flashbots transactions",
                  description: `${from} interacted with ${to} in a flashbots transaction`,
                  alertId: "FLASHBOTS-TRANSACTIONS",
                  severity: FindingSeverity.Low,
                  type: FindingType.Info,
                  addresses,
                  metadata: {
                    from,
                    to,
                    hash,
                    blockNumber,
                  },
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

    return cachedFindings.slice(0, 4);
  };
}

module.exports = {
  provideHandleBlock,
  handleBlock: provideHandleBlock(getTransactionReceipt),
  resetLastBlockNumber: () => {
    lastBlockNumber = 0;
  }, // Exported for unit tests
};
