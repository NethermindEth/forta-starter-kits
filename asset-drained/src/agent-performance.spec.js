const { createBlockEvent, createTransactionEvent, getEthersProvider } = require("forta-agent");
const { default: calculateAlertRate } = require("bot-alert-rate");

const { provideInitialize, provideHandleTransaction, provideHandleBlock } = require("./agent");
const { getValueInUsd, getTotalSupply } = require("./helper");
jest.setTimeout(350000);

describe("Asset drained bot performance test", () => {
  it("tests performance", async () => {
    initialize = provideInitialize(getEthersProvider());
    handleBlock = provideHandleBlock(calculateAlertRate, getValueInUsd, getTotalSupply);
    handleTransaction = provideHandleTransaction();
    await initialize();

    const blocksToRun = 20;
    let totalProcessingTime = 0;
    const startingBlock = 17278834;
    //     Chain: Blocktime
    //     Ethereum: 12s,
    //     BSC: 3s,
    //     Polygon: 2s,
    //     Arbitrum: 1s,
    //     Optimism: 2s,
    //     Fantom: 1s
    //     Avalanche: 24s

    //     Chain: Avg block processing time [choosing the slowest avg time observed]
    //     Ethereum: 2803.19ms (starting block 17278834)
    //     BSC: 3584.50ms (starting block 28287306)
    //     Polygon: 3694.08 (starting block 42811000)
    //     Arbitrum: 676.20ms (starting block 91594904)
    //     Optimism: 504.36ms (starting block 794634)
    //     Fantom: 978.47ms (starting block 62507523)
    //     Avalanche: 1429.75ms (starting block 30134274)

    //      which results in the following sharding config:
    //      Ethereum - 1
    //      BSC - 2
    //      Polygon - 2
    //      Arbitrum - 1
    //      Optimism - 1
    //      Fantom - 2 (Avg Time close to Block Time so 2 shards)

    for (let i = 0; i < blocksToRun; i++) {
      const block = await getEthersProvider().getBlock(startingBlock + i);
      const maxRetries = 2;

      const txReceipts = await Promise.all(
        block.transactions.map(async (hash) => {
          let retries = 0;
          let receipt;

          while (retries < maxRetries) {
            try {
              receipt = await getEthersProvider().getTransactionReceipt(hash);
              break; // If successful, exit the retry loop
            } catch (error) {
              console.log(`Error fetching receipt for transaction ${hash}. Retrying...`);
              retries++;
            }
          }

          return receipt; // Return the receipt (or undefined if retries exhausted)
        })
      );
      const nextBlock = await getEthersProvider().getBlock(startingBlock + i + 1);
      const nextBlockEvent = createBlockEvent({
        block: nextBlock,
      });
      await Promise.all(
        txReceipts.map(async (txReceipt) => {
          const txEvent = createTransactionEvent({
            transaction: {
              hash: txReceipt.transactionHash,
              from: txReceipt.from,
              to: txReceipt.to,
            },
            block: {
              number: txReceipt.blockNumber,
            },
            logs: txReceipt.logs,
          });
          await handleTransaction(txEvent);
        })
      );
      const startTime = performance.now();
      await handleBlock(nextBlockEvent);
      const endTime = performance.now();
      totalProcessingTime += endTime - startTime;
    }
    const processingTimeAvgMs = totalProcessingTime / blocksToRun;
    console.log(`Avg processing time: ${processingTimeAvgMs}ms`);
  });
});
