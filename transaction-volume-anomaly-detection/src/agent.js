const {
  Finding,
  FindingSeverity,
  FindingType,
  getEthersProvider,
  getTransactionReceipt,
} = require("forta-agent");

const {
  getContractsByChainId,
  globalSensitivity,
  getBlocktimeByChainId,
  getMinBucketBlockSizeByChainId,
} = require("./agent.config");

const { persistenceHelper } = require("./persistence.helper");
let { bucketBlockSize } = require("./agent.config");

const ARIMA_SETTINGS = {
  p: 2,
  d: 1,
  q: 2,
  P: 1,
  D: 0,
  Q: 1,
  s: 50,
  verbose: false,
};
let blockTime = 0;
const ARIMA = require("arima");
const provider = getEthersProvider();
let contractTracker = {};
let timestampThreshold = 0; // The timestamp time in seconds based on the bucket block size and blockTime

let contractsForChain = [];
let isFirstBlock = true;
let startTimestamp = 0;
let isTrained = false;
let isRunningJob = false;
let localFindings = [];

//Initialize the TSA for each contract in the list
const initialize = async (PersistenceHelper) => {
  const { chainId } = await provider.getNetwork();
  contractsForChain = getContractsByChainId(chainId);

  blockTime = getBlocktimeByChainId(chainId);
  const minBlockSize = getMinBucketBlockSizeByChainId(chainId);
  if (bucketBlockSize < minBlockSize) {
    console.warn(
      `Min bucket block size for chainId: ${chainId} is ${minBlockSize}, setting it to that value`
    );
    bucketBlockSize = minBlockSize;
  }
  timestampThreshold = bucketBlockSize * blockTime;

  const seasonality = 604_800 / timestampThreshold;
  if (seasonality > 50) {
    throw new Error(
      "Seasonality cannot be greater than 50, please increase bucket block size"
    );
  }
  ARIMA_SETTINGS.s = seasonality;
  contractTracker =  await PersistenceHelper.load("nm-transaction-volume");
  //case when there's nothing to load
  if(contractTracker== []){
    for (let contract of contractsForChain) {
      contractTracker[contract] = {
        successfulTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        failedTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        successfulInternalTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
        failedInternalTx: {
          TSA: new ARIMA(ARIMA_SETTINGS),
          txTracker: [],
          txCount: 0,
          currentBlockCount: 0,
        },
      };
    }
  }
};

//Handle each tx by type and increment if needed
const provideHandleTransaction = (
  contractTracker,
  contractsForChain,
  getTransactionReceipt
) => {
  return async function handleTransaction(txEvent) {
    const findings = [];

    const contract = contractsForChain.find((c) => c == txEvent.to);

    if (contract) {
      const tracker = contractTracker[contract];

      if (txEvent.traces.length > 0) {
        for (const trace of txEvent.traces) {
          if (trace.action.to == contract) {
            if (!trace.error) {
              tracker.successfulInternalTx.txCount++;
            } else if (trace.error) {
              tracker.failedInternalTx.txCount++;
            }
          }
        }
      }
      const { status } = await getTransactionReceipt(txEvent.hash);
      if (status) {
        tracker.successfulTx.txCount++;
      } else if (!status) {
        tracker.failedTx.txCount++;
      }
    }

    return findings;
  };
};

const provideHandleBlock = (contractTracker, contractsForChain) => {
  return async function handleBlock(blockEvent) {
    let findings = [];

    if(blockEvent.blockNumber%240==0){
      await PersistenceHelper.persist(contractTracker,nm-transaction-volume)
    }

    //We skip the first block since it will have no information that we should train the TSA on
    if (!isFirstBlock) {
      //On the second block add the txCount to the txTracker array
      for (let contract of contractsForChain) {
        const tracker = contractTracker[contract];
        tracker.successfulTx.txTracker.push(tracker.successfulTx.txCount);

        tracker.failedTx.txTracker.push(tracker.failedTx.txCount);
        tracker.successfulInternalTx.txTracker.push(
          tracker.successfulInternalTx.txCount
        );

        tracker.failedInternalTx.txTracker.push(
          tracker.failedInternalTx.txCount
        );
        tracker.successfulTx.txCount = 0;
        tracker.failedTx.txCount = 0;
        tracker.successfulInternalTx.txCount = 0;
        tracker.failedInternalTx.txCount = 0;
      }

      //If we pass the timestampThreshold train the SARIMA Model to predict data
      if (
        blockEvent.block.timestamp - startTimestamp <= timestampThreshold &&
        !isTrained
      ) {
        for (let contract of contractsForChain) {
          const tracker = contractTracker[contract];

          if (tracker.successfulTx.currentBlockCount >= bucketBlockSize) {
            tracker.successfulTx.TSA.train(tracker.successfulTx.txTracker);
            tracker.successfulTx.currentBlockCount = 0;
            isTrained = true;
          } else {
            tracker.successfulTx.currentBlockCount++;
          }
          if (tracker.failedTx.currentBlockCount >= bucketBlockSize) {
            tracker.failedTx.TSA.train(tracker.failedTx.txTracker);
            tracker.failedTx.currentBlockCount = 0;
            isTrained = true;
          } else {
            tracker.failedTx.currentBlockCount++;
          }

          if (
            tracker.successfulInternalTx.currentBlockCount >= bucketBlockSize
          ) {
            tracker.successfulInternalTx.TSA.train(
              tracker.successfulInternalTx.txTracker
            );
            tracker.successfulInternalTx.currentBlockCount = 0;
            isTrained = true;
          } else {
            tracker.successfulInternalTx.currentBlockCount++;
          }

          if (tracker.failedInternalTx.currentBlockCount >= bucketBlockSize) {
            tracker.failedInternalTx.TSA.train(
              tracker.failedInternalTx.txTracker
            );
            tracker.failedInternalTx.currentBlockCount = 0;
            isTrained = true;
          } else {
            tracker.failedInternalTx.currentBlockCount++;
          }
        }

        startTimestamp = blockEvent.block.timestamp;
      }

      //If the model is trained and we are not running a job, Run job
      if (!isRunningJob && isTrained) {
        runJob(contractTracker, contractsForChain, blockEvent);
      }
    } else {
      startTimestamp = blockEvent.block.timestamp;
    }
    if (localFindings.length > 0) {
      findings = localFindings;
      localFindings = [];
    }
    isFirstBlock = false;
    return findings;
  };
};

//Returns findings is there are positive cases
const runJob = (contractTracker, contractsForChain, blockEvent) => {
  isRunningJob = true;
  isFirstBlock = true;

  for (let contract of contractsForChain) {
    const tracker = contractTracker[contract];
    console.log("Current contract:", contract);
    {
      const [pred, error] = tracker.successfulTx.TSA.predict(1);

      //The count is the latest txCount
      const count =
        tracker.successfulTx.txTracker[
          tracker.successfulTx.txTracker.length - 1
        ];

      //The baseline is the normal txCount
      const baseline =
        tracker.successfulTx.txTracker[
          tracker.successfulTx.txTracker.length - 2
        ];
      console.log("Current pred successful tx: ", pred);
      console.log("Current count successful tx: ", count);
      console.log("Current pred baseline successful tx:", baseline);
      console.log(
        "Should alert high num successful tx:",
        count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])
      );
      if (count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])) {
        localFindings.push(
          Finding.fromObject({
            name: "Unusually high number of successful transactions",
            description: `Significant increase of successful transactions have been observed from ${
              blockEvent.blockNumber - bucketBlockSize
            } to ${blockEvent.blockNumber}`,
            alertId: "SUCCESSFUL-TRANSACTION-VOL-INCREASE",
            severity: FindingSeverity.Low,
            type: FindingType.Suspicious,
            metadata: {
              COUNT: count,
              EXPECTED_BASELINE: baseline,
            },
          })
        );
        isTrained = false;
        tracker.successfulTx.txTracker = [];
      }
    }

    {
      const [pred, error] = tracker.failedTx.TSA.predict(1);
      tracker.failedTx.TSA.predict(1);

      const count =
        tracker.failedTx.txTracker[tracker.failedTx.txTracker.length - 1];
      const baseline =
        tracker.failedTx.txTracker[tracker.failedTx.txTracker.length - 2];
      console.log("Current pred failed tx: ", pred);
      console.log("Current count failed tx: ", count);
      console.log("Current pred baseline failed tx:", baseline);
      console.log(
        "Should alert high num failed tx:",
        count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])
      );
      if (count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])) {
        localFindings.push(
          Finding.fromObject({
            name: "Unusually high number of failed transactions",
            description: `Significant increase of failed transactions have been observed from  ${
              blockEvent.blockNumber - bucketBlockSize
            } to ${blockEvent.blockNumber}`,
            alertId: "FAILED-TRANSACTION-VOL-INCREASE",
            severity: FindingSeverity.High,
            type: FindingType.Exploit,
            metadata: {
              COUNT: count,
              EXPECTED_BASELINE: baseline,
            },
          })
        );
        isTrained = false;
        tracker.failedTx.txTracker = [];
      }
    }

    {
      const [pred, error] = tracker.successfulInternalTx.TSA.predict(1);

      const count =
        tracker.successfulInternalTx.txTracker[
          tracker.successfulInternalTx.txTracker.length - 1
        ];

      const baseline =
        tracker.successfulInternalTx.txTracker[
          tracker.successfulInternalTx.txTracker.length - 2
        ];
      console.log("Current pred successful internal tx: ", pred);
      console.log("Current count successful internal tx: ", count);
      console.log("Current pred baseline successful internal tx:", baseline);
      console.log(
        "Should alert high num successful internal tx:",
        count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])
      );
      if (count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])) {
        localFindings.push(
          Finding.fromObject({
            name: "Unusually high number of successful internal transactions",
            description: `Significant increase of successful internal transactions have been observed from ${
              blockEvent.blockNumber - bucketBlockSize
            } to ${blockEvent.blockNumber}`,
            alertId: "SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE",
            severity: FindingSeverity.Low,
            type: FindingType.Suspicious,
            metadata: {
              COUNT: count,
              EXPECTED_BASELINE: baseline,
            },
          })
        );
        isTrained = false;
        tracker.successfulInternalTx.txTracker = [];
      }
    }

    {
      const [pred, error] = tracker.failedInternalTx.TSA.predict(1);
      const count =
        tracker.failedInternalTx.txTracker[
          tracker.failedInternalTx.txTracker.length - 1
        ];
      const baseline =
        tracker.failedInternalTx.txTracker[
          tracker.failedInternalTx.txTracker.length - 2
        ];
      console.log("Current pred failed internal tx: ", pred);
      console.log("Current count failed internal tx: ", count);
      console.log("Current pred baseline failed internal tx:", baseline);
      console.log(
        "Should alert high num failed internal tx:",
        count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])
      );
      if (count * globalSensitivity > pred[0] + 1.96 * Math.sqrt(error[0])) {
        localFindings.push(
          Finding.fromObject({
            name: "Unusually high number of failed internal transactions",
            description: `Significant increase of failed internal transactions have been observed from ${
              blockEvent.blockNumber - bucketBlockSize
            } to ${blockEvent.blockNumber}`,
            alertId: "FAILED-INTERNAL-TRANSACTION-VOL-INCREASE",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              COUNT: count,
              EXPECTED_BASELINE: baseline,
            },
          })
        );
        isTrained = false;
        tracker.failedInternalTx.txTracker = [];
      }
    }
  }

  isRunningJob = false;
};

module.exports = {
  initialize,
  handleTransaction: provideHandleTransaction(
    contractTracker,
    contractsForChain,
    getTransactionReceipt
  ),
  handleBlock: provideHandleBlock(contractTracker, contractsForChain),
  provideHandleTransaction,
  provideHandleBlock,
  resetIsFirstBlock: () => (isFirstBlock = true),
  resetIsTrained: () => (isTrained = false),
};
