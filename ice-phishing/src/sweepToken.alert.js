const { ethers } = require("forta-agent");
const { ScanCountType } = require("bot-alert-rate");
const { pullFunctionABI, sweepTokenFunctionABI, BOT_ID } = require("./utils");
const { createSweepTokenAlert } = require("./helper");
const sweepTokenHandleTransaction = async (txEvent, counters, chainId, findings, calculateAlertRate) => {
  const txFrom = ethers.utils.getAddress(txEvent.from);
  const pullFunctions = [...txEvent.filterFunction(pullFunctionABI)];
  const sweepTokenFunctions = [...txEvent.filterFunction(sweepTokenFunctionABI)];
  if (pullFunctions.length && sweepTokenFunctions.length) {
    counters.totalTransfers += 1;
    for (const [i, pullFunction] of pullFunctions.entries()) {
      const { token, value } = pullFunction.args;
      const { token: sweepToken, amountMinimum, recipient } = sweepTokenFunctions[i].args;
      if (token === sweepToken && value.toString() === amountMinimum.toString() && recipient !== txFrom) {
        const anomalyScore = await calculateAlertRate(
          chainId,
          BOT_ID,
          "ICE-PHISHING-PULL-SWEEPTOKEN",
          ScanCountType.CustomScanCount,
          counters.totalTransfers
        );
        console.log(chainId);
        console.log(BOT_ID);
        console.log(ScanCountType.CustomScanCount);
        console.log(counters.totalTransfers);
        console.log(counters);
        console.log("Anomaly score: ", anomalyScore);
        findings.push(createSweepTokenAlert(txFrom, recipient, token, value, anomalyScore, txEvent.hash));
        return findings;
      }
    }
  }
};

module.exports = {
  sweepTokenHandleTransaction,
};
