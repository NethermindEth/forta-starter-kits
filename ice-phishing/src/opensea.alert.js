const { ethers } = require("forta-agent");
const { ScanCountType } = require("bot-alert-rate");
const { upgradedEventABI, BOT_ID } = require("./utils");
const { isOpenseaProxy, getContractCreator, createOpenseaAlert } = require("./helper");
const openseaHandleTransaction = async (txEvent, chainId, counters, findings, calculateAlertRate) => {
  const txFrom = ethers.utils.getAddress(txEvent.from);
  if (Number(chainId) === 1) {
    const upgradedEvents = [...txEvent.filterLog(upgradedEventABI)];
    if (upgradedEvents.length) {
      counters.totalUpgrades += 1;
      // No other events will be emitted in the case of a malicious upgrade
      if (txEvent.logs.length === 1) {
        const {
          address,
          args: { implementation },
        } = upgradedEvents[0];
        const isOpensea = await isOpenseaProxy(address, txEvent.blockNumber, chainId);
        if (isOpensea) {
          const attacker = await getContractCreator(implementation, chainId);
          const anomalyScore = await calculateAlertRate(
            chainId,
            BOT_ID,
            "ICE-PHISHING-OPENSEA-PROXY-UPGRADE",
            ScanCountType.CustomScanCount,
            counters.totalUpgrades
          );
          findings.push(createOpenseaAlert(txFrom, attacker, implementation, anomalyScore, txEvent.hash));
        }
      }
    }
  }
};
module.exports = {
  openseaHandleTransaction,
};
