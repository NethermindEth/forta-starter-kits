const { Finding, FindingSeverity, FindingType, Label, EntityType, getEthersProvider } = require("forta-agent");
const { getContractsByChainId, getInitialFundedByTornadoCash, eventABI, addressLimit } = require("./helper");
const { default: calculateAlertRate } = require("bot-alert-rate");
const { ScanCountType } = require("bot-alert-rate");
const { getSecrets } = require("./storage");
const { LRUCache } = require("lru-cache");

let chainId;
let apiKeys;
let isRelevantChain;
const ethersProvider = getEthersProvider();
const BOT_ID = "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a";
const cache = new LRUCache({ max: 10_000 });

let totalContractInteractions = 0;

let tornadoCashAddresses;

//Adding one placeholder address for testing purposes
let fundedByTornadoCash = new Set(["0x58f970044273705ab3b0e87828e71123a7f95c9d"]);

//Load all properties by chainId
const provideInitialize = (ethersProvider) => async () => {
  chainId = (await ethersProvider.getNetwork()).chainId;
  apiKeys = await getSecrets();
  process.env["ZETTABLOCK_API_KEY"] = apiKeys.generalApiKeys.ZETTABLOCK[0];

  //  Optimism is not yet supported by bot-alert-rate package
  isRelevantChain = Number(chainId) === 10;
  tornadoCashAddresses = getContractsByChainId(chainId);
  fundedByTornadoCash = getInitialFundedByTornadoCash(chainId);
};

function provideHandleTranscation(ethersProvider, calculateAlertRate) {
  return async function handleTransaction(txEvent) {
    const findings = [];
    const filteredForFunded = txEvent.filterLog(eventABI, tornadoCashAddresses);
    filteredForFunded.forEach((tx) => {
      const { to } = tx.args;
      if (fundedByTornadoCash.size >= addressLimit) {
        const tempFundedByTornadoCashArray = [...fundedByTornadoCash];
        tempFundedByTornadoCashArray.shift();
        fundedByTornadoCash = new Set(tempFundedByTornadoCashArray);
      }
      fundedByTornadoCash.add(to.toLowerCase());
    });
    if (!txEvent.to) {
      return findings;
    }

    const cacheKey = `contractCode-${chainId}-${txEvent.to}`;

    let contractCode;
    if (cache.has(cacheKey)) {
      contractCode = cache.get(cacheKey);
    } else {
      contractCode = await ethersProvider.getCode(txEvent.to);
      cache.set(cacheKey, contractCode);
    }

    if (contractCode !== "0x") {
      if (isRelevantChain) {
        totalContractInteractions += 1;
      }
    } else {
      return findings;
    }

    if (tornadoCashAddresses.includes(txEvent.to)) {
      return findings;
    }
    const hasInteractedWith = fundedByTornadoCash.has(txEvent.from);
    if (hasInteractedWith) {
      const anomalyScore = await calculateAlertRate(
        Number(chainId),
        BOT_ID,
        "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
        isRelevantChain ? ScanCountType.CustomScanCount : ScanCountType.ContractInteractionCount,
        totalContractInteractions
      );
      findings.push(
        Finding.fromObject({
          name: "Tornado Cash funded account interacted with contract",
          description: `${txEvent.from} interacted with contract ${txEvent.to}`,
          alertId: "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            anomalyScore: anomalyScore.toString(),
          },
          labels: [
            Label.fromObject({
              entity: txEvent.from,
              entityType: EntityType.Address,
              label: "Attacker",
              confidence: 0.7,
            }),
            Label.fromObject({
              entity: txEvent.hash,
              entityType: EntityType.Transaction,
              label: "Suspicious",
              confidence: 0.7,
            }),
          ],
        })
      );
    }
    return findings;
  };
}

module.exports = {
  initialize: provideInitialize(ethersProvider),
  provideInitialize,
  handleTransaction: provideHandleTranscation(ethersProvider, calculateAlertRate),
  provideHandleTranscation,
};
