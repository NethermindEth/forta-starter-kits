const { Finding, FindingSeverity, FindingType, Label, EntityType, getEthersProvider } = require("forta-agent");
const { getContractsByChainId, getInitialFundedByTornadoCash, eventABI, addressLimit } = require("./helper");
const { PersistenceHelper } = require("./persistence.helper");

let chainId;
const ethersProvider = getEthersProvider();

const DETECT_TC_FUNDED_ACCOUNT_CONTRACT_INTERACTIONS_KEY =
  "nm-tc-funded-account-bot-detected-contract-interactions-key";
const TOTAL_CONTRACT_INTERACTIONS_KEY = "nm-tc-funded-account-bot-total-contract-interactions-key";

let detectedTcFundedAcctInteractions = 0;
let totalContractInteractions = 0;

const DATABASE_URL = "https://research.forta.network/database/bot/";

let tornadoCashAddresses;

//Adding one placeholder address for testing purposes
let fundedByTornadoCash = new Set(["0x58f970044273705ab3b0e87828e71123a7f95c9d"]);

//Load all properties by chainId
const provideInitialize =
  (ethersProvider, persistenceHelper, detectTcFundedAcctInteractionsKey, totalContractInteractionsKey) => async () => {
    chainId = (await ethersProvider.getNetwork()).chainId;
    tornadoCashAddresses = getContractsByChainId(chainId);
    fundedByTornadoCash = getInitialFundedByTornadoCash(chainId);

    detectedTcFundedAcctInteractions = await persistenceHelper.load(
      detectTcFundedAcctInteractionsKey.concat("-", chainId)
    );
    totalContractInteractions = await persistenceHelper.load(totalContractInteractionsKey.concat("-", chainId));
  };

function provideHandleTranscation(ethersProvider) {
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

    const contractCode = await ethersProvider.getCode(txEvent.to);
    if (contractCode !== "0x") {
      totalContractInteractions += 1;
    } else {
      return findings;
    }

    if (tornadoCashAddresses.includes(txEvent.to)) {
      return findings;
    }

    const hasInteractedWith = fundedByTornadoCash.has(txEvent.from);
    if (hasInteractedWith) {
      detectedTcFundedAcctInteractions += 1;
      const anomalyScore = detectedTcFundedAcctInteractions / totalContractInteractions;

      findings.push(
        Finding.fromObject({
          name: "Tornado Cash funded account interacted with contract",
          description: `${txEvent.from} interacted with contract ${txEvent.to}`,
          alertId: "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            anomalyScore: anomalyScore.toFixed(2) === "0.00" ? anomalyScore.toString() : anomalyScore.toFixed(2),
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

function provideHandleBlock(persistenceHelper, detectTcFundedAcctInteractionsKey, totalContractInteractionsKey) {
  return async (blockEvent) => {
    const findings = [];

    if (blockEvent.blockNumber % 240 === 0) {
      await persistenceHelper.persist(
        detectedTcFundedAcctInteractions,
        detectTcFundedAcctInteractionsKey.concat("-", chainId)
      );
      await persistenceHelper.persist(totalContractInteractions, totalContractInteractionsKey.concat("-", chainId));
    }

    return findings;
  };
}

module.exports = {
  initialize: provideInitialize(
    ethersProvider,
    new PersistenceHelper(DATABASE_URL),
    DETECT_TC_FUNDED_ACCOUNT_CONTRACT_INTERACTIONS_KEY,
    TOTAL_CONTRACT_INTERACTIONS_KEY
  ),
  provideInitialize,
  handleTransaction: provideHandleTranscation(ethersProvider),
  provideHandleTranscation,
  handleBlock: provideHandleBlock(
    new PersistenceHelper(DATABASE_URL),
    DETECT_TC_FUNDED_ACCOUNT_CONTRACT_INTERACTIONS_KEY,
    TOTAL_CONTRACT_INTERACTIONS_KEY
  ),
  provideHandleBlock,
};
